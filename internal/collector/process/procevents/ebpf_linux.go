//go:build linux

package procevents

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// The eBPF backend needs BPF ring buffers and bpf_ktime_get_boot_ns, both
// new in Linux 5.8, and BTF for CO-RE and BTF-typed tracepoints.
const (
	ebpfMinMajor = 5
	ebpfMinMinor = 8

	btfPath = "/sys/kernel/btf/vmlinux"
)

// ebpfSpecHook lets a test alter the programs before they are loaded, to
// exercise a real load failure.
var ebpfSpecHook func(*ebpf.CollectionSpec)

type ebpfBackend struct {
	objects processObjects
	links   []link.Link
	reader  *ringbuf.Reader

	starts *StartTimes
	clock  *wallClock
	users  *userCache

	sample       ringbuf.Record
	decodeErrors atomic.Uint64
}

func openEBPF(options Options) (Source, error) {
	major, minor, release, err := kernelRelease()
	if err != nil {
		return nil, err
	}
	if major < ebpfMinMajor || (major == ebpfMinMajor && minor < ebpfMinMinor) {
		return nil, fmt.Errorf("kernel too old: %s is older than %d.%d", release, ebpfMinMajor, ebpfMinMinor)
	}
	if _, err := os.Stat(btfPath); err != nil {
		return nil, fmt.Errorf("missing BTF: %s does not exist (kernel built without CONFIG_DEBUG_INFO_BTF)", btfPath)
	}

	starts, err := NewStartTimes()
	if err != nil {
		return nil, err
	}

	// Kernels before 5.11 charge BPF memory against RLIMIT_MEMLOCK.
	_ = rlimit.RemoveMemlock()

	spec, err := loadProcess()
	if err != nil {
		return nil, fmt.Errorf("load error: %w", err)
	}
	spec.Maps[processMapEvents].MaxEntries = ringBufferEntries(options.RingBufferBytes)
	if ebpfSpecHook != nil {
		ebpfSpecHook(spec)
	}

	b := &ebpfBackend{
		starts: starts,
		clock:  newWallClock(unix.CLOCK_BOOTTIME),
		users:  newUserCache(),
	}

	if err := spec.LoadAndAssign(&b.objects, nil); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("missing capability: loading eBPF needs root, or CAP_BPF and CAP_PERFMON (%v)", err)
		}
		return nil, fmt.Errorf("load error: %w", err)
	}

	for _, program := range []*ebpf.Program{b.objects.OnFork, b.objects.OnExec, b.objects.OnExit} {
		attached, err := link.AttachTracing(link.TracingOptions{Program: program})
		if err != nil {
			b.close()
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				return nil, fmt.Errorf("missing capability: attaching eBPF needs root, or CAP_BPF and CAP_PERFMON (%v)", err)
			}
			return nil, fmt.Errorf("load error: attach %s: %w", program, err)
		}
		b.links = append(b.links, attached)
	}

	b.reader, err = ringbuf.NewReader(b.objects.Events)
	if err != nil {
		b.close()
		return nil, fmt.Errorf("load error: open ring buffer: %w", err)
	}

	return &source{name: BackendEBPF, options: options, backend: b, users: b.users}, nil
}

// ringBufferEntries rounds a requested size up to what the kernel accepts: a
// power of two that is a multiple of the page size.
func ringBufferEntries(bytes int) uint32 {
	size := uint32(os.Getpagesize())
	for size < uint32(bytes) && size < 1<<30 {
		size <<= 1
	}
	return size
}

func (b *ebpfBackend) next(event *raw) error {
	for {
		b.reader.SetDeadline(time.Now().Add(idleWait))

		if err := b.reader.ReadInto(&b.sample); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return errIdle
			}
			return err
		}

		decoded, err := decodeRecord(b.sample.RawSample)
		if err != nil {
			b.decodeErrors.Add(1)
			continue
		}

		b.translate(&decoded, event)
		return nil
	}
}

// translate turns a record into a raw event: kernel times become wall-clock
// time and the start time every collector agrees on, the user ID becomes a
// name, and an exec gets its resolved program path.
func (b *ebpfBackend) translate(r *record, event *raw) {
	*event = raw{
		pid:   r.pid,
		ppid:  r.ppid,
		start: b.starts.FromBootNanos(r.startNanos),
		at:    b.clock.at(r.bootNanos),
		comm:  r.comm,
	}

	switch r.kind {
	case recordKindFork:
		event.kind = rawFork
		event.user = b.users.name(r.uid)

	case recordKindExit:
		event.kind = rawExit

	case recordKindExec:
		event.kind = rawExec
		event.user = b.users.name(r.uid)
		event.cmdline, event.argv0 = r.cmdline, r.argv0
		event.argsTruncated = r.flags&recordArgsTruncated != 0

		// /proc/<pid>/exe is the program actually loaded, with links
		// resolved, and is what every other collector reports. It is
		// gone if the process already is; the path that was passed to
		// execve came from the kernel with the event and is used then.
		if exe, ok := readExe(r.pid); ok {
			event.exe = exe
		} else {
			event.exe = r.filename
			if event.exe != "" && !filepath.IsAbs(event.exe) {
				event.partial = true
			}
		}

		if r.flags&recordArgsUnreadable != 0 {
			if cmdline, argv0, ok := readCmdline(r.pid); ok && cmdline != "" {
				event.cmdline, event.argv0 = cmdline, argv0
			} else {
				event.partial = true
			}
		}
	}
}

func (b *ebpfBackend) stats(stats *Stats) {
	stats.DecodeErrors = b.decodeErrors.Load()
	stats.ClockErrorNanos = b.clock.bound.Load()

	if b.objects.Drops == nil {
		return
	}
	for kind := uint32(0); kind < 3; kind++ {
		var perCPU []uint64
		if err := b.objects.Drops.Lookup(kind, &perCPU); err != nil {
			continue
		}
		for _, count := range perCPU {
			stats.KernelDrops += count
		}
	}
}

func (b *ebpfBackend) syncClock() { b.clock.sync() }

func (b *ebpfBackend) close() error {
	var first error

	if b.reader != nil {
		first = b.reader.Close()
	}
	for _, attached := range b.links {
		if err := attached.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := b.objects.Close(); err != nil && first == nil {
		first = err
	}

	return first
}
