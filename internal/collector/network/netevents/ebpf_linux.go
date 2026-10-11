//go:build linux

package netevents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/arafat2020/sentinel/internal/collector/process/procevents"
	"github.com/arafat2020/sentinel/internal/core"
)

const btfPath = "/sys/kernel/btf/vmlinux"

// specHook lets a test alter the programs before they are loaded, to
// exercise a real load failure.
var specHook func(*ebpf.CollectionSpec)

type ebpfSource struct {
	options Options

	// The programs are loaded as a collection rather than into the
	// generated struct, because one of the two accept programs is left
	// out and the struct would insist on both.
	collection *ebpf.Collection
	events     *ebpf.Map
	ports      *ebpf.Map
	counters   *ebpf.Map
	links      []link.Link
	reader     *ringbuf.Reader

	starts *procevents.StartTimes
	clock  *procevents.BootClock
	users  *procevents.UserNames
	// netns is this process's network namespace, which is the one whose
	// packets Sentinel captures.
	netns uint32

	described *describeCache

	connects, failed, accepts, closes, listens, udp atomic.Uint64
	decodeErrors, undescribed                       atomic.Uint64
}

func openEBPF(options Options) (Source, error) {
	if _, err := os.Stat(btfPath); err != nil {
		return nil, fmt.Errorf("missing BTF: %s does not exist (kernel built without CONFIG_DEBUG_INFO_BTF)", btfPath)
	}

	starts, err := procevents.NewStartTimes()
	if err != nil {
		return nil, err
	}

	_ = rlimit.RemoveMemlock()

	spec, err := loadNetwork()
	if err != nil {
		return nil, fmt.Errorf("load error: %w", err)
	}
	spec.Maps[networkMapEvents].MaxEntries = ringBufferEntries(options.RingBufferBytes)

	// inet_csk_accept changed its arguments in Linux 6.10. Keep the
	// program written for the kernel that is running.
	arguments, err := acceptArguments()
	if err != nil {
		return nil, fmt.Errorf("load error: %w", err)
	}
	switch arguments {
	case 4:
		delete(spec.Programs, networkProgOnAccept2)
	case 2:
		delete(spec.Programs, networkProgOnAccept4)
	default:
		return nil, fmt.Errorf("load error: inet_csk_accept takes %d arguments on this kernel, which is not a form this collector knows", arguments)
	}

	if specHook != nil {
		specHook(spec)
	}

	s := &ebpfSource{
		options:   options,
		starts:    starts,
		clock:     procevents.NewBootClock(),
		users:     procevents.NewUserNames(),
		described: newDescribeCache(),
	}

	s.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("missing capability: loading eBPF needs root, or CAP_BPF and CAP_PERFMON (%v)", err)
		}
		return nil, fmt.Errorf("load error: %w", err)
	}

	s.events = s.collection.Maps[networkMapEvents]
	s.ports = s.collection.Maps[networkMapPorts]
	s.counters = s.collection.Maps[networkMapCounters]

	// Without these there is no collection worth the name.
	required := []string{networkProgOnTcpState, networkProgOnAccept4, networkProgOnAccept2, networkProgOnUdpSend, networkProgOnUdpConnect, networkProgOnUdpDestroy}
	// A kernel without IPv6 has nothing for these to attach to.
	optional := []string{networkProgOnUdp6Send, networkProgOnUdp6Connect, networkProgOnUdp6Destroy}

	for _, name := range required {
		program := s.collection.Programs[name]
		if program == nil {
			continue // the accept variant that was not loaded
		}
		if err := s.attach(program); err != nil {
			s.Close()
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				return nil, fmt.Errorf("missing capability: attaching eBPF needs root, or CAP_BPF and CAP_PERFMON (%v)", err)
			}
			return nil, fmt.Errorf("load error: attach %s: %w (fentry/fexit needs BPF trampolines: Linux 5.5 on x86-64, 6.0 on arm64)", program, err)
		}
	}
	for _, name := range optional {
		if program := s.collection.Programs[name]; program != nil {
			_ = s.attach(program)
		}
	}

	s.reader, err = ringbuf.NewReader(s.events)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("load error: open ring buffer: %w", err)
	}

	var self unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &self); err == nil {
		s.netns = uint32(self.Ino)
	}

	return s, nil
}

func (s *ebpfSource) attach(program *ebpf.Program) error {
	attached, err := link.AttachTracing(link.TracingOptions{Program: program})
	if err != nil {
		return err
	}
	s.links = append(s.links, attached)
	return nil
}

// acceptArguments reads from the kernel's own type information how many
// arguments inet_csk_accept takes.
func acceptArguments() (int, error) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, err
	}

	var function *btf.Func
	if err := kernel.TypeByName("inet_csk_accept", &function); err != nil {
		return 0, fmt.Errorf("inet_csk_accept: %w", err)
	}
	proto, ok := function.Type.(*btf.FuncProto)
	if !ok {
		return 0, errors.New("inet_csk_accept has no prototype in BTF")
	}
	return len(proto.Params), nil
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

func (s *ebpfSource) Backend() Backend { return BackendEBPF }

func (s *ebpfSource) Run(ctx context.Context, emit func(core.Event)) error {
	var sample ringbuf.Record
	synced := time.Now()

	for ctx.Err() == nil {
		s.reader.SetDeadline(time.Now().Add(100 * time.Millisecond))

		if err := s.reader.ReadInto(&sample); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if time.Since(synced) > 10*time.Second {
					s.clock.Sync()
					synced = time.Now()
				}
				continue
			}
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("network collector ebpf: %w", err)
		}

		decoded, err := decodeRecord(sample.RawSample)
		if err != nil {
			s.decodeErrors.Add(1)
			continue
		}

		if event, ok := s.translate(ctx, &decoded); ok {
			emit(event)
		}

		if time.Since(synced) > 10*time.Second {
			s.clock.Sync()
			synced = time.Now()
		}
	}

	return nil
}

// process builds the process a record names. Its identity comes from the
// kernel's start time through the process collector's own conversion; the
// rest of its description from whoever can still describe it.
func (s *ebpfSource) process(ctx context.Context, pid, ppid int32, startNanos uint64, uid uint32, comm string) core.Process {
	known := core.Process{
		PID:       pid,
		PPID:      ppid,
		StartTime: s.starts.FromBootNanos(startNanos),
		Name:      procevents.ImageName(comm),
		User:      s.users.Name(uid),
	}

	if s.options.Describe == nil {
		return known
	}
	if cached, ok := s.described.get(known.Identity()); ok {
		return cached
	}

	described, ok := s.options.Describe(ctx, known)
	if !ok || described.Identity() != known.Identity() {
		s.undescribed.Add(1)
		return known
	}

	s.described.put(described)
	return described
}

func (s *ebpfSource) translate(ctx context.Context, r *record) (core.Event, bool) {
	process := s.process(ctx, r.pid, r.ppid, r.startNanos, r.uid, r.comm)

	connection := core.NetworkConnection{
		PID:           r.pid,
		PPID:          r.ppid,
		Protocol:      "tcp",
		LocalAddress:  r.local,
		LocalPort:     uint32(r.lport),
		RemoteAddress: r.remote,
		RemotePort:    uint32(r.rport),
		Process:       &process,
	}
	if r.direction == directionIn {
		connection.Direction = core.DirectionInbound
	} else {
		connection.Direction = core.DirectionOutbound
	}

	event := core.Event{
		Timestamp: s.clock.At(r.bootNanos),
		Type:      core.EventNetworkConnect,
		Process:   &process,
		Network:   &connection,
		Metadata:  map[string]any{MetaNetNS: r.netns},
	}

	switch r.kind {
	case kindConnect:
		// Stamped when the attempt was made, which is when the process
		// acted, not when its outcome became known.
		if r.openedNanos != 0 {
			event.Timestamp = s.clock.At(r.openedNanos)
		}
		if r.errno == 0 {
			connection.State = stateEstablished
			connection.Result = core.ResultOK
			if r.direction == directionIn {
				s.accepts.Add(1)
			} else {
				s.connects.Add(1)
			}
		} else {
			connection.State = stateClose
			connection.Result = resultOf(r.errno)
			if r.errno != ^uint32(0) {
				event.Metadata[MetaErrno] = r.errno
			}
			s.failed.Add(1)
		}

	case kindClose:
		event.Type = core.EventNetworkClose
		connection.State = stateClose
		connection.Result = core.ResultOK
		connection.Transfer = &core.NetworkTransfer{
			BytesSent:     r.bytesSent,
			BytesReceived: r.bytesReceived,
			DurationMs:    durationMs(r.openedNanos, r.bootNanos),
		}
		s.closes.Add(1)

	case kindListen:
		connection.State = stateListen
		connection.RemoteAddress, connection.RemotePort = "", 0
		s.listens.Add(1)

	case kindUnlisten:
		event.Type = core.EventNetworkClose
		connection.State = stateListen
		connection.RemoteAddress, connection.RemotePort = "", 0

	case kindUDP:
		connection.Protocol = "udp"
		connection.State = stateNone
		connection.Result = core.ResultOK
		s.udp.Add(1)

	default:
		return core.Event{}, false
	}

	connection.Timestamp = event.Timestamp
	return event, true
}

// portKey and portOwner mirror struct port_key and struct port_owner.
type portKey struct {
	NetNS    uint32
	Port     uint16
	Protocol uint8
	_        uint8
}

type portOwner struct {
	Start uint64
	PID   uint32
	PPID  uint32
	UID   uint32
	Comm  [16]byte
	_     [4]byte
}

func (s *ebpfSource) PortOwner(protocol string, port uint16) (core.Process, bool) {
	key := portKey{NetNS: s.netns, Port: port, Protocol: protoUDP}
	if protocol == "tcp" {
		key.Protocol = protoTCP
	}

	var owner portOwner
	if err := s.ports.Lookup(&key, &owner); err != nil {
		return core.Process{}, false
	}

	return s.process(context.Background(), int32(owner.PID), int32(owner.PPID), owner.Start, owner.UID, cString(owner.Comm[:])), true
}

func (s *ebpfSource) Stats() Stats {
	stats := Stats{
		Backend:         BackendEBPF,
		Connects:        s.connects.Load(),
		Failed:          s.failed.Load(),
		Accepts:         s.accepts.Load(),
		Closes:          s.closes.Load(),
		Listens:         s.listens.Load(),
		UDP:             s.udp.Load(),
		DecodeErrors:    s.decodeErrors.Load(),
		Undescribed:     s.undescribed.Load(),
		ClockErrorNanos: s.clock.ErrorNanos(),
	}

	counter := func(index uint32) (total uint64) {
		var perCPU []uint64
		if s.counters == nil || s.counters.Lookup(index, &perCPU) != nil {
			return 0
		}
		for _, n := range perCPU {
			total += n
		}
		return total
	}
	stats.KernelDrops, stats.Unowned = counter(0), counter(1)
	stats.SockInserts, stats.UDPInserts = counter(2), counter(3)

	return stats
}

func (s *ebpfSource) Close() error {
	var first error

	if s.reader != nil {
		first = s.reader.Close()
	}
	for _, attached := range s.links {
		if err := attached.Close(); err != nil && first == nil {
			first = err
		}
	}
	if s.collection != nil {
		s.collection.Close()
	}
	return first
}

// describeCache remembers recent descriptions of processes, so that a
// process making thousands of connections a second is looked up once. An
// entry lives for a second: long enough to matter, short enough that a
// process which execs is soon described as what it has become.
type describeCache struct {
	mu      sync.Mutex
	entries map[core.ProcessIdentity]describedProcess
}

type describedProcess struct {
	process core.Process
	until   time.Time
}

const (
	describeCacheSize = 4096
	describeCacheTTL  = time.Second
)

func newDescribeCache() *describeCache {
	return &describeCache{entries: make(map[core.ProcessIdentity]describedProcess)}
}

func (c *describeCache) get(identity core.ProcessIdentity) (core.Process, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[identity]
	if !ok || time.Now().After(entry.until) {
		return core.Process{}, false
	}
	return entry.process, true
}

func (c *describeCache) put(process core.Process) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= describeCacheSize {
		c.entries = make(map[core.ProcessIdentity]describedProcess)
	}
	c.entries[process.Identity()] = describedProcess{process: process, until: time.Now().Add(describeCacheTTL)}
}
