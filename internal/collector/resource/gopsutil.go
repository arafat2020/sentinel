package resource

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
)

// gopsutilSampler reads counters through gopsutil, which already hides the
// per-OS differences behind its own build tags.
type gopsutilSampler struct{}

// procHandle is the slice of a gopsutil process that sampling needs.
type procHandle interface {
	pid() int32
	createTimeMs(ctx context.Context) (int64, error)
	name(ctx context.Context) (string, error)
	exe(ctx context.Context) (string, error)
	cpuSeconds(ctx context.Context) (float64, error)
	memory(ctx context.Context) (rss, vms uint64, err error)
}

type gopsutilProc struct{ p *gopsprocess.Process }

func (g gopsutilProc) pid() int32 { return g.p.Pid }

func (g gopsutilProc) createTimeMs(ctx context.Context) (int64, error) {
	return g.p.CreateTimeWithContext(ctx)
}

func (g gopsutilProc) name(ctx context.Context) (string, error) {
	return g.p.NameWithContext(ctx)
}

func (g gopsutilProc) exe(ctx context.Context) (string, error) {
	return g.p.ExeWithContext(ctx)
}

func (g gopsutilProc) cpuSeconds(ctx context.Context) (float64, error) {
	t, err := g.p.TimesWithContext(ctx)
	if err != nil {
		return 0, err
	}
	if t == nil {
		return 0, errors.New("no cpu times reported")
	}
	return t.User + t.System, nil
}

func (g gopsutilProc) memory(ctx context.Context) (uint64, uint64, error) {
	m, err := g.p.MemoryInfoWithContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	if m == nil {
		return 0, 0, errors.New("no memory info reported")
	}
	return m.RSS, m.VMS, nil
}

// pidAlive reports whether pid still exists. When the OS cannot say, the
// process is assumed alive: hiding a running process is worse than showing a
// dead one for a single refresh.
func pidAlive(ctx context.Context, pid int32) bool {
	exists, err := gopsprocess.PidExistsWithContext(ctx, pid)
	return err != nil || exists
}

func (gopsutilSampler) processes(ctx context.Context) ([]procSample, error) {
	procs, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	samples := make([]procSample, 0, len(procs))

	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if s, ok := sampleProcess(ctx, gopsutilProc{p}, pidAlive, zeroTaskInfoMeansDenied); ok {
			samples = append(samples, s)
		}
	}

	return samples, nil
}

// sampleProcess reads one process. It returns false only when the process is
// confirmed gone; a live process is always returned, with whatever could not
// be read marked as unavailable.
//
// zeroMeansDenied enables the macOS interpretation of an all-zero reading
// (see zeroTaskInfoMeansDenied).
func sampleProcess(
	ctx context.Context,
	h procHandle,
	alive func(context.Context, int32) bool,
	zeroMeansDenied bool,
) (procSample, bool) {
	s := procSample{pid: h.pid()}

	if ms, err := h.createTimeMs(ctx); err == nil && ms > 0 {
		s.startMs = ms
	}

	// A failed name lookup does not mean the process exited: on macOS the
	// lookup also reads the command line, which is denied for other users'
	// processes. The executable path is usually still readable.
	name, nameErr := h.name(ctx)
	if nameErr != nil {
		name = ""
		if exe, err := h.exe(ctx); err == nil && exe != "" {
			name = filepath.Base(exe)
		}
	}
	s.name = name

	cpuSeconds, cpuErr := h.cpuSeconds(ctx)
	rss, vms, memErr := h.memory(ctx)
	s.cpuOK = cpuErr == nil
	s.memOK = memErr == nil

	if zeroMeansDenied && s.cpuOK && s.memOK && cpuSeconds == 0 && rss == 0 && vms == 0 {
		s.cpuOK, s.memOK = false, false
	}

	if s.cpuOK {
		s.cpuSeconds = cpuSeconds
	}
	if s.memOK {
		s.rss = rss
	}

	// Only pay for a liveness check when something looked wrong.
	if (nameErr != nil || (!s.cpuOK && !s.memOK)) && !alive(ctx, s.pid) {
		return procSample{}, false
	}

	return s, true
}

func (gopsutilSampler) cpu(ctx context.Context) (cpuSample, error) {
	times, err := cpu.TimesWithContext(ctx, false)
	if err != nil {
		return cpuSample{}, err
	}
	if len(times) == 0 {
		return cpuSample{}, errors.New("no cpu times reported")
	}

	// Guest time is already included in User/Nice on Linux, so it is left out.
	t := times[0]
	idle := t.Idle + t.Iowait
	total := t.User + t.System + t.Nice + t.Irq + t.Softirq + t.Steal + idle

	return cpuSample{busy: total - idle, total: total}, nil
}

func (gopsutilSampler) memory(ctx context.Context) (uint64, uint64, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0, 0, err
	}
	return vm.Used, vm.Total, nil
}
