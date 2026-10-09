package resource

import (
	"context"
	"errors"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
)

// gopsutilSampler reads counters through gopsutil, which already hides the
// per-OS differences behind its own build tags.
type gopsutilSampler struct{}

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

		// The name needs no special privilege, so failing to read it means
		// the process exited after it was listed.
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}

		s := procSample{pid: p.Pid, name: name}

		// CPU and memory can be denied for other users' processes; keep the
		// row and report what is available.
		if t, err := p.TimesWithContext(ctx); err == nil && t != nil {
			s.cpuSeconds = t.User + t.System
			s.cpuOK = true
		}
		if m, err := p.MemoryInfoWithContext(ctx); err == nil && m != nil {
			s.rss = m.RSS
		}

		samples = append(samples, s)
	}

	return samples, nil
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
