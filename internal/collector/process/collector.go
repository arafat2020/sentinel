package process

import (
	"context"

	"time"

	gopsprocess "github.com/shirou/gopsutil/v3/process"

	"github.com/arafatmannan/sentinel/internal/core"
)

type Collector struct{}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect(ctx context.Context) (*core.ProcessSnapshot, error) {
	processes, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	snapshot := &core.ProcessSnapshot{
		Processes: make([]core.Process, 0, len(processes)),
	}

	for _, p := range processes {
		name, _ := p.NameWithContext(ctx)
		exe, _ := p.ExeWithContext(ctx)
		cmdline, _ := p.CmdlineWithContext(ctx)
		ppid, _ := p.PpidWithContext(ctx)
		startTime, _ := p.CreateTimeWithContext(ctx)
		process := core.Process{
			PID:         p.Pid,
			PPID:        ppid,
			StartTime:   time.UnixMilli(startTime),
			Name:        name,
			Executable:  exe,
			CommandLine: cmdline,
		}

		snapshot.Processes = append(
			snapshot.Processes,
			process,
		)
	}

	return snapshot, nil
}
