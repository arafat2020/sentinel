package process

import (
	"context"

	gopsprocess "github.com/shirou/gopsutil/v3/process"

	"github.com/arafatmannan/sentinel/internal/core"
)

type Collector struct{}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect(ctx context.Context) ([]core.Event, error) {
	processes, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]core.Event, 0, len(processes))

	for _, p := range processes {
		name, _ := p.NameWithContext(ctx)
		exe, _ := p.ExeWithContext(ctx)
		cmdline, _ := p.CmdlineWithContext(ctx)
		ppid, _ := p.PpidWithContext(ctx)

		event := core.Event{
			Type: core.EventProcessStart,
			Process: &core.ProcessEvent{
				PID:         p.Pid,
				PPID:        ppid,
				Name:        name,
				Executable:  exe,
				CommandLine: cmdline,
			},
		}

		events = append(events, event)
	}

	return events, nil
}
