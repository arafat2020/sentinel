package process

import (
	"context"

	"time"

	gopsprocess "github.com/shirou/gopsutil/v3/process"

	"github.com/arafat2020/sentinel/internal/core"
)

type Collector struct{}

func NewCollector() *Collector {
	return &Collector{}
}

func buildProcess(
	p *gopsprocess.Process,
	ctx context.Context,
) core.Process {
	name, _ := p.NameWithContext(ctx)
	exe, _ := p.ExeWithContext(ctx)
	cmdline, _ := p.CmdlineWithContext(ctx)
	ppid, _ := p.PpidWithContext(ctx)
	startTime, _ := p.CreateTimeWithContext(ctx)
	username, _ := p.UsernameWithContext(ctx)

	return core.Process{
		PID:         p.Pid,
		PPID:        ppid,
		StartTime:   time.UnixMilli(startTime),
		Name:        name,
		Executable:  exe,
		CommandLine: cmdline,
		User:        username,
	}
}

func (c *Collector) Collect(
	ctx context.Context,
) (*core.ProcessSnapshot, error) {
	processes, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	snapshot := &core.ProcessSnapshot{
		Processes: make([]core.Process, 0, len(processes)),
	}

	for _, p := range processes {
		snapshot.Processes = append(
			snapshot.Processes,
			buildProcess(p, ctx),
		)
	}

	return snapshot, nil
}
