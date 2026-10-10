package process

import (
	"context"

	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/arafat2020/sentinel/internal/core"
)

type Collector struct{}

type processMetadata struct {
	Name        string
	Executable  string
	CommandLine string
	User        string
}

func NewCollector() *Collector {
	return &Collector{}
}

func init() {
	// On Linux gopsutil derives a process's creation time from the system
	// boot time, which it re-reads on every call. In Docker and LXC guests
	// that boot time is computed as "now - uptime" and truncated to a
	// second, so two reads for the same process can differ by a second;
	// elsewhere it moves if the system clock is stepped. Caching it makes a
	// process's start time, and therefore its identity, stable for as long
	// as Sentinel runs. It has no effect on other platforms.
	gopsprocess.EnableBootTimeCache(true)
}

// FromGopsutil builds the core.Process for a gopsutil process handle. Every
// collector that attaches a process to an event must use it, so that the
// same live process always gets the same ProcessIdentity whichever collector
// reported it.
func FromGopsutil(ctx context.Context, p *gopsprocess.Process) core.Process {
	return buildProcess(p, ctx)
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
