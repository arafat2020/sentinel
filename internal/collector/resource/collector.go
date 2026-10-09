// Package resource collects live CPU and memory usage for the host and its
// processes. It is independent of the security telemetry collectors.
package resource

import (
	"context"
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// procSample is one process's raw counters at a point in time.
type procSample struct {
	pid        int32
	name       string
	cpuSeconds float64 // cumulative user+system CPU time
	cpuOK      bool    // false when cpuSeconds could not be read
	rss        uint64
}

// cpuSample is the host's cumulative CPU time, in seconds.
type cpuSample struct {
	busy  float64
	total float64
}

// sampler reads raw counters from the OS. Processes that vanish while being
// read must be omitted rather than reported as an error.
type sampler interface {
	processes(ctx context.Context) ([]procSample, error)
	cpu(ctx context.Context) (cpuSample, error)
	memory(ctx context.Context) (used, total uint64, err error)
}

// Collector turns cumulative OS counters into per-interval usage. CPU
// percentages are derived from the difference between consecutive Collect
// calls, so the first call reports 0% for every process and no system CPU.
// It is safe for concurrent use.
type Collector struct {
	src sampler
	now func() time.Time

	mu       sync.Mutex
	prevAt   time.Time
	prevProc map[int32]float64 // pid → cpuSeconds at prevAt
	prevCPU  cpuSample
	hasCPU   bool
}

func NewCollector() *Collector {
	return newCollector(gopsutilSampler{}, time.Now)
}

func newCollector(src sampler, now func() time.Time) *Collector {
	return &Collector{src: src, now: now}
}

func (c *Collector) Collect(
	ctx context.Context,
) (*core.ResourceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	samples, err := c.src.processes(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	at := c.now()
	elapsed := at.Sub(c.prevAt).Seconds()

	snapshot := &core.ResourceSnapshot{
		Timestamp: at,
		Processes: make([]core.ProcessUsage, 0, len(samples)),
	}

	// Rebuilding the baseline from this sample alone drops exited processes.
	nextProc := make(map[int32]float64, len(samples))

	for _, s := range samples {
		usage := core.ProcessUsage{
			PID:         s.pid,
			Name:        s.name,
			MemoryBytes: s.rss,
		}

		if s.cpuOK {
			// A counter that went backwards means the PID was reused by a
			// new process; treat it as having no baseline.
			prev, seen := c.prevProc[s.pid]
			if seen && elapsed > 0 && s.cpuSeconds >= prev {
				usage.CPUPercent = (s.cpuSeconds - prev) / elapsed * 100
			}
			nextProc[s.pid] = s.cpuSeconds
		}

		snapshot.Processes = append(snapshot.Processes, usage)
	}

	c.prevProc = nextProc
	c.prevAt = at

	if cur, err := c.src.cpu(ctx); err == nil {
		if total := cur.total - c.prevCPU.total; c.hasCPU && total > 0 {
			snapshot.System.CPUPercent = clampPercent((cur.busy - c.prevCPU.busy) / total * 100)
			snapshot.System.CPUValid = true
		}
		c.prevCPU = cur
		c.hasCPU = true
	} else {
		c.hasCPU = false
	}

	if used, total, err := c.src.memory(ctx); err == nil && total > 0 {
		snapshot.System.MemoryUsed = used
		snapshot.System.MemoryTotal = total
		snapshot.System.MemoryValid = true
	}

	return snapshot, nil
}

func clampPercent(p float64) float64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}
