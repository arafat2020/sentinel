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
	startMs    int64   // creation time in Unix milliseconds; 0 when unknown
	name       string  // empty when unreadable
	cpuSeconds float64 // cumulative user+system CPU time
	cpuOK      bool    // false when cpuSeconds could not be read
	rss        uint64
	memOK      bool // false when rss could not be read
}

// procKey identifies a process across samples. PIDs are recycled, so the
// creation time is part of the key. When the platform does not report one
// (startMs == 0) the PID alone is used, and the collector falls back to
// noticing that the CPU counter went backwards.
type procKey struct {
	pid     int32
	startMs int64
}

// cpuSample is the host's cumulative CPU time, in seconds.
type cpuSample struct {
	busy  float64
	total float64
}

// sampler reads raw counters from the OS. Processes that vanish while being
// read must be omitted rather than reported as an error; processes that are
// alive but unreadable must be kept, with cpuOK/memOK cleared.
type sampler interface {
	processes(ctx context.Context) ([]procSample, error)
	cpu(ctx context.Context) (cpuSample, error)
	memory(ctx context.Context) (used, total uint64, err error)
}

// Collector turns cumulative OS counters into per-interval usage. CPU
// percentages are derived from the difference between consecutive Collect
// calls, so a process has no valid CPU figure until it has been seen twice
// in a row with a readable counter. It is safe for concurrent use.
type Collector struct {
	src sampler
	now func() time.Time

	mu       sync.Mutex
	prevAt   time.Time
	prevProc map[procKey]float64 // cpuSeconds at prevAt, readable counters only
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

	// Rebuilding the baseline from this sample alone drops exited processes
	// and any process whose counter was unreadable this time, so a gap in
	// readings can never be diffed across.
	nextProc := make(map[procKey]float64, len(samples))

	for _, s := range samples {
		usage := core.ProcessUsage{
			PID:         s.pid,
			Name:        s.name,
			MemoryBytes: s.rss,
			MemoryValid: s.memOK,
		}
		if s.startMs > 0 {
			usage.StartTime = time.UnixMilli(s.startMs)
		}
		if !s.memOK {
			usage.MemoryBytes = 0
		}

		if s.cpuOK {
			key := procKey{pid: s.pid, startMs: s.startMs}

			// A counter that went backwards means the PID was reused by a
			// new process whose start time we could not tell apart; treat
			// it as having no baseline.
			prev, seen := c.prevProc[key]
			if seen && elapsed > 0 && s.cpuSeconds >= prev {
				usage.CPUPercent = (s.cpuSeconds - prev) / elapsed * 100
				usage.CPUValid = true
			}
			nextProc[key] = s.cpuSeconds
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
