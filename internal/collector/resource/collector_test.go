package resource

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeSampler struct {
	procs   []procSample
	procErr error
	cpuNow  cpuSample
	cpuErr  error
	memUsed uint64
	memTot  uint64
	memErr  error
}

func (f *fakeSampler) processes(context.Context) ([]procSample, error) {
	return f.procs, f.procErr
}

func (f *fakeSampler) cpu(context.Context) (cpuSample, error) {
	return f.cpuNow, f.cpuErr
}

func (f *fakeSampler) memory(context.Context) (uint64, uint64, error) {
	return f.memUsed, f.memTot, f.memErr
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestCollector() (*Collector, *fakeSampler, *fakeClock) {
	src := &fakeSampler{memUsed: 4, memTot: 8}
	clock := &fakeClock{t: time.Unix(1_000, 0)}
	return newCollector(src, clock.now), src, clock
}

func mustCollect(t *testing.T, c *Collector) *core.ResourceSnapshot {
	t.Helper()
	snap, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return snap
}

func usageByPID(snap *core.ResourceSnapshot) map[int32]core.ProcessUsage {
	out := make(map[int32]core.ProcessUsage, len(snap.Processes))
	for _, p := range snap.Processes {
		out[p.PID] = p
	}
	return out
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCollectFirstSampleHasNoCPUBaseline(t *testing.T) {
	c, src, _ := newTestCollector()
	src.procs = []procSample{{pid: 1, name: "init", cpuSeconds: 50, cpuOK: true, rss: 1024}}
	src.cpuNow = cpuSample{busy: 10, total: 100}

	snap := mustCollect(t, c)

	if len(snap.Processes) != 1 {
		t.Fatalf("got %d processes, want 1", len(snap.Processes))
	}
	p := snap.Processes[0]
	if p.CPUPercent != 0 {
		t.Errorf("first sample CPU = %v, want 0", p.CPUPercent)
	}
	if p.Name != "init" || p.MemoryBytes != 1024 {
		t.Errorf("unexpected usage: %+v", p)
	}
	if snap.System.CPUValid {
		t.Error("system CPU must be invalid without a previous sample")
	}
	if !snap.System.MemoryValid || snap.System.MemoryUsed != 4 || snap.System.MemoryTotal != 8 {
		t.Errorf("unexpected memory: %+v", snap.System)
	}
}

func TestCollectComputesCPUFromDeltas(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{
		{pid: 1, name: "a", cpuSeconds: 10, cpuOK: true},
		{pid: 2, name: "b", cpuSeconds: 20, cpuOK: true},
	}
	src.cpuNow = cpuSample{busy: 100, total: 1000}
	mustCollect(t, c)

	clock.advance(2 * time.Second)
	src.procs = []procSample{
		{pid: 1, name: "a", cpuSeconds: 11, cpuOK: true}, // 1s over 2s  → 50%
		{pid: 2, name: "b", cpuSeconds: 24, cpuOK: true}, // 4s over 2s  → 200%
	}
	src.cpuNow = cpuSample{busy: 104, total: 1016} // 4 of 16 → 25%

	snap := mustCollect(t, c)
	got := usageByPID(snap)

	if !approx(got[1].CPUPercent, 50) {
		t.Errorf("pid 1 CPU = %v, want 50", got[1].CPUPercent)
	}
	if !approx(got[2].CPUPercent, 200) {
		t.Errorf("pid 2 CPU = %v, want 200", got[2].CPUPercent)
	}
	if !snap.System.CPUValid || !approx(snap.System.CPUPercent, 25) {
		t.Errorf("system CPU = %+v, want valid 25", snap.System)
	}
}

func TestCollectHandlesExitedAndReusedPIDs(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{
		{pid: 1, name: "stays", cpuSeconds: 5, cpuOK: true},
		{pid: 2, name: "exits", cpuSeconds: 5, cpuOK: true},
		{pid: 3, name: "old", cpuSeconds: 90, cpuOK: true},
	}
	mustCollect(t, c)

	clock.advance(time.Second)
	src.procs = []procSample{
		{pid: 1, name: "stays", cpuSeconds: 5.5, cpuOK: true},
		{pid: 3, name: "reused", cpuSeconds: 0.1, cpuOK: true}, // counter went backwards
		{pid: 4, name: "new", cpuSeconds: 3, cpuOK: true},
	}
	got := usageByPID(mustCollect(t, c))

	if _, ok := got[2]; ok {
		t.Error("exited process still reported")
	}
	if !approx(got[1].CPUPercent, 50) {
		t.Errorf("pid 1 CPU = %v, want 50", got[1].CPUPercent)
	}
	if got[3].CPUPercent != 0 {
		t.Errorf("reused pid CPU = %v, want 0", got[3].CPUPercent)
	}
	if got[4].CPUPercent != 0 {
		t.Errorf("new pid CPU = %v, want 0", got[4].CPUPercent)
	}

	// The exited PID's baseline must be gone: if it comes back it starts at 0.
	clock.advance(time.Second)
	src.procs = []procSample{{pid: 2, name: "back", cpuSeconds: 50, cpuOK: true}}
	got = usageByPID(mustCollect(t, c))
	if got[2].CPUPercent != 0 {
		t.Errorf("returning pid CPU = %v, want 0", got[2].CPUPercent)
	}
}

func TestCollectKeepsProcessWhenCPUUnreadable(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{{pid: 7, name: "denied", rss: 2048}}
	mustCollect(t, c)

	clock.advance(time.Second)
	got := usageByPID(mustCollect(t, c))

	p, ok := got[7]
	if !ok {
		t.Fatal("process with unreadable CPU was dropped")
	}
	if p.CPUPercent != 0 || p.MemoryBytes != 2048 {
		t.Errorf("unexpected usage: %+v", p)
	}
}

func TestCollectProcessListErrorPreservesBaseline(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{{pid: 1, name: "a", cpuSeconds: 10, cpuOK: true}}
	mustCollect(t, c)

	clock.advance(time.Second)
	src.procErr = errors.New("boom")
	if snap, err := c.Collect(context.Background()); err == nil || snap != nil {
		t.Fatalf("Collect = %v, %v; want nil snapshot and an error", snap, err)
	}

	clock.advance(time.Second)
	src.procErr = nil
	src.procs = []procSample{{pid: 1, name: "a", cpuSeconds: 11, cpuOK: true}}
	got := usageByPID(mustCollect(t, c))

	// 1s of CPU over the 2s since the last successful sample.
	if !approx(got[1].CPUPercent, 50) {
		t.Errorf("CPU after failed sample = %v, want 50", got[1].CPUPercent)
	}
}

func TestCollectSystemMetricErrorsAreNotFatal(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{{pid: 1, name: "a"}}
	src.cpuNow = cpuSample{busy: 1, total: 10}
	mustCollect(t, c)

	clock.advance(time.Second)
	src.cpuErr = errors.New("no cpu")
	src.memErr = errors.New("no mem")
	snap := mustCollect(t, c)

	if snap.System.CPUValid || snap.System.MemoryValid {
		t.Errorf("system metrics should be invalid: %+v", snap.System)
	}
	if len(snap.Processes) != 1 {
		t.Errorf("got %d processes, want 1", len(snap.Processes))
	}

	// After a CPU read failure the next good read is only a new baseline.
	clock.advance(time.Second)
	src.cpuErr = nil
	src.cpuNow = cpuSample{busy: 5, total: 20}
	if snap := mustCollect(t, c); snap.System.CPUValid {
		t.Error("system CPU should need a fresh baseline after an error")
	}
}

func TestCollectCancelledContext(t *testing.T) {
	c, src, _ := newTestCollector()
	src.procs = []procSample{{pid: 1, name: "a"}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Collect error = %v, want context.Canceled", err)
	}
}

// TestCollectLive exercises the real gopsutil sampler against this host.
func TestCollectLive(t *testing.T) {
	c := NewCollector()

	mustCollect(t, c)
	snap := mustCollect(t, c)

	self, ok := usageByPID(snap)[int32(os.Getpid())]
	if !ok {
		t.Fatalf("own pid %d missing from %d processes", os.Getpid(), len(snap.Processes))
	}
	if self.Name == "" || self.MemoryBytes == 0 {
		t.Errorf("own process usage looks empty: %+v", self)
	}
	if !snap.System.MemoryValid || snap.System.MemoryUsed > snap.System.MemoryTotal {
		t.Errorf("implausible system memory: %+v", snap.System)
	}
	if snap.System.CPUValid && (snap.System.CPUPercent < 0 || snap.System.CPUPercent > 100) {
		t.Errorf("system CPU out of range: %v", snap.System.CPUPercent)
	}
}
