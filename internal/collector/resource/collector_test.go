package resource

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"testing"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"

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
	src.procs = []procSample{{pid: 1, startMs: 5000, name: "init", cpuSeconds: 50, cpuOK: true, rss: 1024, memOK: true}}
	src.cpuNow = cpuSample{busy: 10, total: 100}

	snap := mustCollect(t, c)

	if len(snap.Processes) != 1 {
		t.Fatalf("got %d processes, want 1", len(snap.Processes))
	}
	p := snap.Processes[0]
	if p.CPUValid || p.CPUPercent != 0 {
		t.Errorf("first sample CPU = %v (valid=%v), want unavailable", p.CPUPercent, p.CPUValid)
	}
	if p.Name != "init" || p.MemoryBytes != 1024 || !p.MemoryValid {
		t.Errorf("unexpected usage: %+v", p)
	}
	if !p.StartTime.Equal(time.UnixMilli(5000)) {
		t.Errorf("start time = %v, want %v", p.StartTime, time.UnixMilli(5000))
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

	if !got[1].CPUValid || !approx(got[1].CPUPercent, 50) {
		t.Errorf("pid 1 CPU = %v (valid=%v), want 50", got[1].CPUPercent, got[1].CPUValid)
	}
	if !got[2].CPUValid || !approx(got[2].CPUPercent, 200) {
		t.Errorf("pid 2 CPU = %v (valid=%v), want 200", got[2].CPUPercent, got[2].CPUValid)
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
	if got[3].CPUValid {
		t.Errorf("reused pid CPU = %v, want unavailable", got[3].CPUPercent)
	}
	if got[4].CPUValid {
		t.Errorf("new pid CPU = %v, want unavailable", got[4].CPUPercent)
	}

	// The exited PID's baseline must be gone: if it comes back it starts at 0.
	clock.advance(time.Second)
	src.procs = []procSample{{pid: 2, name: "back", cpuSeconds: 50, cpuOK: true}}
	got = usageByPID(mustCollect(t, c))
	if got[2].CPUValid {
		t.Errorf("returning pid CPU = %v, want unavailable", got[2].CPUPercent)
	}
}

func TestCollectMarksUnreadableMetricsUnavailable(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{
		{pid: 7, name: "denied"},
		{pid: 8, name: "cpu-only", cpuSeconds: 1, cpuOK: true},
		{pid: 9, name: "mem-only", rss: 2048, memOK: true},
	}
	mustCollect(t, c)

	clock.advance(time.Second)
	src.procs[1].cpuSeconds = 1.5
	got := usageByPID(mustCollect(t, c))

	if len(got) != 3 {
		t.Fatalf("got %d processes, want all 3 kept", len(got))
	}
	if p := got[7]; p.CPUValid || p.MemoryValid || p.Name != "denied" {
		t.Errorf("fully unreadable process: %+v", p)
	}
	if p := got[8]; !p.CPUValid || !approx(p.CPUPercent, 50) || p.MemoryValid {
		t.Errorf("cpu-only process: %+v", p)
	}
	if p := got[9]; p.CPUValid || !p.MemoryValid || p.MemoryBytes != 2048 {
		t.Errorf("mem-only process: %+v", p)
	}
}

// A reading that drops out must not be diffed across: the sample after the
// gap has no baseline, rather than a spike covering the whole gap.
func TestCollectUnavailableCPUDoesNotPoisonBaseline(t *testing.T) {
	c, src, clock := newTestCollector()
	step := func(s procSample) core.ProcessUsage {
		t.Helper()
		clock.advance(time.Second)
		src.procs = []procSample{s}
		return usageByPID(mustCollect(t, c))[1]
	}

	step(procSample{pid: 1, startMs: 10, cpuSeconds: 3600, cpuOK: true})
	if p := step(procSample{pid: 1, startMs: 10, cpuSeconds: 3600.5, cpuOK: true}); !p.CPUValid || !approx(p.CPUPercent, 50) {
		t.Fatalf("steady state: %+v, want 50%%", p)
	}

	// The counter becomes unreadable (reported as zero by the sampler).
	if p := step(procSample{pid: 1, startMs: 10}); p.CPUValid {
		t.Errorf("unreadable sample reported CPU %v", p.CPUPercent)
	}

	// It comes back with an hour of accumulated CPU time.
	if p := step(procSample{pid: 1, startMs: 10, cpuSeconds: 3601, cpuOK: true}); p.CPUValid {
		t.Errorf("first sample after the gap reported CPU %v, want unavailable", p.CPUPercent)
	}
	if p := step(procSample{pid: 1, startMs: 10, cpuSeconds: 3601.25, cpuOK: true}); !p.CPUValid || !approx(p.CPUPercent, 25) {
		t.Errorf("second sample after the gap: %+v, want 25%%", p)
	}
}

func TestCollectReusedPIDDoesNotInheritBaseline(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{{pid: 42, startMs: 1000, name: "old", cpuSeconds: 0.01, cpuOK: true}}
	mustCollect(t, c)

	// Same PID, different process. Its counter is higher than the old
	// baseline, so only the start time tells them apart.
	clock.advance(2 * time.Second)
	src.procs = []procSample{{pid: 42, startMs: 2000, name: "new", cpuSeconds: 1.5, cpuOK: true}}
	p := usageByPID(mustCollect(t, c))[42]
	if p.CPUValid {
		t.Errorf("reused PID inherited a baseline: CPU = %v", p.CPUPercent)
	}

	clock.advance(2 * time.Second)
	src.procs = []procSample{{pid: 42, startMs: 2000, name: "new", cpuSeconds: 2.5, cpuOK: true}}
	p = usageByPID(mustCollect(t, c))[42]
	if !p.CPUValid || !approx(p.CPUPercent, 50) {
		t.Errorf("new process second sample: %+v, want 50%%", p)
	}
}

// Without a creation time the PID is the only identity available; the
// backwards-counter check is then the remaining defence against reuse.
func TestCollectUnknownStartTimeFallsBackToPID(t *testing.T) {
	c, src, clock := newTestCollector()
	src.procs = []procSample{{pid: 5, cpuSeconds: 10, cpuOK: true}}
	if p := mustCollect(t, c).Processes[0]; !p.StartTime.IsZero() {
		t.Errorf("unknown start time reported as %v", p.StartTime)
	}

	clock.advance(time.Second)
	src.procs = []procSample{{pid: 5, cpuSeconds: 10.5, cpuOK: true}}
	if p := mustCollect(t, c).Processes[0]; !p.CPUValid || !approx(p.CPUPercent, 50) {
		t.Errorf("same PID without start time: %+v, want 50%%", p)
	}

	// The start time becoming known is not proof it is the same process.
	clock.advance(time.Second)
	src.procs = []procSample{{pid: 5, startMs: 777, cpuSeconds: 11, cpuOK: true}}
	if p := mustCollect(t, c).Processes[0]; p.CPUValid {
		t.Errorf("identity changed but CPU reported as %v", p.CPUPercent)
	}

	clock.advance(time.Second)
	src.procs = []procSample{{pid: 5, startMs: 777, cpuSeconds: 0.2, cpuOK: true}}
	if p := mustCollect(t, c).Processes[0]; p.CPUValid {
		t.Errorf("counter went backwards but CPU reported as %v", p.CPUPercent)
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
	ctx := context.Background()
	c := NewCollector()

	mustCollect(t, c)
	listed, err := gopsprocess.PidsWithContext(ctx)
	if err != nil {
		t.Fatalf("list pids: %v", err)
	}
	snap := mustCollect(t, c)

	// Processes come and go between the two calls, but a large shortfall
	// means live processes are being dropped for being unreadable.
	if got, floor := len(snap.Processes), len(listed)*9/10; got < floor {
		t.Errorf("snapshot has %d processes but the OS lists %d", got, len(listed))
	}

	self, ok := usageByPID(snap)[int32(os.Getpid())]
	if !ok {
		t.Fatalf("own pid %d missing from %d processes", os.Getpid(), len(snap.Processes))
	}
	if self.Name == "" || !self.MemoryValid || self.MemoryBytes == 0 || !self.CPUValid {
		t.Errorf("own process usage looks wrong: %+v", self)
	}
	if self.StartTime.IsZero() || self.StartTime.After(time.Now()) {
		t.Errorf("own process start time = %v", self.StartTime)
	}

	for _, p := range snap.Processes {
		if !p.MemoryValid && p.MemoryBytes != 0 {
			t.Fatalf("pid %d: unavailable memory carries a value: %+v", p.PID, p)
		}
		if !p.CPUValid && p.CPUPercent != 0 {
			t.Fatalf("pid %d: unavailable CPU carries a value: %+v", p.PID, p)
		}
		// Where a refused query comes back as zeros (macOS), a zero must
		// never be presented as a measurement.
		if runtime.GOOS == "darwin" && p.MemoryValid && p.MemoryBytes == 0 {
			t.Fatalf("pid %d: zero memory reported as measured: %+v", p.PID, p)
		}
	}

	if !snap.System.MemoryValid || snap.System.MemoryUsed > snap.System.MemoryTotal {
		t.Errorf("implausible system memory: %+v", snap.System)
	}
	if snap.System.CPUValid && (snap.System.CPUPercent < 0 || snap.System.CPUPercent > 100) {
		t.Errorf("system CPU out of range: %v", snap.System.CPUPercent)
	}
}
