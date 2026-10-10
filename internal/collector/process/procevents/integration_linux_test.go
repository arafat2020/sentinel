//go:build linux && integration

package procevents

// These tests load eBPF programs and open a netlink connector, so they need a
// real Linux kernel and root:
//
//	sudo go test -tags integration ./internal/collector/process/...

import (
	"context"
	"os"
	osexec "os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	gopsprocess "github.com/shirou/gopsutil/v4/process"

	processcollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/core"
	lifecycle "github.com/arafat2020/sentinel/internal/detection/process"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// capture collects the events a backend delivers.
type capture struct {
	mu     sync.Mutex
	events []core.Event
	stats  func() Stats
}

func (c *capture) add(event core.Event) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func (c *capture) snapshot() []core.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]core.Event(nil), c.events...)
}

// byPID indexes the captured events of one type by PID.
func (c *capture) byPID(eventType core.EventType) map[int32]core.Event {
	found := make(map[int32]core.Event)
	for _, event := range c.snapshot() {
		if event.Type == eventType {
			found[event.Process.PID] = event
		}
	}
	return found
}

// waitFor polls until done reports true or the timeout passes.
func waitFor(timeout time.Duration, done func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

func snapshotProcesses(ctx context.Context) ([]core.Process, error) {
	snapshot, err := processcollector.NewCollector().Collect(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Processes, nil
}

// pollInterval is the interval the entrypoints poll at.
const pollInterval = 2 * time.Second

// start runs a backend until the test ends. For BackendPoll it runs the same
// collector and detector the poll monitor uses, at the same interval.
func start(t *testing.T, backend Backend) *capture {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	recorded := &capture{stats: func() Stats { return Stats{Backend: backend} }}
	done := make(chan struct{})

	if backend == BackendPoll {
		collector, detector := processcollector.NewCollector(), lifecycle.NewLifecycleDetector()
		poll := func() {
			if snapshot, err := collector.Collect(ctx); err == nil {
				for _, event := range detector.Detect(snapshot) {
					recorded.add(event)
				}
			}
		}
		poll()

		go func() {
			defer close(done)
			ticker := time.NewTicker(pollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					poll()
				}
			}
		}()

		t.Cleanup(func() { cancel(); <-done })
		return recorded
	}

	source, _, err := Open(backend, Options{Snapshot: snapshotProcesses})
	if err != nil {
		cancel()
		t.Fatalf("open %s: %v", backend, err)
	}
	recorded.stats = source.Stats

	seed, err := snapshotProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer close(done)
		if err := source.Run(ctx, seed, recorded.add); err != nil {
			t.Errorf("%s stopped: %v", backend, err)
		}
	}()

	t.Cleanup(func() {
		cancel()
		<-done
		source.Close()
	})

	return recorded
}

func truePath(t *testing.T) string {
	t.Helper()
	path, err := osexec.LookPath("true")
	if err != nil {
		t.Skip("no true(1) on this host")
	}
	return path
}

// A process that exits within a millisecond or two must still be seen. Each
// backend is asked to report 2,000 runs of true(1), started as fast as eight
// workers can start them.
func TestShortLivedProcessCapture(t *testing.T) {
	requireRoot(t)
	binary := truePath(t)

	const runs, workers = 2000, 8

	for _, backend := range []Backend{BackendEBPF, BackendProcConnector, BackendPoll} {
		t.Run(string(backend), func(t *testing.T) {
			recorded := start(t, backend)
			time.Sleep(200 * time.Millisecond)

			var mu sync.Mutex
			pids := make(map[int32]bool, runs)

			began := time.Now()
			var wg sync.WaitGroup
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < runs/workers; i++ {
						cmd := osexec.Command(binary)
						if err := cmd.Start(); err != nil {
							t.Error(err)
							return
						}
						mu.Lock()
						pids[int32(cmd.Process.Pid)] = true
						mu.Unlock()
						cmd.Wait()
					}
				}()
			}
			wg.Wait()
			elapsed := time.Since(began)

			if len(pids) != runs {
				t.Fatalf("started %d distinct processes, want %d", len(pids), runs)
			}

			count := func() (starts, complete, exits int) {
				started, exited := recorded.byPID(core.EventProcessStart), recorded.byPID(core.EventProcessExit)
				for pid := range pids {
					if event, ok := started[pid]; ok {
						starts++
						if event.Process.Name == "true" && strings.HasSuffix(event.Process.Executable, "/true") && event.Metadata[MetaPartial] == nil {
							complete++
						}
					}
					if _, ok := exited[pid]; ok {
						exits++
					}
				}
				return
			}

			settle := time.Second
			if backend == BackendPoll {
				settle = 2*pollInterval + time.Second
			}
			waitFor(5*time.Second, func() bool { _, _, exits := count(); return exits == runs })
			time.Sleep(settle)

			starts, complete, exits := count()
			stats := recorded.stats()
			t.Logf("%s: %d runs in %v (%.0f/s): %d starts (%.2f%%), %d described as true(1) (%.2f%%), %d exits; kernel drops %d, partial %d",
				backend, runs, elapsed.Round(time.Millisecond), float64(runs)/elapsed.Seconds(),
				starts, 100*float64(starts)/runs, complete, 100*float64(complete)/runs, exits,
				stats.KernelDrops, stats.Partial)

			if backend == BackendEBPF {
				if float64(complete) < 0.999*runs {
					t.Errorf("eBPF described %d of %d runs as true(1), want at least 99.9%%", complete, runs)
				}
				if exits != starts {
					t.Errorf("eBPF saw %d starts but %d exits", starts, exits)
				}
			}
		})
	}
}

// The start time an event-driven backend reports must be the identical value
// every other collector reports for that process. Compared here, for more
// than 200 long-lived processes, against what the snapshot, the resolver and
// attribution all use: process.FromGopsutil.
func TestStartTimeEqualsEveryOtherCollectors(t *testing.T) {
	requireRoot(t)

	const spawned = 220

	for _, backend := range []Backend{BackendEBPF, BackendProcConnector} {
		t.Run(string(backend), func(t *testing.T) {
			recorded := start(t, backend)
			time.Sleep(200 * time.Millisecond)

			ctx, cancel := context.WithCancel(context.Background())

			var sleepers []*osexec.Cmd
			defer func() {
				cancel() // kills them
				for _, cmd := range sleepers {
					cmd.Wait()
				}
			}()

			pids := make(map[int32]bool, spawned)
			for i := 0; i < spawned; i++ {
				cmd := osexec.CommandContext(ctx, "sleep", "120")
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				pids[int32(cmd.Process.Pid)] = true
				sleepers = append(sleepers, cmd)
			}

			if !waitFor(10*time.Second, func() bool {
				started := recorded.byPID(core.EventProcessStart)
				for pid := range pids {
					if _, ok := started[pid]; !ok {
						return false
					}
				}
				return true
			}) {
				t.Fatalf("%s did not report all %d processes", backend, spawned)
			}

			started := recorded.byPID(core.EventProcessStart)
			resolver := processcollector.NewResolver()
			compared, mismatches := 0, 0

			for pid := range pids {
				event := started[pid]

				handle, err := gopsprocess.NewProcess(pid)
				if err != nil {
					t.Fatalf("pid %d: %v", pid, err)
				}
				polled := processcollector.FromGopsutil(ctx, handle)

				resolved, err := resolver.Resolve(ctx, pid)
				if err != nil {
					t.Fatalf("resolve pid %d: %v", pid, err)
				}

				compared++
				// Identity is a map key, so this is the comparison
				// that matters: ==, not Equal.
				if event.Process.Identity() != polled.Identity() || event.Process.Identity() != resolved.Identity() {
					mismatches++
					t.Errorf("pid %d: %s says %v (%d ms), snapshot says %v (%d ms), resolver says %v",
						pid, backend, event.Process.StartTime, event.Process.StartTime.UnixMilli(),
						polled.StartTime, polled.StartTime.UnixMilli(), resolved.StartTime)
				}
				if event.Process.Name != polled.Name || event.Process.Executable != polled.Executable ||
					event.Process.CommandLine != polled.CommandLine || event.Process.User != polled.User || event.Process.PPID != polled.PPID {
					t.Errorf("pid %d: %s describes %+v\n         the snapshot describes %+v", pid, backend, *event.Process, polled)
				}
			}

			// Every process already running goes through the same
			// conversion from its /proc start time.
			starts, err := NewStartTimes()
			if err != nil {
				t.Fatal(err)
			}
			running, err := snapshotProcesses(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, process := range running {
				if pids[process.PID] {
					continue
				}
				_, _, ticks, err := readStat(int(process.PID))
				if err != nil {
					continue // exited since the snapshot
				}
				compared++
				if converted := starts.FromTicks(ticks); converted != process.StartTime {
					mismatches++
					t.Errorf("pid %d (%s): converted %v, snapshot %v", process.PID, process.Name, converted, process.StartTime)
				}
			}

			t.Logf("%s: compared %d processes (%d spawned, %d already running): %d mismatches",
				backend, compared, spawned, compared-spawned, mismatches)
			if compared < 200 {
				t.Errorf("only %d processes compared", compared)
			}
		})
	}
}

// The eBPF backend reads the arguments in the kernel, so it has them for a
// process that is gone long before userspace hears of it.
func TestArgumentsOfProcessThatExitsAtOnce(t *testing.T) {
	requireRoot(t)
	binary := truePath(t)

	recorded := start(t, BackendEBPF)
	time.Sleep(200 * time.Millisecond)

	args := []string{"--sentinel-argv-test", "second argument", "", "last"}
	const attempts = 50
	pids := make([]int32, 0, attempts)

	for i := 0; i < attempts; i++ {
		cmd := osexec.Command(binary, args...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, int32(cmd.Process.Pid))
		cmd.Wait()
	}

	waitFor(5*time.Second, func() bool { return len(recorded.byPID(core.EventProcessExit)) >= attempts })
	started, exited := recorded.byPID(core.EventProcessStart), recorded.byPID(core.EventProcessExit)

	// As the polling collector would print it: joined by spaces, the empty
	// argument dropped.
	wantCmdline := binary + " --sentinel-argv-test second argument last"
	user := "root"

	var longest, shortest time.Duration = 0, time.Hour
	fallbacks := 0
	for _, pid := range pids {
		begin, ok := started[pid]
		if !ok {
			t.Fatalf("pid %d: no PROCESS_START", pid)
		}
		end, ok := exited[pid]
		if !ok {
			t.Fatalf("pid %d: no PROCESS_EXIT", pid)
		}

		process := begin.Process
		if process.CommandLine != wantCmdline {
			t.Errorf("pid %d: command line %q, want %q", pid, process.CommandLine, wantCmdline)
		}
		if process.Name != "true" || process.PPID != int32(os.Getpid()) || process.User != user {
			t.Errorf("pid %d: described as %+v", pid, *process)
		}
		if !strings.HasSuffix(process.Executable, "/true") || !strings.HasPrefix(process.Executable, "/") {
			t.Errorf("pid %d: executable %q", pid, process.Executable)
		}
		if begin.Metadata[MetaPartial] != nil {
			fallbacks++
		}

		lifetime := end.Timestamp.Sub(begin.Timestamp)
		if lifetime > longest {
			longest = lifetime
		}
		if lifetime < shortest {
			shortest = lifetime
		}
	}

	t.Logf("%d processes, each reported with its full command line; exec-to-exit between %v and %v; %d marked partial",
		attempts, shortest, longest, fallbacks)
	if shortest > 5*time.Millisecond {
		t.Errorf("the shortest-lived process lasted %v; the test did not exercise a process that exits within 5 ms", shortest)
	}
}

// Event timestamps are when the kernel says the thing happened. A process
// started between two readings of the wall clock must be stamped between
// them, give or take the conversion error.
func TestEventTimestampsAreWhenItHappened(t *testing.T) {
	requireRoot(t)
	binary := truePath(t)

	for _, backend := range []Backend{BackendEBPF, BackendProcConnector} {
		t.Run(string(backend), func(t *testing.T) {
			recorded := start(t, backend)
			time.Sleep(200 * time.Millisecond)

			type window struct{ before, after time.Time }
			windows := make(map[int32]window)

			for i := 0; i < 200; i++ {
				cmd := osexec.Command(binary)
				before := time.Now()
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				cmd.Wait()
				windows[int32(cmd.Process.Pid)] = window{before, time.Now()}
			}

			waitFor(5*time.Second, func() bool { return len(recorded.byPID(core.EventProcessExit)) >= len(windows) })

			var worst time.Duration
			checked := 0
			for _, event := range recorded.snapshot() {
				w, ours := windows[event.Process.PID]
				if !ours {
					continue
				}
				checked++

				var outside time.Duration
				switch {
				case event.Timestamp.Before(w.before):
					outside = w.before.Sub(event.Timestamp)
				case event.Timestamp.After(w.after):
					outside = event.Timestamp.Sub(w.after)
				}
				if outside > worst {
					worst = outside
				}
			}

			bound := time.Duration(recorded.stats().ClockErrorNanos)
			t.Logf("%s: %d events; worst timestamp fell %v outside the interval in which its process ran; conversion error bound %v",
				backend, checked, worst, bound)

			if checked < 2*len(windows) {
				t.Errorf("only %d events for %d processes", checked, len(windows))
			}
			if worst > time.Millisecond {
				t.Errorf("a timestamp was %v away from when the event happened", worst)
			}
		})
	}
}

// When eBPF cannot be loaded, auto must fall back and say why.
func TestAutoFallsBackWhenEBPFCannotLoad(t *testing.T) {
	requireRoot(t)

	// A ring buffer whose size is not a power of two is rejected by the
	// kernel, so this is a genuine load failure, not a simulated one.
	ebpfSpecHook = func(spec *ebpf.CollectionSpec) { spec.Maps[processMapEvents].MaxEntries = 12345 }
	defer func() { ebpfSpecHook = nil }()

	if _, _, err := Open(BackendEBPF, Options{}); err == nil || !strings.Contains(err.Error(), "load error") {
		t.Fatalf("asking for ebpf by name: err = %v, want a load error", err)
	}

	source, skipped, err := Open(BackendAuto, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	if source.Backend() != BackendProcConnector {
		t.Errorf("auto chose %s, want proc-connector", source.Backend())
	}
	if len(skipped) != 1 || skipped[0].Backend != BackendEBPF || !strings.Contains(skipped[0].Reason, "load error") {
		t.Fatalf("skipped = %v, want ebpf with its load error", skipped)
	}
	t.Logf("auto skipped %s", skipped[0])

	// With both forced to fail, auto reports both and leaves polling.
	real := openers[BackendProcConnector]
	openers[BackendProcConnector] = func(Options) (Source, error) {
		return nil, os.ErrPermission
	}
	defer func() { openers[BackendProcConnector] = real }()

	source, skipped, err = Open(BackendAuto, Options{})
	if err != nil || source != nil || len(skipped) != 2 {
		t.Fatalf("with nothing available: source %v, skipped %v, err %v; want no source and two reasons", source, skipped, err)
	}
}

func TestOpenWithoutPrivilegeSaysWhy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs to run without root")
	}

	_, _, err := Open(BackendEBPF, Options{})
	if err == nil || !strings.Contains(err.Error(), "missing capability") {
		t.Fatalf("ebpf without root: err = %v, want it to name the missing capability", err)
	}
	t.Logf("ebpf by name: %v", err)

	// auto must not fail: it moves on, and says why. Whether the proc
	// connector is open to unprivileged users depends on the kernel.
	source, skipped, err := Open(BackendAuto, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if source != nil {
		t.Logf("auto chose %s", source.Backend())
		source.Close()
	}
	if len(skipped) == 0 || skipped[0].Backend != BackendEBPF {
		t.Fatalf("skipped = %v, want ebpf first", skipped)
	}
	for _, skip := range skipped {
		t.Logf("auto skipped %s", skip)
		if !strings.Contains(skip.Reason, "missing capability") {
			t.Errorf("%s: reason %q does not name the missing capability", skip.Backend, skip.Reason)
		}
	}
}
