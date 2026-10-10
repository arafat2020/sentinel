package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/arafat2020/sentinel/internal/collector/process/procevents"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

// sampleHealth gives every counter a different value, so that a counter
// printed under the wrong name, or not at all, is noticed.
func sampleHealth() healthReport {
	return healthReport{
		Requested: procevents.BackendAuto,
		Skipped:   []procevents.Skip{{Backend: procevents.BackendEBPF, Reason: "missing BTF: nope"}},
		Collector: procevents.Stats{
			Backend:  procevents.BackendProcConnector,
			RawForks: 101, RawExecs: 102, RawExits: 103,
			KernelDrops: 104, DecodeErrors: 105,
			Starts: 106, Execs: 107, Exits: 108,
			StartsAtExec: 109, StartsAtFork: 110,
			Partial: 111, ArgsTruncated: 112,
			Tracked: 113, Pending: 114, TrackedCapHits: 115,
			UntrackedExecs: 116, UntrackedExits: 117,
			PIDReuses: 118, DuplicateForks: 119,
			ReconciledStarts: 120, ReconciledExits: 121,
			UserCacheSize: 122, UserCacheResets: 123,
			ClockErrorNanos: 124,
		},
		Bus: eventbus.Stats{Published: 201, Waited: 202, Dropped: 203, Depth: 204, Capacity: 205},
		Engine: correlation.Metrics{
			DescendantWalksTruncated: 301,
			ThresholdCounters:        302, ThresholdCountersEvicted: 303, ThresholdCounterCapHits: 304,
			SequencesPossiblyTruncated: 305, SequenceSearchesAborted: 306,
			FindingsEmitted: 307, FindingsExcluded: 308, FindingsSuppressed: 309,
			ActiveSuppressions: 310, Processes: 311, Tombstones: 312, TombstonesEvicted: 313,
			DetectionLatency: correlation.LatencySummary{Count: 314, P50: 315 * time.Microsecond, P99: 316 * time.Microsecond, Max: 317 * time.Microsecond},
		},
		Excluded: map[string]int{"rule-b": 402, "rule-a": 401},
	}
}

// Every counter the collector, the bus and the engine keep must appear in
// both renderings of the report.
func TestHealthReportShowsEveryCounter(t *testing.T) {
	report := sampleHealth()
	text := strings.Join(report.Lines(), "\n")
	line := report.LogLine()

	for value := 101; value <= 124; value++ {
		if value == 124 {
			// The clock error is shown as a duration in the text.
			if !strings.Contains(text, "124ns") {
				t.Errorf("text lacks the clock error:\n%s", text)
			}
		} else if !strings.Contains(text, fmt.Sprintf(" %d", value)) {
			t.Errorf("text lacks collector counter %d:\n%s", value, text)
		}
		if !strings.Contains(line, fmt.Sprintf("=%d", value)) {
			t.Errorf("log line lacks collector counter %d:\n%s", value, line)
		}
	}
	for _, value := range []int{201, 202, 203, 204, 205, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317} {
		if !strings.Contains(text, fmt.Sprint(value)) {
			t.Errorf("text lacks bus or engine counter %d:\n%s", value, text)
		}
		if !strings.Contains(line, fmt.Sprintf("=%d", value)) {
			t.Errorf("log line lacks bus or engine counter %d:\n%s", value, line)
		}
	}

	for _, want := range []string{
		"Process collector  proc-connector  (requested: auto)",
		"skipped ebpf: missing BTF: nope",
		"Excluded  rule-a 401   rule-b 402",
		"network: poll every 2s",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if !strings.HasPrefix(line, "process_collector=proc-connector ") || strings.Contains(line, "\n") {
		t.Errorf("log line = %q", line)
	}
}

// Polling has no collector counters; the report says how it polls instead of
// printing a row of zeros that look like measurements.
func TestHealthReportWhenPolling(t *testing.T) {
	report := sampleHealth()
	report.Collector = procevents.Stats{Backend: procevents.BackendPoll}
	report.Failure = "ring buffer closed; falling back to poll"

	text := strings.Join(report.Lines(), "\n")
	if !strings.Contains(text, "Process collector  poll  (requested: auto)  snapshot every 2s") {
		t.Errorf("text does not describe polling:\n%s", text)
	}
	if !strings.Contains(text, "falling back to poll") {
		t.Errorf("text does not say why polling is in use:\n%s", text)
	}
	if strings.Contains(text, "Kernel ") || strings.Contains(report.LogLine(), "kernel_drops") {
		t.Errorf("collector counters shown for polling:\n%s\n%s", text, report.LogLine())
	}
	if !strings.Contains(text, "Bus ") || !strings.Contains(text, "Engine ") {
		t.Errorf("bus and engine are missing:\n%s", text)
	}
}

// The report is assembled from the live objects.
func TestHealthReadsCollectionBusAndEngine(t *testing.T) {
	bus := eventbus.New(4)
	engine := correlation.NewEngine(correlation.DefaultWindow)
	engine.Seed([]core.Process{{PID: 1, StartTime: time.Unix(1000, 0), Name: "init"}})

	bus.Publish(core.Event{Type: core.EventProcessStart})

	source := &health{
		collection: &processCollection{requested: procevents.BackendPoll},
		bus:        bus,
		engine:     engine,
	}
	report := source.Report()

	if report.Collector.Backend != procevents.BackendPoll || report.Requested != procevents.BackendPoll {
		t.Errorf("collector = %+v", report.Collector)
	}
	if report.Bus.Published != 1 || report.Bus.Depth != 1 || report.Bus.Capacity != 4 {
		t.Errorf("bus = %+v", report.Bus)
	}
	if report.Engine.Processes != 1 {
		t.Errorf("engine = %+v", report.Engine)
	}
	if !strings.Contains(source.Text(), "published 1") {
		t.Errorf("text = %s", source.Text())
	}
}

// The Health tab is the ninth tab. It shows the current report whenever it is
// on screen, and never takes the keys that switch tabs.
func TestHealthTab(t *testing.T) {
	h := newUIHarness(t)

	var calls atomic.Int64
	h.onLoop(func() {
		h.ui.health.maxAge = 0
		h.ui.SetHealth(func() string {
			return fmt.Sprintf("Process collector  ebpf  reading %d", calls.Add(1))
		})
	})

	// Not drawn, not asked.
	h.key(tcell.KeyRune, '2')
	if calls.Load() != 0 {
		t.Fatalf("the report was fetched %d times while the tab was hidden", calls.Load())
	}

	h.key(tcell.KeyRune, '9')
	h.wantTab(tabHealth)
	h.wantOnScreen("Process collector  ebpf  reading")
	h.wantOnScreen("9:Health")

	// A resource sample arriving redraws the tab, with a fresh report.
	before := calls.Load()
	h.update(&core.ResourceSnapshot{})
	if calls.Load() <= before {
		t.Error("the Health tab was not refreshed by the periodic tick")
	}

	// Digits and arrows still switch tabs from here.
	h.key(tcell.KeyRune, '1')
	h.wantTab(tabProcess)
	h.key(tcell.KeyLeft, 0)
	h.wantTab(tabHealth)
	h.key(tcell.KeyRight, 0)
	h.wantTab(tabProcess)
}
