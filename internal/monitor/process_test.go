package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type fakeCoordinator struct{}

type fakeFindingSink struct{}

func (f *fakeFindingSink) Handle(
	finding *core.Finding,
) {
}

func (f *fakeCoordinator) UpdateSnapshot(
	snapshot *core.ProcessSnapshot,
) {
}

type fakeCollector struct {
	snapshot *core.ProcessSnapshot
}

func (f *fakeCollector) Collect(
	ctx context.Context,
) (*core.ProcessSnapshot, error) {
	return f.snapshot, nil
}

type fakeDetector struct {
	events []core.Event
}

func (f *fakeDetector) Detect(
	snapshot *core.ProcessSnapshot,
) []core.Event {
	return f.events
}

func TestProcessMonitorPublishesLifecycleEvents(t *testing.T) {

	bus := eventbus.New(1)

	received := make(chan core.Event, 1)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	collector := &fakeCollector{
		snapshot: &core.ProcessSnapshot{},
	}

	detector := &fakeDetector{
		events: []core.Event{
			{
				Type:      core.EventProcessStart,
				Timestamp: time.Now(),
			},
		},
	}

	monitor := NewProcessMonitor(
		collector,
		detector,
		time.Second,
		bus,
		&fakeCoordinator{},
	)

	// We are testing the monitor's event publishing path.
	// The real collector will produce the current process snapshot.
	monitor.collectAndDetect(context.Background())

	bus.Start(context.Background())

	select {
	case <-received:
		// Event successfully reached the bus.
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lifecycle event")
	}

	bus.Shutdown()
	bus.Wait()
}

func TestProcessMonitorUpdatesCoordinatorBeforePublishing(t *testing.T) {
	bus := eventbus.New(1)

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:  100,
				Name: "node",
			},
			{
				PID:  101,
				PPID: 100,
				Name: "python",
			},
		},
	}

	collector := &fakeCollector{
		snapshot: snapshot,
	}

	detector := &fakeDetector{
		events: []core.Event{
			{
				Type:      core.EventProcessStart,
				Timestamp: time.Now(),
			},
		},
	}

	registry := processDetector.NewRegistry()
	registry.Register(processDetector.NewSuspiciousChildProcessRule())

	engine := processDetector.NewEngine(registry)
	sink := &fakeFindingSink{}

	coordinator := processDetector.NewCoordinator(
		engine,
		sink,
	)

	findingsReceived := make(chan []*core.Finding, 1)

	coordinator.UpdateSnapshot(snapshot)

	bus.Subscribe(func(event core.Event) {
		findings := coordinator.Handle(event)
		findingsReceived <- findings
	})

	monitor := NewProcessMonitor(
		collector,
		detector,
		time.Second,
		bus,
		coordinator,
	)

	bus.Start(context.Background())

	monitor.collectAndDetect(context.Background())

	select {
	case findings := <-findingsReceived:
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}

	case <-time.After(time.Second):
		t.Fatal("timed out waiting for finding")
	}

	bus.Shutdown()
	bus.Wait()
}

func TestProcessMonitorRunPublishesEvents(t *testing.T) {
	bus := eventbus.New(1)

	received := make(chan core.Event, 1)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	collector := &fakeCollector{
		snapshot: &core.ProcessSnapshot{},
	}

	detector := &fakeDetector{
		events: []core.Event{
			{
				Type:      core.EventProcessStart,
				Timestamp: time.Now(),
			},
		},
	}

	coordinator := &fakeCoordinator{}

	monitor := NewProcessMonitor(
		collector,
		detector,
		10*time.Millisecond,
		bus,
		coordinator,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Start(ctx)

	go monitor.Run(ctx)

	select {
	case event := <-received:
		if event.Type != core.EventProcessStart {
			t.Fatalf(
				"expected PROCESS_START, got %s",
				event.Type,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lifecycle event")
	}

	cancel()

	bus.Shutdown()
	bus.Wait()
}

type trackingCollector struct {
	snapshot  *core.ProcessSnapshot
	collected chan struct{}
}

func (f *trackingCollector) Collect(
	ctx context.Context,
) (*core.ProcessSnapshot, error) {
	f.collected <- struct{}{}
	return f.snapshot, nil
}

func TestProcessMonitorCollectsImmediately(t *testing.T) {
	bus := eventbus.New(1)

	collected := make(chan struct{}, 1)

	collector := &trackingCollector{
		collected: collected,
		snapshot:  &core.ProcessSnapshot{},
	}

	detector := &fakeDetector{}

	coordinator := &fakeCoordinator{}

	monitor := NewProcessMonitor(
		collector,
		detector,
		10*time.Second,
		bus,
		coordinator,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go monitor.Run(ctx)

	select {
	case <-collected:
		// Initial collection happened immediately.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("monitor did not collect immediately")
	}

	cancel()
}
