package process

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type findingCoordinatorRule struct{}

type fakeFindingSink struct {
	findings []*core.Finding
}

func (s *fakeFindingSink) Handle(
	finding *core.Finding,
) {
	s.findings = append(s.findings, finding)
}

func (r *findingCoordinatorRule) Evaluate(
	ctx *RuleContext,
	identity core.ProcessIdentity,
) *core.Finding {
	process, ok := ctx.Tree.Process(identity)
	if !ok {
		return nil
	}

	if process.Name != "python" {
		return nil
	}

	return &core.Finding{
		Rule:     "test-coordinator-rule",
		Severity: core.SeverityHigh,
		Title:    "Test coordinator finding",
	}
}

func TestCoordinatorEvaluatesProcessStart(t *testing.T) {
	registry := NewRegistry()

	registry.Register(&findingCoordinatorRule{})

	engine := NewEngine(registry)

	sink := &fakeFindingSink{}

	coordinator := NewCoordinator(engine, sink)

	parent := core.Process{
		PID:       100,
		PPID:      1,
		StartTime: time.Unix(1000, 0),
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "python",
	}

	event := core.Event{
		Type:      core.EventProcessStart,
		Timestamp: time.Now(),
		Process:   &child,
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			parent,
			child,
		},
	}

	coordinator.UpdateSnapshot(snapshot)

	findings := coordinator.Handle(event)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	if findings[0].Rule != "test-coordinator-rule" {
		t.Fatalf(
			"expected test-coordinator-rule, got %q",
			findings[0].Rule,
		)
	}
}

func TestCoordinatorIgnoresProcessExit(t *testing.T) {
	registry := NewRegistry()

	registry.Register(&findingCoordinatorRule{})

	engine := NewEngine(registry)

	sink := &fakeFindingSink{}
	coordinator := NewCoordinator(engine, sink)

	parent := core.Process{
		PID:       100,
		PPID:      1,
		StartTime: time.Unix(1000, 0),
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "python",
	}

	event := core.Event{
		Type:      core.EventProcessExit,
		Timestamp: time.Now(),
		Process:   &child,
	}

	coordinator.UpdateSnapshot(&core.ProcessSnapshot{
		Processes: []core.Process{
			parent,
			child,
		},
	})

	findings := coordinator.Handle(event)

	if len(findings) != 0 {
		t.Fatalf(
			"expected 0 findings for PROCESS_EXIT, got %d",
			len(findings),
		)
	}
}

func TestCoordinatorCanHandleBusEvents(t *testing.T) {
	registry := NewRegistry()
	done := make(chan struct{})
	registry.Register(&findingCoordinatorRule{})

	engine := NewEngine(registry)
	sink := &fakeFindingSink{}
	coordinator := NewCoordinator(engine, sink)

	bus := eventbus.New(1)

	var findings []*core.Finding
	var mu sync.Mutex

	bus.Subscribe(func(event core.Event) {
		snapshot := &core.ProcessSnapshot{
			Processes: []core.Process{
				{
					PID:       100,
					PPID:      1,
					StartTime: time.Unix(1000, 0),
					Name:      "node",
				},
				{
					PID:       200,
					PPID:      100,
					StartTime: time.Unix(2000, 0),
					Name:      "python",
				},
			},
		}

		coordinator.UpdateSnapshot(snapshot)

		result := coordinator.Handle(event)

		mu.Lock()
		findings = append(findings, result...)
		mu.Unlock()

		close(done)
	})

	bus.Start(context.Background())

	bus.Publish(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: time.Now(),
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coordinator")
	}

	bus.Shutdown()
	bus.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

}

func TestCoordinatorUsesCurrentProcessState(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&findingCoordinatorRule{})

	engine := NewEngine(registry)
	sink := &fakeFindingSink{}
	coordinator := NewCoordinator(engine, sink)

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				PPID:      1,
				StartTime: time.Unix(1000, 0),
				Name:      "node",
			},
			{
				PID:       200,
				PPID:      100,
				StartTime: time.Unix(2000, 0),
				Name:      "python",
			},
		},
	}

	coordinator.UpdateSnapshot(snapshot)

	event := core.Event{
		Type:      core.EventProcessStart,
		Timestamp: time.Now(),
		Process:   &snapshot.Processes[1],
	}

	findings := coordinator.Handle(event)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}
}

func TestCoordinatorSendsFindingsToSink(t *testing.T) {
	sink := &fakeFindingSink{}

	registry := NewRegistry()
	registry.Register(NewSuspiciousChildProcessRule())

	engine := NewEngine(registry)
	coordinator := NewCoordinator(engine, sink)

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

	coordinator.UpdateSnapshot(snapshot)

	event := core.Event{
		Type: core.EventProcessStart,
	}

	findings := coordinator.Handle(event)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	if len(sink.findings) != 1 {
		t.Fatalf(
			"expected sink to receive 1 finding, got %d",
			len(sink.findings),
		)
	}

	if sink.findings[0] == nil {
		t.Fatal("sink received nil finding")
	}

	if findings[0] == nil {
		t.Fatal("coordinator returned nil finding")
	}

	if sink.findings[0].ID != findings[0].ID {
		t.Fatalf(
			"sink received finding ID %q, coordinator returned %q",
			sink.findings[0].ID,
			findings[0].ID,
		)
	}
}
