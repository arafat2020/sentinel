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

func trackedCoordinator(running ...core.Process) (*Coordinator, *fakeFindingSink) {
	registry := NewRegistry()
	registry.Register(NewSuspiciousChildProcessRule())

	sink := &fakeFindingSink{}
	coordinator := NewCoordinator(NewEngine(registry), sink)
	coordinator.Track(running)

	return coordinator, sink
}

func livePID(pid, ppid int32, name string) core.Process {
	return core.Process{PID: pid, PPID: ppid, Name: name, StartTime: time.Unix(1000+int64(pid), 0)}
}

func processEvent(eventType core.EventType, process core.Process) core.Event {
	return core.Event{Type: eventType, Process: &process}
}

// With an event-driven collector there are no snapshots. The coordinator
// follows the events and reports a pair once, when the child starts.
func TestCoordinatorFollowsEventsWithoutSnapshots(t *testing.T) {
	coordinator, sink := trackedCoordinator(livePID(100, 1, "node"))

	coordinator.Handle(processEvent(core.EventProcessStart, livePID(200, 100, "python")))
	if len(sink.findings) != 1 || sink.findings[0].Rule != "suspicious-child-process" {
		t.Fatalf("findings = %d, want the node → python pair", len(sink.findings))
	}
	if got := sink.findings[0].Evidence.Process.PID; got != 200 {
		t.Errorf("finding is about PID %d", got)
	}

	// Unrelated activity does not report the same pair again.
	coordinator.Handle(processEvent(core.EventProcessStart, livePID(300, 1, "ls")))
	coordinator.Handle(processEvent(core.EventProcessStart, livePID(400, 300, "cat")))
	coordinator.Handle(processEvent(core.EventProcessExit, livePID(300, 1, "ls")))
	if len(sink.findings) != 1 {
		t.Fatalf("%d findings after unrelated events, want still 1", len(sink.findings))
	}

	// Once the parent has exited, a new child of that PID has no parent to
	// be judged against.
	coordinator.Handle(processEvent(core.EventProcessExit, livePID(100, 1, "node")))
	coordinator.Handle(processEvent(core.EventProcessStart, livePID(500, 100, "python")))
	if len(sink.findings) != 1 {
		t.Fatalf("a child of an exited parent was reported")
	}
}

// A process is judged by what it is running now.
func TestCoordinatorJudgesTheCurrentImage(t *testing.T) {
	coordinator, sink := trackedCoordinator(livePID(100, 1, "node"))

	// Forked as a copy of node, then became python.
	coordinator.Handle(processEvent(core.EventProcessStart, livePID(200, 100, "node")))
	if len(sink.findings) != 0 {
		t.Fatal("node → node was reported")
	}
	coordinator.Handle(processEvent(core.EventProcessExec, livePID(200, 100, "python")))
	if len(sink.findings) != 1 {
		t.Fatalf("findings = %d after the child became python, want 1", len(sink.findings))
	}

	// A parent that becomes node makes its existing python child a match.
	coordinator, sink = trackedCoordinator(livePID(10, 1, "sh"), livePID(20, 10, "python"), livePID(30, 10, "ls"))
	coordinator.Handle(processEvent(core.EventProcessExec, livePID(10, 1, "node")))
	if len(sink.findings) != 1 || sink.findings[0].Evidence.Process.PID != 20 {
		t.Fatalf("findings = %+v, want the python child of the new node", sink.findings)
	}
}

// An exit that names a different process from the one holding the PID leaves
// the holder alone.
func TestCoordinatorIgnoresExitOfAnotherIdentity(t *testing.T) {
	coordinator, sink := trackedCoordinator(livePID(100, 1, "node"))

	stale := livePID(100, 1, "node")
	stale.StartTime = stale.StartTime.Add(-time.Hour)
	coordinator.Handle(processEvent(core.EventProcessExit, stale))

	coordinator.Handle(processEvent(core.EventProcessStart, livePID(200, 100, "python")))
	if len(sink.findings) != 1 {
		t.Fatalf("the parent was dropped by an exit that was not its own")
	}
}

// Polling is unchanged: a snapshot is required, and every start evaluates
// the whole of the latest one.
func TestCoordinatorWithSnapshotsEvaluatesEverything(t *testing.T) {
	registry := NewRegistry()
	registry.Register(NewSuspiciousChildProcessRule())
	sink := &fakeFindingSink{}
	coordinator := NewCoordinator(NewEngine(registry), sink)

	start := processEvent(core.EventProcessStart, livePID(300, 1, "ls"))
	coordinator.Handle(start)
	if len(sink.findings) != 0 {
		t.Fatal("evaluated without a snapshot")
	}

	coordinator.UpdateSnapshot(&core.ProcessSnapshot{Processes: []core.Process{
		livePID(100, 1, "node"), livePID(200, 100, "python"), livePID(300, 1, "ls"),
	}})
	coordinator.Handle(start)
	coordinator.Handle(start)
	if len(sink.findings) != 2 {
		t.Fatalf("findings = %d, want the pair reported on each start as before", len(sink.findings))
	}
}
