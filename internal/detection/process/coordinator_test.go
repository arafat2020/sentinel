package process

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type findingCoordinatorRule struct{}

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

	coordinator := NewCoordinator(engine)

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

	findings := coordinator.Handle(
		event,
		&core.ProcessSnapshot{
			Processes: []core.Process{
				parent,
				child,
			},
		},
	)

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

	coordinator := NewCoordinator(engine)

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

	findings := coordinator.Handle(
		event,
		&core.ProcessSnapshot{
			Processes: []core.Process{
				parent,
				child,
			},
		},
	)

	if len(findings) != 0 {
		t.Fatalf(
			"expected 0 findings for PROCESS_EXIT, got %d",
			len(findings),
		)
	}
}
