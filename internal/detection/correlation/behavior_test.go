package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestEngineDetectsNetworkActiveParentSpawningNetworkActivePython(t *testing.T) {
	now := time.Now()

	parent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: now.Add(time.Second),
		Name:      "python",
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(2 * time.Second),
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(3 * time.Second),
		Process:   &child,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(4 * time.Second),
		Process:   &child,
	})

	findings := engine.DetectBehaviors()

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	finding := findings[0]

	if finding.Rule != "network-active-parent-spawns-python" {
		t.Fatalf(
			"unexpected rule: %s",
			finding.Rule,
		)
	}

	if finding.Severity != core.SeverityMedium {
		t.Fatalf(
			"expected severity %s, got %s",
			core.SeverityMedium,
			finding.Severity,
		)
	}

	if finding.Title == "" {
		t.Fatal("expected finding title")
	}

	if finding.Description == "" {
		t.Fatal("expected finding description")
	}
}

func TestEngineDoesNotDetectWithoutParentNetworkActivity(t *testing.T) {
	now := time.Now()

	parent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: now.Add(time.Second),
		Name:      "python",
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(time.Second),
		Process:   &child,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(2 * time.Second),
		Process:   &child,
	})

	findings := engine.DetectBehaviors()

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestEngineDoesNotDetectWithoutPythonNetworkActivity(t *testing.T) {
	now := time.Now()

	parent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: now.Add(time.Second),
		Name:      "python",
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(time.Second),
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(2 * time.Second),
		Process:   &child,
	})

	findings := engine.DetectBehaviors()

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestEngineDoesNotDetectDifferentChildProcess(t *testing.T) {
	now := time.Now()

	parent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: now.Add(time.Second),
		Name:      "bash",
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(time.Second),
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(2 * time.Second),
		Process:   &child,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(3 * time.Second),
		Process:   &child,
	})

	findings := engine.DetectBehaviors()

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestEngineDoesNotDetectWithoutPythonChild(t *testing.T) {
	now := time.Now()

	parent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &parent,
	})

	engine.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(time.Second),
		Process:   &parent,
	})

	findings := engine.DetectBehaviors()

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
