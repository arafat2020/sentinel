package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestRelationshipLinksParentAndChildProcesses(t *testing.T) {
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

	relationship := NewProcessRelationship(
		parent,
		child,
	)

	if relationship.Parent.Identity() != parent.Identity() {
		t.Fatal("expected parent process identity to match")
	}

	if relationship.Child.Identity() != child.Identity() {
		t.Fatal("expected child process identity to match")
	}

	if relationship.Type != RelationshipSpawned {
		t.Fatalf(
			"expected relationship type %s, got %s",
			RelationshipSpawned,
			relationship.Type,
		)
	}
}

func TestEngineDiscoversParentChildRelationship(t *testing.T) {
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

	relationships := engine.RelationshipsForProcess(
		child.Identity(),
	)

	if len(relationships) != 1 {
		t.Fatalf(
			"expected 1 relationship, got %d",
			len(relationships),
		)
	}

	relationship := relationships[0]

	if relationship.Parent.Identity() != parent.Identity() {
		t.Fatal("expected relationship parent to be parent process")
	}

	if relationship.Child.Identity() != child.Identity() {
		t.Fatal("expected relationship child to be child process")
	}

	if relationship.Type != RelationshipSpawned {
		t.Fatalf(
			"expected relationship type %s, got %s",
			RelationshipSpawned,
			relationship.Type,
		)
	}
}

func TestEngineDoesNotUseStaleParentAfterPIDReuse(t *testing.T) {
	now := time.Now()

	oldParent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "old-parent",
	}

	newParent := core.Process{
		PID:       100,
		StartTime: now.Add(10 * time.Second),
		Name:      "new-parent",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: now.Add(11 * time.Second),
		Name:      "python",
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &oldParent,
	})

	// PID 100 is reused by a different process.
	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(10 * time.Second),
		Process:   &newParent,
	})

	engine.Process(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(11 * time.Second),
		Process:   &child,
	})

	relationships := engine.RelationshipsForProcess(
		child.Identity(),
	)

	if len(relationships) != 1 {
		t.Fatalf(
			"expected 1 relationship, got %d",
			len(relationships),
		)
	}

	if relationships[0].Parent.Identity() != newParent.Identity() {
		t.Fatal("expected relationship to use the new parent")
	}
}
