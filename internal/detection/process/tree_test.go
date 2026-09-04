package process

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestProcessTreeBuildsParentChildRelationship(t *testing.T) {
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

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			parent,
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	children := tree.Children(parent.Identity())

	if len(children) != 1 {
		t.Fatalf("expected 1 child, got %d", len(children))
	}

	if children[0].Identity() != child.Identity() {
		t.Fatalf("expected child PID %d, got PID %d",
			child.PID,
			children[0].PID,
		)
	}
}

func TestProcessTreeHandlesPIDReuse(t *testing.T) {
	oldParent := core.Process{
		PID:       100,
		PPID:      1,
		StartTime: time.Unix(1000, 0),
		Name:      "old-parent",
	}

	newParent := core.Process{
		PID:       100,
		PPID:      1,
		StartTime: time.Unix(2000, 0),
		Name:      "new-parent",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(3000, 0),
		Name:      "child",
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			oldParent,
			newParent,
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	children := tree.Children(oldParent.Identity())

	if len(children) != 0 {
		t.Fatalf(
			"expected old parent to have 0 children, got %d",
			len(children),
		)
	}

	children = tree.Children(newParent.Identity())

	if len(children) != 1 {
		t.Fatalf(
			"expected new parent to have 1 child, got %d",
			len(children),
		)
	}

	if children[0].Identity() != child.Identity() {
		t.Fatalf("expected child PID %d", child.PID)
	}
}

func TestProcessTreeIgnoresMissingParent(t *testing.T) {
	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "child",
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	identity := core.ProcessIdentity{
		PID:       100,
		StartTime: time.Unix(1000, 0),
	}

	children := tree.Children(identity)

	if len(children) != 0 {
		t.Fatalf(
			"expected 0 children for missing parent, got %d",
			len(children),
		)
	}
}

func TestProcessTreeFindsParent(t *testing.T) {
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

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			parent,
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	foundParent, ok := tree.Parent(child.Identity())

	if !ok {
		t.Fatal("expected parent to exist")
	}

	if foundParent.Identity() != parent.Identity() {
		t.Fatalf(
			"expected parent PID %d, got PID %d",
			parent.PID,
			foundParent.PID,
		)
	}
}

func TestProcessTreeParentReturnsFalseWhenMissing(t *testing.T) {
	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "python",
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	_, ok := tree.Parent(child.Identity())

	if ok {
		t.Fatal("expected parent lookup to fail")
	}
}

func TestProcessTreeFindsProcess(t *testing.T) {
	process := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "python",
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			process,
		},
	}

	tree := NewProcessTree(snapshot)

	found, ok := tree.Process(process.Identity())

	if !ok {
		t.Fatal("expected process to exist")
	}

	if found.Identity() != process.Identity() {
		t.Fatalf(
			"expected PID %d, got PID %d",
			process.PID,
			found.PID,
		)
	}
}
