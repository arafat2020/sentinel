package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestMatcherMatchesProcessName(t *testing.T) {
	matcher := NewMatcher()

	pattern := ProcessPattern{
		ID: "child",
		Conditions: []Condition{
			{
				Type:  ConditionProcessName,
				Value: "python",
			},
		},
	}

	process := core.Process{
		PID:  200,
		Name: "python",
	}

	if !matcher.MatchProcess(pattern, process) {
		t.Fatal("expected process to match pattern")
	}
}

func TestMatcherRejectsDifferentProcessName(t *testing.T) {
	matcher := NewMatcher()

	pattern := ProcessPattern{
		ID: "child",
		Conditions: []Condition{
			{
				Type:  ConditionProcessName,
				Value: "python",
			},
		},
	}

	process := core.Process{
		PID:  200,
		Name: "bash",
	}

	if matcher.MatchProcess(pattern, process) {
		t.Fatal("expected process not to match pattern")
	}
}

func TestMatcherRequiresAllConditions(t *testing.T) {
	matcher := NewMatcher()

	pattern := ProcessPattern{
		ID: "child",
		Conditions: []Condition{
			{
				Type:  ConditionProcessName,
				Value: "python",
			},
			{
				Type:  ConditionProcessUser,
				Value: "root",
			},
		},
	}

	process := core.Process{
		PID:  200,
		Name: "python",
		User: "arafat",
	}

	if matcher.MatchProcess(pattern, process) {
		t.Fatal("expected process to fail condition matching")
	}
}

func TestMatcherMatchesRequiredEvents(t *testing.T) {
	matcher := NewMatcher()

	now := time.Now()

	process := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	chain := NewChain(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &process,
	})

	chain.Add(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(time.Second),
		Process:   &process,
	})

	pattern := ProcessPattern{
		ID: "parent",
		Events: []EventPattern{
			{Type: core.EventProcessStart},
			{Type: core.EventNetworkConnect},
		},
	}

	if !matcher.MatchEvents(pattern, chain) {
		t.Fatal("expected chain to match required events")
	}
}

func TestMatcherMatchesRelationship(t *testing.T) {
	matcher := NewMatcher()

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

	relationship := NewProcessRelationship(parent, child)

	pattern := RelationshipPattern{
		Type:   RelationshipSpawned,
		Parent: "parent",
		Child:  "child",
	}

	parentPattern := ProcessPattern{
		ID: "parent",
	}

	childPattern := ProcessPattern{
		ID: "child",
	}

	if !matcher.MatchRelationship(
		pattern,
		relationship,
		parentPattern,
		childPattern,
	) {
		t.Fatal("expected relationship to match pattern")
	}
}

func TestMatcherRejectsWrongRelationshipType(t *testing.T) {
	matcher := NewMatcher()

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

	relationship := NewProcessRelationship(parent, child)

	pattern := RelationshipPattern{
		Type:   RelationshipSpawned,
		Parent: "parent",
		Child:  "child",
	}

	// Same processes, but pretend the observed relationship
	// is not the relationship the pattern expects.
	relationship.Type = RelationshipType("NETWORK")

	parentPattern := ProcessPattern{
		ID: "parent",
	}

	childPattern := ProcessPattern{
		ID: "child",
	}

	if matcher.MatchRelationship(
		pattern,
		relationship,
		parentPattern,
		childPattern,
	) {
		t.Fatal("expected relationship not to match")
	}
}

func TestMatcherMatchesCompleteBehaviorPattern(t *testing.T) {
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

	parentChain := NewChain(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now,
		Process:   &parent,
	})

	parentChain.Add(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(time.Second),
		Process:   &parent,
	})

	childChain := NewChain(core.Event{
		Type:      core.EventProcessStart,
		Timestamp: now.Add(2 * time.Second),
		Process:   &child,
	})

	childChain.Add(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: now.Add(3 * time.Second),
		Process:   &child,
	})

	relationship := NewProcessRelationship(parent, child)

	pattern := BehaviorPattern{
		Name:     "network-active-parent-spawns-python",
		Severity: core.SeverityMedium,

		Processes: []ProcessPattern{
			{
				ID: "parent",
				Events: []EventPattern{
					{Type: core.EventNetworkConnect},
				},
			},
			{
				ID: "child",
				Conditions: []Condition{
					{
						Type:  ConditionProcessName,
						Value: "python",
					},
				},
				Events: []EventPattern{
					{Type: core.EventNetworkConnect},
				},
			},
		},

		Relationships: []RelationshipPattern{
			{
				Type:   RelationshipSpawned,
				Parent: "parent",
				Child:  "child",
			},
		},
	}

	chains := map[core.ProcessIdentity][]*Chain{
		parent.Identity(): {parentChain},
		child.Identity():  {childChain},
	}

	matcher := NewMatcher()

	if !matcher.MatchPattern(
		pattern,
		[]ProcessRelationship{relationship},
		chains,
	) {
		t.Fatal("expected behavior pattern to match")
	}
}

func TestMatcherMatchPattern(t *testing.T) {
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

	pattern := BehaviorPattern{
		Name:     "network-active-parent-spawns-python",
		Severity: core.SeverityMedium,

		Processes: []ProcessPattern{
			{
				ID: "parent",
				Events: []EventPattern{
					{Type: core.EventNetworkConnect},
				},
			},
			{
				ID: "child",
				Conditions: []Condition{
					{
						Type:  ConditionProcessName,
						Value: "python",
					},
				},
				Events: []EventPattern{
					{Type: core.EventNetworkConnect},
				},
			},
		},

		Relationships: []RelationshipPattern{
			{
				Type:   RelationshipSpawned,
				Parent: "parent",
				Child:  "child",
			},
		},
	}

	relationship := NewProcessRelationship(parent, child)

	chains := map[core.ProcessIdentity][]*Chain{
		parent.Identity(): {
			NewChain(core.Event{
				Type:      core.EventProcessStart,
				Timestamp: now,
				Process:   &parent,
			}),
			NewChain(core.Event{
				Type:      core.EventNetworkConnect,
				Timestamp: now.Add(time.Second),
				Process:   &parent,
			}),
		},

		child.Identity(): {
			NewChain(core.Event{
				Type:      core.EventProcessStart,
				Timestamp: now.Add(2 * time.Second),
				Process:   &child,
			}),
			NewChain(core.Event{
				Type:      core.EventNetworkConnect,
				Timestamp: now.Add(3 * time.Second),
				Process:   &child,
			}),
		},
	}

	matcher := NewMatcher()

	matched := matcher.MatchPattern(
		pattern,
		[]ProcessRelationship{relationship},
		chains,
	)

	if !matched {
		t.Fatal("expected pattern to match")
	}
}

func TestMatcherFindMatchesReturnsBindingsInRoleOrder(t *testing.T) {
	now := time.Now()

	a := core.Process{PID: 1, StartTime: now, Name: "a"}
	b := core.Process{PID: 2, PPID: 1, StartTime: now, Name: "b"}
	c := core.Process{PID: 3, PPID: 2, StartTime: now, Name: "c"}
	stray := core.Process{PID: 9, PPID: 1, StartTime: now, Name: "b"} // a "b" with no "c" child

	role := func(id, name string) ProcessPattern {
		return ProcessPattern{ID: id, Conditions: []Condition{{Type: ConditionProcessName, Value: name}}}
	}
	// Roles deliberately listed out of chain order.
	pattern := BehaviorPattern{
		Name:      "chain",
		Processes: []ProcessPattern{role("c", "c"), role("a", "a"), role("b", "b")},
		Relationships: []RelationshipPattern{
			{Type: RelationshipSpawned, Parent: "b", Child: "c"},
			{Type: RelationshipSpawned, Parent: "a", Child: "b"},
		},
	}

	matcher := NewMatcher()

	partial := []ProcessRelationship{NewProcessRelationship(a, b), NewProcessRelationship(a, stray)}
	if matcher.MatchPattern(pattern, partial, nil) {
		t.Fatal("pattern matched with only one of its two relationships present")
	}

	full := append(partial, NewProcessRelationship(b, c))
	matches := matcher.FindMatches(pattern, full, nil)
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}

	got := matches[0].Processes
	if len(got) != 3 || got[0].PID != c.PID || got[1].PID != a.PID || got[2].PID != b.PID {
		t.Fatalf("bindings = %+v, want [c, a, b] in role order", got)
	}
	if !matcher.MatchPattern(pattern, full, nil) {
		t.Fatal("MatchPattern disagrees with FindMatches")
	}
}

func TestMatcherFindMatchesAfterAppliesCutoff(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	parent := core.Process{PID: 100, StartTime: base, Name: "node"}
	child := core.Process{PID: 200, PPID: 100, StartTime: base, Name: "python"}

	chains := map[core.ProcessIdentity][]*Chain{
		parent.Identity(): {NewChain(core.Event{Type: core.EventNetworkConnect, Timestamp: base, Process: &parent})},
		child.Identity():  {NewChain(core.Event{Type: core.EventNetworkConnect, Timestamp: base.Add(10 * time.Second), Process: &child})},
	}
	relationships := []ProcessRelationship{NewProcessRelationship(parent, child)}
	pattern := DefaultPatterns()[0]
	matcher := NewMatcher()

	if got := matcher.FindMatchesAfter(pattern, relationships, chains, base.Add(-time.Second)); len(got) != 1 {
		t.Errorf("both events after the cutoff: matches = %d, want 1", len(got))
	}
	// The cutoff is exclusive, so the parent's event at the cutoff is out.
	if got := matcher.FindMatchesAfter(pattern, relationships, chains, base); len(got) != 0 {
		t.Errorf("parent event at the cutoff: matches = %d, want 0", len(got))
	}
	if got := matcher.FindMatches(pattern, relationships, chains); len(got) != 1 {
		t.Errorf("FindMatches ignores age: matches = %d, want 1", len(got))
	}
}

func TestMatcherRoleWithoutEventsNeedsNoChain(t *testing.T) {
	matcher := NewMatcher()

	if !matcher.MatchAnyChain(ProcessPattern{ID: "p"}, nil) {
		t.Error("a role requiring no events should match a process with no chains")
	}

	needsConnect := ProcessPattern{ID: "p", Events: []EventPattern{{Type: core.EventNetworkConnect}}}
	if matcher.MatchAnyChain(needsConnect, nil) {
		t.Error("a role requiring an event should not match a process with no chains")
	}
}
