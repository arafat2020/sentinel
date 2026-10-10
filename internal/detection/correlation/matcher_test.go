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

func eventChain(base time.Time, process *core.Process, types ...core.EventType) *Chain {
	var chain *Chain

	for i, eventType := range types {
		event := core.Event{
			Type:      eventType,
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Process:   process,
		}
		if chain == nil {
			chain = NewChain(event)
			continue
		}
		chain.Add(event)
	}

	return chain
}

func TestMatcherOrderedEvents(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	process := core.Process{PID: 100, StartTime: base}
	matcher := NewMatcher()

	required := []EventPattern{
		{Type: core.EventDNSQuery},
		{Type: core.EventNetworkConnect},
	}
	ordered := ProcessPattern{ID: "p", Events: required, Ordered: true}
	unordered := ProcessPattern{ID: "p", Events: required}

	inOrder := eventChain(base, &process, core.EventProcessStart, core.EventDNSQuery, core.EventFileCreate, core.EventNetworkConnect)
	reversed := eventChain(base, &process, core.EventProcessStart, core.EventNetworkConnect, core.EventDNSQuery)

	if !matcher.MatchEvents(ordered, inOrder) {
		t.Error("ordered pattern should match events in order")
	}
	if matcher.MatchEvents(ordered, reversed) {
		t.Error("ordered pattern should reject reversed events")
	}
	if !matcher.MatchEvents(unordered, inOrder) || !matcher.MatchEvents(unordered, reversed) {
		t.Error("unordered pattern should match either order")
	}

	// An ordered pattern with nothing to require is satisfied, like an
	// unordered one.
	if !matcher.MatchEvents(ProcessPattern{ID: "p", Ordered: true}, inOrder) {
		t.Error("ordered pattern without events should match")
	}
}

func TestMatcherEventsAfterCutoff(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	process := core.Process{PID: 100, StartTime: base}
	matcher := NewMatcher()

	// DNS at +0s, connect at +1s.
	chain := eventChain(base, &process, core.EventDNSQuery, core.EventNetworkConnect)
	both := ProcessPattern{ID: "p", Events: []EventPattern{
		{Type: core.EventDNSQuery},
		{Type: core.EventNetworkConnect},
	}}

	if !matcher.MatchEventsAfter(both, chain, base.Add(-time.Second)) {
		t.Error("both events are after the cutoff: should match")
	}
	// The cutoff is exclusive: an event exactly at it does not count.
	if matcher.MatchEventsAfter(both, chain, base) {
		t.Error("the DNS query is at the cutoff: should not match")
	}
	if !matcher.MatchEvents(both, chain) {
		t.Error("MatchEvents ignores age and should still match")
	}
	if matcher.MatchEventsAfter(both, nil, base) {
		t.Error("nil chain should not match")
	}
}

func TestMatcherProcessWithoutEventsNeedsNoChain(t *testing.T) {
	matcher := NewMatcher()

	if !matcher.MatchAnyChain(ProcessPattern{ID: "p"}, nil) {
		t.Error("a pattern requiring no events should match a process with no chains")
	}

	needsConnect := ProcessPattern{ID: "p", Events: []EventPattern{{Type: core.EventNetworkConnect}}}
	if matcher.MatchAnyChain(needsConnect, nil) {
		t.Error("a pattern requiring an event should not match a process with no chains")
	}
}
