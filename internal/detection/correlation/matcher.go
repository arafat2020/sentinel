package correlation

import (
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type Matcher struct{}

func NewMatcher() *Matcher {
	return &Matcher{}
}

func (m *Matcher) MatchProcess(
	pattern ProcessPattern,
	process core.Process,
) bool {
	for _, condition := range pattern.Conditions {
		if !matchCondition(condition, process) {
			return false
		}
	}

	return true
}

func matchCondition(
	condition Condition,
	process core.Process,
) bool {
	switch condition.Type {
	case ConditionProcessName:
		return process.Name == condition.Value
	case ConditionProcessUser:
		return process.User == condition.Value

	default:
		return false
	}
}

// MatchEvents reports whether the chain satisfies the pattern's event
// requirements, considering every event in the chain regardless of age.
func (m *Matcher) MatchEvents(
	pattern ProcessPattern,
	chain *Chain,
) bool {
	if chain == nil {
		return false
	}

	return matchEvents(pattern, chain.Events())
}

// MatchEventsAfter is MatchEvents restricted to events whose timestamp is
// strictly after cutoff.
func (m *Matcher) MatchEventsAfter(
	pattern ProcessPattern,
	chain *Chain,
	cutoff time.Time,
) bool {
	if chain == nil {
		return false
	}

	return matchEvents(pattern, chain.EventsAfter(cutoff))
}

// matchEvents applies a process pattern's event requirements to events,
// which must be in time order.
func matchEvents(pattern ProcessPattern, events []core.Event) bool {
	if pattern.Ordered {
		return containsSequence(events, pattern.Events)
	}

	for _, required := range pattern.Events {
		found := false

		for _, event := range events {
			if event.Type == required.Type {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// containsSequence reports whether events contains the required types as a
// subsequence. Taking the earliest possible event for each step never rules
// out a later one, so a single pass decides it.
func containsSequence(events []core.Event, required []EventPattern) bool {
	next := 0

	for _, event := range events {
		if next == len(required) {
			break
		}
		if event.Type == required[next].Type {
			next++
		}
	}

	return next == len(required)
}

func (m *Matcher) MatchRelationship(
	pattern RelationshipPattern,
	relationship ProcessRelationship,
	parentPattern ProcessPattern,
	childPattern ProcessPattern,
) bool {
	if relationship.Type != pattern.Type {
		return false
	}

	if parentPattern.ID != pattern.Parent {
		return false
	}

	if childPattern.ID != pattern.Child {
		return false
	}

	return true
}

func findProcessPattern(
	pattern BehaviorPattern,
	id string,
) *ProcessPattern {
	for i := range pattern.Processes {
		if pattern.Processes[i].ID == id {
			return &pattern.Processes[i]
		}
	}

	return nil
}

// MatchPattern reports whether any relationship satisfies the pattern,
// considering every event in the chains regardless of age.
func (m *Matcher) MatchPattern(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
) bool {
	return m.matchPattern(pattern, relationships, chains, m.MatchEvents)
}

// MatchPatternAfter is MatchPattern restricted to events whose timestamp is
// strictly after cutoff: the lower edge of the correlation window.
func (m *Matcher) MatchPatternAfter(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
	cutoff time.Time,
) bool {
	return m.matchPattern(
		pattern,
		relationships,
		chains,
		func(p ProcessPattern, chain *Chain) bool {
			return m.MatchEventsAfter(p, chain, cutoff)
		},
	)
}

func (m *Matcher) matchPattern(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
	matchEvents func(ProcessPattern, *Chain) bool,
) bool {
	if len(pattern.Processes) == 0 {
		return false
	}

	if len(pattern.Relationships) == 0 {
		return false
	}

	for _, relationshipPattern := range pattern.Relationships {
		for _, relationship := range relationships {
			if relationship.Type != relationshipPattern.Type {
				continue
			}

			parentPattern := findProcessPattern(
				pattern,
				relationshipPattern.Parent,
			)

			childPattern := findProcessPattern(
				pattern,
				relationshipPattern.Child,
			)

			if parentPattern == nil || childPattern == nil {
				continue
			}

			if !m.MatchRelationship(
				relationshipPattern,
				relationship,
				*parentPattern,
				*childPattern,
			) {
				continue
			}

			if !m.MatchProcess(
				*parentPattern,
				relationship.Parent,
			) {
				continue
			}

			if !m.MatchProcess(
				*childPattern,
				relationship.Child,
			) {
				continue
			}

			parentChains := chains[relationship.Parent.Identity()]

			childChains := chains[relationship.Child.Identity()]

			if !matchAnyChain(*parentPattern, parentChains, matchEvents) {
				continue
			}

			if !matchAnyChain(*childPattern, childChains, matchEvents) {
				continue
			}

			return true
		}
	}

	return false
}

// MatchAnyChain reports whether any one chain satisfies the pattern's event
// requirements. A pattern that requires no events is satisfied even by a
// process with no chains.
func (m *Matcher) MatchAnyChain(
	pattern ProcessPattern,
	chains []*Chain,
) bool {
	return matchAnyChain(pattern, chains, m.MatchEvents)
}

func matchAnyChain(
	pattern ProcessPattern,
	chains []*Chain,
	matchEvents func(ProcessPattern, *Chain) bool,
) bool {
	// Nothing is required, so there is nothing a chain could fail to
	// provide. Without this a process would stop matching as soon as its
	// last event aged out of the window.
	if len(pattern.Events) == 0 {
		return true
	}

	for _, chain := range chains {
		if matchEvents(pattern, chain) {
			return true
		}
	}

	return false
}
