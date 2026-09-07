package correlation

import "github.com/arafat2020/sentinel/internal/core"

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

func (m *Matcher) MatchEvents(
	pattern ProcessPattern,
	chain *Chain,
) bool {
	if chain == nil {
		return false
	}

	events := chain.Events()

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

func (m *Matcher) MatchPattern(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
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

			if !m.MatchAnyChain(*parentPattern, parentChains) {
				continue
			}

			if !m.MatchAnyChain(*childPattern, childChains) {
				continue
			}

			return true
		}
	}

	return false
}

func (m *Matcher) MatchAnyChain(
	pattern ProcessPattern,
	chains []*Chain,
) bool {
	for _, chain := range chains {
		if m.MatchEvents(pattern, chain) {
			return true
		}
	}

	return false
}
