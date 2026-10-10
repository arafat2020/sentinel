package correlation

import (
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
)

// compiledPattern is a pattern prepared for matching: its structure resolved
// and every predicate turned into a function, once, so that evaluating it
// parses nothing and allocates nothing per event.
type compiledPattern struct {
	BehaviorPattern
	// matchable is false for a pattern that failed to compile or has no
	// roles; such a pattern never matches.
	matchable bool
	roles     []compiledRole
	// relationships holds, for each relationship pattern, the indexes of
	// its parent and child roles in Processes.
	relationships []roleLink
	// maxFindings is the rule's findings-per-window limit, defaults applied.
	maxFindings int
	// deep is true when a relationship spans more than one generation, so a
	// change anywhere in a process's ancestry can affect a match.
	deep bool
}

type roleLink struct {
	parent, child int
	// depth is how many generations may separate the two: 1 for a direct
	// parent and child.
	depth int
}

// compiledRole is what a process must satisfy to fill a role.
type compiledRole struct {
	// accepts are the conditions and match block; all must hold.
	accepts []processPredicate
	// rejects are the pattern's exclusions for this role; none may hold.
	rejects []processPredicate
	events  []compiledEvent
}

// compiledEvent is one event requirement: an event of the type that passes
// the filter.
type compiledEvent struct {
	eventType core.EventType
	where     eventPredicate // nil accepts any event of the type
}

// suitsProcess reports whether the process itself, leaving its events aside,
// may fill the role.
func (r *compiledRole) suitsProcess(process *core.Process) bool {
	for _, accept := range r.accepts {
		if !accept(process) {
			return false
		}
	}
	for _, reject := range r.rejects {
		if reject(process) {
			return false
		}
	}
	return true
}

// satisfiedBy reports whether events, taken together, meet every event
// requirement of the role. Each requirement needs one event of its type that
// passes its filter; the requirements are independent of each other.
func (r *compiledRole) satisfiedBy(events []core.Event) bool {
	for i := range r.events {
		required := &r.events[i]
		found := false

		for j := range events {
			if events[j].Type != required.eventType {
				continue
			}
			if required.where == nil || required.where(&events[j]) {
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

// compilePattern prepares a pattern for matching. The returned pattern is
// always usable: when err is non-nil it simply never matches.
func compilePattern(pattern BehaviorPattern) (*compiledPattern, error) {
	compiled := &compiledPattern{
		BehaviorPattern: pattern,
		maxFindings:     pattern.MaxFindingsPerWindow,
	}
	if compiled.maxFindings == 0 {
		compiled.maxFindings = DefaultMaxFindingsPerWindow
	}

	if err := pattern.validateStructure(); err != nil {
		return compiled, err
	}

	indexes := make(map[string]int, len(pattern.Processes))
	roles := make([]compiledRole, len(pattern.Processes))

	for i, role := range pattern.Processes {
		indexes[role.ID] = i

		compiledRole, err := compileRole(role)
		if err != nil {
			return compiled, fmt.Errorf("role %q: %w", role.ID, err)
		}
		roles[i] = *compiledRole
	}

	for i, exclusion := range pattern.Exclude {
		reject, err := compileProcessMatch(exclusion.Match, "match")
		if err != nil {
			return compiled, fmt.Errorf("exclude[%d] (role %q): %w", i, exclusion.Role, err)
		}
		if exclusion.Match.IsEmpty() {
			return compiled, fmt.Errorf("exclude[%d] (role %q): match: an exclusion must say which processes it excludes", i, exclusion.Role)
		}

		role := &roles[indexes[exclusion.Role]]
		role.rejects = append(role.rejects, reject)
	}

	for _, relationship := range pattern.Relationships {
		link := roleLink{
			parent: indexes[relationship.Parent],
			child:  indexes[relationship.Child],
			depth:  relationship.depth(),
		}
		if link.depth > 1 {
			compiled.deep = true
		}
		compiled.relationships = append(compiled.relationships, link)
	}

	compiled.roles = roles
	// A pattern with no roles is a draft: valid, but there is nothing to
	// match.
	compiled.matchable = len(roles) > 0

	return compiled, nil
}

// compileRole prepares one role's conditions, match block and event
// requirements.
func compileRole(role ProcessPattern) (*compiledRole, error) {
	compiled := &compiledRole{}

	for _, condition := range role.Conditions {
		accept, err := compileCondition(condition)
		if err != nil {
			return nil, err
		}
		compiled.accepts = append(compiled.accepts, accept)
	}

	if role.Match != nil {
		accept, err := compileProcessMatch(role.Match, "match")
		if err != nil {
			return nil, err
		}
		compiled.accepts = append(compiled.accepts, accept)
	}

	for i, event := range role.Events {
		required := compiledEvent{eventType: event.Type}

		if event.Where != nil {
			where, err := compileEventWhere(event.Where, event.Type, "where")
			if err != nil {
				return nil, fmt.Errorf("events[%d] (%s): %w", i, event.Type, err)
			}
			required.where = where
		}

		compiled.events = append(compiled.events, required)
	}

	return compiled, nil
}

// compileCondition turns an original-schema condition into the equality
// predicate it has always meant.
func compileCondition(condition Condition) (processPredicate, error) {
	value := condition.Value

	switch condition.Type {
	case ConditionProcessName:
		return func(p *core.Process) bool { return p.Name == value }, nil
	case ConditionProcessUser:
		return func(p *core.Process) bool { return p.User == value }, nil
	default:
		return nil, fmt.Errorf("unknown condition type %q", condition.Type)
	}
}
