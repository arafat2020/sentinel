package correlation

import (
	"fmt"
	"time"

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
	// sequence is the ordered-events constraint, or nil.
	sequence *compiledSequence
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
	// events are the requirements met by a single matching event.
	events []compiledEvent
	// thresholds are the requirements that need counting.
	thresholds []compiledEvent
}

// compiledEvent is one event requirement: an event of the type that passes
// the filter.
type compiledEvent struct {
	eventType core.EventType
	where     eventPredicate // nil accepts any event of the type
	// threshold is set for a requirement that needs counting.
	threshold *thresholdSpec
}

// matches reports whether one event counts towards the requirement.
func (e *compiledEvent) matches(event *core.Event) bool {
	return event.Type == e.eventType && (e.where == nil || e.where(event))
}

// thresholdsMetBy reports whether events, which must be in time order, meet
// every counting requirement of the role, by replaying them.
func (r *compiledRole) thresholdsMetBy(events []core.Event) bool {
	for i := range r.thresholds {
		if r.thresholds[i].replay(events).metAt.IsZero() {
			return false
		}
	}
	return true
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
//
// window is the correlation window of the engine the pattern is for; spans
// in the pattern default to it and may not exceed it.
func compilePattern(pattern BehaviorPattern, window time.Duration) (*compiledPattern, error) {
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

		compiledRole, err := compileRole(role, window)
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

	if pattern.Sequence != nil {
		sequence, err := compileSequence(pattern.Sequence, indexes, window)
		if err != nil {
			return compiled, fmt.Errorf("sequence: %w", err)
		}
		compiled.sequence = sequence
	}

	compiled.roles = roles
	// A pattern with no roles is a draft: valid, but there is nothing to
	// match.
	compiled.matchable = len(roles) > 0

	return compiled, nil
}

// compileRole prepares one role's conditions, match block and event
// requirements.
func compileRole(role ProcessPattern, window time.Duration) (*compiledRole, error) {
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

		if !event.isThreshold() {
			if event.Count < 0 {
				return nil, fmt.Errorf("events[%d] (%s): count must be at least 1, got %d", i, event.Type, event.Count)
			}
			compiled.events = append(compiled.events, required)
			continue
		}

		threshold, err := compileThreshold(event, window)
		if err != nil {
			return nil, fmt.Errorf("events[%d] (%s): %w", i, event.Type, err)
		}
		required.threshold = threshold
		compiled.thresholds = append(compiled.thresholds, required)
	}

	return compiled, nil
}

// compileThreshold checks and prepares the counting part of an event
// requirement.
func compileThreshold(event EventPattern, window time.Duration) (*thresholdSpec, error) {
	spec := &thresholdSpec{count: event.Count, within: event.Within}

	if spec.count == 0 {
		spec.count = 1
	}
	if spec.count < 1 {
		return nil, fmt.Errorf("count must be at least 1, got %d", event.Count)
	}
	if spec.count > MaxThresholdCount {
		return nil, fmt.Errorf("count must be at most %d, got %d", MaxThresholdCount, event.Count)
	}

	if event.Within < 0 || event.Within > window {
		return nil, fmt.Errorf("within must be more than 0 and at most the correlation window (%s), got %s", window, event.Within)
	}
	if event.Within != 0 && spec.count == 1 && event.Distinct == "" {
		return nil, fmt.Errorf("within needs a count above 1 or distinct: one event is always within any span")
	}
	if spec.within == 0 {
		spec.within = window
	}

	if event.Distinct != "" {
		f, known := eventFields(event.Type)[event.Distinct]
		if !known {
			return nil, fmt.Errorf("distinct: %q is not a field of %s events (valid fields: %s)",
				event.Distinct, event.Type, fieldNames(eventFields(event.Type)))
		}

		if f.kind == kindNumber {
			read := f.number
			spec.distinct = func(e *core.Event) (distinctValue, bool) {
				number, ok := read(e)
				return distinctValue{number: number}, ok
			}
		} else {
			read := f.text
			spec.distinct = func(e *core.Event) (distinctValue, bool) {
				text := read(e)
				return distinctValue{text: text}, text != ""
			}
		}
	}

	return spec, nil
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
