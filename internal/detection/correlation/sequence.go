package correlation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

const (
	// DefaultOrderTolerance is how much later than the following step a
	// sequence step's event may be timestamped, when the pattern does not
	// say. Event timestamps record when Sentinel observed something, and
	// process and network activity is observed by polling every two
	// seconds, so an earlier action can carry a later timestamp than a
	// later one seen by a collector that reports at once. Three seconds
	// covers the polling interval and the time a collection takes.
	DefaultOrderTolerance = 3 * time.Second

	// MaxSequenceSteps is the most steps a sequence may have.
	MaxSequenceSteps = 8

	// maxSequenceSearch bounds the work of looking for one sequence among
	// the events of the bound processes.
	maxSequenceSearch = 20000
)

// SequencePattern requires events to have happened in a given order, on the
// processes bound to the pattern's roles.
type SequencePattern struct {
	// Within is the most time allowed between the first and last step's
	// events. Zero means the whole correlation window.
	Within time.Duration
	// OrderTolerance is how much later than the following step an earlier
	// step's event may be timestamped. Nil means DefaultOrderTolerance.
	OrderTolerance *time.Duration
	Steps          []SequenceStep
}

// SequenceStep is satisfied by one event of Type, on the process bound to
// Role, that satisfies Where.
type SequenceStep struct {
	Role  string
	Type  core.EventType
	Where *MatchBlock
	// Capture names the matched event so that later steps can compare
	// against its fields, writing $name.field as an operator's value.
	Capture string
}

// stepPredicate decides whether an event satisfies a step, given the events
// captured by earlier steps.
type stepPredicate func(event *core.Event, captured []*core.Event) bool

type compiledSequence struct {
	within    time.Duration
	tolerance time.Duration
	steps     []compiledStep
	captures  int
}

type compiledStep struct {
	role      int
	eventType core.EventType
	where     stepPredicate // nil accepts any event of the type
	// capture is where the matched event is stored for later steps, or -1.
	capture int
}

// capture is a named event available to later steps.
type capture struct {
	index     int
	step      int
	eventType core.EventType
}

var referencePattern = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)\.([a-z_]+)$`)

// parseReference splits "$name.field".
func parseReference(text string) (name, fieldName string, ok bool) {
	parts := referencePattern.FindStringSubmatch(text)
	if parts == nil {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// compileSequence checks and prepares a pattern's sequence. roles maps role
// IDs to their index.
func compileSequence(sequence *SequencePattern, roles map[string]int, window time.Duration) (*compiledSequence, error) {
	compiled := &compiledSequence{within: sequence.Within, tolerance: DefaultOrderTolerance}

	if sequence.Within < 0 || sequence.Within > window {
		return nil, fmt.Errorf("within must be more than 0 and at most the correlation window (%s), got %s", window, sequence.Within)
	}
	if compiled.within == 0 {
		compiled.within = window
	}

	if sequence.OrderTolerance != nil {
		if *sequence.OrderTolerance < 0 || *sequence.OrderTolerance > window {
			return nil, fmt.Errorf("order_tolerance must be between 0 and the correlation window (%s), got %s", window, *sequence.OrderTolerance)
		}
		compiled.tolerance = *sequence.OrderTolerance
	}

	if len(sequence.Steps) == 0 {
		return nil, fmt.Errorf("steps: a sequence needs at least one step")
	}
	if len(sequence.Steps) > MaxSequenceSteps {
		return nil, fmt.Errorf("steps: at most %d steps, got %d", MaxSequenceSteps, len(sequence.Steps))
	}

	// Every capture name, so that a reference to one defined later can be
	// told apart from a reference to one that does not exist.
	definedAt := make(map[string]int)
	for i, step := range sequence.Steps {
		if step.Capture == "" {
			continue
		}
		if !captureNamePattern.MatchString(step.Capture) {
			return nil, fmt.Errorf("steps[%d]: capture %q: a name is letters, digits and underscores, not starting with a digit", i, step.Capture)
		}
		if first, duplicate := definedAt[step.Capture]; duplicate {
			return nil, fmt.Errorf("steps[%d]: capture %q is already defined by steps[%d]", i, step.Capture, first)
		}
		definedAt[step.Capture] = i
	}

	available := make(map[string]capture)

	for i, step := range sequence.Steps {
		role, known := roles[step.Role]
		if !known {
			return nil, fmt.Errorf("steps[%d]: unknown role %q", i, step.Role)
		}
		if step.Type == "" {
			return nil, fmt.Errorf("steps[%d]: type is required", i)
		}

		prepared := compiledStep{role: role, eventType: step.Type, capture: -1}

		if step.Where != nil {
			scope := &referenceScope{step: i, available: available, definedAt: definedAt}
			where, err := compileStepWhere(step.Where, step.Type, "where", scope)
			if err != nil {
				return nil, fmt.Errorf("steps[%d] (%s): %w", i, step.Type, err)
			}
			prepared.where = where
		}

		// A step's own capture is available to later steps only.
		if step.Capture != "" {
			prepared.capture = compiled.captures
			available[step.Capture] = capture{index: compiled.captures, step: i, eventType: step.Type}
			compiled.captures++
		}

		compiled.steps = append(compiled.steps, prepared)
	}

	return compiled, nil
}

var captureNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// referenceScope is what a step's where block may refer to.
type referenceScope struct {
	step      int
	available map[string]capture
	definedAt map[string]int
}

// resolve finds the captured field a reference names.
func (s *referenceScope) resolve(text string) (capture, field[core.Event], error) {
	name, fieldName, _ := parseReference(text)

	captured, ok := s.available[name]
	if !ok {
		if at, later := s.definedAt[name]; later {
			if at == s.step {
				return capture{}, field[core.Event]{}, fmt.Errorf("reference %s: capture %q is defined by this step; only later steps can use it", text, name)
			}
			return capture{}, field[core.Event]{}, fmt.Errorf("reference %s: capture %q is defined by steps[%d], after this step", text, name, at)
		}
		return capture{}, field[core.Event]{}, fmt.Errorf("reference %s: unknown capture %q", text, name)
	}

	fields := eventFields(captured.eventType)
	f, ok := fields[fieldName]
	if !ok {
		return capture{}, field[core.Event]{}, fmt.Errorf("reference %s: %q is not a field of the captured %s event (valid fields: %s)",
			text, fieldName, captured.eventType, fieldNames(fields))
	}

	return captured, f, nil
}

// compileStepWhere compiles a step's where block. It differs from an
// ordinary where block only in that operator values may be references to
// captured events.
func compileStepWhere(block *MatchBlock, eventType core.EventType, path string, scope *referenceScope) (stepPredicate, error) {
	fields := eventFields(eventType)
	if fields == nil && !block.IsEmpty() {
		return nil, fmt.Errorf("%s: %s events have no fields to filter on", path, eventType)
	}

	return compileStepBlock(block, fields, path, scope)
}

func compileStepBlock(block *MatchBlock, fields map[string]field[core.Event], path string, scope *referenceScope) (stepPredicate, error) {
	// A block with no references is an ordinary block.
	if !blockHasReference(block) {
		static, err := compileBlock(block, fields, path)
		if err != nil {
			return nil, err
		}
		return func(event *core.Event, _ []*core.Event) bool { return static(event) }, nil
	}

	var tests []stepPredicate

	for _, fp := range block.Fields {
		where := path + "." + fp.Field

		f, known := fields[fp.Field]
		if !known {
			return nil, fmt.Errorf("%s: unknown field (valid fields: %s)", where, fieldNames(fields))
		}

		test, err := compileStepField(f, fp.Predicate, scope)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		tests = append(tests, test)
	}

	if block.AnyOf != nil {
		if len(block.AnyOf) == 0 {
			return nil, fmt.Errorf("%s.any_of: needs at least one alternative", path)
		}

		alternatives := make([]stepPredicate, len(block.AnyOf))
		for i := range block.AnyOf {
			alternative, err := compileStepBlock(&block.AnyOf[i], fields, fmt.Sprintf("%s.any_of[%d]", path, i), scope)
			if err != nil {
				return nil, err
			}
			alternatives[i] = alternative
		}

		tests = append(tests, func(event *core.Event, captured []*core.Event) bool {
			for _, alternative := range alternatives {
				if alternative(event, captured) {
					return true
				}
			}
			return false
		})
	}

	return func(event *core.Event, captured []*core.Event) bool {
		for _, test := range tests {
			if !test(event, captured) {
				return false
			}
		}
		return true
	}, nil
}

// compileStepField compiles one field's predicate, which may mix ordinary
// operators with ones whose value is a reference.
func compileStepField(f field[core.Event], p Predicate, scope *referenceScope) (stepPredicate, error) {
	if !predicateHasReference(p) {
		static, err := compileField(f, p)
		if err != nil {
			return nil, err
		}
		return func(event *core.Event, _ []*core.Event) bool { return static(event) }, nil
	}

	for _, unsupported := range []struct {
		name  string
		value *string
	}{{"glob", p.Glob}, {"regex", p.Regex}, {"gt", p.Gt}, {"gte", p.Gte}, {"lt", p.Lt}, {"lte", p.Lte}} {
		if unsupported.value != nil && isReference(*unsupported.value) {
			return nil, fmt.Errorf("reference %s: %q cannot take a captured value; use eq, in, prefix, suffix or contains", *unsupported.value, unsupported.name)
		}
	}
	for _, network := range p.CIDR {
		if isReference(network) {
			return nil, fmt.Errorf(`reference %s: "cidr" cannot take a captured value; use eq, in, prefix, suffix or contains`, network)
		}
	}

	var tests []stepPredicate

	// The operators with literal values compile as they always do.
	literal := p
	literal.Not = nil

	for _, operator := range []struct {
		name  string
		value **string
	}{{"eq", &literal.Eq}, {"prefix", &literal.Prefix}, {"suffix", &literal.Suffix}, {"contains", &literal.Contains}} {
		if *operator.value == nil || !isReference(**operator.value) {
			continue
		}

		test, err := compileReference(f, operator.name, **operator.value, p.NoCase, scope)
		if err != nil {
			return nil, err
		}
		tests = append(tests, test)
		*operator.value = nil
	}

	if containsReference(literal.In) {
		if len(literal.In) != 1 {
			return nil, fmt.Errorf(`"in" with a captured value takes exactly one element, got %d`, len(literal.In))
		}
		test, err := compileReference(f, "in", literal.In[0], p.NoCase, scope)
		if err != nil {
			return nil, err
		}
		tests = append(tests, test)
		literal.In = nil
	}

	if hasOperator(literal) {
		static, err := compileField(f, literal)
		if err != nil {
			return nil, err
		}
		tests = append(tests, func(event *core.Event, _ []*core.Event) bool { return static(event) })
	}

	if p.Not != nil {
		inner, err := compileStepField(f, *p.Not, scope)
		if err != nil {
			return nil, fmt.Errorf("not: %w", err)
		}
		tests = append(tests, func(event *core.Event, captured []*core.Event) bool {
			return !inner(event, captured)
		})
	}

	return func(event *core.Event, captured []*core.Event) bool {
		for _, test := range tests {
			if !test(event, captured) {
				return false
			}
		}
		return true
	}, nil
}

// compileReference builds the comparison of a field with a captured field.
// Like any positive operator it is false when either value is missing.
func compileReference(f field[core.Event], operator, text string, nocase bool, scope *referenceScope) (stepPredicate, error) {
	captured, other, err := scope.resolve(text)
	if err != nil {
		return nil, err
	}

	if f.kind != other.kind {
		return nil, fmt.Errorf("reference %s: a %s field cannot be compared with a %s field", text, f.kind, other.kind)
	}

	index := captured.index

	if f.kind == kindNumber {
		if operator != "eq" && operator != "in" {
			return nil, fmt.Errorf("reference %s: %q is not valid for a numeric field", text, operator)
		}
		if nocase {
			return nil, wrongKind("nocase", kindNumber)
		}

		own, their := f.number, other.number
		return func(event *core.Event, capturedEvents []*core.Event) bool {
			source := capturedEvents[index]
			if source == nil {
				return false
			}
			want, ok := their(source)
			if !ok {
				return false
			}
			got, ok := own(event)
			return ok && got == want
		}, nil
	}

	var compare func(got, want string) bool
	switch operator {
	case "eq", "in":
		compare = equalFunc(nocase)
	case "prefix", "suffix":
		compare = foldAware(operator, nocase)
	case "contains":
		compare = strings.Contains
		if nocase {
			// Only reached while a binding is being attempted, on a value
			// that is not known until then.
			compare = func(got, want string) bool {
				return strings.Contains(strings.ToLower(got), strings.ToLower(want))
			}
		}
	}

	// Two paths are the same file however they are spelt.
	clean := f.path && other.path
	own, their := f.text, other.text

	return func(event *core.Event, capturedEvents []*core.Event) bool {
		source := capturedEvents[index]
		if source == nil {
			return false
		}

		want, got := their(source), own(event)
		if want == "" || got == "" {
			return false
		}
		if clean {
			want, got = filepath.Clean(want), filepath.Clean(got)
		}

		return compare(got, want)
	}, nil
}

// foldAware returns prefix or suffix comparison of a value against a
// pattern that is only known when the comparison is made.
func foldAware(operator string, nocase bool) func(got, want string) bool {
	if operator == "prefix" {
		if !nocase {
			return strings.HasPrefix
		}
		return func(got, want string) bool {
			return len(got) >= len(want) && strings.EqualFold(got[:len(want)], want)
		}
	}

	if !nocase {
		return strings.HasSuffix
	}
	return func(got, want string) bool {
		return len(got) >= len(want) && strings.EqualFold(got[len(got)-len(want):], want)
	}
}

func isReference(text string) bool {
	_, _, ok := parseReference(text)
	return ok
}

func containsReference(values []string) bool {
	for _, value := range values {
		if isReference(value) {
			return true
		}
	}
	return false
}

// predicateHasReference reports whether any operator value in p, at any
// depth of not, is a reference.
func predicateHasReference(p Predicate) bool {
	for _, value := range []*string{p.Eq, p.Contains, p.Prefix, p.Suffix, p.Glob, p.Regex, p.Gt, p.Gte, p.Lt, p.Lte} {
		if value != nil && isReference(*value) {
			return true
		}
	}

	if containsReference(p.In) || containsReference(p.CIDR) {
		return true
	}

	return p.Not != nil && predicateHasReference(*p.Not)
}

func blockHasReference(block *MatchBlock) bool {
	if block == nil {
		return false
	}
	for _, fp := range block.Fields {
		if predicateHasReference(fp.Predicate) {
			return true
		}
	}
	for i := range block.AnyOf {
		if blockHasReference(&block.AnyOf[i]) {
			return true
		}
	}
	return false
}

// hasOperator reports whether p has any operator of its own left, apart
// from not.
func hasOperator(p Predicate) bool {
	return p.Eq != nil || p.In != nil || p.Contains != nil || p.Prefix != nil || p.Suffix != nil ||
		p.Glob != nil || p.Regex != nil || p.CIDR != nil || p.Gt != nil || p.Gte != nil ||
		p.Lt != nil || p.Lte != nil
}

// sequenceSearch looks for events, one per step, that satisfy a sequence.
type sequenceSearch struct {
	sequence *compiledSequence
	// candidates holds, for each step, the in-window events of the process
	// bound to the step's role, in time order.
	candidates [][]core.Event
	chosen     []*core.Event
	captured   []*core.Event
	budget     int
	exhausted  bool
}

// find reports whether the candidates contain a valid assignment, leaving it
// in chosen.
func (q *sequenceSearch) find() bool {
	return q.place(0, time.Time{})
}

// place chooses an event for step and those after it. latest is the latest
// timestamp among the events chosen so far.
func (q *sequenceSearch) place(step int, latest time.Time) bool {
	if step == len(q.sequence.steps) {
		return true
	}

	prepared := &q.sequence.steps[step]
	events := q.candidates[step]

	// An event may carry an earlier timestamp than one for a step before
	// it, but by no more than the tolerance.
	earliest := latest.Add(-q.sequence.tolerance)

	for i := range events {
		event := &events[i]

		if event.Type != prepared.eventType {
			continue
		}
		if step > 0 && event.Timestamp.Before(earliest) {
			continue
		}

		if step > 0 {
			// The first and last events must be no further apart than
			// within. Events are in time order, so once one is too late
			// every remaining one is.
			gap := event.Timestamp.Sub(q.chosen[0].Timestamp)
			if gap > q.sequence.within+q.sequence.tolerance {
				break
			}
			if step == len(q.sequence.steps)-1 && (gap > q.sequence.within || -gap > q.sequence.within) {
				continue
			}
		}

		if q.taken(event, step) {
			continue
		}

		if q.budget--; q.budget < 0 {
			q.exhausted = true
			return false
		}

		if prepared.where != nil && !prepared.where(event, q.captured) {
			continue
		}

		q.chosen[step] = event
		if prepared.capture >= 0 {
			q.captured[prepared.capture] = event
		}

		next := latest
		if event.Timestamp.After(next) {
			next = event.Timestamp
		}
		if q.place(step+1, next) {
			return true
		}
		if q.exhausted {
			return false
		}

		if prepared.capture >= 0 {
			q.captured[prepared.capture] = nil
		}
	}

	return false
}

// taken reports whether an earlier step already uses the event: one event
// cannot be two steps.
func (q *sequenceSearch) taken(event *core.Event, step int) bool {
	for i := 0; i < step; i++ {
		if q.chosen[i] == event {
			return true
		}
	}
	return false
}
