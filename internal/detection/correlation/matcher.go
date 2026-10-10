package correlation

import (
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type Matcher struct{}

func NewMatcher() *Matcher {
	return &Matcher{}
}

// Match is one way of filling every role of a pattern: an assignment of a
// distinct process to each role under which all of the pattern's conditions,
// event requirements and relationships hold.
type Match struct {
	// Processes are the bound processes, in the order the pattern lists its
	// roles.
	Processes []core.Process
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

// MatchEvents reports whether the chain contains every event type the
// pattern requires, considering every event in the chain regardless of age.
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

func matchEvents(pattern ProcessPattern, events []core.Event) bool {
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

// MatchPattern reports whether the pattern can be fully matched: whether
// some assignment of processes to roles satisfies every role and every
// relationship. Events of any age count.
func (m *Matcher) MatchPattern(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
) bool {
	return len(m.FindMatches(pattern, relationships, chains)) > 0
}

// FindMatches returns every assignment of processes to roles that satisfies
// the pattern, drawing processes from the given relationships. Events of any
// age count.
func (m *Matcher) FindMatches(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
) []Match {
	return m.find(compilePattern(pattern), newSliceWorld(relationships, chains), m.MatchEvents, nil)
}

// FindMatchesAfter is FindMatches restricted to events whose timestamp is
// strictly after cutoff: the lower edge of the correlation window.
func (m *Matcher) FindMatchesAfter(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
	cutoff time.Time,
) []Match {
	return m.find(
		compilePattern(pattern),
		newSliceWorld(relationships, chains),
		func(p ProcessPattern, chain *Chain) bool {
			return m.MatchEventsAfter(p, chain, cutoff)
		},
		nil,
	)
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

// world is what a pattern is matched against: the known processes, how they
// are related, and what they have done.
type world interface {
	process(core.ProcessIdentity) (core.Process, bool)
	parentOf(child core.ProcessIdentity) (core.ProcessIdentity, bool)
	// The each* methods stop when visit returns false.
	eachChild(parent core.ProcessIdentity, visit func(core.ProcessIdentity) bool)
	eachRelationship(visit func(parent, child core.ProcessIdentity) bool)
	eachProcess(visit func(core.ProcessIdentity) bool)
	chainsOf(core.ProcessIdentity) []*Chain
}

// compiledPattern is a pattern with its structure resolved once, so that
// evaluating it does not repeat validation and role lookups.
type compiledPattern struct {
	BehaviorPattern
	// matchable is false for a pattern that is structurally invalid or has
	// no roles; such a pattern never matches.
	matchable bool
	// relationships holds, for each relationship pattern, the indexes of
	// its parent and child roles in Processes.
	relationships []roleLink
}

type roleLink struct {
	parent, child int
}

func compilePattern(pattern BehaviorPattern) *compiledPattern {
	compiled := &compiledPattern{BehaviorPattern: pattern}

	if len(pattern.Processes) == 0 || pattern.Validate() != nil {
		return compiled
	}

	roles := make(map[string]int, len(pattern.Processes))
	for i, role := range pattern.Processes {
		roles[role.ID] = i
	}

	for _, relationship := range pattern.Relationships {
		compiled.relationships = append(compiled.relationships, roleLink{
			parent: roles[relationship.Parent],
			child:  roles[relationship.Child],
		})
	}
	compiled.matchable = true

	return compiled
}

// find searches w for ways of binding the pattern's roles.
//
// With seeds nil it returns every match. With seeds given it returns only
// the matches that include at least one seed process, which is all that can
// have become true when only those processes have changed. A match that
// includes several seeds may be returned more than once.
func (m *Matcher) find(
	pattern *compiledPattern,
	w world,
	matchEvents func(ProcessPattern, *Chain) bool,
	seeds []core.ProcessIdentity,
) []Match {
	if !pattern.matchable {
		return nil
	}

	s := &search{
		matcher:     m,
		pattern:     pattern,
		world:       w,
		matchEvents: matchEvents,
		bound:       make([]core.ProcessIdentity, len(pattern.Processes)),
		isBound:     make([]bool, len(pattern.Processes)),
		done:        make([]bool, len(pattern.relationships)),
	}

	if seeds == nil {
		s.searchEverything()
	} else {
		s.searchAround(seeds)
	}

	return s.matches
}

// search is a backtracking search for role bindings. Roles are bound one
// relationship at a time, always extending from a role that is already
// bound when there is one, so candidates come from a bound process's parent
// or children rather than from every known process.
type search struct {
	matcher     *Matcher
	pattern     *compiledPattern
	world       world
	matchEvents func(ProcessPattern, *Chain) bool

	bound   []core.ProcessIdentity
	isBound []bool
	done    []bool // relationship patterns already satisfied

	matches []Match
}

func (s *search) searchEverything() {
	if len(s.pattern.relationships) == 0 {
		// A valid pattern without relationships has exactly one role.
		s.world.eachProcess(func(identity core.ProcessIdentity) bool {
			s.try(0, identity)
			return true
		})
		return
	}

	// With no role bound yet, satisfy seeds itself from the relationships.
	s.satisfy()
}

// searchAround tries each seed process in each role and completes the
// binding from there.
func (s *search) searchAround(seeds []core.ProcessIdentity) {
	for _, seed := range seeds {
		for role := range s.pattern.Processes {
			s.try(role, seed)
		}
	}
}

// satisfy binds roles until every relationship pattern holds, recording a
// match each time none remain.
func (s *search) satisfy() {
	index := s.nextRelationship()
	if index < 0 {
		s.emit()
		return
	}

	link := s.pattern.relationships[index]

	s.done[index] = true
	defer func() { s.done[index] = false }()

	switch {
	case s.isBound[link.parent] && s.isBound[link.child]:
		if actual, ok := s.world.parentOf(s.bound[link.child]); ok && actual == s.bound[link.parent] {
			s.satisfy()
		}

	case s.isBound[link.parent]:
		s.world.eachChild(s.bound[link.parent], func(identity core.ProcessIdentity) bool {
			s.try(link.child, identity)
			return true
		})

	case s.isBound[link.child]:
		if identity, ok := s.world.parentOf(s.bound[link.child]); ok {
			s.try(link.parent, identity)
		}

	default:
		// Nothing to extend from: start from the known relationships.
		s.world.eachRelationship(func(parentID, childID core.ProcessIdentity) bool {
			if s.bind(link.parent, parentID) {
				s.try(link.child, childID)
				s.unbind(link.parent)
			}
			return true
		})
	}
}

// nextRelationship picks an unsatisfied relationship pattern, preferring one
// that touches a bound role. It returns -1 when all are satisfied.
func (s *search) nextRelationship() int {
	first := -1

	for i, link := range s.pattern.relationships {
		if s.done[i] {
			continue
		}
		if first < 0 {
			first = i
		}
		if s.isBound[link.parent] || s.isBound[link.child] {
			return i
		}
	}

	return first
}

// try binds role to identity, continues the search, and undoes the binding.
func (s *search) try(role int, identity core.ProcessIdentity) {
	if s.bind(role, identity) {
		s.satisfy()
		s.unbind(role)
	}
}

// bind assigns identity to role if the process suits the role and is not
// already bound to another one.
func (s *search) bind(role int, identity core.ProcessIdentity) bool {
	for i, taken := range s.bound {
		if s.isBound[i] && taken == identity {
			return false
		}
	}

	if !s.suits(role, identity) {
		return false
	}

	s.bound[role] = identity
	s.isBound[role] = true

	return true
}

func (s *search) unbind(role int) {
	s.isBound[role] = false
}

// suits reports whether the process meets the role's conditions and event
// requirements. Conditions are checked first: they are cheap and usually
// rule a process out before its events need to be examined.
func (s *search) suits(role int, identity core.ProcessIdentity) bool {
	process, ok := s.world.process(identity)
	if !ok {
		return false
	}

	pattern := s.pattern.Processes[role]

	return s.matcher.MatchProcess(pattern, process) &&
		matchAnyChain(pattern, s.world.chainsOf(identity), s.matchEvents)
}

// emit records the current bindings as a match.
func (s *search) emit() {
	processes := make([]core.Process, len(s.bound))

	for i, identity := range s.bound {
		process, ok := s.world.process(identity)
		if !s.isBound[i] || !ok {
			return
		}
		processes[i] = process
	}

	s.matches = append(s.matches, Match{Processes: processes})
}

// sliceWorld is a world built from a list of relationships, for callers that
// hold one rather than an Engine.
type sliceWorld struct {
	processes map[core.ProcessIdentity]core.Process
	topology  *topology
	chains    map[core.ProcessIdentity][]*Chain
}

func newSliceWorld(
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
) *sliceWorld {
	w := &sliceWorld{
		processes: make(map[core.ProcessIdentity]core.Process),
		topology:  newTopology(),
		chains:    chains,
	}

	for _, relationship := range relationships {
		if relationship.Type != RelationshipSpawned {
			continue
		}

		parent, child := relationship.Parent.Identity(), relationship.Child.Identity()
		w.processes[parent] = relationship.Parent
		w.processes[child] = relationship.Child
		w.topology.link(parent, child)
	}

	return w
}

func (w *sliceWorld) process(identity core.ProcessIdentity) (core.Process, bool) {
	process, ok := w.processes[identity]
	return process, ok
}

func (w *sliceWorld) parentOf(child core.ProcessIdentity) (core.ProcessIdentity, bool) {
	parent, ok := w.topology.parent[child]
	return parent, ok
}

func (w *sliceWorld) eachChild(parent core.ProcessIdentity, visit func(core.ProcessIdentity) bool) {
	for child := range w.topology.children[parent] {
		if !visit(child) {
			return
		}
	}
}

func (w *sliceWorld) eachRelationship(visit func(parent, child core.ProcessIdentity) bool) {
	for child, parent := range w.topology.parent {
		if !visit(parent, child) {
			return
		}
	}
}

func (w *sliceWorld) eachProcess(visit func(core.ProcessIdentity) bool) {
	for identity := range w.processes {
		if !visit(identity) {
			return
		}
	}
}

func (w *sliceWorld) chainsOf(identity core.ProcessIdentity) []*Chain {
	return w.chains[identity]
}
