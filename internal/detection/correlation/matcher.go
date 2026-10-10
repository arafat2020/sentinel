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
	// Events are the events that satisfied the pattern's sequence, one per
	// step and in step order. It is nil for a pattern without a sequence.
	Events []core.Event
}

// MatchProcess reports whether the process meets the role's conditions and
// match block. A role that does not compile matches nothing.
func (m *Matcher) MatchProcess(
	pattern ProcessPattern,
	process core.Process,
) bool {
	role, err := compileRole(pattern, DefaultWindow)
	if err != nil {
		return false
	}

	return role.suitsProcess(&process)
}

// MatchEvents reports whether the chain contains, for each event the pattern
// requires, an event of that type passing its filter. Events of any age
// count.
func (m *Matcher) MatchEvents(
	pattern ProcessPattern,
	chain *Chain,
) bool {
	role, err := compileRole(pattern, DefaultWindow)
	if err != nil || chain == nil {
		return false
	}

	return role.satisfiedBy(chain.Events()) && role.thresholdsMetBy(chain.Events())
}

// MatchEventsAfter is MatchEvents restricted to events whose timestamp is
// strictly after cutoff.
func (m *Matcher) MatchEventsAfter(
	pattern ProcessPattern,
	chain *Chain,
	cutoff time.Time,
) bool {
	role, err := compileRole(pattern, DefaultWindow)
	if err != nil || chain == nil {
		return false
	}

	events := chain.EventsAfter(cutoff)

	return role.satisfiedBy(events) && role.thresholdsMetBy(events)
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
	compiled, _ := compilePattern(pattern, DefaultWindow)

	return m.find(compiled, newSliceWorld(relationships, chains, (*Chain).Events), (*Chain).Events, nil)
}

// FindMatchesAfter is FindMatches restricted to events whose timestamp is
// strictly after cutoff: the lower edge of the correlation window.
func (m *Matcher) FindMatchesAfter(
	pattern BehaviorPattern,
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
	cutoff time.Time,
) []Match {
	compiled, _ := compilePattern(pattern, DefaultWindow)
	window := func(chain *Chain) []core.Event { return chain.EventsAfter(cutoff) }

	return m.find(compiled, newSliceWorld(relationships, chains, window), window, nil)
}

// MatchAnyChain reports whether any one chain satisfies the pattern's event
// requirements. A pattern that requires no events is satisfied even by a
// process with no chains.
func (m *Matcher) MatchAnyChain(
	pattern ProcessPattern,
	chains []*Chain,
) bool {
	role, err := compileRole(pattern, DefaultWindow)
	if err != nil {
		return false
	}

	for _, chain := range chains {
		if !role.thresholdsMetBy(chain.Events()) {
			return false
		}
	}

	return anyChainSatisfies(role, chains, (*Chain).Events)
}

// anyChainSatisfies reports whether the events that window selects from some
// one chain meet the role's event requirements.
func anyChainSatisfies(
	role *compiledRole,
	chains []*Chain,
	window func(*Chain) []core.Event,
) bool {
	// Nothing is required, so there is nothing a chain could fail to
	// provide. Without this a process would stop matching as soon as its
	// last event aged out of the window.
	if len(role.events) == 0 && len(role.implied) == 0 {
		return true
	}

	for _, chain := range chains {
		events := window(chain)
		if role.satisfiedBy(events) && role.impliedBy(events) {
			return true
		}
	}

	return false
}

// world is what a pattern is matched against: the known processes, how they
// are related, and what they have done.
type world interface {
	// process returns a process that must not be modified.
	process(core.ProcessIdentity) (*core.Process, bool)
	parentOf(child core.ProcessIdentity) (core.ProcessIdentity, bool)
	// The each* methods stop when visit returns false.
	eachChild(parent core.ProcessIdentity, visit func(core.ProcessIdentity) bool)
	// eachDescendant visits the descendants of parent down to maxDepth
	// generations. The walk is bounded; an implementation that cuts it
	// short records that it did.
	eachDescendant(parent core.ProcessIdentity, maxDepth int, visit func(core.ProcessIdentity) bool)
	eachRelationship(visit func(parent, child core.ProcessIdentity) bool)
	eachProcess(visit func(core.ProcessIdentity) bool)
	chainsOf(core.ProcessIdentity) []*Chain
	// childCount is how many children a process has, visible or not.
	childCount(parent core.ProcessIdentity) int
	// having returns the processes that may have had an event of the given
	// type: every process that has one in the window is in it, and others
	// may be. ok is false when the world keeps no such record.
	having(eventType core.EventType) (processes map[core.ProcessIdentity]struct{}, ok bool)
	// searched is told how many candidate bindings a search considered.
	searched(candidates uint64)
	// thresholdMet reports whether the process currently meets a counting
	// requirement.
	thresholdMet(requirement *compiledEvent, process core.ProcessIdentity) bool
	// sequenceNotFound is told when roles were bound but no events
	// satisfied the pattern's sequence, so that an implementation can count
	// the cases where that may be for want of retained events or of search
	// budget rather than because the sequence did not happen.
	sequenceNotFound(processes []core.ProcessIdentity, searchExhausted bool)
}

// find searches w for ways of binding the pattern's roles.
//
// With seeds nil it returns every match. With seeds given it returns only
// the matches that include at least one seed process, which is all that can
// have become true when only those processes have changed. A match that
// includes several seeds may be returned more than once.
//
// window selects the events of a chain that count: all of them, or those
// inside the correlation window.
func (m *Matcher) find(
	pattern *compiledPattern,
	w world,
	window func(*Chain) []core.Event,
	seeds []core.ProcessIdentity,
) []Match {
	if !pattern.matchable {
		return nil
	}

	s := &search{
		pattern: pattern,
		world:   w,
		window:  window,
		bound:   make([]core.ProcessIdentity, len(pattern.Processes)),
		isBound: make([]bool, len(pattern.Processes)),
		done:    make([]bool, len(pattern.relationships)),
	}

	if seeds == nil {
		s.searchEverything()
	} else {
		s.searchAround(seeds)
	}

	w.searched(s.tried)

	return s.matches
}

// search is a backtracking search for role bindings. Roles are bound one
// relationship at a time, always extending from a role that is already
// bound when there is one, so candidates come from a bound process's parent
// or children rather than from every known process.
type search struct {
	pattern *compiledPattern
	world   world
	window  func(*Chain) []core.Event

	bound   []core.ProcessIdentity
	isBound []bool
	done    []bool // relationship patterns already satisfied

	matches []Match
	// tried counts the candidate bindings considered.
	tried uint64
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
		if s.isAncestor(s.bound[link.parent], s.bound[link.child], link.depth) {
			s.satisfy()
		}

	case s.isBound[link.parent]:
		parent := s.bound[link.parent]

		// A parent can have a great many children, of which the role
		// wants the few that did something in particular. When there are
		// fewer processes that did that thing than there are children to
		// look through, start from those and keep the ones this parent is
		// above.
		if candidates, ok := s.candidatesBelow(link); ok {
			for identity := range candidates {
				if s.isAncestor(parent, identity, link.depth) {
					s.try(link.child, identity)
				}
			}
			break
		}

		visit := func(identity core.ProcessIdentity) bool {
			s.try(link.child, identity)
			return true
		}
		if link.depth == 1 {
			s.world.eachChild(parent, visit)
		} else {
			s.world.eachDescendant(parent, link.depth, visit)
		}

	case s.isBound[link.child]:
		s.eachAncestor(s.bound[link.child], link.depth, func(identity core.ProcessIdentity) {
			s.try(link.parent, identity)
		})

	case link.depth == 1:
		// Nothing to extend from: start from the known relationships.
		s.world.eachRelationship(func(parentID, childID core.ProcessIdentity) bool {
			if s.bind(link.parent, parentID) {
				s.try(link.child, childID)
				s.unbind(link.parent)
			}
			return true
		})

	default:
		// Nothing to extend from, and the pairs are not listed anywhere:
		// take each process as the descendant and look up its ancestry.
		s.world.eachProcess(func(childID core.ProcessIdentity) bool {
			if s.bind(link.child, childID) {
				s.eachAncestor(childID, link.depth, func(identity core.ProcessIdentity) {
					s.try(link.parent, identity)
				})
				s.unbind(link.child)
			}
			return true
		})
	}
}

// candidatesBelow returns a set of processes that includes everything below
// the link's bound parent that could fill its child role, when that set is a
// better place to look than the parent's children.
func (s *search) candidatesBelow(link roleLink) (map[core.ProcessIdentity]struct{}, bool) {
	needs := s.pattern.roles[link.child].needs
	if len(needs) == 0 {
		return nil, false
	}

	var smallest map[core.ProcessIdentity]struct{}
	for i, eventType := range needs {
		having, ok := s.world.having(eventType)
		if !ok {
			return nil, false
		}
		if i == 0 || len(having) < len(smallest) {
			smallest = having
		}
	}

	// Going through the children costs one step each. Going through the
	// candidates costs a walk up the tree each, of at most depth steps.
	limit := s.world.childCount(s.bound[link.parent])
	if link.depth > 1 {
		// The descendants are not counted anywhere; a walk through them
		// stops at maxDescendantVisits.
		limit = maxDescendantVisits
	}
	if len(smallest)*link.depth >= limit {
		return nil, false
	}

	return smallest, true
}

// eachAncestor visits the ancestors of a process, nearest first, up to
// maxDepth generations. The chain stops at the first process whose parent is
// not known: ancestry is never assumed across a gap.
func (s *search) eachAncestor(identity core.ProcessIdentity, maxDepth int, visit func(core.ProcessIdentity)) {
	current := identity

	for generation := 0; generation < maxDepth; generation++ {
		parent, ok := s.world.parentOf(current)
		if !ok {
			return
		}
		visit(parent)
		current = parent
	}
}

// isAncestor reports whether ancestor is within maxDepth generations above
// descendant.
func (s *search) isAncestor(ancestor, descendant core.ProcessIdentity, maxDepth int) bool {
	current := descendant

	for generation := 0; generation < maxDepth; generation++ {
		parent, ok := s.world.parentOf(current)
		if !ok {
			return false
		}
		if parent == ancestor {
			return true
		}
		current = parent
	}

	return false
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
	s.tried++

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

// suits reports whether the process may fill the role and has produced the
// events the role requires. The process itself is checked first: that is
// cheap and usually rules a candidate out before its events are examined.
func (s *search) suits(role int, identity core.ProcessIdentity) bool {
	process, ok := s.world.process(identity)
	if !ok {
		return false
	}

	compiled := &s.pattern.roles[role]

	if !compiled.suitsProcess(process) ||
		!anyChainSatisfies(compiled, s.world.chainsOf(identity), s.window) {
		return false
	}

	for i := range compiled.thresholds {
		if !s.world.thresholdMet(&compiled.thresholds[i], identity) {
			return false
		}
	}

	return true
}

// emit records the current bindings as a match.
func (s *search) emit() {
	for i := range s.bound {
		if !s.isBound[i] {
			return
		}
	}

	// Most bindings fail here, so nothing is built for the match until
	// the sequence has been found.
	var events []core.Event
	if s.pattern.sequence != nil {
		found, ok := s.findSequence()
		if !ok {
			return
		}
		events = found
	}

	processes := make([]core.Process, len(s.bound))
	for i, identity := range s.bound {
		process, ok := s.world.process(identity)
		if !ok {
			return
		}
		processes[i] = *process
	}

	s.matches = append(s.matches, Match{Processes: processes, Events: events})
}

// findSequence looks, among the in-window events of the bound processes,
// for one event per step that satisfies the pattern's sequence. It is run
// only once every role is bound, so the sequence is a constraint on a
// binding rather than something tracked as events arrive: events that reach
// the engine out of order need no special handling.
func (s *search) findSequence() ([]core.Event, bool) {
	sequence := s.pattern.sequence

	q := sequenceSearch{
		sequence:   sequence,
		candidates: make([][]core.Event, len(sequence.steps)),
		chosen:     make([]*core.Event, len(sequence.steps)),
		captured:   make([]*core.Event, sequence.captures),
		budget:     maxSequenceSearch,
	}

	for i, step := range sequence.steps {
		// A process has one chain in an engine; a caller holding its own
		// chains is expected to keep a process's events together.
		for _, chain := range s.world.chainsOf(s.bound[step.role]) {
			q.candidates[i] = s.window(chain)
			break
		}
	}

	if !q.find() {
		s.world.sequenceNotFound(s.bound, q.exhausted)
		return nil, false
	}

	events := make([]core.Event, len(q.chosen))
	for i, event := range q.chosen {
		events[i] = *event
	}

	return events, true
}

// sliceWorld is a world built from a list of relationships, for callers that
// hold one rather than an Engine.
type sliceWorld struct {
	processes map[core.ProcessIdentity]*core.Process
	topology  *topology
	chains    map[core.ProcessIdentity][]*Chain
	// window selects the events of a chain that count.
	window func(*Chain) []core.Event
}

func newSliceWorld(
	relationships []ProcessRelationship,
	chains map[core.ProcessIdentity][]*Chain,
	window func(*Chain) []core.Event,
) *sliceWorld {
	w := &sliceWorld{
		processes: make(map[core.ProcessIdentity]*core.Process),
		topology:  newTopology(),
		chains:    chains,
		window:    window,
	}

	for _, relationship := range relationships {
		if relationship.Type != RelationshipSpawned {
			continue
		}

		relationship := relationship
		parent, child := relationship.Parent.Identity(), relationship.Child.Identity()
		w.processes[parent] = &relationship.Parent
		w.processes[child] = &relationship.Child
		w.topology.link(parent, child)
	}

	return w
}

func (w *sliceWorld) process(identity core.ProcessIdentity) (*core.Process, bool) {
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

func (w *sliceWorld) eachDescendant(parent core.ProcessIdentity, maxDepth int, visit func(core.ProcessIdentity) bool) {
	walkDescendants(w.topology, parent, maxDepth, nil, visit)
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

func (w *sliceWorld) sequenceNotFound([]core.ProcessIdentity, bool) {}

func (w *sliceWorld) childCount(parent core.ProcessIdentity) int {
	return len(w.topology.children[parent])
}

func (w *sliceWorld) searched(uint64) {}

// A sliceWorld keeps no record of which processes have had which events.
func (w *sliceWorld) having(core.EventType) (map[core.ProcessIdentity]struct{}, bool) {
	return nil, false
}

// thresholdMet counts over the events the chains happen to hold: there is no
// engine here keeping counters as events arrive.
func (w *sliceWorld) thresholdMet(requirement *compiledEvent, process core.ProcessIdentity) bool {
	for _, chain := range w.chains[process] {
		if !requirement.replay(w.window(chain)).metAt.IsZero() {
			return true
		}
	}
	return false
}
