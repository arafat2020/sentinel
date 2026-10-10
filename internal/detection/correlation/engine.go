package correlation

import (
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// maxSweepInterval caps how long expired state may linger before a sweep
// removes it. Matching never depends on a sweep having run; sweeping only
// releases memory.
const maxSweepInterval = 30 * time.Second

// Engine correlates process events into behavioral findings. The time-window
// and retention rules it guarantees are described in the package
// documentation. It is safe for concurrent use.
type Engine struct {
	mu sync.Mutex

	window time.Duration
	// latest is the high-water mark of evaluation time; see advance.
	latest    time.Time
	lastSweep time.Time

	// chains holds one bounded chain per process with in-window events.
	chains map[core.ProcessIdentity][]*Chain
	// relationships holds the parent of each child, keyed by the child.
	relationships map[core.ProcessIdentity]ProcessRelationship
	// processes are the processes seen starting and not yet exited, by PID.
	// It is only ever consulted together with an identity or start-time
	// check, because a PID alone does not identify a process.
	processes map[int32]core.Process
	// exited records when a process ended, so its relationship can be
	// released once its last events have left the window.
	exited map[core.ProcessIdentity]time.Time

	patterns []BehaviorPattern
	matcher  *Matcher
	emitted  map[string]time.Time // rule name → last emitted time
}

func NewEngine(window time.Duration) *Engine {
	return &Engine{
		chains:        make(map[core.ProcessIdentity][]*Chain),
		relationships: make(map[core.ProcessIdentity]ProcessRelationship),
		processes:     make(map[int32]core.Process),
		exited:        make(map[core.ProcessIdentity]time.Time),
		window:        window,
		patterns:      DefaultPatterns(),
		matcher:       NewMatcher(),
		emitted:       make(map[string]time.Time),
	}
}

// Process ingests an event received now.
func (e *Engine) Process(event core.Event) {
	e.ProcessAt(event, time.Now())
}

// ProcessAt ingests an event received at the given time.
func (e *Engine) ProcessAt(event core.Event, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now = e.advance(now)
	defer e.sweep(now)

	if event.Process == nil {
		return
	}

	process := *event.Process
	identity := process.Identity()

	// An event cannot be observed before it happens, and one that carries
	// no timestamp is taken to have happened when it arrived.
	if event.Timestamp.IsZero() || event.Timestamp.After(now) {
		event.Timestamp = now
	}

	switch event.Type {
	case core.EventProcessStart:
		e.trackStart(process, now)
	case core.EventProcessExit:
		e.trackExit(process, event.Timestamp)
	}

	// Already outside the window: the lifecycle bookkeeping above still
	// applies, but the event can never contribute to a match.
	cutoff := now.Add(-e.window)
	if !event.Timestamp.After(cutoff) {
		return
	}

	chains := e.chains[identity]

	if len(chains) == 0 {
		e.chains[identity] = []*Chain{
			NewChain(event),
		}
		return
	}

	// A process has exactly one chain, bounded by the window and by
	// MaxEventsPerType rather than by being split.
	chain := chains[0]
	chain.Add(event)
	chain.Prune(cutoff)
}

// trackStart records a started process and its parent, if the parent is
// known.
func (e *Engine) trackStart(process core.Process, now time.Time) {
	identity := process.Identity()

	if parent, ok := e.processes[process.PPID]; ok && plausibleParent(parent, process) {
		e.relationships[identity] = NewProcessRelationship(parent, process)
	}

	// The PID was held by a different process: that process must have
	// ended for the PID to be handed out again, whether or not its exit
	// event has arrived yet.
	if previous, ok := e.processes[process.PID]; ok && previous.Identity() != identity {
		if _, recorded := e.exited[previous.Identity()]; !recorded {
			e.exited[previous.Identity()] = now
		}
		e.reattributeChildren(previous, process)
	}

	// A start event that arrives after the same process's exit must not
	// bring it back as a candidate parent: nothing would remove it again.
	if _, gone := e.exited[identity]; gone {
		return
	}

	// Remember this process for future children.
	e.processes[process.PID] = process
}

// trackExit forgets an exited process as a candidate parent. The identity
// check matters: the exit of an old holder of a PID can arrive after the
// start of the new holder, which must stay.
func (e *Engine) trackExit(process core.Process, at time.Time) {
	identity := process.Identity()

	if current, ok := e.processes[process.PID]; ok && current.Identity() == identity {
		delete(e.processes, process.PID)
	}

	if _, recorded := e.exited[identity]; !recorded {
		e.exited[identity] = at
	}
}

// reattributeChildren corrects relationships made while a reused PID still
// pointed at its previous holder. Start events are not delivered in start
// order, so a child can be seen before the process that actually spawned
// it. A child that started no earlier than the new holder cannot belong to
// the previous one, which was already gone by then.
func (e *Engine) reattributeChildren(previous, current core.Process) {
	if !startKnown(current.StartTime) {
		return
	}

	for child, relationship := range e.relationships {
		if relationship.Parent.Identity() != previous.Identity() {
			continue
		}
		if !startKnown(relationship.Child.StartTime) ||
			relationship.Child.StartTime.Before(current.StartTime) {
			continue
		}

		relationship.Parent = current
		e.relationships[child] = relationship
	}
}

// plausibleParent rejects a candidate parent that cannot have spawned the
// child: the child itself, or a process that started after it (the PID has
// been reused since the real parent ended). When either start time is
// unknown there is nothing to compare, and the PID match is accepted.
func plausibleParent(parent, child core.Process) bool {
	if parent.Identity() == child.Identity() {
		return false
	}

	if startKnown(parent.StartTime) && startKnown(child.StartTime) &&
		parent.StartTime.After(child.StartTime) {
		return false
	}

	return true
}

// startKnown reports whether t is a real process start time. Collectors
// report the Unix epoch, not the zero Time, when the OS withholds it.
func startKnown(t time.Time) bool {
	return t.Unix() > 0
}

// advance folds now into the engine's evaluation time, which never moves
// backwards, and returns the time to use.
func (e *Engine) advance(now time.Time) time.Time {
	if now.After(e.latest) {
		e.latest = now
	}

	return e.latest
}

// sweep releases state that can no longer affect a match. It runs at most
// once per sweep interval.
func (e *Engine) sweep(now time.Time) {
	interval := e.window / 4
	if interval > maxSweepInterval {
		interval = maxSweepInterval
	}

	if !e.lastSweep.IsZero() && now.Sub(e.lastSweep) < interval {
		return
	}
	e.lastSweep = now

	cutoff := now.Add(-e.window)

	for identity, chains := range e.chains {
		kept := chains[:0]
		for _, chain := range chains {
			if chain.Prune(cutoff) > 0 {
				kept = append(kept, chain)
			}
		}

		if len(kept) == 0 {
			delete(e.chains, identity)
			continue
		}
		e.chains[identity] = kept
	}

	// One window after a process exits, none of its events remain.
	for identity, at := range e.exited {
		if !at.After(cutoff) {
			delete(e.exited, identity)
			delete(e.relationships, identity)
		}
	}

	for rule, last := range e.emitted {
		if now.Sub(last) >= e.window {
			delete(e.emitted, rule)
		}
	}
}

func (e *Engine) ChainsForProcess(
	identity core.ProcessIdentity,
) []*Chain {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.chains[identity]
}

func (e *Engine) RelationshipsForProcess(
	identity core.ProcessIdentity,
) []ProcessRelationship {
	e.mu.Lock()
	defer e.mu.Unlock()

	relationship, ok := e.relationships[identity]
	if !ok {
		return nil
	}

	return []ProcessRelationship{relationship}
}

func hasNetworkActivity(chains []*Chain) bool {
	for _, chain := range chains {
		for _, event := range chain.Events() {
			if event.Type == core.EventNetworkConnect {
				return true
			}
		}
	}

	return false
}

// DetectBehaviors evaluates all registered patterns as of now.
func (e *Engine) DetectBehaviors() []core.Finding {
	return e.DetectBehaviorsAt(time.Now())
}

// DetectBehaviorsAt evaluates all registered patterns against the events in
// the window ending at now and returns any newly triggered findings. A
// finding for a given rule is suppressed until at least one window duration
// has elapsed since it was last emitted, preventing duplicate alerts for a
// sustained behaviour.
func (e *Engine) DetectBehaviorsAt(now time.Time) []core.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()

	now = e.advance(now)
	e.sweep(now)

	var findings []core.Finding

	cutoff := now.Add(-e.window)
	relationships := e.liveRelationships(cutoff)

	for _, pattern := range e.patterns {
		// Suppress if the same rule fired within the current window.
		if last, ok := e.emitted[pattern.Name]; ok && now.Sub(last) < e.window {
			continue
		}

		if !e.matcher.MatchPatternAfter(pattern, relationships, e.chains, cutoff) {
			continue
		}

		e.emitted[pattern.Name] = now

		findings = append(findings, core.Finding{
			Timestamp:   now,
			Rule:        pattern.Name,
			Severity:    pattern.Severity,
			Title:       pattern.Title,
			Description: pattern.Description,
		})
	}

	return findings
}

// SetPatterns replaces the engine's pattern set and clears the suppression
// cache so newly added or edited patterns can fire immediately.
func (e *Engine) SetPatterns(patterns []BehaviorPattern) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.patterns = patterns
	e.emitted = make(map[string]time.Time)
}

// liveRelationships returns the relationships that can still take part in a
// match: every one except those whose child exited a full window or more
// ago. That is decided here rather than left to sweep so that matching does
// not depend on when memory was last released.
func (e *Engine) liveRelationships(cutoff time.Time) []ProcessRelationship {
	relationships := make([]ProcessRelationship, 0, len(e.relationships))

	for child, relationship := range e.relationships {
		if at, exited := e.exited[child]; exited && !at.After(cutoff) {
			continue
		}

		relationships = append(relationships, relationship)
	}

	return relationships
}
