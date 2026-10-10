package correlation

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

const (
	// maxSweepInterval caps how long expired state may linger before a
	// sweep removes it. Matching never depends on a sweep having run;
	// sweeping only releases memory.
	maxSweepInterval = 30 * time.Second

	// sweepEveryEvents forces a sweep after this many events even if the
	// clock has barely moved, so a burst cannot defer cleanup indefinitely.
	sweepEveryEvents = 4096
)

// record is what the engine knows about one process.
type record struct {
	process core.Process
	// exitedAt is zero while the process is believed to be running. Once
	// set, the record is a tombstone: it stays for one window so that
	// patterns through an exited process can still match, then is evicted.
	exitedAt time.Time
}

// Engine correlates process events into behavioral findings. The time-window
// and retention rules it guarantees are described in the package
// documentation. It is safe for concurrent use.
type Engine struct {
	mu sync.Mutex

	window time.Duration
	now    func() time.Time

	// latest is the high-water mark of evaluation time; see advance.
	latest     time.Time
	lastSweep  time.Time
	sinceSweep int

	// records holds every known process, running or tombstoned.
	records map[core.ProcessIdentity]*record
	// pids maps a PID to the process that currently holds it (or last held
	// it, until that tombstone is evicted). A PID alone never identifies a
	// process; this index is only a way to find candidates.
	pids map[int32]core.ProcessIdentity
	// tree is the parent/child structure of the processes in records.
	tree *topology
	// orphans are processes whose parent is not known yet, by parent PID,
	// so they can be linked if the parent is seen later.
	orphans map[int32]map[core.ProcessIdentity]struct{}
	// chains holds one bounded chain per process with in-window events. It
	// is the only event store.
	chains map[core.ProcessIdentity][]*Chain

	patterns []*compiledPattern
	matcher  *Matcher
	// touched are the processes that have changed since the last
	// evaluation: those with a new event or a new place in the tree. A
	// match can only have become true if it includes one of them.
	touched []core.ProcessIdentity
	// rescan requests one evaluation of everything, after a change that is
	// not about particular processes: new patterns, or a seeded batch.
	rescan bool
	// emitted maps a finding's dedup key to when it was last emitted.
	emitted map[string]time.Time
	// suppressed lists the emitted findings in the order they were emitted,
	// which is also the order their suppression lapses.
	suppressed []suppression
	lastID     int64

	// exclusions drop findings whose processes match; excluded counts the
	// findings dropped, per rule.
	exclusions []compiledExclusion
	excluded   map[string]int
	// rates tracks each rule's findings in its current window, for the
	// per-rule limit. limited is how many rules have findings held back.
	rates   map[string]*rateState
	limited int
}

// suppression is one emitted finding that must not be repeated yet.
type suppression struct {
	key       string
	at        time.Time
	processes []core.ProcessIdentity
}

// compiledExclusion is an Exclusion ready to apply.
type compiledExclusion struct {
	Exclusion
	matches processPredicate
}

// rateState is one rule's use of its findings-per-window allowance.
type rateState struct {
	windowStart time.Time
	emitted     int
	// heldBack counts findings not emitted because the rule was over its
	// limit; it is reported once when the window rolls over.
	heldBack int
}

// Option configures an Engine.
type Option func(*Engine)

// WithClock makes the engine read the time from now instead of the wall
// clock.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		e.now = now
	}
}

func NewEngine(window time.Duration, options ...Option) *Engine {
	e := &Engine{
		window:   window,
		now:      time.Now,
		records:  make(map[core.ProcessIdentity]*record),
		pids:     make(map[int32]core.ProcessIdentity),
		tree:     newTopology(),
		orphans:  make(map[int32]map[core.ProcessIdentity]struct{}),
		chains:   make(map[core.ProcessIdentity][]*Chain),
		patterns: compilePatterns(DefaultPatterns()),
		matcher:  NewMatcher(),
		rescan:   true,
		emitted:  make(map[string]time.Time),
		excluded: make(map[string]int),
		rates:    make(map[string]*rateState),
	}

	for _, option := range options {
		option(e)
	}

	return e
}

// Seed registers processes that are already running, such as those found by
// the first process collection. Without it a process that started before the
// engine did is unknown until it produces an event, and cannot be recognised
// as a parent until then.
func (e *Engine) Seed(processes []core.Process) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.advance(e.now())

	for _, process := range processes {
		e.observe(e.canonical(process), now)
	}

	e.rescan = true
}

// Process ingests one event.
func (e *Engine) Process(event core.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.advance(e.now())

	e.sinceSweep++
	defer e.maybeSweep(now)

	if event.Process == nil {
		return
	}

	// Resolve the event to the process the engine already knows, when the
	// event itself does not say which one it is.
	process := e.canonical(*event.Process)
	if process.Identity() != event.Process.Identity() {
		event.Process = &process
	}
	identity := process.Identity()

	// An event cannot be observed before it happens, and one that carries
	// no timestamp is taken to have happened when it arrived.
	if event.Timestamp.IsZero() || event.Timestamp.After(now) {
		event.Timestamp = now
	}

	// Any event is evidence that its process exists, not only a start.
	known := e.observe(process, now)
	e.touch(identity)

	if event.Type == core.EventProcessExit && known.exitedAt.IsZero() {
		known.exitedAt = event.Timestamp
	}

	// Already outside the window: the bookkeeping above still applies, but
	// the event can never contribute to a match.
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

// canonical resolves a process description that lacks a start time to the
// process known to hold that PID.
//
// Collectors report a process's start time on every event, and it is half of
// the process's identity. When the OS will not give one (the process is
// exiting, or access is denied at that moment) the event arrives with a PID
// and no start time. Treating that as a separate process would split one
// process's activity in two, and its events would never be correlated with
// the rest. The holder of the PID is the only process the event can be
// about, so the event is attributed to it. With no known holder the
// description is kept as it is.
func (e *Engine) canonical(process core.Process) core.Process {
	if startKnown(process.StartTime) {
		return process
	}

	holderID, held := e.pids[process.PID]
	if !held {
		return process
	}

	holder := e.records[holderID]
	if holder == nil || !holder.exitedAt.IsZero() {
		return process
	}

	return holder.process
}

// observe returns the record for process, creating it and working out its
// place among the known processes the first time it is seen.
func (e *Engine) observe(process core.Process, now time.Time) *record {
	identity := process.Identity()

	if known, ok := e.records[identity]; ok {
		return known
	}

	added := &record{process: process}
	e.records[identity] = added

	e.claimPID(added, now)
	e.linkToParent(added)
	e.adoptOrphans(added)

	// A new process changes what its neighbours can match as well; the
	// search reaches them from here.
	e.touch(identity)

	return added
}

// touch marks a process as changed since the last evaluation.
func (e *Engine) touch(identity core.ProcessIdentity) {
	for _, already := range e.touched {
		if already == identity {
			return
		}
	}

	e.touched = append(e.touched, identity)
}

// claimPID decides whether a newly seen process is the current holder of its
// PID. Two processes can only share a PID one after the other, so seeing a
// second one means the earlier one has ended, whether or not its exit event
// has arrived.
func (e *Engine) claimPID(added *record, now time.Time) {
	pid := added.process.PID

	holderID, held := e.pids[pid]
	holder := e.records[holderID]
	if !held || holder == nil {
		e.pids[pid] = added.process.Identity()
		return
	}

	switch {
	case startKnown(added.process.StartTime) && startKnown(holder.process.StartTime):
		if added.process.StartTime.Before(holder.process.StartTime) {
			// A late event from the process that held the PID before.
			e.markGone(added, now)
			return
		}

	case !holder.exitedAt.IsZero():
		// Start times cannot be compared, but the holder is known to have
		// ended, so the PID is free to have been handed out again.

	case !startKnown(holder.process.StartTime) && startKnown(added.process.StartTime):
		// The holder was only ever seen without a start time. This is the
		// first full description of the process with that PID, so it takes
		// over, and later events without a start time resolve to it.
		e.markGone(holder, now)
		e.pids[pid] = added.process.Identity()
		e.inheritChildren(holder, added)
		return

	default:
		// Start times cannot be compared and the holder is still running.
		// Keep the holder: replacing it on every disagreement between
		// event sources would discard a live process's relationships.
		e.markGone(added, now)
		return
	}

	e.markGone(holder, now)
	e.pids[pid] = added.process.Identity()
	e.reattributeChildren(holder, added)
}

func (e *Engine) markGone(r *record, now time.Time) {
	if r.exitedAt.IsZero() {
		r.exitedAt = now
	}
}

// reattributeChildren corrects links made while a reused PID still pointed
// at its previous holder. Events are not delivered in start order, so a
// child can be seen before the process that actually spawned it. A child
// that started no earlier than the new holder cannot belong to the previous
// one, which was already gone by then.
func (e *Engine) reattributeChildren(previous, current *record) {
	if !startKnown(current.process.StartTime) {
		return
	}

	var moved []core.ProcessIdentity

	for childID := range e.tree.children[previous.process.Identity()] {
		child := e.records[childID]
		if child == nil || !startKnown(child.process.StartTime) ||
			child.process.StartTime.Before(current.process.StartTime) {
			continue
		}
		moved = append(moved, childID)
	}

	for _, childID := range moved {
		e.tree.link(current.process.Identity(), childID)
	}
}

// inheritChildren moves every child of previous to current that current can
// plausibly have spawned.
func (e *Engine) inheritChildren(previous, current *record) {
	var moved []core.ProcessIdentity

	for childID := range e.tree.children[previous.process.Identity()] {
		if child := e.records[childID]; child != nil && plausibleParent(current, child.process) {
			moved = append(moved, childID)
		}
	}

	for _, childID := range moved {
		e.tree.link(current.process.Identity(), childID)
	}
}

// linkToParent links a process to the holder of its parent PID when that
// holder can really be its parent, and otherwise remembers it as an orphan.
func (e *Engine) linkToParent(child *record) {
	ppid := child.process.PPID
	identity := child.process.Identity()

	if parentID, held := e.pids[ppid]; held {
		if parent := e.records[parentID]; parent != nil && plausibleParent(parent, child.process) {
			e.tree.link(parentID, identity)
			return
		}
	}

	waiting := e.orphans[ppid]
	if waiting == nil {
		waiting = make(map[core.ProcessIdentity]struct{})
		e.orphans[ppid] = waiting
	}
	waiting[identity] = struct{}{}
}

// adoptOrphans links already-known processes that were waiting for a parent
// with this process's PID, if it can really be their parent.
func (e *Engine) adoptOrphans(parent *record) {
	pid := parent.process.PID

	// Only the current holder of a PID can be a parent found through it.
	if e.pids[pid] != parent.process.Identity() {
		return
	}

	waiting := e.orphans[pid]

	for childID := range waiting {
		child := e.records[childID]
		if child == nil || !plausibleParent(parent, child.process) {
			continue
		}

		e.tree.link(parent.process.Identity(), childID)
		delete(waiting, childID)
	}

	if len(waiting) == 0 {
		delete(e.orphans, pid)
	}
}

// plausibleParent reports whether parent can have spawned child. A PID match
// is not enough: the parent must have existed when the child started, which
// rules out a later holder of a reused PID, and must not have ended before
// then, which rules out an earlier one.
func plausibleParent(parent *record, child core.Process) bool {
	if parent.process.Identity() == child.Identity() {
		return false
	}

	childStarted := startKnown(child.StartTime)

	if childStarted && startKnown(parent.process.StartTime) &&
		parent.process.StartTime.After(child.StartTime) {
		return false
	}

	if !parent.exitedAt.IsZero() {
		// Without the child's start time there is no telling whether it
		// predates the parent's exit.
		if !childStarted || parent.exitedAt.Before(child.StartTime) {
			return false
		}
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

// maybeSweep runs a sweep when enough time has passed or enough events have
// arrived since the last one, rather than on every event.
func (e *Engine) maybeSweep(now time.Time) {
	interval := e.window / 4
	if interval > maxSweepInterval {
		interval = maxSweepInterval
	}

	due := e.lastSweep.IsZero() ||
		now.Sub(e.lastSweep) >= interval ||
		e.sinceSweep >= sweepEveryEvents
	if !due {
		return
	}

	e.sweep(now)
}

// sweep releases everything that can no longer affect a match: events that
// have left the window, processes that exited a window or more ago, and
// suppression records that have lapsed.
func (e *Engine) sweep(now time.Time) {
	e.lastSweep = now
	e.sinceSweep = 0

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

	for identity, known := range e.records {
		if expired(known, cutoff) {
			e.evict(identity, known)
		}
	}
}

// releaseSuppressions drops suppression records that have lapsed and marks
// their processes as changed. The behaviour may still be going on, in which
// case it is due to be reported again; nothing else would prompt a look at
// processes that have not produced an event since.
func (e *Engine) releaseSuppressions(now time.Time) {
	released := 0

	for _, lapsed := range e.suppressed {
		if now.Sub(lapsed.at) < e.window {
			break
		}
		released++

		// Skip a record superseded by a later emission of the same finding.
		if last, ok := e.emitted[lapsed.key]; !ok || !last.Equal(lapsed.at) {
			continue
		}

		delete(e.emitted, lapsed.key)
		for _, identity := range lapsed.processes {
			e.touch(identity)
		}
	}

	if released > 0 {
		// Copy down rather than re-slice, so the released records are freed.
		n := copy(e.suppressed, e.suppressed[released:])
		clear(e.suppressed[n:])
		e.suppressed = e.suppressed[:n]
	}
}

// expired reports whether a record is a tombstone whose window has passed.
func expired(r *record, cutoff time.Time) bool {
	return !r.exitedAt.IsZero() && !r.exitedAt.After(cutoff)
}

// evict forgets a process entirely: its record, events, relationships and
// index entries.
func (e *Engine) evict(identity core.ProcessIdentity, known *record) {
	delete(e.records, identity)
	delete(e.chains, identity)
	e.tree.remove(identity)

	if e.pids[known.process.PID] == identity {
		delete(e.pids, known.process.PID)
	}

	if waiting := e.orphans[known.process.PPID]; waiting != nil {
		delete(waiting, identity)
		if len(waiting) == 0 {
			delete(e.orphans, known.process.PPID)
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

// RelationshipsForProcess returns the relationship in which the process is
// the child, if its parent is known.
func (e *Engine) RelationshipsForProcess(
	identity core.ProcessIdentity,
) []ProcessRelationship {
	e.mu.Lock()
	defer e.mu.Unlock()

	parentID, ok := e.tree.parent[identity]
	if !ok {
		return nil
	}

	parent, child := e.records[parentID], e.records[identity]
	if parent == nil || child == nil {
		return nil
	}

	return []ProcessRelationship{
		NewProcessRelationship(parent.process, child.process),
	}
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

// DetectBehaviors evaluates all registered patterns against the events in
// the current window and returns any newly triggered findings.
//
// A finding is identified by its rule and the set of processes bound to the
// rule's roles. The same finding is not emitted again until one window has
// elapsed since it was last emitted, preventing duplicate alerts for a
// sustained behaviour; a different set of processes matching the same rule
// is a different finding and is reported.
//
// A new finding is dropped if an exclusion covers it, and held back if its
// rule has already produced its limit of findings in the current window. A
// rule's held-back findings are reported as a single INFO finding when its
// window rolls over.
func (e *Engine) DetectBehaviors() []core.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.advance(e.now())
	e.maybeSweep(now)
	e.releaseSuppressions(now)

	findings := e.rateLimitSummaries(now)

	// Only matches that include a changed process can be new or newly
	// reportable. Everything else was evaluated the last time round, time
	// passing only ever takes events out of the window, and a finding whose
	// suppression has just lapsed had its processes marked as changed.
	seeds := e.touched
	if e.rescan {
		seeds = nil
	} else if len(seeds) == 0 {
		return findings
	}

	defer func() {
		e.touched = e.touched[:0]
		e.rescan = false
	}()

	cutoff := now.Add(-e.window)
	view := engineWorld{engine: e, cutoff: cutoff}
	window := func(chain *Chain) []core.Event {
		return chain.EventsAfter(cutoff)
	}

	for _, pattern := range e.patterns {
		matches := e.matcher.find(pattern, view, window, seeds)
		if len(matches) == 0 {
			continue
		}

		// The search visits maps, so impose an order on what it found.
		keys := make([]string, len(matches))
		for i, match := range matches {
			keys[i] = dedupKey(pattern.Name, match)
		}
		sort.Sort(byKey{keys: keys, matches: matches})

		for i, match := range matches {
			if last, ok := e.emitted[keys[i]]; ok && now.Sub(last) < e.window {
				continue
			}

			// Whatever happens to it next, this incident has been dealt
			// with for one window: it is counted once, not on every
			// evaluation.
			e.suppress(keys[i], match, now)

			if e.isExcluded(pattern.Name, match) {
				e.excluded[pattern.Name]++
				continue
			}

			if !e.withinRateLimit(pattern, now) {
				continue
			}

			findings = append(findings, e.finding(pattern.BehaviorPattern, match, now))
		}
	}

	return findings
}

// isExcluded reports whether an exclusion covers a finding of the rule with
// these processes.
func (e *Engine) isExcluded(rule string, match Match) bool {
	for i := range e.exclusions {
		exclusion := &e.exclusions[i]
		if !exclusion.AppliesTo(rule) {
			continue
		}

		for j := range match.Processes {
			if exclusion.matches(&match.Processes[j]) {
				return true
			}
		}
	}

	return false
}

// withinRateLimit records one more finding for the rule and reports whether
// it may be emitted. A rule's window starts with its first finding and lasts
// one correlation window.
func (e *Engine) withinRateLimit(pattern *compiledPattern, now time.Time) bool {
	state := e.rates[pattern.Name]
	if state == nil {
		state = &rateState{windowStart: now}
		e.rates[pattern.Name] = state
	}

	if state.emitted < pattern.maxFindings {
		state.emitted++
		return true
	}

	if state.heldBack == 0 {
		e.limited++
	}
	state.heldBack++

	return false
}

// rateLimitSummaries closes every rule window that has ended. A rule that
// had findings held back gets one INFO finding saying how many.
func (e *Engine) rateLimitSummaries(now time.Time) []core.Finding {
	// Windows only need closing promptly when something was held back;
	// otherwise the next sweep-sized check is soon enough, and the common
	// case costs nothing.
	if e.limited == 0 && len(e.rates) == 0 {
		return nil
	}

	var rules []string

	for rule, state := range e.rates {
		if now.Sub(state.windowStart) < e.window {
			continue
		}

		if state.heldBack > 0 {
			rules = append(rules, rule)
			continue
		}
		delete(e.rates, rule)
	}

	if len(rules) == 0 {
		return nil
	}

	sort.Strings(rules)

	findings := make([]core.Finding, 0, len(rules))
	for _, rule := range rules {
		state := e.rates[rule]

		findings = append(findings, core.Finding{
			ID:          e.nextFindingID(now),
			Timestamp:   now,
			Rule:        rule,
			Severity:    core.SeverityInfo,
			Title:       "Findings suppressed by rate limit",
			Description: fmt.Sprintf("rule %s: %d additional findings suppressed", rule, state.heldBack),
		})

		delete(e.rates, rule)
		e.limited--
	}

	return findings
}

func (e *Engine) finding(pattern BehaviorPattern, match Match, now time.Time) core.Finding {
	processes := append([]core.Process(nil), match.Processes...)

	// The role listed last is the one the pattern leads up to.
	subject := processes[len(processes)-1]

	return core.Finding{
		ID:          e.nextFindingID(now),
		Timestamp:   now,
		Rule:        pattern.Name,
		Severity:    pattern.Severity,
		Title:       pattern.Title,
		Description: pattern.Description,
		Evidence: core.Evidence{
			Process:   &subject,
			Processes: processes,
		},
	}
}

// suppress records that a finding was emitted now.
func (e *Engine) suppress(key string, match Match, now time.Time) {
	processes := make([]core.ProcessIdentity, len(match.Processes))
	for i, process := range match.Processes {
		processes[i] = process.Identity()
	}

	e.emitted[key] = now
	e.suppressed = append(e.suppressed, suppression{key: key, at: now, processes: processes})
}

// nextFindingID returns an ID in the same form the process rules use,
// finding-<unix nanoseconds>, kept unique when several findings are emitted
// in the same instant.
func (e *Engine) nextFindingID(now time.Time) string {
	id := now.UnixNano()
	if id <= e.lastID {
		id = e.lastID + 1
	}
	e.lastID = id

	return fmt.Sprintf("finding-%d", id)
}

// dedupKey identifies a finding by its rule and the processes involved,
// whichever roles they fill.
func dedupKey(rule string, match Match) string {
	parts := make([]string, len(match.Processes))
	for i, process := range match.Processes {
		parts[i] = fmt.Sprintf("%d@%d", process.PID, process.StartTime.UnixNano())
	}
	sort.Strings(parts)

	return rule + "\x00" + strings.Join(parts, ",")
}

type byKey struct {
	keys    []string
	matches []Match
}

func (b byKey) Len() int           { return len(b.keys) }
func (b byKey) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b byKey) Swap(i, j int) {
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
	b.matches[i], b.matches[j] = b.matches[j], b.matches[i]
}

// SetPatterns replaces the engine's pattern set and clears the suppression
// cache and rate-limit counters so newly added or edited patterns can fire
// immediately. A pattern that does not validate is kept but never matches;
// use BehaviorPattern.Validate to find out why.
func (e *Engine) SetPatterns(patterns []BehaviorPattern) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.patterns = compilePatterns(patterns)
	e.emitted = make(map[string]time.Time)
	e.suppressed = nil
	e.rates = make(map[string]*rateState)
	e.limited = 0
	e.rescan = true
}

func compilePatterns(patterns []BehaviorPattern) []*compiledPattern {
	compiled := make([]*compiledPattern, len(patterns))
	for i, pattern := range patterns {
		// An invalid pattern compiles to one that never matches.
		compiled[i], _ = compilePattern(pattern)
	}

	return compiled
}

// SetExclusions replaces the exclusions applied to findings. Exclusions that
// do not validate are left out, and the first such error is returned; the
// valid ones take effect regardless.
func (e *Engine) SetExclusions(exclusions []Exclusion) error {
	var firstErr error

	compiled := make([]compiledExclusion, 0, len(exclusions))
	for i, exclusion := range exclusions {
		if err := exclusion.Validate(); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("exclusions[%d]: %w", i, err)
			}
			continue
		}

		matches, _ := compileProcessMatch(exclusion.Match, "match")
		compiled = append(compiled, compiledExclusion{Exclusion: exclusion, matches: matches})
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.exclusions = compiled

	return firstErr
}

// ExcludedFindings returns, for each rule, how many findings exclusions have
// dropped since the engine started.
func (e *Engine) ExcludedFindings() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()

	counts := make(map[string]int, len(e.excluded))
	for rule, count := range e.excluded {
		counts[rule] = count
	}

	return counts
}

// engineWorld presents the engine's state to the matcher as of one
// evaluation. Tombstones whose window has passed are hidden here rather than
// left to the sweep, so that matching does not depend on when memory was
// last released.
type engineWorld struct {
	engine *Engine
	cutoff time.Time
}

func (w engineWorld) visible(identity core.ProcessIdentity) (*record, bool) {
	known, ok := w.engine.records[identity]
	if !ok || expired(known, w.cutoff) {
		return nil, false
	}

	return known, true
}

func (w engineWorld) process(identity core.ProcessIdentity) (*core.Process, bool) {
	known, ok := w.visible(identity)
	if !ok {
		return nil, false
	}

	return &known.process, true
}

func (w engineWorld) parentOf(child core.ProcessIdentity) (core.ProcessIdentity, bool) {
	parent, ok := w.engine.tree.parent[child]
	if !ok {
		return core.ProcessIdentity{}, false
	}
	if _, ok := w.visible(parent); !ok {
		return core.ProcessIdentity{}, false
	}

	return parent, true
}

func (w engineWorld) eachChild(parent core.ProcessIdentity, visit func(core.ProcessIdentity) bool) {
	for child := range w.engine.tree.children[parent] {
		if !visit(child) {
			return
		}
	}
}

func (w engineWorld) eachRelationship(visit func(parent, child core.ProcessIdentity) bool) {
	for child, parent := range w.engine.tree.parent {
		if !visit(parent, child) {
			return
		}
	}
}

func (w engineWorld) eachProcess(visit func(core.ProcessIdentity) bool) {
	for identity := range w.engine.records {
		if !visit(identity) {
			return
		}
	}
}

func (w engineWorld) chainsOf(identity core.ProcessIdentity) []*Chain {
	return w.engine.chains[identity]
}
