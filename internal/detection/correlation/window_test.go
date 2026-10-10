package correlation

import (
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// All tests here drive the engine with explicit times; none of them sleeps or
// reads the wall clock.

const testWindow = 30 * time.Second

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// at returns the test epoch plus d.
func at(d time.Duration) time.Time { return t0.Add(d) }

func proc(pid, ppid int32, name string, started time.Time) core.Process {
	return core.Process{PID: pid, PPID: ppid, Name: name, StartTime: started}
}

// feed ingests an event that happened, and was received, at ts.
func feed(e *Engine, eventType core.EventType, p core.Process, ts time.Time) {
	e.ProcessAt(core.Event{Type: eventType, Timestamp: ts, Process: &p}, ts)
}

func findingsAt(e *Engine, now time.Time) int {
	return len(e.DetectBehaviorsAt(now))
}

// spawnPair starts a parent and its python child at the test epoch.
func spawnPair(e *Engine) (parent, child core.Process) {
	parent = proc(100, 1, "node", at(-time.Hour))
	child = proc(200, 100, "python", at(0))

	feed(e, core.EventProcessStart, parent, at(0))
	feed(e, core.EventProcessStart, child, at(0))

	return parent, child
}

// childPattern is a one-relationship pattern whose child must be python and
// produce the given events; the parent has no event requirement.
func childPattern(ordered bool, events ...core.EventType) []BehaviorPattern {
	required := make([]EventPattern, len(events))
	for i, eventType := range events {
		required[i] = EventPattern{Type: eventType}
	}

	return []BehaviorPattern{{
		Name:     "child-activity",
		Severity: core.SeverityLow,
		Processes: []ProcessPattern{
			{ID: "parent"},
			{
				ID:         "child",
				Conditions: []Condition{{Type: ConditionProcessName, Value: "python"}},
				Events:     required,
				Ordered:    ordered,
			},
		},
		Relationships: []RelationshipPattern{
			{Type: RelationshipSpawned, Parent: "parent", Child: "child"},
		},
	}}
}

func TestWindowMatchesEventsInsideWindow(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	feed(e, core.EventNetworkConnect, parent, at(2*time.Second))
	feed(e, core.EventNetworkConnect, child, at(4*time.Second))

	if got := findingsAt(e, at(10*time.Second)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}
}

func TestWindowBoundaryIsExclusiveAtFullAge(t *testing.T) {
	// The parent's event is exactly one window old at at(30s): out.
	// One nanosecond earlier it is still in.
	for _, c := range []struct {
		name string
		eval time.Duration
		want int
	}{
		{"just inside", testWindow - time.Nanosecond, 1},
		{"exactly one window old", testWindow, 0},
		{"older", testWindow + time.Second, 0},
	} {
		e := NewEngine(testWindow)
		parent, child := spawnPair(e)

		feed(e, core.EventNetworkConnect, parent, at(0))
		feed(e, core.EventNetworkConnect, child, at(20*time.Second))

		if got := findingsAt(e, at(c.eval)); got != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestWindowRejectsRequiredEventsTooFarApart(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	// Each event is recent when it happens, but they are never in the same
	// window.
	feed(e, core.EventNetworkConnect, parent, at(0))
	if got := findingsAt(e, at(time.Second)); got != 0 {
		t.Fatalf("findings with only the parent active = %d, want 0", got)
	}

	feed(e, core.EventNetworkConnect, child, at(40*time.Second))
	if got := findingsAt(e, at(41*time.Second)); got != 0 {
		t.Fatalf("findings with events 40s apart = %d, want 0", got)
	}
}

func TestWindowIgnoresEventsThatArriveAlreadyExpired(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	// Six-hour-old activity delivered now.
	old := at(-6 * time.Hour)
	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Timestamp: old, Process: &parent}, at(time.Second))
	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Timestamp: old, Process: &child}, at(time.Second))

	if got := findingsAt(e, at(2*time.Second)); got != 0 {
		t.Fatalf("findings from expired events = %d, want 0", got)
	}
	for _, p := range []core.Process{parent, child} {
		for _, chain := range e.chains[p.Identity()] {
			for _, event := range chain.Events() {
				if event.Type == core.EventNetworkConnect {
					t.Fatalf("expired event was stored for %s", p.Name)
				}
			}
		}
	}
}

func TestExpiredEventDoesNotCreateState(t *testing.T) {
	e := NewEngine(testWindow)
	spawnPair(e) // also uses up the periodic sweep, so nothing tidies up below
	unseen := proc(700, 1, "curl", at(-time.Hour))

	// First and only event for this process, already a window old.
	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Timestamp: at(-time.Minute), Process: &unseen}, at(time.Second))

	if _, stored := e.chains[unseen.Identity()]; stored {
		t.Fatal("an expired event created a chain")
	}
}

func TestWindowNonPositiveMatchesNothing(t *testing.T) {
	for _, window := range []time.Duration{0, -time.Second} {
		e := NewEngine(window)
		parent, child := spawnPair(e)
		feed(e, core.EventNetworkConnect, parent, at(0))
		feed(e, core.EventNetworkConnect, child, at(0))

		if got := findingsAt(e, at(0)); got != 0 {
			t.Errorf("window %v: findings = %d, want 0", window, got)
		}
		if n := len(e.chains); n != 0 {
			t.Errorf("window %v: %d chains retained, want 0", window, n)
		}
	}
}

func TestOrderedSequenceMatchesInOrderOnly(t *testing.T) {
	sequence := []core.EventType{core.EventDNSQuery, core.EventNetworkConnect, core.EventFileCreate}

	cases := []struct {
		name    string
		ordered bool
		events  []core.EventType // in the order they happen, one second apart
		want    int
	}{
		{"ordered, correct order", true, sequence, 1},
		{"ordered, reversed", true, []core.EventType{core.EventFileCreate, core.EventNetworkConnect, core.EventDNSQuery}, 0},
		{"ordered, last two swapped", true, []core.EventType{core.EventDNSQuery, core.EventFileCreate, core.EventNetworkConnect}, 0},
		{"ordered, other events in between", true, []core.EventType{
			core.EventFileModify, core.EventDNSQuery, core.EventNetworkClose,
			core.EventNetworkConnect, core.EventDNSQuery, core.EventFileCreate,
		}, 1},
		{"ordered, a step missing", true, []core.EventType{core.EventDNSQuery, core.EventFileCreate}, 0},
		{"unordered, correct order", false, sequence, 1},
		{"unordered, reversed", false, []core.EventType{core.EventFileCreate, core.EventNetworkConnect, core.EventDNSQuery}, 1},
		{"unordered, a type missing", false, []core.EventType{core.EventDNSQuery, core.EventFileCreate}, 0},
	}

	for _, c := range cases {
		e := NewEngine(testWindow)
		e.SetPatterns(childPattern(c.ordered, sequence...))
		_, child := spawnPair(e)

		for i, eventType := range c.events {
			feed(e, eventType, child, at(time.Duration(i+1)*time.Second))
		}

		if got := findingsAt(e, at(10*time.Second)); got != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestOrderedSequenceNeedsDistinctEvents(t *testing.T) {
	twice := []core.EventType{core.EventNetworkConnect, core.EventNetworkConnect}

	for _, c := range []struct {
		name     string
		ordered  bool
		connects int
		want     int
	}{
		{"ordered, one event for two steps", true, 1, 0},
		{"ordered, two events", true, 2, 1},
		{"unordered, a repeated type is one requirement", false, 1, 1},
	} {
		e := NewEngine(testWindow)
		e.SetPatterns(childPattern(c.ordered, twice...))
		_, child := spawnPair(e)

		for i := 0; i < c.connects; i++ {
			feed(e, core.EventNetworkConnect, child, at(time.Duration(i+1)*time.Second))
		}

		if got := findingsAt(e, at(10*time.Second)); got != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestOrderedSequenceIsBrokenWhenItsStartExpires(t *testing.T) {
	e := NewEngine(testWindow)
	e.SetPatterns(childPattern(true, core.EventDNSQuery, core.EventNetworkConnect))
	_, child := spawnPair(e)

	feed(e, core.EventDNSQuery, child, at(1*time.Second))
	feed(e, core.EventNetworkConnect, child, at(35*time.Second))

	// At 35s the DNS query is 34s old: the sequence never existed inside
	// one window.
	if got := findingsAt(e, at(35*time.Second)); got != 0 {
		t.Fatalf("findings = %d, want 0", got)
	}
}

func TestOrderingFollowsTimestampsNotArrival(t *testing.T) {
	sequence := []core.EventType{core.EventDNSQuery, core.EventNetworkConnect}

	// The DNS query happened first but is delivered second, as a packet
	// capture timestamp can be.
	e := NewEngine(testWindow)
	e.SetPatterns(childPattern(true, sequence...))
	_, child := spawnPair(e)

	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Timestamp: at(5 * time.Second), Process: &child}, at(5*time.Second))
	e.ProcessAt(core.Event{Type: core.EventDNSQuery, Timestamp: at(3 * time.Second), Process: &child}, at(6*time.Second))

	if got := findingsAt(e, at(7*time.Second)); got != 1 {
		t.Errorf("late-delivered earlier event: findings = %d, want 1", got)
	}

	// With identical timestamps, arrival order decides, deterministically.
	for _, c := range []struct {
		name  string
		order []core.EventType
		want  int
	}{
		{"same instant, arrived in order", sequence, 1},
		{"same instant, arrived reversed", []core.EventType{core.EventNetworkConnect, core.EventDNSQuery}, 0},
	} {
		e := NewEngine(testWindow)
		e.SetPatterns(childPattern(true, sequence...))
		_, child := spawnPair(e)

		for _, eventType := range c.order {
			feed(e, eventType, child, at(5*time.Second))
		}

		if got := findingsAt(e, at(6*time.Second)); got != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestMissingAndFutureTimestampsUseArrivalTime(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	// No timestamp at all, and one far in the future.
	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Process: &parent}, at(5*time.Second))
	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Timestamp: at(24 * time.Hour), Process: &child}, at(6*time.Second))

	for _, p := range []core.Process{parent, child} {
		events := e.chains[p.Identity()][0].Events()
		last := events[len(events)-1]
		if last.Timestamp.Before(at(5*time.Second)) || last.Timestamp.After(at(6*time.Second)) {
			t.Errorf("%s: stored timestamp %v, want the arrival time", p.Name, last.Timestamp)
		}
	}

	if got := findingsAt(e, at(7*time.Second)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}

	// A future-dated event must expire like any other; it cannot keep
	// matching until its bogus timestamp is reached.
	if got := findingsAt(e, at(6*time.Second+testWindow)); got != 0 {
		t.Fatalf("findings one window later = %d, want 0", got)
	}
}

func TestEvaluationTimeNeverMovesBackwards(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)
	feed(e, core.EventNetworkConnect, parent, at(1*time.Second))
	feed(e, core.EventNetworkConnect, child, at(2*time.Second))

	if got := findingsAt(e, at(5*time.Minute)); got != 0 {
		t.Fatalf("findings after expiry = %d, want 0", got)
	}

	// An earlier evaluation time, as after a clock step, cannot bring the
	// expired events back.
	if got := findingsAt(e, at(3*time.Second)); got != 0 {
		t.Fatalf("findings after the clock stepped back = %d, want 0", got)
	}

	// Events received while the clock is behind are placed at the latest
	// time the engine has seen, not in the past.
	feed(e, core.EventNetworkConnect, parent, at(6*time.Minute))
	e.ProcessAt(core.Event{Type: core.EventNetworkConnect, Process: &child}, at(10*time.Second))

	events := e.chains[child.Identity()][0].Events()
	if got := events[len(events)-1].Timestamp; !got.Equal(at(6 * time.Minute)) {
		t.Fatalf("event received during a clock step stored at %v, want %v", got, at(6*time.Minute))
	}
	if got := findingsAt(e, at(6*time.Minute+time.Second)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}
}

func TestProcessWithoutEventRequirementMatchesAfterItsEventsExpire(t *testing.T) {
	e := NewEngine(testWindow)
	e.SetPatterns(childPattern(false, core.EventNetworkConnect))
	_, child := spawnPair(e)

	// Ten minutes later the parent has no events left in the window, but
	// it is still the process that spawned the child.
	feed(e, core.EventNetworkConnect, child, at(10*time.Minute))

	if got := findingsAt(e, at(10*time.Minute)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}
}

func TestStateIsReleasedAfterExpiration(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	feed(e, core.EventNetworkConnect, parent, at(1*time.Second))
	feed(e, core.EventNetworkConnect, child, at(2*time.Second))
	if got := findingsAt(e, at(3*time.Second)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}

	feed(e, core.EventProcessExit, child, at(4*time.Second))
	feed(e, core.EventProcessExit, parent, at(5*time.Second))

	if n := len(e.processes); n != 0 {
		t.Errorf("exited processes still tracked as parents: %d", n)
	}

	// Still inside the window: the events and the relationship are needed.
	findingsAt(e, at(20*time.Second))
	if len(e.chains) != 2 || len(e.relationships) != 1 {
		t.Fatalf("in-window state dropped early: chains=%d relationships=%d", len(e.chains), len(e.relationships))
	}

	findingsAt(e, at(2*time.Minute))

	if len(e.chains) != 0 || len(e.relationships) != 0 || len(e.exited) != 0 ||
		len(e.processes) != 0 || len(e.emitted) != 0 {
		t.Fatalf("state retained after expiry: chains=%d relationships=%d exited=%d processes=%d emitted=%d",
			len(e.chains), len(e.relationships), len(e.exited), len(e.processes), len(e.emitted))
	}
}

func TestLiveProcessKeepsRelationshipButNotOldEvents(t *testing.T) {
	e := NewEngine(testWindow)
	_, child := spawnPair(e)
	feed(e, core.EventNetworkConnect, child, at(time.Second))

	findingsAt(e, at(time.Hour))

	if n := len(e.chains); n != 0 {
		t.Errorf("events of idle processes retained: %d chains", n)
	}
	if got := len(e.RelationshipsForProcess(child.Identity())); got != 1 {
		t.Errorf("relationship of a live child = %d, want 1", got)
	}
	if n := len(e.processes); n != 2 {
		t.Errorf("live processes tracked = %d, want 2", n)
	}
}

func TestEventFloodIsBoundedWithoutEvictingOtherTypes(t *testing.T) {
	e := NewEngine(testWindow)
	e.SetPatterns(childPattern(false, core.EventDNSQuery, core.EventNetworkConnect))
	_, child := spawnPair(e)

	// One DNS query, then far more connects than a chain keeps, all inside
	// the window.
	feed(e, core.EventDNSQuery, child, at(time.Second))
	for i := 0; i < 50*MaxEventsPerType; i++ {
		feed(e, core.EventNetworkConnect, child, at(2*time.Second+time.Duration(i)*time.Microsecond))
	}

	events := e.chains[child.Identity()][0].Events()
	if want := MaxEventsPerType + 2; len(events) != want { // connects + start + DNS
		t.Fatalf("chain holds %d events, want %d", len(events), want)
	}
	if got := findingsAt(e, at(5*time.Second)); got != 1 {
		t.Fatalf("the single DNS query was evicted by the flood: findings = %d", got)
	}
}

func TestShortLivedChildMatchesUntilOneWindowAfterExit(t *testing.T) {
	for _, c := range []struct {
		name string
		eval time.Duration
		want int
	}{
		{"just after exit", 4 * time.Second, 1},
		{"one window after exit", 3*time.Second + testWindow, 0},
	} {
		e := NewEngine(testWindow)
		e.SetPatterns(childPattern(false)) // child needs no events at all
		_, child := spawnPair(e)
		feed(e, core.EventProcessExit, child, at(3*time.Second))

		if got := findingsAt(e, at(c.eval)); got != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, got, c.want)
		}
	}

	// The cut-off is exact, not rounded to whenever memory is next
	// released: the first evaluation runs the periodic sweep, the second
	// follows too soon for another, and still must not match.
	e := NewEngine(testWindow)
	e.SetPatterns(childPattern(false))
	_, child := spawnPair(e)
	feed(e, core.EventProcessExit, child, at(3*time.Second))
	e.SetPatterns(childPattern(false)) // no suppression in the way

	exitExpiry := 3*time.Second + testWindow
	if got := findingsAt(e, at(exitExpiry-time.Second)); got != 1 {
		t.Fatalf("findings one second before the exit expires = %d, want 1", got)
	}
	e.SetPatterns(childPattern(false))
	if got := findingsAt(e, at(exitExpiry)); got != 0 {
		t.Fatalf("findings once the exit has expired = %d, want 0", got)
	}
	if _, lingering := e.relationships[child.Identity()]; !lingering {
		t.Fatal("test no longer exercises the between-sweeps case")
	}
}

func TestExitedParentIsNotAParentCandidate(t *testing.T) {
	e := NewEngine(testWindow)
	parent, _ := spawnPair(e)
	feed(e, core.EventNetworkConnect, parent, at(time.Second))
	feed(e, core.EventProcessExit, parent, at(2*time.Second))

	// PID 100 is free again. A process claiming it as parent is not the
	// exited process's child.
	stranger := proc(300, 100, "python", at(3*time.Second))
	feed(e, core.EventProcessStart, stranger, at(3*time.Second))
	feed(e, core.EventNetworkConnect, stranger, at(4*time.Second))

	if got := e.RelationshipsForProcess(stranger.Identity()); len(got) != 0 {
		t.Fatalf("stale parent used: %+v", got)
	}

	// Only the genuine child (PID 200, which has not connected) could
	// match, so nothing does.
	if got := findingsAt(e, at(5*time.Second)); got != 0 {
		t.Fatalf("findings = %d, want 0", got)
	}
}

// Start events are not delivered in start order, and exits come after starts,
// so a child can be seen while its parent's PID still points at the previous
// holder.
func TestPIDReuseDoesNotAttributeChildToPreviousHolder(t *testing.T) {
	e := NewEngine(testWindow)

	oldHolder := proc(100, 1, "old-parent", at(-time.Hour))
	newHolder := proc(100, 1, "new-parent", at(8*time.Second))
	child := proc(300, 100, "python", at(9*time.Second))

	feed(e, core.EventProcessStart, oldHolder, at(0))
	feed(e, core.EventNetworkConnect, oldHolder, at(1*time.Second))

	// One poll delivers: child start, new holder start, old holder exit.
	feed(e, core.EventProcessStart, child, at(10*time.Second))
	feed(e, core.EventProcessStart, newHolder, at(10*time.Second))
	feed(e, core.EventProcessExit, oldHolder, at(10*time.Second))
	feed(e, core.EventNetworkConnect, child, at(11*time.Second))

	relationships := e.RelationshipsForProcess(child.Identity())
	if len(relationships) != 1 || relationships[0].Parent.Identity() != newHolder.Identity() {
		t.Fatalf("child's parent = %+v, want the new holder of PID 100", relationships)
	}

	// The old holder's network activity must not be credited to the child's
	// real parent, which has none.
	if got := findingsAt(e, at(12*time.Second)); got != 0 {
		t.Fatalf("findings = %d, want 0", got)
	}

	// The late exit of the old holder must not evict the new one.
	later := proc(400, 100, "python", at(13*time.Second))
	feed(e, core.EventProcessStart, later, at(13*time.Second))
	got := e.RelationshipsForProcess(later.Identity())
	if len(got) != 1 || got[0].Parent.Identity() != newHolder.Identity() {
		t.Fatalf("later child's parent = %+v, want the new holder", got)
	}
}

func TestParentThatStartedAfterChildIsRejected(t *testing.T) {
	e := NewEngine(testWindow)

	// The child's real parent is gone and its PID now belongs to a process
	// younger than the child.
	newHolder := proc(100, 1, "new-parent", at(5*time.Second))
	child := proc(300, 100, "python", at(1*time.Second))

	feed(e, core.EventProcessStart, newHolder, at(6*time.Second))
	feed(e, core.EventProcessStart, child, at(6*time.Second))

	if got := e.RelationshipsForProcess(child.Identity()); len(got) != 0 {
		t.Fatalf("impossible parent accepted: %+v", got)
	}
}

func TestUnknownStartTimesFallBackToPID(t *testing.T) {
	e := NewEngine(testWindow)

	// Collectors report the Unix epoch when the OS withholds a start time.
	parent := proc(100, 1, "node", time.UnixMilli(0))
	child := proc(200, 100, "python", time.UnixMilli(0))

	feed(e, core.EventProcessStart, parent, at(0))
	feed(e, core.EventProcessStart, child, at(0))

	if got := e.RelationshipsForProcess(child.Identity()); len(got) != 1 {
		t.Fatalf("relationships = %d, want 1 (nothing contradicts the PID match)", len(got))
	}
}

func TestDuplicateStartEventsDoNotDuplicateRelationships(t *testing.T) {
	e := NewEngine(testWindow)
	_, child := spawnPair(e)

	for i := 0; i < 5; i++ {
		feed(e, core.EventProcessStart, child, at(time.Second))
	}

	if got := len(e.RelationshipsForProcess(child.Identity())); got != 1 {
		t.Fatalf("relationships = %d, want 1", got)
	}
}

func TestStartAfterExitDoesNotResurrectProcess(t *testing.T) {
	e := NewEngine(testWindow)
	parent := proc(100, 1, "node", at(0))

	feed(e, core.EventProcessExit, parent, at(time.Second))
	feed(e, core.EventProcessStart, parent, at(time.Second))

	if n := len(e.processes); n != 0 {
		t.Fatalf("exited process tracked as a live parent: %d", n)
	}
}

func TestRepeatedEvaluationDoesNotDuplicateFindings(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)
	feed(e, core.EventNetworkConnect, parent, at(1*time.Second))
	feed(e, core.EventNetworkConnect, child, at(2*time.Second))

	total := 0
	for d := 2 * time.Second; d < 2*time.Second+testWindow; d += 500 * time.Millisecond {
		total += findingsAt(e, at(d))
	}
	if total != 1 {
		t.Fatalf("findings across one suppression window = %d, want 1", total)
	}

	// Suppression has lapsed, and so have the events: one incident, one
	// finding, however long evaluation continues.
	for d := testWindow; d < 10*testWindow; d += time.Second {
		total += findingsAt(e, at(2*time.Second+d))
	}
	if total != 1 {
		t.Fatalf("findings for a single incident = %d, want 1", total)
	}
}

func TestSustainedBehaviourFiresOncePerWindow(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	total := 0
	for d := time.Duration(0); d < 3*testWindow; d += time.Second {
		feed(e, core.EventNetworkConnect, parent, at(d))
		feed(e, core.EventNetworkConnect, child, at(d))
		total += findingsAt(e, at(d))
	}

	if total != 3 {
		t.Fatalf("findings over three windows of continuous activity = %d, want 3", total)
	}
}

func TestSuppressionIsPerRule(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)
	feed(e, core.EventNetworkConnect, parent, at(1*time.Second))
	feed(e, core.EventNetworkConnect, child, at(2*time.Second))
	if got := findingsAt(e, at(3*time.Second)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}

	// A second, unrelated pair matching the same rule inside the
	// suppression window does not produce a second finding.
	other := proc(500, 1, "ruby", at(4*time.Second))
	otherChild := proc(600, 500, "python", at(5*time.Second))
	feed(e, core.EventProcessStart, other, at(4*time.Second))
	feed(e, core.EventProcessStart, otherChild, at(5*time.Second))
	feed(e, core.EventNetworkConnect, other, at(6*time.Second))
	feed(e, core.EventNetworkConnect, otherChild, at(7*time.Second))

	if got := findingsAt(e, at(8*time.Second)); got != 0 {
		t.Fatalf("findings for a second pair inside the suppression window = %d, want 0", got)
	}
}

func TestSetPatternsClearsSuppression(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)
	feed(e, core.EventNetworkConnect, parent, at(1*time.Second))
	feed(e, core.EventNetworkConnect, child, at(2*time.Second))

	if got := findingsAt(e, at(3*time.Second)); got != 1 {
		t.Fatalf("findings = %d, want 1", got)
	}

	e.SetPatterns(DefaultPatterns())
	if got := findingsAt(e, at(4*time.Second)); got != 1 {
		t.Fatalf("findings after SetPatterns = %d, want 1", got)
	}
}

// Patterns are replaced from the UI goroutine while the event bus goroutine
// processes events. Meaningful under -race.
func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	e := NewEngine(testWindow)
	parent, child := spawnPair(e)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			feed(e, core.EventNetworkConnect, parent, at(time.Duration(i)*time.Millisecond))
			feed(e, core.EventNetworkConnect, child, at(time.Duration(i)*time.Millisecond))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			e.DetectBehaviorsAt(at(time.Duration(i) * time.Millisecond))
			e.ChainsForProcess(child.Identity())
			e.RelationshipsForProcess(child.Identity())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			e.SetPatterns(DefaultPatterns())
		}
	}()
	wg.Wait()
}
