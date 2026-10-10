package correlation

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// Everything here runs on an injected clock: no test sleeps or reads the
// wall clock.

const testWindow = 30 * time.Second

var epoch = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// at returns the test epoch plus d.
func at(d time.Duration) time.Time { return epoch.Add(d) }

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// harness is an engine on a fake clock.
type harness struct {
	*Engine
	clock *fakeClock
}

func newHarness(window time.Duration) *harness {
	clock := &fakeClock{t: epoch}
	return &harness{
		Engine: NewEngine(window, WithClock(clock.now)),
		clock:  clock,
	}
}

// feed delivers an event that happened, and is received, at ts.
func (h *harness) feed(eventType core.EventType, p core.Process, ts time.Time) {
	h.clock.set(ts)
	h.Process(core.Event{Type: eventType, Timestamp: ts, Process: &p})
}

func (h *harness) start(p core.Process, ts time.Time) { h.feed(core.EventProcessStart, p, ts) }
func (h *harness) connect(p core.Process, ts time.Time) {
	h.feed(core.EventNetworkConnect, p, ts)
}
func (h *harness) exit(p core.Process, ts time.Time) { h.feed(core.EventProcessExit, p, ts) }

// detect evaluates the patterns at ts.
func (h *harness) detect(ts time.Time) []core.Finding {
	h.clock.set(ts)
	return h.DetectBehaviors()
}

func (h *harness) parentOf(p core.Process) (core.Process, bool) {
	relationships := h.RelationshipsForProcess(p.Identity())
	if len(relationships) != 1 {
		return core.Process{}, false
	}
	return relationships[0].Parent, true
}

func proc(pid, ppid int32, name string, started time.Time) core.Process {
	return core.Process{PID: pid, PPID: ppid, Name: name, StartTime: started}
}

// named is a role that only requires a process name.
func named(id, name string, events ...core.EventType) ProcessPattern {
	role := ProcessPattern{
		ID:         id,
		Conditions: []Condition{{Type: ConditionProcessName, Value: name}},
	}
	for _, eventType := range events {
		role.Events = append(role.Events, EventPattern{Type: eventType})
	}
	return role
}

func spawned(parent, child string) RelationshipPattern {
	return RelationshipPattern{Type: RelationshipSpawned, Parent: parent, Child: child}
}

// chainPattern is the three-role chain a → b → c.
func chainPattern() []BehaviorPattern {
	return []BehaviorPattern{{
		Name:          "a-b-c",
		Severity:      core.SeverityHigh,
		Processes:     []ProcessPattern{named("a", "a"), named("b", "b"), named("c", "c")},
		Relationships: []RelationshipPattern{spawned("a", "b"), spawned("b", "c")},
	}}
}

// defaultPair starts a node parent and its python child at the epoch.
func (h *harness) defaultPair() (parent, child core.Process) {
	parent = proc(100, 1, "node", at(-time.Hour))
	child = proc(200, 100, "python", at(0))
	h.start(parent, at(0))
	h.start(child, at(0))
	return parent, child
}

// --- Bug 1: partial matches and inconsistent role binding ---------------

func TestChainPatternNeedsEveryRelationship(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(chainPattern())

	a := proc(1, 0, "a", at(0))
	b := proc(2, 1, "b", at(time.Second))
	c := proc(3, 2, "c", at(2*time.Second))

	h.start(a, at(0))
	h.start(b, at(time.Second))

	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("a→b alone produced %d finding(s); a→b→c needs both links", len(got))
	}

	h.start(c, at(2*time.Second))

	got := h.detect(at(2 * time.Second))
	if len(got) != 1 {
		t.Fatalf("complete chain produced %d finding(s), want 1", len(got))
	}
	if names := evidenceNames(got[0]); names != "a,b,c" {
		t.Errorf("bound processes = %s, want a,b,c", names)
	}
}

func TestChainPatternNeedsTheSameProcessInSharedRole(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(chainPattern())

	// a spawned one "b"; a different "b" spawned c. Each relationship
	// pattern is satisfied somewhere, but never through one process.
	a := proc(1, 0, "a", at(0))
	b1 := proc(2, 1, "b", at(time.Second))
	other := proc(10, 0, "launcher", at(0))
	b2 := proc(11, 10, "b", at(time.Second))
	c := proc(12, 11, "c", at(2*time.Second))

	for _, p := range []core.Process{a, b1, other, b2, c} {
		h.start(p, at(2*time.Second))
	}

	if got := h.detect(at(3 * time.Second)); len(got) != 0 {
		t.Fatalf("chain through two different b processes produced %d finding(s)", len(got))
	}

	// Give the first b a child named c: now one b sits in both links.
	c2 := proc(4, 2, "c", at(4*time.Second))
	h.start(c2, at(4*time.Second))

	got := h.detect(at(4 * time.Second))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if bound := got[0].Evidence.Processes; bound[1].Identity() != b1.Identity() || bound[2].Identity() != c2.Identity() {
		t.Errorf("bound b/c = %d/%d, want %d/%d", bound[1].PID, bound[2].PID, b1.PID, c2.PID)
	}
}

func TestRolesBindToDistinctProcesses(t *testing.T) {
	h := newHarness(testWindow)

	// Two sibling roles with identical requirements under one parent.
	h.SetPatterns([]BehaviorPattern{{
		Name: "two-workers",
		Processes: []ProcessPattern{
			named("boss", "boss"), named("first", "worker"), named("second", "worker"),
		},
		Relationships: []RelationshipPattern{spawned("boss", "first"), spawned("boss", "second")},
	}})

	boss := proc(1, 0, "boss", at(0))
	h.start(boss, at(0))
	h.start(proc(2, 1, "worker", at(time.Second)), at(time.Second))

	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("one worker filled both roles: %d finding(s)", len(got))
	}

	h.start(proc(3, 1, "worker", at(2*time.Second)), at(2*time.Second))

	// The two workers can fill the roles either way round, but it is one
	// set of processes and so one finding.
	if got := h.detect(at(2 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

// A relationship between two roles that are both already bound has to be
// checked against the real tree, not assumed.
func TestRelationshipBetweenAlreadyBoundRolesIsChecked(t *testing.T) {
	boss := proc(1, 0, "boss", at(0))
	lead := proc(2, 1, "lead", at(0))
	worker := proc(3, 1, "worker", at(0)) // child of boss, not of lead

	roles := []ProcessPattern{named("boss", "boss"), named("lead", "lead"), named("worker", "worker")}

	for _, c := range []struct {
		name          string
		relationships []RelationshipPattern
		want          int
	}{
		{"siblings under one parent", []RelationshipPattern{spawned("boss", "lead"), spawned("boss", "worker")}, 1},
		{"same relationship listed twice", []RelationshipPattern{spawned("boss", "lead"), spawned("boss", "lead"), spawned("boss", "worker")}, 1},
		{"worker must also be the lead's child", []RelationshipPattern{spawned("boss", "lead"), spawned("boss", "worker"), spawned("lead", "worker")}, 0},
	} {
		h := newHarness(testWindow)
		h.SetPatterns([]BehaviorPattern{{Name: "team", Processes: roles, Relationships: c.relationships}})
		for _, p := range []core.Process{boss, lead, worker} {
			h.start(p, at(time.Second))
		}

		if got := h.detect(at(time.Second)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}
}

func TestSingleRolePatternMatchesOneProcess(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "nc-connects",
		Processes: []ProcessPattern{named("tool", "nc", core.EventNetworkConnect)},
	}})

	nc := proc(50, 1, "nc", at(0))
	h.start(nc, at(0))
	h.start(proc(51, 1, "ls", at(0)), at(0))

	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("findings before any connection = %d, want 0", len(got))
	}

	h.connect(nc, at(2*time.Second))

	got := h.detect(at(2 * time.Second))
	if len(got) != 1 || len(got[0].Evidence.Processes) != 1 || got[0].Evidence.Processes[0].PID != 50 {
		t.Fatalf("findings = %+v, want one bound to nc", got)
	}
}

func TestInvalidPatternsNeverMatch(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{
		{Name: "unrelated-roles", Processes: []ProcessPattern{{ID: "x"}, {ID: "y"}}},
		{Name: "unknown-role", Processes: []ProcessPattern{{ID: "x"}}, Relationships: []RelationshipPattern{spawned("x", "ghost")}},
		{Name: "duplicate-role", Processes: []ProcessPattern{{ID: "x"}, {ID: "x"}}, Relationships: []RelationshipPattern{spawned("x", "x")}},
		{Name: "no-roles"},
	})
	h.defaultPair()

	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("invalid patterns produced findings: %+v", got)
	}
}

// --- Bug 2: window and bounded memory -----------------------------------

func TestEventsOutsideWindowDoNotMatch(t *testing.T) {
	// The parent's event is exactly one window old at at(30s): out. One
	// nanosecond earlier it is still in.
	for _, c := range []struct {
		name string
		eval time.Duration
		want int
	}{
		{"just inside", testWindow - time.Nanosecond, 1},
		{"exactly one window old", testWindow, 0},
		{"older", testWindow + time.Second, 0},
	} {
		h := newHarness(testWindow)
		parent, child := h.defaultPair()
		h.connect(parent, at(0))
		h.connect(child, at(20*time.Second))

		if got := h.detect(at(c.eval)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}
}

func TestRequiredEventsMustShareAWindow(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()

	h.connect(parent, at(0))
	h.connect(child, at(40*time.Second))

	if got := h.detect(at(41 * time.Second)); len(got) != 0 {
		t.Fatalf("events 40s apart in a 30s window produced %d finding(s)", len(got))
	}
}

func TestEventsThatArriveExpiredAreNotStored(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()

	// Six-hour-old activity delivered now.
	old := at(-6 * time.Hour)
	h.clock.set(at(time.Second))
	h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: old, Process: &parent})
	h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: old, Process: &child})

	if got := h.detect(at(2 * time.Second)); len(got) != 0 {
		t.Fatalf("expired events produced %d finding(s)", len(got))
	}
	for _, p := range []core.Process{parent, child} {
		for _, chain := range h.chains[p.Identity()] {
			for _, event := range chain.Events() {
				if event.Type == core.EventNetworkConnect {
					t.Fatalf("expired event stored for %s", p.Name)
				}
			}
		}
	}
}

func TestMissingAndFutureTimestampsUseArrivalTime(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()

	h.clock.set(at(5 * time.Second))
	h.Process(core.Event{Type: core.EventNetworkConnect, Process: &parent})
	h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: at(24 * time.Hour), Process: &child})

	for _, p := range []core.Process{parent, child} {
		events := h.chains[p.Identity()][0].Events()
		if got := events[len(events)-1].Timestamp; !got.Equal(at(5 * time.Second)) {
			t.Errorf("%s: stored timestamp %v, want the arrival time", p.Name, got)
		}
	}

	if got := h.detect(at(6 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	// A future-dated event expires like any other.
	if got := h.detect(at(5*time.Second + testWindow)); len(got) != 0 {
		t.Fatalf("findings one window later = %d, want 0", len(got))
	}
}

func TestClockSteppingBackDoesNotReviveEvents(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	if got := h.detect(at(5 * time.Minute)); len(got) != 0 {
		t.Fatalf("findings after expiry = %d, want 0", len(got))
	}
	if got := h.detect(at(3 * time.Second)); len(got) != 0 {
		t.Fatalf("findings after the clock stepped back = %d, want 0", len(got))
	}
}

func (h *harness) sizes() map[string]int {
	return map[string]int{
		"records":       len(h.records),
		"pids":          len(h.pids),
		"chains":        len(h.chains),
		"relationships": len(h.tree.parent),
		"parents":       len(h.tree.children),
		"orphans":       len(h.orphans),
		"emitted":       len(h.emitted),
		"suppressed":    len(h.suppressed),
	}
}

func TestSweepReleasesExpiredState(t *testing.T) {
	h := newHarness(testWindow)

	// Twenty short-lived parent/child pairs, each producing a finding.
	const pairs = 20
	for i := int32(0); i < pairs; i++ {
		parent := proc(1000+i, 1, "node", at(0))
		child := proc(2000+i, 1000+i, "python", at(time.Second))
		h.start(parent, at(time.Second))
		h.start(child, at(time.Second))
		h.connect(parent, at(2*time.Second))
		h.connect(child, at(2*time.Second))
	}
	if got := h.detect(at(3 * time.Second)); len(got) != pairs {
		t.Fatalf("findings = %d, want %d", len(got), pairs)
	}

	before := h.sizes()
	for name, want := range map[string]int{
		"records": 2 * pairs, "pids": 2 * pairs, "chains": 2 * pairs,
		"relationships": pairs, "parents": pairs, "emitted": pairs,
	} {
		if before[name] != want {
			t.Fatalf("before expiry: %s = %d, want %d (%v)", name, before[name], want, before)
		}
	}

	for i := int32(0); i < pairs; i++ {
		h.exit(proc(2000+i, 1000+i, "python", at(time.Second)), at(4*time.Second))
		h.exit(proc(1000+i, 1, "node", at(0)), at(4*time.Second))
	}

	// Inside the window the tombstones and their events are still needed.
	h.detect(at(20 * time.Second))
	if got := h.sizes(); got["records"] != 2*pairs || got["chains"] != 2*pairs {
		t.Fatalf("state dropped while still in the window: %v", got)
	}

	h.detect(at(2 * time.Minute))

	for name, size := range h.sizes() {
		if size != 0 {
			t.Errorf("after expiry: %s = %d, want 0", name, size)
		}
	}
}

func TestLiveProcessesKeepRecordsButNotOldEvents(t *testing.T) {
	h := newHarness(testWindow)
	_, child := h.defaultPair()
	h.connect(child, at(time.Second))

	h.detect(at(time.Hour))

	sizes := h.sizes()
	if sizes["chains"] != 0 {
		t.Errorf("idle processes still hold %d chain(s)", sizes["chains"])
	}
	if sizes["records"] != 2 || sizes["relationships"] != 1 {
		t.Errorf("live processes forgotten: %v", sizes)
	}
}

func TestSweepAlsoRunsOnEventCount(t *testing.T) {
	h := newHarness(time.Hour) // time-based sweeps are 30s apart
	p := proc(1, 0, "busy", at(0))

	// The clock barely moves, so only the event count can trigger a sweep.
	for i := 0; i < 2*sweepEveryEvents+10; i++ {
		h.feed(core.EventFileModify, p, at(time.Duration(i)*time.Microsecond))
	}

	if h.sinceSweep >= sweepEveryEvents {
		t.Fatalf("%d events since the last sweep; expected one every %d", h.sinceSweep, sweepEveryEvents)
	}
	if h.lastSweep.Equal(at(0)) {
		t.Fatal("no sweep ran after the first event")
	}
}

func TestEventFloodIsBoundedWithoutEvictingOtherTypes(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "lookup-and-connect",
		Processes: []ProcessPattern{named("p", "python", core.EventDNSQuery, core.EventNetworkConnect)},
	}})
	_, child := h.defaultPair()

	h.feed(core.EventDNSQuery, child, at(time.Second))
	for i := 0; i < 50*MaxEventsPerType; i++ {
		h.connect(child, at(2*time.Second+time.Duration(i)*time.Microsecond))
	}

	events := h.chains[child.Identity()][0].Events()
	if want := MaxEventsPerType + 2; len(events) != want { // connects + start + DNS
		t.Fatalf("chain holds %d events, want %d", len(events), want)
	}
	if got := h.detect(at(5 * time.Second)); len(got) != 1 {
		t.Fatalf("the single DNS query was evicted by the flood: findings = %d", len(got))
	}
}

func TestExitedParentStillMatchesForOneWindow(t *testing.T) {
	for _, c := range []struct {
		name string
		eval time.Duration
		want int
	}{
		{"shortly after the parent exits", 10 * time.Second, 1},
		{"one window after the parent exits", 3*time.Second + testWindow, 0},
	} {
		patterns := []BehaviorPattern{{
			Name:          "node-spawns-python",
			Processes:     []ProcessPattern{named("parent", "node"), named("child", "python")},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
		}}

		h := newHarness(testWindow)
		h.SetPatterns(patterns)
		parent, _ := h.defaultPair()
		h.exit(parent, at(3*time.Second))

		// Evaluate once just before, so the periodic sweep has already run
		// and cannot be what hides the tombstone at the boundary. Setting
		// the patterns again clears suppression and forces a full
		// evaluation.
		h.detect(at(c.eval - time.Second))
		h.SetPatterns(patterns)

		if got := h.detect(at(c.eval)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}
}

// --- Bug 3: PID reuse ---------------------------------------------------

func TestRecycledPIDIsNotParentOfOlderChildren(t *testing.T) {
	h := newHarness(testWindow)

	// The child's real parent held PID 100 and was never seen. PID 100 now
	// belongs to a process younger than the child.
	child := proc(300, 100, "python", at(time.Second))
	newHolder := proc(100, 1, "node", at(5*time.Second))

	h.start(child, at(6*time.Second))
	h.start(newHolder, at(6*time.Second))

	if parent, ok := h.parentOf(child); ok {
		t.Fatalf("older child attributed to recycled PID holder %q", parent.Name)
	}

	// Same outcome when the new holder is seen first.
	h = newHarness(testWindow)
	h.start(newHolder, at(6*time.Second))
	h.start(child, at(6*time.Second))

	if parent, ok := h.parentOf(child); ok {
		t.Fatalf("older child attributed to recycled PID holder %q", parent.Name)
	}
}

func TestExitedProcessIsNotParentOfLaterChildren(t *testing.T) {
	h := newHarness(testWindow)

	oldHolder := proc(100, 1, "node", at(-time.Hour))
	h.start(oldHolder, at(0))
	h.connect(oldHolder, at(time.Second))
	h.exit(oldHolder, at(2*time.Second))

	// A process that started after the old holder exited names PID 100 as
	// its parent: the PID has been recycled by a process not seen yet.
	child := proc(300, 100, "python", at(5*time.Second))
	h.start(child, at(6*time.Second))
	h.connect(child, at(6*time.Second))

	if parent, ok := h.parentOf(child); ok {
		t.Fatalf("child attributed to exited process %q", parent.Name)
	}
	if got := h.detect(at(7 * time.Second)); len(got) != 0 {
		t.Fatalf("exited process's activity credited to an unrelated child: %d finding(s)", len(got))
	}

	// Once the real parent turns up, the child is linked to it.
	newHolder := proc(100, 1, "bash", at(4*time.Second))
	h.start(newHolder, at(8*time.Second))

	parent, ok := h.parentOf(child)
	if !ok || parent.Identity() != newHolder.Identity() {
		t.Fatalf("child's parent = %+v (found=%v), want the new holder of PID 100", parent, ok)
	}
}

// Start events are not delivered in start order, and the exit of the old
// holder comes last, so a child can be seen while its parent's PID still
// points at the previous holder.
func TestChildSeenBeforeItsRecycledParentIsReattributed(t *testing.T) {
	h := newHarness(testWindow)

	oldHolder := proc(100, 1, "old-parent", at(-time.Hour))
	newHolder := proc(100, 1, "new-parent", at(8*time.Second))
	child := proc(300, 100, "python", at(9*time.Second))

	h.start(oldHolder, at(0))
	h.connect(oldHolder, at(time.Second))

	h.start(child, at(10*time.Second))
	h.start(newHolder, at(10*time.Second))
	h.exit(oldHolder, at(10*time.Second))
	h.connect(child, at(11*time.Second))

	parent, ok := h.parentOf(child)
	if !ok || parent.Identity() != newHolder.Identity() {
		t.Fatalf("child's parent = %+v (found=%v), want the new holder", parent, ok)
	}
	if got := h.detect(at(12 * time.Second)); len(got) != 0 {
		t.Fatalf("old holder's activity credited to the new holder's child: %d finding(s)", len(got))
	}

	// The late exit of the old holder must not dislodge the new one.
	later := proc(400, 100, "python", at(13*time.Second))
	h.start(later, at(13*time.Second))
	if parent, ok := h.parentOf(later); !ok || parent.Identity() != newHolder.Identity() {
		t.Fatalf("later child's parent = %+v (found=%v), want the new holder", parent, ok)
	}
}

func TestLateEventFromPreviousHolderDoesNotTakeOverPID(t *testing.T) {
	h := newHarness(testWindow)

	current := proc(100, 1, "node", at(5*time.Second))
	previous := proc(100, 1, "old", at(-time.Hour))

	h.start(current, at(6*time.Second))
	h.connect(previous, at(7*time.Second)) // delayed event from the earlier holder

	child := proc(300, 100, "python", at(8*time.Second))
	h.start(child, at(8*time.Second))

	if parent, ok := h.parentOf(child); !ok || parent.Identity() != current.Identity() {
		t.Fatalf("child's parent = %+v (found=%v), want the current holder", parent, ok)
	}
}

func TestUnknownStartTimesFallBackToPID(t *testing.T) {
	h := newHarness(testWindow)

	// Collectors report the Unix epoch when the OS withholds a start time.
	parent := proc(100, 1, "node", time.UnixMilli(0))
	child := proc(200, 100, "python", time.UnixMilli(0))

	h.start(parent, at(0))
	h.start(child, at(0))

	if _, ok := h.parentOf(child); !ok {
		t.Fatal("nothing contradicts the PID match, so the parent should be linked")
	}

	// But an exited parent cannot be confirmed without the child's start
	// time, so it is not assumed.
	h = newHarness(testWindow)
	h.start(parent, at(0))
	h.exit(parent, at(time.Second))
	h.start(child, at(2*time.Second))

	if _, ok := h.parentOf(child); ok {
		t.Fatal("exited parent linked to a child whose start time is unknown")
	}
}

// --- Bug 4: processes that predate the engine ---------------------------

func TestSeededProcessIsAValidParent(t *testing.T) {
	h := newHarness(testWindow)

	parent := proc(100, 1, "node", at(-24*time.Hour))
	h.Seed([]core.Process{parent, proc(1, 0, "launchd", at(-48*time.Hour))})

	child := proc(200, 100, "python", at(time.Second))
	h.start(child, at(time.Second))
	h.connect(parent, at(2*time.Second))
	h.connect(child, at(3*time.Second))

	if got, ok := h.parentOf(child); !ok || got.Identity() != parent.Identity() {
		t.Fatalf("child's parent = %+v (found=%v), want the seeded process", got, ok)
	}
	if got, ok := h.parentOf(parent); !ok || got.Name != "launchd" {
		t.Fatalf("seeded processes not linked to each other: %+v (found=%v)", got, ok)
	}
	if got := h.detect(at(4 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestProcessSeenOnlyThroughOtherEventsIsAValidParent(t *testing.T) {
	h := newHarness(testWindow)

	// No start event for the parent: it was running before the engine.
	parent := proc(100, 1, "node", at(-24*time.Hour))
	h.connect(parent, at(time.Second))

	child := proc(200, 100, "python", at(2*time.Second))
	h.start(child, at(2*time.Second))
	h.connect(child, at(3*time.Second))

	if got, ok := h.parentOf(child); !ok || got.Identity() != parent.Identity() {
		t.Fatalf("child's parent = %+v (found=%v), want the process seen via its network event", got, ok)
	}
	if got := h.detect(at(4 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestOrphanIsLinkedWhenItsParentIsSeenLater(t *testing.T) {
	h := newHarness(testWindow)

	child := proc(200, 100, "python", at(time.Second))
	h.start(child, at(time.Second))
	h.connect(child, at(2*time.Second))

	if _, ok := h.parentOf(child); ok {
		t.Fatal("parent known before it was ever seen")
	}

	// The parent's first appearance is a network event, after the child.
	parent := proc(100, 1, "node", at(-24*time.Hour))
	h.connect(parent, at(3*time.Second))

	if got, ok := h.parentOf(child); !ok || got.Identity() != parent.Identity() {
		t.Fatalf("orphan not linked: %+v (found=%v)", got, ok)
	}
	if waiting := h.orphans[parent.PID]; len(waiting) != 0 {
		t.Errorf("linked child still listed as an orphan: %v", waiting)
	}
	if got := h.detect(at(4 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestRepeatedEventsDoNotDuplicateRelationships(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()

	for i := 0; i < 5; i++ {
		h.start(child, at(time.Second))
		h.connect(parent, at(time.Second))
	}
	h.Seed([]core.Process{parent, child})

	if got := len(h.RelationshipsForProcess(child.Identity())); got != 1 {
		t.Fatalf("relationships for child = %d, want 1", got)
	}
	if got := h.sizes()["relationships"]; got != 1 {
		t.Fatalf("relationships in total = %d, want 1", got)
	}
}

// --- Bug 5: deduplication -----------------------------------------------

func TestDifferentProcessPairsProduceSeparateFindings(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("first pair: findings = %d, want 1", len(got))
	}

	// A second, unrelated pair matches the same rule inside the window.
	other := proc(500, 1, "ruby", at(4*time.Second))
	otherChild := proc(600, 500, "python", at(5*time.Second))
	h.start(other, at(4*time.Second))
	h.start(otherChild, at(5*time.Second))
	h.connect(other, at(6*time.Second))
	h.connect(otherChild, at(7*time.Second))

	got := h.detect(at(8 * time.Second))
	if len(got) != 1 {
		t.Fatalf("second pair: findings = %d, want 1 new finding", len(got))
	}
	if got[0].Evidence.Processes[0].Identity() != other.Identity() {
		t.Errorf("second finding is about PID %d, want %d", got[0].Evidence.Processes[0].PID, other.PID)
	}
}

func TestSamePairProducesOneFindingPerWindow(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	total := 0
	for d := 2 * time.Second; d < 2*time.Second+testWindow; d += 500 * time.Millisecond {
		total += len(h.detect(at(d)))
	}
	if total != 1 {
		t.Fatalf("findings across one window = %d, want 1", total)
	}

	// Suppression has lapsed and so have the events: one incident, one
	// finding, however long evaluation continues.
	for d := testWindow; d < 10*testWindow; d += time.Second {
		total += len(h.detect(at(2*time.Second + d)))
	}
	if total != 1 {
		t.Fatalf("findings for a single incident = %d, want 1", total)
	}
}

func TestSustainedBehaviourFiresOncePerWindow(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()

	total := 0
	for d := time.Duration(0); d < 3*testWindow; d += time.Second {
		h.connect(parent, at(d))
		h.connect(child, at(d))
		total += len(h.detect(at(d)))
	}

	if total != 3 {
		t.Fatalf("findings over three windows of continuous activity = %d, want 3", total)
	}
}

func TestSetPatternsResetsSuppression(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}

	h.SetPatterns(DefaultPatterns())
	if got := h.detect(at(4 * time.Second)); len(got) != 1 {
		t.Fatalf("findings after SetPatterns = %d, want 1", len(got))
	}
}

// --- Bug 6: concurrency -------------------------------------------------

// The pattern editor replaces patterns from the UI goroutine while the bus
// goroutine processes events. Meaningful under -race.
func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ts := at(time.Duration(i) * time.Millisecond)
			h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: ts, Process: &parent})
			h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: ts, Process: &child})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			h.DetectBehaviors()
			h.ChainsForProcess(child.Identity())
			h.RelationshipsForProcess(child.Identity())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			h.SetPatterns(DefaultPatterns())
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			h.clock.set(at(time.Duration(i) * time.Millisecond))
			h.Seed([]core.Process{parent, child})
		}
	}()
	wg.Wait()
}

// --- Bug 7: evidence ----------------------------------------------------

func evidenceNames(f core.Finding) string {
	names := make([]string, len(f.Evidence.Processes))
	for i, p := range f.Evidence.Processes {
		names[i] = p.Name
	}
	return strings.Join(names, ",")
}

func TestFindingCarriesBoundProcessesAsEvidence(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	findings := h.detect(at(3 * time.Second))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]

	// Role order of the default pattern: parent, then child.
	bound := f.Evidence.Processes
	if len(bound) != 2 || bound[0].Identity() != parent.Identity() || bound[1].Identity() != child.Identity() {
		t.Fatalf("evidence processes = %+v, want [parent, child]", bound)
	}
	if f.Evidence.Process == nil || f.Evidence.Process.Identity() != child.Identity() {
		t.Fatalf("evidence subject = %+v, want the last role (child)", f.Evidence.Process)
	}
	if !strings.HasPrefix(f.ID, "finding-") || len(f.ID) == len("finding-") {
		t.Errorf("finding ID = %q, want finding-<n>", f.ID)
	}
	if !f.Timestamp.Equal(at(3 * time.Second)) {
		t.Errorf("finding timestamp = %v, want the evaluation time", f.Timestamp)
	}
}

func TestFindingIDsAreUniqueWithinOneEvaluation(t *testing.T) {
	h := newHarness(testWindow)

	for i := int32(0); i < 5; i++ {
		parent := proc(1000+i, 1, "node", at(0))
		child := proc(2000+i, 1000+i, "python", at(0))
		h.start(parent, at(0))
		h.start(child, at(0))
		h.connect(parent, at(time.Second))
		h.connect(child, at(time.Second))
	}

	findings := h.detect(at(2 * time.Second))
	if len(findings) != 5 {
		t.Fatalf("findings = %d, want 5", len(findings))
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		if seen[f.ID] {
			t.Fatalf("duplicate finding ID %q", f.ID)
		}
		seen[f.ID] = true
	}

	// Findings come out in a stable order, not map order.
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Evidence.Processes[0].PID > findings[i].Evidence.Processes[0].PID {
			t.Fatalf("findings not in a deterministic order: %d before %d",
				findings[i-1].Evidence.Processes[0].PID, findings[i].Evidence.Processes[0].PID)
		}
	}
}

// --- Evaluation scope ---------------------------------------------------

func findingKeys(findings []core.Finding) string {
	keys := make([]string, len(findings))
	for i, f := range findings {
		pids := make([]string, len(f.Evidence.Processes))
		for j, p := range f.Evidence.Processes {
			pids[j] = fmt.Sprint(p.PID)
		}
		keys[i] = f.Rule + ":" + strings.Join(pids, ">")
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

// DetectBehaviors only searches around processes that changed since the last
// evaluation. That must find exactly what evaluating everything finds. Two
// engines are fed the same pseudo-random activity; one is forced to evaluate
// everything every time.
func TestIncrementalEvaluationMatchesFullEvaluation(t *testing.T) {
	patterns := append(DefaultPatterns(),
		chainPattern()[0],
		BehaviorPattern{
			Name:      "lone-dns",
			Processes: []ProcessPattern{named("p", "c", core.EventDNSQuery)},
		},
		BehaviorPattern{
			Name:          "any-spawn-with-connect",
			Processes:     []ProcessPattern{{ID: "parent"}, {ID: "child", Events: []EventPattern{{Type: core.EventNetworkConnect}}}},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
		},
		// Predicates, event filters, a per-pattern exclusion and a low rate
		// limit, so that all of them are exercised on both paths.
		BehaviorPattern{
			Name: "odd-port-from-non-root",
			Processes: []ProcessPattern{
				{ID: "parent", Match: &MatchBlock{Fields: []FieldPredicate{
					{Field: "name", Predicate: Predicate{Regex: stringPtr("^(a|b|node)$")}},
				}}},
				{
					ID: "child",
					Match: &MatchBlock{
						Fields: []FieldPredicate{{Field: "user", Predicate: Predicate{Not: &Predicate{Eq: stringPtr("root")}}}},
						AnyOf: []MatchBlock{
							{Fields: []FieldPredicate{{Field: "name", Predicate: Predicate{Prefix: stringPtr("py")}}}},
							{Fields: []FieldPredicate{{Field: "name", Predicate: Predicate{In: []string{"c", "b"}}}}},
						},
					},
					Events: []EventPattern{{
						Type: core.EventNetworkConnect,
						Where: &MatchBlock{Fields: []FieldPredicate{
							{Field: "remote_port", Predicate: Predicate{Not: &Predicate{In: []string{"80", "443"}}}},
							{Field: "remote_addr", Predicate: Predicate{Not: &Predicate{CIDR: []string{"10.0.0.0/8", "::1/128"}}}},
						}},
					}},
				},
			},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
			Exclude: []RoleExclusion{{Role: "parent", Match: &MatchBlock{Fields: []FieldPredicate{
				{Field: "user", Predicate: Predicate{Eq: stringPtr("svc")}},
			}}}},
			MaxFindingsPerWindow: 3,
		},
		BehaviorPattern{
			Name: "suspicious-lookup",
			Processes: []ProcessPattern{{ID: "p", Events: []EventPattern{{
				Type:  core.EventDNSQuery,
				Where: &MatchBlock{Fields: []FieldPredicate{{Field: "domain", Predicate: Predicate{Glob: stringPtr("**.top")}}}},
			}}}},
			MaxFindingsPerWindow: 2,
		},
	)
	for _, pattern := range patterns {
		if err := pattern.Validate(); err != nil {
			t.Fatalf("pattern %q: %v", pattern.Name, err)
		}
	}

	exclusions := []Exclusion{
		{Rules: []string{"*"}, Match: &MatchBlock{Fields: []FieldPredicate{{Field: "user", Predicate: Predicate{Eq: stringPtr("trusted")}}}}},
		{Rules: []string{"lone-dns"}, Match: &MatchBlock{Fields: []FieldPredicate{{Field: "name", Predicate: Predicate{Eq: stringPtr("c")}}, {Field: "user", Predicate: Predicate{Eq: stringPtr("app")}}}}},
	}

	incremental, full := newHarness(testWindow), newHarness(testWindow)
	for _, h := range []*harness{incremental, full} {
		h.SetPatterns(patterns)
		if err := h.SetExclusions(exclusions); err != nil {
			t.Fatal(err)
		}
	}

	rng := rand.New(rand.NewSource(1))
	names := []string{"a", "b", "c", "node", "python"}
	users := []string{"root", "app", "svc", "trusted"}
	addresses := []string{"10.1.1.1", "203.0.113.5", "::1", "2001:db8::5"}
	ports := []uint32{80, 443, 4444, 8080}
	domains := []string{"example.com", "c2.evil.top", "updates.vendor.io"}
	eventTypes := []core.EventType{
		core.EventProcessStart, core.EventNetworkConnect, core.EventDNSQuery,
		core.EventNetworkConnect, core.EventProcessExit,
	}

	// PIDs are reused with new start times, and parents are drawn from the
	// same small range, so exits, reuse and orphans all occur.
	var live []core.Process
	total := 0
	sawRateLimitSummary := false

	for step := 0; step < 4000; step++ {
		ts := at(time.Duration(step) * 250 * time.Millisecond)

		var p core.Process
		if len(live) == 0 || rng.Intn(4) == 0 {
			p = proc(int32(1+rng.Intn(40)), int32(1+rng.Intn(40)), names[rng.Intn(len(names))], ts)
			p.User = users[rng.Intn(len(users))]
			live = append(live, p)
		} else {
			p = live[rng.Intn(len(live))]
		}
		eventType := eventTypes[rng.Intn(len(eventTypes))]

		event := core.Event{Type: eventType, Timestamp: ts}
		switch eventType {
		case core.EventNetworkConnect:
			event.Network = &core.NetworkConnection{
				RemoteAddress: addresses[rng.Intn(len(addresses))],
				RemotePort:    ports[rng.Intn(len(ports))],
			}
		case core.EventDNSQuery:
			event.DNS = &core.DNSQuery{Domain: domains[rng.Intn(len(domains))]}
		}

		for _, h := range []*harness{incremental, full} {
			subject := p
			event.Process = &subject
			h.clock.set(ts)
			h.Process(event)
		}

		full.rescan = true
		got, want := findingKeys(incremental.detect(ts)), findingKeys(full.detect(ts))
		if got != want {
			t.Fatalf("step %d (%s pid %d): incremental found [%s], full evaluation found [%s]",
				step, eventType, p.PID, got, want)
		}
		if want != "" {
			total++
		}
		if strings.Contains(want, "odd-port-from-non-root:") || strings.Contains(want, "suspicious-lookup:") {
			// A finding with no evidence is a rate-limit summary.
			for _, key := range strings.Fields(want) {
				if strings.HasSuffix(key, ":") {
					sawRateLimitSummary = true
				}
			}
		}
	}

	if total < 50 {
		t.Fatalf("only %d steps produced findings; the comparison is not exercising much", total)
	}

	// Exclusions and the rate limit must have come into play, and counted
	// the same on both paths.
	got, want := incremental.ExcludedFindings(), full.ExcludedFindings()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("excluded counts differ: incremental %v, full %v", got, want)
	}
	if len(want) == 0 {
		t.Fatal("no finding was excluded; the comparison is not exercising exclusions")
	}
	if !sawRateLimitSummary {
		t.Fatal("no rate-limit summary was emitted; the comparison is not exercising the rate limit")
	}
}

func TestEvaluationWithNothingChangedFindsNothingNew(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if len(h.touched) != 0 || h.rescan {
		t.Fatalf("evaluation left work pending: touched=%d rescan=%v", len(h.touched), h.rescan)
	}

	// Events for processes the engine cannot attribute change nothing.
	h.clock.set(at(4 * time.Second))
	h.Process(core.Event{Type: core.EventDNSQuery, Timestamp: at(4 * time.Second)})
	if got := h.detect(at(4 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}
