package correlation

import (
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func (h *harness) fileCreate(p core.Process, path string, ts time.Time) {
	h.clock.set(ts)
	h.Process(core.Event{
		Type:      core.EventFileCreate,
		Timestamp: ts,
		Process:   &p,
		File:      &core.FileEvent{Path: path, Operation: core.FileCreate},
	})
}

func step(role string, eventType core.EventType) SequenceStep {
	return SequenceStep{Role: role, Type: eventType}
}

func tolerance(d time.Duration) *time.Duration { return &d }

// oneRoleSequence is a single role, any process named "p", with a sequence.
func oneRoleSequence(sequence SequencePattern) []BehaviorPattern {
	return []BehaviorPattern{{
		Name:      "sequence",
		Processes: []ProcessPattern{named("r", "p")},
		Sequence:  &sequence,
	}}
}

func newSequenceHarness(t *testing.T, patterns []BehaviorPattern) *harness {
	t.Helper()
	for _, pattern := range patterns {
		if err := pattern.ValidateFor(testWindow); err != nil {
			t.Fatalf("pattern %q does not validate: %v", pattern.Name, err)
		}
	}
	h := newHarness(testWindow)
	h.SetPatterns(patterns)
	return h
}

// timed is an event type at an offset from the test epoch.
type timed struct {
	eventType core.EventType
	at        time.Duration
}

func (h *harness) play(p core.Process, events ...timed) {
	for _, e := range events {
		switch e.eventType {
		case core.EventDNSQuery:
			h.query(p, "example.com", at(e.at))
		case core.EventFileCreate:
			h.fileCreate(p, "/tmp/x", at(e.at))
		default:
			h.feed(e.eventType, p, at(e.at))
		}
	}
}

func TestSequenceOrder(t *testing.T) {
	sequence := SequencePattern{
		OrderTolerance: tolerance(0),
		Steps: []SequenceStep{
			step("r", core.EventDNSQuery),
			step("r", core.EventNetworkConnect),
			step("r", core.EventFileCreate),
		},
	}

	cases := []struct {
		name   string
		events []timed
		want   int
	}{
		{"in order", []timed{{core.EventDNSQuery, 1 * time.Second}, {core.EventNetworkConnect, 2 * time.Second}, {core.EventFileCreate, 3 * time.Second}}, 1},
		{"reversed", []timed{{core.EventFileCreate, 1 * time.Second}, {core.EventNetworkConnect, 2 * time.Second}, {core.EventDNSQuery, 3 * time.Second}}, 0},
		{"last two swapped", []timed{{core.EventDNSQuery, 1 * time.Second}, {core.EventFileCreate, 2 * time.Second}, {core.EventNetworkConnect, 3 * time.Second}}, 0},
		{"a step missing", []timed{{core.EventDNSQuery, 1 * time.Second}, {core.EventFileCreate, 3 * time.Second}}, 0},
		{"other events in between", []timed{
			{core.EventFileCreate, 1 * time.Second}, {core.EventDNSQuery, 2 * time.Second}, {core.EventNetworkClose, 3 * time.Second},
			{core.EventNetworkConnect, 4 * time.Second}, {core.EventDNSQuery, 5 * time.Second}, {core.EventFileCreate, 6 * time.Second},
		}, 1},
		{"same instant counts as in order", []timed{{core.EventDNSQuery, time.Second}, {core.EventNetworkConnect, time.Second}, {core.EventFileCreate, time.Second}}, 1},
		// A wrong-order pair early on must not hide a correct one later.
		{"correct order found after a false start", []timed{
			{core.EventNetworkConnect, 1 * time.Second}, {core.EventDNSQuery, 2 * time.Second},
			{core.EventNetworkConnect, 3 * time.Second}, {core.EventFileCreate, 4 * time.Second},
		}, 1},
	}

	for _, c := range cases {
		h := newSequenceHarness(t, oneRoleSequence(sequence))
		p := proc(50, 1, "p", at(0))
		h.start(p, at(0))
		h.play(p, c.events...)

		if got := h.detect(at(10 * time.Second)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}
}

// An earlier step's event may be timestamped later than the next step's, but
// by no more than the tolerance.
func TestSequenceOrderToleranceBoundary(t *testing.T) {
	const tol = 3 * time.Second

	sequence := SequencePattern{
		OrderTolerance: tolerance(tol),
		Steps:          []SequenceStep{step("r", core.EventNetworkConnect), step("r", core.EventFileCreate)},
	}

	// The connection is step 1 but, being polled, is stamped after the file
	// creation it preceded.
	for _, c := range []struct {
		name string
		late time.Duration // how much later than the file event the connect is stamped
		want int
	}{
		{"well inside the tolerance", time.Second, 1},
		{"exactly the tolerance", tol, 1},
		{"just beyond the tolerance", tol + time.Nanosecond, 0},
		{"far beyond", 10 * time.Second, 0},
	} {
		h := newSequenceHarness(t, oneRoleSequence(sequence))
		p := proc(50, 1, "p", at(0))
		h.start(p, at(0))
		h.fileCreate(p, "/tmp/x", at(5*time.Second))
		h.connect(p, at(5*time.Second+c.late))

		if got := h.detect(at(20 * time.Second)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}

	// With no tolerance written, the default applies.
	defaulted := SequencePattern{Steps: sequence.Steps}
	for late, want := range map[time.Duration]int{DefaultOrderTolerance: 1, DefaultOrderTolerance + time.Millisecond: 0} {
		h := newSequenceHarness(t, oneRoleSequence(defaulted))
		p := proc(50, 1, "p", at(0))
		h.start(p, at(0))
		h.fileCreate(p, "/tmp/x", at(5*time.Second))
		h.connect(p, at(5*time.Second+late))

		if got := h.detect(at(20 * time.Second)); len(got) != want {
			t.Errorf("default tolerance, connect %v late: findings = %d, want %d", late, len(got), want)
		}
	}
}

// The tolerance applies between every earlier and later step, not just
// neighbours: it cannot be chained to walk backwards.
func TestSequenceToleranceDoesNotAccumulate(t *testing.T) {
	sequence := SequencePattern{
		OrderTolerance: tolerance(3 * time.Second),
		Steps: []SequenceStep{
			step("r", core.EventDNSQuery), step("r", core.EventNetworkConnect), step("r", core.EventFileCreate),
		},
	}

	h := newSequenceHarness(t, oneRoleSequence(sequence))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))
	// Each step is 2.5s before the one before it: neighbours are within
	// tolerance, but the third is 5s before the first.
	h.play(p, timed{core.EventFileCreate, 5 * time.Second}, timed{core.EventNetworkConnect, 7500 * time.Millisecond}, timed{core.EventDNSQuery, 10 * time.Second})

	if got := h.detect(at(15 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestSequenceWithinBoundary(t *testing.T) {
	const within = 10 * time.Second

	sequence := SequencePattern{
		Within:         within,
		OrderTolerance: tolerance(0),
		Steps: []SequenceStep{
			step("r", core.EventDNSQuery), step("r", core.EventNetworkConnect), step("r", core.EventFileCreate),
		},
	}

	for _, c := range []struct {
		name string
		last time.Duration // offset of the last step from the first
		want int
	}{
		{"well inside", 4 * time.Second, 1},
		{"exactly within", within, 1},
		{"just beyond", within + time.Nanosecond, 0},
	} {
		h := newSequenceHarness(t, oneRoleSequence(sequence))
		p := proc(50, 1, "p", at(0))
		h.start(p, at(0))
		h.play(p,
			timed{core.EventDNSQuery, 2 * time.Second},
			timed{core.EventNetworkConnect, 3 * time.Second},
			timed{core.EventFileCreate, 2*time.Second + c.last},
		)

		if got := h.detect(at(20 * time.Second)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}

	// The tolerance loosens ordering, not the span: with a tolerance, a last
	// step just beyond within is still too far.
	withTolerance := sequence
	withTolerance.OrderTolerance = tolerance(3 * time.Second)
	for last, want := range map[time.Duration]int{within: 1, within + time.Second: 0} {
		h := newSequenceHarness(t, oneRoleSequence(withTolerance))
		p := proc(50, 1, "p", at(0))
		h.start(p, at(0))
		h.play(p,
			timed{core.EventDNSQuery, 2 * time.Second},
			timed{core.EventNetworkConnect, 3 * time.Second},
			timed{core.EventFileCreate, 2*time.Second + last},
		)
		if got := h.detect(at(20 * time.Second)); len(got) != want {
			t.Errorf("with a tolerance, last step %v after the first: findings = %d, want %d", last, len(got), want)
		}
	}

	// A later first step can still be within reach when an earlier one is not.
	h := newSequenceHarness(t, oneRoleSequence(sequence))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))
	h.play(p,
		timed{core.EventDNSQuery, 1 * time.Second}, // too far from the file event
		timed{core.EventDNSQuery, 8 * time.Second}, // close enough
		timed{core.EventNetworkConnect, 9 * time.Second},
		timed{core.EventFileCreate, 15 * time.Second},
	)
	if got := h.detect(at(20 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1 using the later DNS query", len(got))
	}
}

// Sequences are checked against stored events, so the order events reach the
// engine in does not matter: only their timestamps do.
func TestSequenceEventsArrivingOutOfOrder(t *testing.T) {
	sequence := SequencePattern{
		OrderTolerance: tolerance(0),
		Steps:          []SequenceStep{step("r", core.EventDNSQuery), step("r", core.EventNetworkConnect)},
	}

	h := newSequenceHarness(t, oneRoleSequence(sequence))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))

	// The connection (second step) is delivered first.
	h.clock.set(at(6 * time.Second))
	h.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: at(5 * time.Second), Process: &p})
	if got := h.detect(at(6 * time.Second)); len(got) != 0 {
		t.Fatalf("findings with only the second step = %d", len(got))
	}

	// The DNS query that happened before it is delivered late.
	h.clock.set(at(7 * time.Second))
	h.Process(core.Event{Type: core.EventDNSQuery, Timestamp: at(4 * time.Second), Process: &p, DNS: &core.DNSQuery{Domain: "x"}})
	if got := h.detect(at(7 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1: by timestamp the events are in order", len(got))
	}
}

func TestSequenceEventCannotSatisfyTwoSteps(t *testing.T) {
	sequence := SequencePattern{
		Steps: []SequenceStep{step("r", core.EventNetworkConnect), step("r", core.EventNetworkConnect)},
	}

	h := newSequenceHarness(t, oneRoleSequence(sequence))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))

	h.connect(p, at(time.Second))
	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("one connection satisfied both steps: %d finding(s)", len(got))
	}

	h.connect(p, at(2*time.Second))
	got := h.detect(at(2 * time.Second))
	if len(got) != 1 {
		t.Fatalf("findings with two connections = %d, want 1", len(got))
	}
	if events := got[0].Evidence.Events; len(events) < 2 || !events[0].Timestamp.Before(events[1].Timestamp) {
		t.Errorf("evidence events = %+v, want the two connections in order", events)
	}
}

// dropAndRun is the dropper/payload sequence: the dropper connects out and
// creates a file under /tmp, then the payload it spawned starts from exactly
// that file.
func dropAndRun(nocase bool) []BehaviorPattern {
	return []BehaviorPattern{{
		Name:          "download-and-execute",
		Severity:      core.SeverityCritical,
		Processes:     []ProcessPattern{{ID: "dropper"}, {ID: "payload"}},
		Relationships: []RelationshipPattern{spawned("dropper", "payload")},
		Sequence: &SequencePattern{
			Within: 20 * time.Second,
			Steps: []SequenceStep{
				{Role: "dropper", Type: core.EventNetworkConnect},
				{Role: "dropper", Type: core.EventFileCreate, Where: block(fieldIs("path", Predicate{Glob: sp("/tmp/**")})), Capture: "dropped"},
				{Role: "payload", Type: core.EventProcessStart, Where: block(fieldIs("exe", Predicate{Eq: sp("$dropped.path"), NoCase: nocase}))},
			},
		},
	}}
}

// runDropper plays a dropper that creates createdPath and spawns a child
// running payloadExe.
func runDropper(t *testing.T, patterns []BehaviorPattern, createdPath, payloadExe string) (*harness, []core.Finding) {
	t.Helper()

	h := newSequenceHarness(t, patterns)

	dropper := proc(100, 1, "sh", at(0))
	payload := proc(200, 100, "x", at(4*time.Second))
	payload.Executable = payloadExe

	h.start(dropper, at(time.Second))
	h.connect(dropper, at(2*time.Second))
	h.fileCreate(dropper, createdPath, at(3*time.Second))
	h.start(payload, at(4*time.Second))

	return h, h.detect(at(5 * time.Second))
}

func TestCaptureDownloadAndExecute(t *testing.T) {
	cases := []struct {
		name    string
		created string
		exe     string
		nocase  bool
		want    int
	}{
		{"payload runs the dropped file", "/tmp/payload", "/tmp/payload", false, 1},
		{"payload runs a different file", "/tmp/payload", "/tmp/other", false, 0},
		{"payload runs a system binary", "/tmp/payload", "/usr/bin/id", false, 0},
		{"file dropped outside /tmp", "/home/u/payload", "/home/u/payload", false, 0},
		{"paths differ only in spelling", "/tmp//stage/../payload", "/tmp/payload", false, 1},
		{"trailing slash and dot segments", "/tmp/a/./b", "/tmp/a/b/", false, 1},
		{"case differs", "/tmp/Payload", "/tmp/payload", false, 0},
		{"case differs, nocase", "/tmp/Payload", "/tmp/payload", true, 1},
		{"payload executable unknown", "/tmp/payload", "", false, 0},
	}

	for _, c := range cases {
		_, got := runDropper(t, dropAndRun(c.nocase), c.created, c.exe)
		if len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}
}

func TestSequenceAcrossRolesUsesEachRolesOwnEvents(t *testing.T) {
	h := newSequenceHarness(t, dropAndRun(false))

	dropper := proc(100, 1, "sh", at(0))
	payload := proc(200, 100, "x", at(4*time.Second))
	payload.Executable = "/tmp/payload"
	bystander := proc(300, 1, "curl", at(0))

	h.start(dropper, at(time.Second))
	h.start(bystander, at(time.Second))

	// The connection and the file creation are by an unrelated process.
	h.connect(bystander, at(2*time.Second))
	h.fileCreate(bystander, "/tmp/payload", at(3*time.Second))
	h.start(payload, at(4*time.Second))

	if got := h.detect(at(5 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: the dropper role's own process did neither", len(got))
	}

	// Once the dropper itself does them the sequence holds; the payload's
	// start is then earlier than the dropper's steps, within tolerance.
	h.connect(dropper, at(5*time.Second))
	h.fileCreate(dropper, "/tmp/payload", at(6*time.Second))

	got := h.detect(at(6 * time.Second))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}

	events := got[0].Evidence.Events
	if len(events) != 3 ||
		events[0].Type != core.EventNetworkConnect || events[0].Process.PID != dropper.PID ||
		events[1].Type != core.EventFileCreate || events[1].File.Path != "/tmp/payload" ||
		events[2].Type != core.EventProcessStart || events[2].Process.PID != payload.PID {
		t.Errorf("evidence events are not the three steps in order: %+v", events)
	}
}

// The sequence is re-checked when any process bound to a role changes,
// whichever step that completes.
func TestSequenceIsRecheckedWhenAnyBoundProcessChanges(t *testing.T) {
	for _, last := range []string{"dropper connects last", "dropper creates the file last", "payload starts last"} {
		h := newSequenceHarness(t, dropAndRun(false))

		dropper := proc(100, 1, "sh", at(0))
		payload := proc(200, 100, "x", at(2*time.Second))
		payload.Executable = "/tmp/payload"
		h.start(dropper, at(time.Second))

		steps := map[string]func(ts time.Time){
			"connect": func(ts time.Time) { h.connect(dropper, ts) },
			"create":  func(ts time.Time) { h.fileCreate(dropper, "/tmp/payload", ts) },
			"start":   func(ts time.Time) { h.start(payload, ts) },
		}

		order := map[string][]string{
			"dropper connects last":         {"create", "start", "connect"},
			"dropper creates the file last": {"connect", "start", "create"},
			"payload starts last":           {"connect", "create", "start"},
		}[last]

		// All three happen at nearly the same moment, so any arrival order
		// is within the default tolerance.
		for i, name := range order {
			ts := at(3*time.Second + time.Duration(i)*100*time.Millisecond)
			if i == len(order)-1 {
				if got := h.detect(ts); len(got) != 0 {
					t.Fatalf("%s: findings before the last step = %d", last, len(got))
				}
			}
			steps[name](ts)
		}

		// "connect" is step 1 but may be stamped last; it is within 3s.
		if got := h.detect(at(4 * time.Second)); len(got) != 1 {
			t.Errorf("%s: findings = %d, want 1", last, len(got))
		}
	}
}

func TestSequenceObeysTheCorrelationWindow(t *testing.T) {
	sequence := SequencePattern{Steps: []SequenceStep{step("r", core.EventDNSQuery), step("r", core.EventNetworkConnect)}}

	h := newSequenceHarness(t, oneRoleSequence(sequence))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))
	h.play(p, timed{core.EventDNSQuery, 1 * time.Second}, timed{core.EventNetworkConnect, 25 * time.Second})

	// At 31s the DNS query has left the 30s window.
	if got := h.detect(at(31 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestSequenceWithRolePredicatesAndRelationship(t *testing.T) {
	h := newSequenceHarness(t, []BehaviorPattern{{
		Name: "interpreter-persistence",
		Processes: []ProcessPattern{
			{ID: "interp", Match: block(fieldIs("name", Predicate{Regex: sp("^python")}))},
		},
		Sequence: &SequencePattern{
			Within: 10 * time.Second,
			Steps: []SequenceStep{
				{Role: "interp", Type: core.EventNetworkConnect},
				{Role: "interp", Type: core.EventFileCreate, Where: block(fieldIs("path", Predicate{Prefix: sp("/etc/cron")}))},
			},
		},
	}})

	python := proc(10, 1, "python3", at(0))
	bash := proc(11, 1, "bash", at(0))
	h.start(python, at(0))
	h.start(bash, at(0))

	// bash does the whole sequence but cannot fill the role.
	h.connect(bash, at(time.Second))
	h.fileCreate(bash, "/etc/cron.d/x", at(2*time.Second))
	// python creates a file, but not in the right place.
	h.connect(python, at(time.Second))
	h.fileCreate(python, "/tmp/x", at(2*time.Second))
	if got := h.detect(at(3 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}

	h.fileCreate(python, "/etc/cron.d/job", at(4*time.Second))
	if got := h.detect(at(4 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

// When a bound process produced more events of a type than a chain keeps,
// the events a sequence needed may have been discarded. That is counted.
func TestSequencePossiblyTruncatedIsCounted(t *testing.T) {
	sequence := SequencePattern{
		OrderTolerance: tolerance(0),
		Steps:          []SequenceStep{step("r", core.EventDNSQuery), step("r", core.EventNetworkConnect), step("r", core.EventFileCreate)},
	}

	h := newSequenceHarness(t, oneRoleSequence(sequence))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))

	// A failed sequence with nothing discarded is just a failed sequence.
	h.query(p, "example.com", at(time.Second))
	h.detect(at(time.Second))
	if got := h.Metrics().SequencesPossiblyTruncated; got != 0 {
		t.Fatalf("possibly-truncated count = %d before any event was discarded", got)
	}

	// The one connection is pushed out by a flood of later ones... of the
	// same type, which is the only way the per-type cap discards anything.
	h.connect(p, at(2*time.Second))
	h.fileCreate(p, "/tmp/x", at(3*time.Second))
	h.SetPatterns(oneRoleSequence(sequence))
	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("findings before the flood = %d, want 1", len(got))
	}

	for i := 0; i < 2*MaxEventsPerType; i++ {
		h.connect(p, at(4*time.Second+time.Duration(i)*time.Millisecond))
	}
	h.SetPatterns(oneRoleSequence(sequence))

	// DNS(1s) → connect(2s) → file(3s) happened, but the connect at 2s is
	// gone: every retained connect is after the file event.
	if got := h.detect(at(5 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d; the test expects the sequence to be lost to the cap", len(got))
	}
	if got := h.Metrics().SequencesPossiblyTruncated; got == 0 {
		t.Fatal("a sequence lost to the event cap was not counted")
	}
}

func TestSequenceSearchIsBoundedAndCounted(t *testing.T) {
	// Seven steps of one type and an eighth that never comes: without a
	// bound the search would try every way of choosing seven events.
	steps := make([]SequenceStep, 0, MaxSequenceSteps)
	for i := 0; i < MaxSequenceSteps-1; i++ {
		steps = append(steps, step("r", core.EventNetworkConnect))
	}
	steps = append(steps, SequenceStep{
		Role: "r", Type: core.EventNetworkConnect,
		Where: block(fieldIs("remote_port", Predicate{Eq: sp("1")})),
	})

	h := newSequenceHarness(t, oneRoleSequence(SequencePattern{Steps: steps}))
	p := proc(50, 1, "p", at(0))
	h.start(p, at(0))
	for i := 0; i < MaxEventsPerType; i++ {
		h.connectTo(p, "203.0.113.1", 443, at(time.Second+time.Duration(i)*time.Millisecond))
	}

	if got := h.detect(at(2 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
	if got := h.Metrics().SequenceSearchesAborted; got != 1 {
		t.Fatalf("aborted searches = %d, want 1", got)
	}
}

func TestSequenceValidationErrors(t *testing.T) {
	roles := []ProcessPattern{{ID: "dropper"}, {ID: "payload"}}
	related := []RelationshipPattern{spawned("dropper", "payload")}

	pattern := func(sequence SequencePattern) BehaviorPattern {
		return BehaviorPattern{Name: "p", Processes: roles, Relationships: related, Sequence: &sequence}
	}
	capturing := SequenceStep{Role: "dropper", Type: core.EventFileCreate, Capture: "dropped"}
	using := func(field string, p Predicate) SequenceStep {
		return SequenceStep{Role: "payload", Type: core.EventProcessStart, Where: block(fieldIs(field, p))}
	}

	cases := map[string]struct {
		sequence SequencePattern
		want     []string
	}{
		"unknown capture": {
			SequencePattern{Steps: []SequenceStep{capturing, using("exe", Predicate{Eq: sp("$missing.path")})}},
			[]string{"sequence: steps[1] (PROCESS_START)", "where.exe", "reference $missing.path", `unknown capture "missing"`},
		},
		"capture defined after use": {
			SequencePattern{Steps: []SequenceStep{using("exe", Predicate{Eq: sp("$dropped.path")}), capturing}},
			[]string{"steps[0] (PROCESS_START)", "reference $dropped.path", `capture "dropped" is defined by steps[1], after this step`},
		},
		"capture used by its own step": {
			SequencePattern{Steps: []SequenceStep{{Role: "dropper", Type: core.EventFileCreate, Capture: "f", Where: block(fieldIs("path", Predicate{Eq: sp("$f.old_path")}))}}},
			[]string{"steps[0] (FILE_CREATE)", "reference $f.old_path", "defined by this step"},
		},
		"field not valid for the captured event": {
			SequencePattern{Steps: []SequenceStep{capturing, using("exe", Predicate{Eq: sp("$dropped.domain")})}},
			[]string{"steps[1] (PROCESS_START)", "reference $dropped.domain", `"domain" is not a field of the captured FILE_CREATE event`, "old_path, path"},
		},
		"kind mismatch": {
			SequencePattern{Steps: []SequenceStep{
				{Role: "dropper", Type: core.EventNetworkConnect, Capture: "conn"},
				using("exe", Predicate{Eq: sp("$conn.remote_port")}),
			}},
			[]string{"steps[1] (PROCESS_START)", "reference $conn.remote_port", "a string field cannot be compared with a numeric field"},
		},
		"address against string": {
			SequencePattern{Steps: []SequenceStep{
				{Role: "dropper", Type: core.EventDNSQuery, Capture: "q"},
				{Role: "dropper", Type: core.EventNetworkConnect, Where: block(fieldIs("remote_addr", Predicate{Eq: sp("$q.domain")}))},
			}},
			[]string{"steps[1] (NETWORK_CONNECT)", "reference $q.domain", "a address field cannot be compared with a string field"},
		},
		"duplicate capture name": {
			SequencePattern{Steps: []SequenceStep{capturing, {Role: "dropper", Type: core.EventFileModify, Capture: "dropped"}}},
			[]string{"steps[1]", `capture "dropped" is already defined by steps[0]`},
		},
		"bad capture name": {
			SequencePattern{Steps: []SequenceStep{{Role: "dropper", Type: core.EventFileCreate, Capture: "my-file"}}},
			[]string{"steps[0]", `capture "my-file"`, "letters, digits and underscores"},
		},
		"operator that cannot take a reference": {
			SequencePattern{Steps: []SequenceStep{capturing, using("exe", Predicate{Regex: sp("$dropped.path")})}},
			[]string{"steps[1] (PROCESS_START)", "reference $dropped.path", `"regex" cannot take a captured value`},
		},
		"in with several elements": {
			SequencePattern{Steps: []SequenceStep{capturing, using("exe", Predicate{In: []string{"$dropped.path", "/bin/sh"}})}},
			[]string{"steps[1] (PROCESS_START)", "where.exe", `"in" with a captured value takes exactly one element, got 2`},
		},
		"prefix on numeric reference": {
			SequencePattern{Steps: []SequenceStep{
				{Role: "dropper", Type: core.EventNetworkConnect, Capture: "c"},
				{Role: "dropper", Type: core.EventNetworkConnect, Where: block(fieldIs("remote_port", Predicate{Prefix: sp("$c.remote_port")}))},
			}},
			[]string{"steps[1] (NETWORK_CONNECT)", "reference $c.remote_port", `"prefix" is not valid for a numeric field`},
		},
		"reference inside not is still checked": {
			SequencePattern{Steps: []SequenceStep{capturing, using("exe", Predicate{Not: &Predicate{Eq: sp("$nope.path")}})}},
			[]string{"steps[1] (PROCESS_START)", "not:", `unknown capture "nope"`},
		},
		"unknown role": {
			SequencePattern{Steps: []SequenceStep{step("ghost", core.EventDNSQuery)}},
			[]string{"sequence: steps[0]", `unknown role "ghost"`},
		},
		"step without a type": {
			SequencePattern{Steps: []SequenceStep{{Role: "dropper"}}},
			[]string{"sequence: steps[0]", "type is required"},
		},
		"no steps": {
			SequencePattern{},
			[]string{"sequence: steps", "at least one step"},
		},
		"too many steps": {
			SequencePattern{Steps: make([]SequenceStep, MaxSequenceSteps+1)},
			[]string{"sequence: steps", "at most 8 steps, got 9"},
		},
		"within longer than the window": {
			SequencePattern{Within: DefaultWindow + time.Second, Steps: []SequenceStep{step("dropper", core.EventDNSQuery)}},
			[]string{"sequence: within", "at most the correlation window (5m0s)"},
		},
		"negative tolerance": {
			SequencePattern{OrderTolerance: tolerance(-time.Second), Steps: []SequenceStep{step("dropper", core.EventDNSQuery)}},
			[]string{"sequence: order_tolerance", "between 0 and the correlation window"},
		},
		"unknown field in a step": {
			SequencePattern{Steps: []SequenceStep{{Role: "dropper", Type: core.EventDNSQuery, Where: block(fieldIs("path", Predicate{Eq: sp("x")}))}}},
			[]string{"steps[0] (DNS_QUERY)", "where.path", "unknown field"},
		},
	}

	for name, c := range cases {
		err := pattern(c.sequence).Validate()
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		for _, want := range c.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q does not mention %q", name, err, want)
			}
		}
	}
}

func TestCaptureOperatorsAndKinds(t *testing.T) {
	// One role; step 1 captures a connection, step 2 compares against it.
	sequenceWith := func(first SequenceStep, field string, p Predicate, second core.EventType) []BehaviorPattern {
		first.Capture = "first"
		first.Role = "r"
		return oneRoleSequence(SequencePattern{Steps: []SequenceStep{
			first,
			{Role: "r", Type: second, Where: block(fieldIs(field, p))},
		}})
	}

	type scenario struct {
		name     string
		patterns []BehaviorPattern
		play     func(h *harness, p core.Process)
		want     int
	}

	connectStep := SequenceStep{Type: core.EventNetworkConnect}
	fileStep := SequenceStep{Type: core.EventFileCreate}

	scenarios := []scenario{
		{
			"numeric eq: same port twice",
			sequenceWith(connectStep, "remote_port", Predicate{Eq: sp("$first.remote_port")}, core.EventNetworkConnect),
			func(h *harness, p core.Process) {
				h.connectTo(p, "1.1.1.1", 4444, at(time.Second))
				h.connectTo(p, "2.2.2.2", 4444, at(2*time.Second))
			}, 1,
		},
		{
			"numeric eq: different ports",
			sequenceWith(connectStep, "remote_port", Predicate{Eq: sp("$first.remote_port")}, core.EventNetworkConnect),
			func(h *harness, p core.Process) {
				h.connectTo(p, "1.1.1.1", 4444, at(time.Second))
				h.connectTo(p, "2.2.2.2", 4445, at(2*time.Second))
			}, 0,
		},
		{
			"address in (single element)",
			sequenceWith(connectStep, "remote_addr", Predicate{In: []string{"$first.remote_addr"}}, core.EventNetworkClose),
			func(h *harness, p core.Process) {
				h.connectTo(p, "203.0.113.9", 443, at(time.Second))
				h.clock.set(at(2 * time.Second))
				h.Process(core.Event{Type: core.EventNetworkClose, Timestamp: at(2 * time.Second), Process: &p,
					Network: &core.NetworkConnection{RemoteAddress: "203.0.113.9", RemotePort: 443}})
			}, 1,
		},
		{
			"prefix: a file created under the directory created first",
			sequenceWith(fileStep, "path", Predicate{Prefix: sp("$first.path")}, core.EventFileCreate),
			func(h *harness, p core.Process) {
				h.fileCreate(p, "/tmp/stage", at(time.Second))
				h.fileCreate(p, "/tmp/stage/payload.sh", at(2*time.Second))
			}, 1,
		},
		{
			"suffix nocase",
			sequenceWith(fileStep, "path", Predicate{Suffix: sp("$first.path"), NoCase: true}, core.EventFileCreate),
			func(h *harness, p core.Process) {
				h.fileCreate(p, "run.SH", at(time.Second))
				h.fileCreate(p, "/opt/app/run.sh", at(2*time.Second))
			}, 1,
		},
		{
			"contains",
			sequenceWith(SequenceStep{Type: core.EventDNSQuery}, "cmdline", Predicate{Contains: sp("$first.domain")}, core.EventProcessExit),
			func(h *harness, p core.Process) {
				h.query(p, "example.com", at(time.Second))
				withArgs := p
				withArgs.CommandLine = "curl https://example.com/x"
				h.clock.set(at(2 * time.Second))
				h.Process(core.Event{Type: core.EventProcessExit, Timestamp: at(2 * time.Second), Process: &withArgs})
			}, 1,
		},
		{
			"not: a second connection to a different address",
			sequenceWith(connectStep, "remote_addr", Predicate{Not: &Predicate{Eq: sp("$first.remote_addr")}}, core.EventNetworkConnect),
			func(h *harness, p core.Process) {
				h.connectTo(p, "1.1.1.1", 443, at(time.Second))
				h.connectTo(p, "1.1.1.1", 443, at(2*time.Second))
			}, 0,
		},
		{
			"reference mixed with a literal operator",
			sequenceWith(fileStep, "path", Predicate{Prefix: sp("$first.path"), Suffix: sp(".sh")}, core.EventFileCreate),
			func(h *harness, p core.Process) {
				h.fileCreate(p, "/tmp/stage", at(time.Second))
				h.fileCreate(p, "/tmp/stage/notes.txt", at(2*time.Second))
			}, 0,
		},
	}

	for _, s := range scenarios {
		h := newSequenceHarness(t, s.patterns)
		p := proc(50, 1, "p", at(0))
		h.start(p, at(0))
		s.play(h, p)

		if got := h.detect(at(5 * time.Second)); len(got) != s.want {
			t.Errorf("%s: findings = %d, want %d", s.name, len(got), s.want)
		}
	}
}

// Outside a sequence step a value that looks like a reference is just text.
func TestReferenceSyntaxIsLiteralOutsideSequences(t *testing.T) {
	role := ProcessPattern{ID: "p", Match: block(fieldIs("cmdline", Predicate{Contains: sp("$x.path")}))}

	if !NewMatcher().MatchProcess(role, core.Process{CommandLine: "echo $x.path"}) {
		t.Error("a literal $x.path in a role's match block should match itself")
	}
}

func TestSequenceWorksWithoutAnEngine(t *testing.T) {
	base := at(0)
	p := core.Process{PID: 1, StartTime: base, Name: "p"}
	parent := core.Process{PID: 2, StartTime: base, Name: "parent"}

	chain := NewChain(core.Event{Type: core.EventDNSQuery, Timestamp: base, Process: &p})
	chain.Add(core.Event{Type: core.EventNetworkConnect, Timestamp: base.Add(time.Second), Process: &p})

	pattern := BehaviorPattern{
		Name:          "s",
		Processes:     []ProcessPattern{{ID: "parent"}, {ID: "r"}},
		Relationships: []RelationshipPattern{spawned("parent", "r")},
		Sequence: &SequencePattern{
			OrderTolerance: tolerance(0),
			Steps:          []SequenceStep{step("r", core.EventDNSQuery), step("r", core.EventNetworkConnect)},
		},
	}
	relationships := []ProcessRelationship{NewProcessRelationship(parent, p)}
	chains := map[core.ProcessIdentity][]*Chain{p.Identity(): {chain}}

	matches := NewMatcher().FindMatches(pattern, relationships, chains)
	if len(matches) != 1 || len(matches[0].Events) != 2 {
		t.Fatalf("matches = %+v, want one with its two step events", matches)
	}

	pattern.Sequence.Steps[0], pattern.Sequence.Steps[1] = pattern.Sequence.Steps[1], pattern.Sequence.Steps[0]
	if got := NewMatcher().FindMatches(pattern, relationships, chains); len(got) != 0 {
		t.Fatalf("reversed sequence matched: %+v", got)
	}
}
