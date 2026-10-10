package correlation

import (
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func (h *harness) exec(p core.Process, ts time.Time) { h.feed(core.EventProcessExec, p, ts) }

// image returns p running a different program.
func image(p core.Process, name, exe, cmdline string) core.Process {
	p.Name, p.Executable, p.CommandLine = name, exe, cmdline
	return p
}

// An exec changes what a process is, not which process it is: the identity,
// parent and earlier events stay, and roles match the new image.
func TestExecUpdatesTheCurrentImage(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:          "shell-runs-python",
		Processes:     []ProcessPattern{named("parent", "bash"), named("child", "python", core.EventNetworkConnect)},
		Relationships: []RelationshipPattern{spawned("parent", "child")},
	}})

	parent := proc(10, 1, "bash", at(0))
	child := image(proc(20, 10, "bash", at(time.Second)), "bash", "/bin/bash", "bash")

	h.start(parent, at(0))
	h.start(child, at(time.Second))
	h.connect(child, at(2*time.Second))
	if findings := h.detect(at(2 * time.Second)); len(findings) != 0 {
		t.Fatalf("matched while the child was still bash: %s", findingKeys(findings))
	}

	python := image(child, "python", "/usr/bin/python3", "python3 -c pass")
	h.exec(python, at(3*time.Second))

	findings := h.detect(at(3 * time.Second))
	if findingKeys(findings) != "shell-runs-python:10>20" {
		t.Fatalf("after exec: findings = %q, want the child matched as python", findingKeys(findings))
	}

	// The connection made before the exec belongs to the same process.
	evidence := findings[0].Evidence
	if got := evidence.Roles["child"]; got.Name != "python" || got.Executable != "/usr/bin/python3" || got.CommandLine != "python3 -c pass" {
		t.Errorf("child role shows %+v, want the current image", got)
	}
	if got := evidence.Roles["child"].Identity(); got != child.Identity() {
		t.Errorf("exec changed the identity to %+v", got)
	}
	if parentOf, ok := h.parentOf(child); !ok || parentOf.PID != 10 {
		t.Errorf("exec lost the parent link: %+v %v", parentOf, ok)
	}

	want := []core.ProcessImage{{Name: "bash", Executable: "/bin/bash", CommandLine: "bash", ReplacedAt: at(3 * time.Second)}}
	if got := evidence.PreviousImages["child"]; !reflect.DeepEqual(got, want) {
		t.Errorf("previous images = %+v, want %+v", got, want)
	}
	if _, has := evidence.PreviousImages["parent"]; has {
		t.Error("a process that never exec'd has previous images")
	}
}

// A role stops matching a process once it has become something else.
func TestExecStopsTheOldImageMatching(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "curl-connects",
		Processes: []ProcessPattern{named("p", "curl", core.EventNetworkConnect)},
	}})

	p := proc(30, 1, "curl", at(0))
	h.start(p, at(0))
	h.exec(image(p, "sleep", "/bin/sleep", "sleep 60"), at(time.Second))
	h.connect(p, at(2*time.Second))

	if findings := h.detect(at(2 * time.Second)); len(findings) != 0 {
		t.Fatalf("matched a process that is no longer curl: %s", findingKeys(findings))
	}
}

func TestExecHistoryIsBounded(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "final-image",
		Processes: []ProcessPattern{named("p", "stage7")},
	}})

	p := proc(40, 1, "stage0", at(0))
	h.start(p, at(0))
	for i := 1; i <= 7; i++ {
		h.exec(image(p, "stage"+string(rune('0'+i)), "", ""), at(time.Duration(i)*time.Second))
	}
	// Repeating the current image, or an exec that says nothing, adds no
	// history.
	h.exec(image(p, "stage7", "", ""), at(8*time.Second))
	h.exec(image(p, "", "", ""), at(8*time.Second))

	findings := h.detect(at(8 * time.Second))
	if len(findings) != 1 {
		t.Fatalf("findings = %q", findingKeys(findings))
	}

	previous := findings[0].Evidence.PreviousImages["p"]
	if len(previous) != MaxPreviousImages {
		t.Fatalf("kept %d previous images, want %d", len(previous), MaxPreviousImages)
	}
	for i, want := range []string{"stage3", "stage4", "stage5", "stage6"} {
		if previous[i].Name != want {
			t.Errorf("previous[%d] = %q, want %q (most recent kept, oldest first)", i, previous[i].Name, want)
		}
	}
}

// PROCESS_EXEC is an event like any other: it can be required, filtered with
// where, and be a sequence step, with the fields of PROCESS_START.
func TestExecEventInRequirementsAndSequences(t *testing.T) {
	h := newHarness(testWindow)
	patterns := []BehaviorPattern{
		{
			Name: "execs-from-tmp",
			Processes: []ProcessPattern{{ID: "p", Events: []EventPattern{{
				Type:  core.EventProcessExec,
				Where: block(fieldIs("exe", Predicate{Prefix: sp("/tmp/")})),
			}}}},
		},
		{
			Name:      "drop-then-exec",
			Processes: []ProcessPattern{{ID: "p"}},
			Sequence: &SequencePattern{Steps: []SequenceStep{
				{Role: "p", Type: core.EventFileCreate, Capture: "dropped"},
				{Role: "p", Type: core.EventProcessExec, Where: block(fieldIs("exe", Predicate{Eq: sp("$dropped.path")}))},
			}},
		},
	}
	for _, pattern := range patterns {
		if err := pattern.ValidateFor(testWindow); err != nil {
			t.Fatalf("%s: %v", pattern.Name, err)
		}
	}
	h.SetPatterns(patterns)

	p := image(proc(50, 1, "sh", at(0)), "sh", "/bin/sh", "sh")
	h.start(p, at(0))

	h.clock.set(at(time.Second))
	created := p
	h.Process(core.Event{Type: core.EventFileCreate, Timestamp: at(time.Second), Process: &created, File: &core.FileEvent{Path: "/tmp/x", Operation: core.FileCreate}})

	h.exec(image(p, "ls", "/bin/ls", "ls"), at(2*time.Second))
	if findings := h.detect(at(2 * time.Second)); len(findings) != 0 {
		t.Fatalf("an exec of /bin/ls matched: %s", findingKeys(findings))
	}

	h.exec(image(p, "x", "/tmp/x", "/tmp/x"), at(3*time.Second))
	if got := findingKeys(h.detect(at(3 * time.Second))); got != "drop-then-exec:50 execs-from-tmp:50" {
		t.Fatalf("findings = %q, want both exec rules", got)
	}
}

// A backend that never reports PROCESS_EXEC (polling) must see exactly what it
// saw before: later events carrying a different image do not rewrite the
// process, and no finding has previous images.
func TestWithoutExecEventsTheImageIsFixed(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "bash-connects",
		Processes: []ProcessPattern{named("p", "bash", core.EventNetworkConnect)},
	}})

	p := proc(60, 1, "bash", at(0))
	h.start(p, at(0))
	// The same identity reported under another name by a later event.
	h.connect(image(p, "python", "/usr/bin/python3", "python3"), at(time.Second))

	findings := h.detect(at(time.Second))
	if findingKeys(findings) != "bash-connects:60" {
		t.Fatalf("findings = %q, want the process still matched as bash", findingKeys(findings))
	}
	if findings[0].Evidence.PreviousImages != nil {
		t.Errorf("previous images without an exec: %+v", findings[0].Evidence.PreviousImages)
	}
}

// Incremental evaluation must agree with evaluating everything when processes
// change image under the rules, as it does for every other kind of change.
func TestIncrementalEvaluationMatchesFullEvaluationWithExec(t *testing.T) {
	patterns := []BehaviorPattern{
		{
			Name:          "a-spawns-b",
			Processes:     []ProcessPattern{named("parent", "a"), named("child", "b")},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
		},
		{
			Name:          "a-above-c-connecting",
			Processes:     []ProcessPattern{named("top", "a"), named("bottom", "c", core.EventNetworkConnect)},
			Relationships: []RelationshipPattern{{Type: RelationshipDescendant, Parent: "top", Child: "bottom", MaxDepth: 3}},
		},
		{
			Name:      "became-c",
			Processes: []ProcessPattern{{ID: "p", Events: []EventPattern{{Type: core.EventProcessExec, Where: block(fieldIs("name", Predicate{Eq: sp("c")}))}}}},
		},
		{
			Name:      "connect-then-exec",
			Processes: []ProcessPattern{named("p", "b")},
			Sequence: &SequencePattern{OrderTolerance: tolerance(0), Steps: []SequenceStep{
				{Role: "p", Type: core.EventNetworkConnect},
				{Role: "p", Type: core.EventProcessExec},
			}},
		},
	}
	for _, pattern := range patterns {
		if err := pattern.ValidateFor(testWindow); err != nil {
			t.Fatalf("%s: %v", pattern.Name, err)
		}
	}

	incremental, full := newHarness(testWindow), newHarness(testWindow)
	incremental.SetPatterns(patterns)
	full.SetPatterns(patterns)

	rng := rand.New(rand.NewSource(7))
	names := []string{"a", "b", "c", "d"}
	eventTypes := []core.EventType{
		core.EventProcessStart, core.EventProcessExec, core.EventProcessExec,
		core.EventNetworkConnect, core.EventProcessExit,
	}

	var live []core.Process
	fired := map[string]int{}

	for step := 0; step < 4000; step++ {
		ts := at(time.Duration(step) * 250 * time.Millisecond)

		var p core.Process
		index := -1
		if len(live) == 0 || rng.Intn(4) == 0 {
			p = proc(int32(1+rng.Intn(40)), int32(1+rng.Intn(40)), names[rng.Intn(len(names))], ts)
			live = append(live, p)
			index = len(live) - 1
		} else {
			index = rng.Intn(len(live))
			p = live[index]
		}

		eventType := eventTypes[rng.Intn(len(eventTypes))]
		if eventType == core.EventProcessExec {
			p.Name = names[rng.Intn(len(names))]
			live[index] = p
		}

		for _, h := range []*harness{incremental, full} {
			subject := p
			h.clock.set(ts)
			h.Process(core.Event{Type: eventType, Timestamp: ts, Process: &subject})
		}

		full.rescan = true
		fullFindings := full.detect(ts)
		for _, f := range fullFindings {
			fired[f.Rule]++
		}

		got, want := findingKeys(incremental.detect(ts)), findingKeys(fullFindings)
		if got != want {
			t.Fatalf("step %d (%s pid %d as %q): incremental found [%s], full evaluation found [%s]",
				step, eventType, p.PID, p.Name, got, want)
		}
	}

	for _, pattern := range patterns {
		if fired[pattern.Name] == 0 {
			t.Errorf("%s never fired; the comparison does not exercise it", pattern.Name)
		}
	}
}

// Exited processes are remembered for a window, but only so many at once.
// Beyond the cap the oldest are forgotten early, and counted.
func TestTombstonesAreCapped(t *testing.T) {
	clock := &fakeClock{t: epoch}
	h := &harness{Engine: NewEngine(testWindow, WithClock(clock.now), WithMaxTombstones(3)), clock: clock}
	h.SetPatterns([]BehaviorPattern{{
		Name:          "a-spawned-b",
		Processes:     []ProcessPattern{named("parent", "a"), named("child", "b")},
		Relationships: []RelationshipPattern{spawned("parent", "child")},
	}})

	// A long-lived parent, and five children that each exit at once.
	parent := proc(1, 0, "a", at(0))
	h.start(parent, at(0))
	h.detect(at(0))

	for i := int32(0); i < 5; i++ {
		child := proc(100+i, 1, "c", at(time.Duration(i+1)*time.Second))
		h.start(child, at(time.Duration(i+1)*time.Second))
		h.exit(child, at(time.Duration(i+1)*time.Second))
	}

	metrics := h.Metrics()
	if metrics.Tombstones != 3 || metrics.TombstonesEvicted != 2 {
		t.Fatalf("tombstones %d, evicted %d; want 3 kept and 2 forgotten", metrics.Tombstones, metrics.TombstonesEvicted)
	}
	if metrics.Processes != 4 {
		t.Fatalf("engine knows %d processes, want the parent and three tombstones", metrics.Processes)
	}

	// The oldest were the ones forgotten; the newest are still known.
	if h.ChainsForProcess(proc(100, 1, "c", at(time.Second)).Identity()) != nil {
		t.Error("the first process to exit is still remembered")
	}
	if h.ChainsForProcess(proc(104, 1, "c", at(5*time.Second)).Identity()) == nil {
		t.Error("the last process to exit was forgotten")
	}

	// A running process is never forgotten, however many exit after it, and
	// still matches.
	h.start(proc(200, 1, "b", at(6*time.Second)), at(6*time.Second))
	if got := findingKeys(h.detect(at(6 * time.Second))); got != "a-spawned-b:1>200" {
		t.Fatalf("findings = %q", got)
	}

	// The window still removes tombstones, and the count follows.
	h.detect(at(6*time.Second + 2*testWindow))
	h.start(proc(300, 1, "c", at(6*time.Second+2*testWindow)), at(6*time.Second+2*testWindow))
	h.sweep(at(6*time.Second + 2*testWindow))
	if got := h.Metrics().Tombstones; got != 0 {
		t.Errorf("%d tombstones after the window passed, want 0", got)
	}
}

// Below the cap nothing changes: every exited process is kept for the window.
func TestTombstoneCapDoesNotApplyBelowIt(t *testing.T) {
	h := newHarness(testWindow)

	for i := int32(0); i < 500; i++ {
		p := proc(1000+i, 1, "c", at(time.Duration(i)*time.Millisecond))
		h.start(p, at(time.Duration(i)*time.Millisecond))
		h.exit(p, at(time.Duration(i)*time.Millisecond))
		// A second exit for the same process is not a second tombstone.
		h.exit(p, at(time.Duration(i)*time.Millisecond))
	}

	metrics := h.Metrics()
	if metrics.Tombstones != 500 || metrics.TombstonesEvicted != 0 || metrics.Processes != 500 {
		t.Fatalf("metrics = %+v", metrics)
	}
}
