package correlation

import (
	"math/rand"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// downloadAndExecute is the guide's three-role example: a launcher starts a
// downloader, which connects out and creates a file, and then starts that
// file. None of the roles says what kind of process it is.
func downloadAndExecute() BehaviorPattern {
	return BehaviorPattern{
		Name:      "download-and-execute",
		Processes: []ProcessPattern{{ID: "launcher"}, {ID: "downloader"}, {ID: "payload"}},
		Relationships: []RelationshipPattern{
			spawned("launcher", "downloader"),
			spawned("launcher", "payload"),
		},
		Sequence: &SequencePattern{
			Within: 20 * time.Second,
			Steps: []SequenceStep{
				{Role: "downloader", Type: core.EventNetworkConnect},
				{Role: "downloader", Type: core.EventFileCreate, Capture: "dropped",
					Where: block(fieldIs("path", Predicate{Prefix: sp("/tmp/")}))},
				{Role: "payload", Type: core.EventProcessStart,
					Where: block(fieldIs("exe", Predicate{Eq: sp("$dropped.path")}))},
			},
		},
	}
}

func (h *harness) send(event core.Event, p core.Process, ts time.Time) {
	h.clock.set(ts)
	event.Timestamp, event.Process = ts, &p
	h.Process(event)
}

// attack plays curl-then-run under launcher, ending at ts. It returns the
// payload's PID.
func (h *harness) attack(launcher core.Process, pid int32, path string, ts time.Time) {
	curl := core.Process{PID: pid, PPID: launcher.PID, Name: "curl", Executable: "/usr/bin/curl", StartTime: ts.Add(-3 * time.Second)}
	payload := core.Process{PID: pid + 1, PPID: launcher.PID, Name: "x", Executable: path, StartTime: ts}

	h.send(core.Event{Type: core.EventProcessStart}, curl, ts.Add(-3*time.Second))
	h.send(core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{RemoteAddress: "203.0.113.9", RemotePort: 80}}, curl, ts.Add(-2*time.Second))
	h.send(core.Event{Type: core.EventFileCreate, File: &core.FileEvent{Path: path, Operation: core.FileCreate}}, curl, ts.Add(-time.Second))
	h.send(core.Event{Type: core.EventProcessStart}, payload, ts)
}

// A role that follows from a sequence step is only filled by a process that
// has had an event the step could be. Nothing else is tried against the
// sequence.
func TestSequenceStepsRuleOutProcessesWithoutTheirEvents(t *testing.T) {
	compiled, err := compilePattern(downloadAndExecute(), testWindow)
	if err != nil {
		t.Fatal(err)
	}

	downloader, payload := &compiled.roles[1], &compiled.roles[2]
	if len(compiled.roles[0].implied) != 0 || len(downloader.implied) != 2 || len(payload.implied) != 1 {
		t.Fatalf("implied requirements: launcher %d, downloader %d, payload %d", len(compiled.roles[0].implied), len(downloader.implied), len(payload.implied))
	}

	// Only the selective types are worth looking candidates up by.
	if len(downloader.needs) != 2 || len(payload.needs) != 0 {
		t.Errorf("needs: downloader %v, payload %v", downloader.needs, payload.needs)
	}

	p := proc(1, 0, "p", at(0))
	connect := core.Event{Type: core.EventNetworkConnect, Process: &p}
	inTmp := core.Event{Type: core.EventFileCreate, Process: &p, File: &core.FileEvent{Path: "/tmp/x"}}
	elsewhere := core.Event{Type: core.EventFileCreate, Process: &p, File: &core.FileEvent{Path: "/home/u/x"}}
	started := core.Event{Type: core.EventProcessStart, Process: &p}

	cases := []struct {
		name   string
		role   *compiledRole
		events []core.Event
		want   bool
	}{
		{"downloader with both events", downloader, []core.Event{connect, inTmp}, true},
		{"downloader that never connected", downloader, []core.Event{inTmp}, false},
		{"downloader that wrote elsewhere", downloader, []core.Event{connect, elsewhere}, false},
		{"downloader with nothing", downloader, []core.Event{started}, false},
		// What the payload must run depends on a capture, so any start
		// could be it; that part is left to the sequence.
		{"payload that started", payload, []core.Event{started}, true},
		{"payload with no start", payload, []core.Event{connect}, false},
	}
	for _, c := range cases {
		if got := c.role.impliedBy(c.events); got != c.want {
			t.Errorf("%s: impliedBy = %v, want %v", c.name, got, c.want)
		}
	}
}

// Process spam must not blind detection. One parent starts tens of thousands
// of short-lived children; the work an event costs must not grow with them,
// and an attack elsewhere on the host must still be found at once.
func TestFanOutDoesNotSlowTheSearch(t *testing.T) {
	const children = 20000

	clock := &fakeClock{t: epoch}
	h := &harness{Engine: NewEngine(testWindow, WithClock(clock.now), WithMaxTombstones(children)), clock: clock}
	h.SetPatterns([]BehaviorPattern{
		downloadAndExecute(),
		{
			Name:          "node-runs-python",
			Processes:     []ProcessPattern{named("parent", "node"), named("child", "python")},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
		},
		{
			Name:          "shell-below-nginx-connects",
			Processes:     []ProcessPattern{named("web", "nginx"), named("shell", "sh", core.EventNetworkConnect)},
			Relationships: []RelationshipPattern{{Type: RelationshipDescendant, Parent: "web", Child: "shell", MaxDepth: 4}},
		},
	})

	spammer := core.Process{PID: 10, PPID: 1, Name: "spam", StartTime: at(0)}
	shell := core.Process{PID: 20, PPID: 1, Name: "sh", StartTime: at(0)}
	h.send(core.Event{Type: core.EventProcessStart}, spammer, at(0))
	h.send(core.Event{Type: core.EventProcessStart}, shell, at(0))
	h.detect(at(0))

	spam := func(i int, ts time.Time) {
		child := core.Process{PID: int32(1000 + i), PPID: spammer.PID, Name: "true", Executable: "/bin/true", StartTime: ts}
		h.send(core.Event{Type: core.EventProcessStart}, child, ts)
		h.detect(ts)
		h.send(core.Event{Type: core.EventProcessExit}, child, ts)
		h.detect(ts)
	}

	ts := at(time.Second)
	for i := 0; i < children; i++ {
		ts = ts.Add(100 * time.Microsecond)
		spam(i, ts)
	}

	// With twenty thousand siblings in place, what does one more cost?
	before := h.Metrics().SearchCandidates
	const more = 1000
	for i := 0; i < more; i++ {
		ts = ts.Add(100 * time.Microsecond)
		spam(children+i, ts)
	}
	perEvent := float64(h.Metrics().SearchCandidates-before) / (2 * more)
	t.Logf("%.1f candidate bindings per event with %d siblings", perEvent, children)
	if perEvent > 40 {
		t.Errorf("an event among %d siblings cost %.0f candidate bindings; the search is walking the siblings", children, perEvent)
	}

	// An attack under another parent, in the middle of the spam.
	ts = ts.Add(4 * time.Second)
	h.attack(shell, 30, "/tmp/x", ts)
	if got := findingKeys(h.detect(ts)); got != "download-and-execute:20>30>31" {
		t.Fatalf("attack beside the spam: findings = %q", got)
	}

	// And the same attack launched by the spamming process itself, so the
	// downloader and the payload are two among its twenty thousand
	// children. It must still be found.
	ts = ts.Add(4 * time.Second)
	before = h.Metrics().SearchCandidates
	h.attack(spammer, 40, "/tmp/y", ts)
	if got := findingKeys(h.detect(ts)); got != "download-and-execute:10>40>41" {
		t.Fatalf("attack from inside the spam: findings = %q", got)
	}
	t.Logf("%d candidate bindings to find an attack launched by the spamming parent", h.Metrics().SearchCandidates-before)
}

// The incremental search must find exactly what a full evaluation finds when
// one parent has a great many children: candidates are then drawn from the
// processes that have had the required events rather than from the parent's
// children, on both paths, and the two must still agree.
func TestIncrementalEvaluationMatchesFullEvaluationUnderFanOut(t *testing.T) {
	patterns := []BehaviorPattern{
		downloadAndExecute(),
		{
			Name:          "spawned-connector",
			Processes:     []ProcessPattern{{ID: "parent"}, {ID: "child", Events: []EventPattern{{Type: core.EventNetworkConnect}}}},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
		},
		{
			Name:      "deep-file-writer",
			Processes: []ProcessPattern{named("top", "spam"), {ID: "writer", Events: []EventPattern{{Type: core.EventFileCreate}}}},
			Relationships: []RelationshipPattern{
				{Type: RelationshipDescendant, Parent: "top", Child: "writer", MaxDepth: 3},
			},
		},
		{
			Name:          "spam-runs-x",
			Processes:     []ProcessPattern{named("parent", "spam"), named("child", "x")},
			Relationships: []RelationshipPattern{spawned("parent", "child")},
		},
	}
	for _, pattern := range patterns {
		if err := pattern.ValidateFor(testWindow); err != nil {
			t.Fatalf("%s: %v", pattern.Name, err)
		}
	}

	// A small tombstone cap keeps the full evaluation affordable while the
	// parent still has hundreds of children at any moment.
	engine := func() *harness {
		clock := &fakeClock{t: epoch}
		h := &harness{Engine: NewEngine(testWindow, WithClock(clock.now), WithMaxTombstones(150)), clock: clock}
		h.SetPatterns(patterns)
		return h
	}
	incremental, full := engine(), engine()

	rng := rand.New(rand.NewSource(11))
	spammer := core.Process{PID: 10, PPID: 1, Name: "spam", StartTime: at(0)}
	shell := core.Process{PID: 20, PPID: 1, Name: "sh", StartTime: at(0)}

	fired := map[string]int{}
	var ts time.Time

	both := func(event core.Event, p core.Process) {
		for _, h := range []*harness{incremental, full} {
			h.send(event, p, ts)
		}

		full.rescan = true
		fullFindings := full.detect(ts)
		for _, f := range fullFindings {
			fired[f.Rule]++
		}

		if got, want := findingKeys(incremental.detect(ts)), findingKeys(fullFindings); got != want {
			t.Fatalf("at %v (%s pid %d): incremental found [%s], full evaluation found [%s]",
				ts.Sub(epoch), event.Type, p.PID, got, want)
		}
	}

	ts = at(0)
	both(core.Event{Type: core.EventProcessStart}, spammer)
	both(core.Event{Type: core.EventProcessStart}, shell)

	nextPID := int32(1000)
	var grandchildren []core.Process

	for step := 0; step < 500; step++ {
		ts = at(time.Duration(step+1) * 20 * time.Millisecond)

		parent := spammer
		if rng.Intn(10) == 0 {
			parent = shell
		}
		// Now and then a child of an earlier child, for the relationship
		// that spans generations.
		if len(grandchildren) > 0 && rng.Intn(15) == 0 {
			parent = grandchildren[rng.Intn(len(grandchildren))]
		}

		nextPID++
		child := core.Process{PID: nextPID, PPID: parent.PID, Name: "true", Executable: "/bin/true", StartTime: ts}

		switch rng.Intn(12) {
		case 0:
			child.Name, child.Executable = "curl", "/usr/bin/curl"
			both(core.Event{Type: core.EventProcessStart}, child)
			both(core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{RemotePort: 80}}, child)
			path := "/tmp/" + string(rune('a'+rng.Intn(3)))
			both(core.Event{Type: core.EventFileCreate, File: &core.FileEvent{Path: path, Operation: core.FileCreate}}, child)
		case 1:
			child.Name = "x"
			child.Executable = "/tmp/" + string(rune('a'+rng.Intn(3)))
			both(core.Event{Type: core.EventProcessStart}, child)
		case 2:
			both(core.Event{Type: core.EventProcessStart}, child)
			both(core.Event{Type: core.EventFileCreate, File: &core.FileEvent{Path: "/var/x", Operation: core.FileCreate}}, child)
			grandchildren = append(grandchildren, child)
			if len(grandchildren) > 8 {
				grandchildren = grandchildren[1:]
			}
		default:
			both(core.Event{Type: core.EventProcessStart}, child)
			both(core.Event{Type: core.EventProcessExit}, child)
		}
	}

	for _, pattern := range patterns {
		if fired[pattern.Name] == 0 {
			t.Errorf("%s never fired; the comparison does not exercise it", pattern.Name)
		}
	}
	if evicted := full.Metrics().TombstonesEvicted; evicted == 0 {
		t.Error("the tombstone cap was never reached; the parent did not have many children at once")
	}
	t.Logf("findings: %v", fired)
}

// When a process with a large subtree gains a parent, everything below it has
// new ancestors. That used to make the next evaluation look at every process.
// The subtree is now marked a bounded amount at a time; it is slower to
// finish, but nothing is skipped.
func TestLargeRelinkIsSpreadOverEvaluations(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "connector-below-nginx",
		Processes: []ProcessPattern{named("web", "nginx"), {ID: "worker", Events: []EventPattern{{Type: core.EventNetworkConnect}}}},
		Relationships: []RelationshipPattern{
			{Type: RelationshipDescendant, Parent: "web", Child: "worker", MaxDepth: 4},
		},
	}})

	// A manager with 1,500 workers, each of which has connected out, is
	// seen before its own parent is.
	manager := core.Process{PID: 50, PPID: 5, Name: "manager", StartTime: at(time.Second)}
	h.send(core.Event{Type: core.EventProcessStart}, manager, at(time.Second))

	const workers = 1500
	for i := 0; i < workers; i++ {
		worker := core.Process{PID: int32(1000 + i), PPID: 50, Name: "worker", StartTime: at(2 * time.Second)}
		h.send(core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{RemotePort: 443}}, worker, at(2*time.Second))
	}
	if got := h.detect(at(2 * time.Second)); len(got) != 0 {
		t.Fatalf("findings before nginx is known: %d", len(got))
	}

	// nginx turns out to be the manager's parent: all 1,500 workers are
	// now below a web server.
	nginx := core.Process{PID: 5, PPID: 1, Name: "nginx", StartTime: at(0)}
	h.send(core.Event{Type: core.EventProcessStart}, nginx, at(3*time.Second))

	found := len(h.detect(at(3 * time.Second)))
	if h.Metrics().FullRescans != 0 {
		t.Fatal("the relink fell back to a full rescan")
	}

	// Later evaluations finish the job without any further event.
	passes := 1
	for h.Metrics().DeferredProcesses > 0 && passes < 100 {
		found += len(h.detect(at(3 * time.Second)))
		passes++
	}
	found += len(h.detect(at(3 * time.Second)))

	metrics := h.Metrics()
	t.Logf("%d findings over %d evaluations; %d ended with work deferred", found, passes, metrics.SearchWorkDeferred)

	// The rule's own rate limit caps how many are reported; what matters
	// is that the search reached the workers at all, and in stages.
	if found == 0 {
		t.Fatal("no worker was found below nginx")
	}
	if metrics.SearchWorkDeferred == 0 || passes < 2 {
		t.Errorf("a %d-process subtree was marked in one evaluation (deferred %d, passes %d)", workers, metrics.SearchWorkDeferred, passes)
	}
	if metrics.DeferredProcesses != 0 {
		t.Errorf("%d processes still waiting", metrics.DeferredProcesses)
	}
}
