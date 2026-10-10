package correlation

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func descendant(parent, child string, maxDepth int) RelationshipPattern {
	return RelationshipPattern{Type: RelationshipDescendant, Parent: parent, Child: child, MaxDepth: maxDepth}
}

// webShellPattern is "a shell somewhere below a web server".
func webShellPattern(maxDepth int) []BehaviorPattern {
	return []BehaviorPattern{{
		Name:          "web-shell",
		Processes:     []ProcessPattern{named("web", "nginx"), named("shell", "sh")},
		Relationships: []RelationshipPattern{descendant("web", "shell", maxDepth)},
	}}
}

// lineage starts a chain of processes, each the child of the one before:
// names[0] is the root. PIDs count up from firstPID.
func (h *harness) lineage(firstPID int32, ts time.Time, names ...string) []core.Process {
	chain := make([]core.Process, len(names))
	for i, name := range names {
		ppid := int32(1)
		if i > 0 {
			ppid = chain[i-1].PID
		}
		chain[i] = proc(firstPID+int32(i), ppid, name, ts.Add(time.Duration(i)*time.Millisecond))
		h.start(chain[i], ts)
	}
	return chain
}

func TestDescendantMatchesAtEveryDepthUpToMax(t *testing.T) {
	const maxDepth = 4

	for depth := 1; depth <= maxDepth+2; depth++ {
		h := newHarness(testWindow)
		h.SetPatterns(webShellPattern(maxDepth))

		// nginx, then depth-1 intermediates, then sh: sh is depth
		// generations below nginx.
		names := []string{"nginx"}
		for i := 1; i < depth; i++ {
			names = append(names, fmt.Sprintf("worker%d", i))
		}
		names = append(names, "sh")
		chain := h.lineage(100, at(time.Second), names...)

		want := 0
		if depth <= maxDepth {
			want = 1
		}

		got := h.detect(at(2 * time.Second))
		if len(got) != want {
			t.Errorf("shell %d generation(s) below, max_depth %d: findings = %d, want %d", depth, maxDepth, len(got), want)
			continue
		}
		if want == 1 {
			bound := got[0].Evidence.Processes
			if bound[0].PID != chain[0].PID || bound[1].PID != chain[len(chain)-1].PID {
				t.Errorf("depth %d: bound %d→%d, want %d→%d", depth, bound[0].PID, bound[1].PID, chain[0].PID, chain[len(chain)-1].PID)
			}
		}
	}
}

func TestDescendantDefaultDepthAndSpawnedEquivalence(t *testing.T) {
	// max_depth left out means DefaultMaxDepth generations.
	for depth, want := range map[int]int{DefaultMaxDepth: 1, DefaultMaxDepth + 1: 0} {
		h := newHarness(testWindow)
		h.SetPatterns(webShellPattern(0))

		names := []string{"nginx"}
		for i := 1; i < depth; i++ {
			names = append(names, "mid")
		}
		h.lineage(100, at(time.Second), append(names, "sh")...)

		if got := h.detect(at(2 * time.Second)); len(got) != want {
			t.Errorf("default depth, shell %d below: findings = %d, want %d", depth, len(got), want)
		}
	}

	// SPAWNED and DESCENDANT with max_depth 1 agree on every shape.
	for _, names := range [][]string{{"nginx", "sh"}, {"nginx", "mid", "sh"}, {"sh", "nginx"}} {
		results := map[string]int{}
		for label, relationship := range map[string]RelationshipPattern{
			"SPAWNED":            spawned("web", "shell"),
			"DESCENDANT depth 1": descendant("web", "shell", 1),
		} {
			h := newHarness(testWindow)
			h.SetPatterns([]BehaviorPattern{{
				Name:          "p",
				Processes:     []ProcessPattern{named("web", "nginx"), named("shell", "sh")},
				Relationships: []RelationshipPattern{relationship},
			}})
			h.lineage(100, at(time.Second), names...)
			results[label] = len(h.detect(at(2 * time.Second)))
		}
		if results["SPAWNED"] != results["DESCENDANT depth 1"] {
			t.Errorf("%v: SPAWNED found %d, DESCENDANT depth 1 found %d", names, results["SPAWNED"], results["DESCENDANT depth 1"])
		}
	}
}

func TestDescendantThroughTombstonedIntermediate(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(webShellPattern(4))

	chain := h.lineage(100, at(time.Second), "nginx", "php-fpm", "sh")
	h.exit(chain[1], at(2*time.Second)) // the intermediate exits

	// While the intermediate's tombstone is retained the chain still holds.
	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("with a tombstoned intermediate: findings = %d, want 1", len(got))
	}

	// One window after it exited it is forgotten, and with it the proof
	// that the shell descends from nginx.
	h.SetPatterns(webShellPattern(4))
	if got := h.detect(at(2*time.Second + testWindow)); len(got) != 0 {
		t.Fatalf("after the intermediate was evicted: findings = %d, want 0", len(got))
	}
}

func TestDescendantDoesNotBridgeAnUnknownIntermediate(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(webShellPattern(4))

	nginx := proc(100, 1, "nginx", at(0))
	shell := proc(300, 200, "sh", at(time.Second)) // parent PID 200 was never seen
	h.start(nginx, at(time.Second))
	h.start(shell, at(time.Second))

	if got := h.detect(at(2 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: nothing proves the shell descends from nginx", len(got))
	}

	// Once the missing link turns up, the chain is complete.
	middle := proc(200, 100, "php-fpm", at(500*time.Millisecond))
	h.connect(middle, at(3*time.Second))

	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("after the intermediate was seen: findings = %d, want 1", len(got))
	}
}

// A PID in the middle of the chain that has been reused does not connect the
// processes above the old holder to the processes below the new one.
func TestDescendantChainBrokenByReusedIntermediatePID(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(webShellPattern(4))

	nginx := proc(100, 1, "nginx", at(0))
	oldMiddle := proc(200, 100, "php-fpm", at(time.Second))
	h.start(nginx, at(time.Second))
	h.start(oldMiddle, at(time.Second))
	h.exit(oldMiddle, at(2*time.Second))

	// PID 200 now belongs to an unrelated process, which spawns a shell.
	newMiddle := proc(200, 1, "cron", at(5*time.Second))
	shell := proc(300, 200, "sh", at(6*time.Second))
	h.start(newMiddle, at(6*time.Second))
	h.start(shell, at(6*time.Second))

	if parent, ok := h.parentOf(shell); !ok || parent.Name != "cron" {
		t.Fatalf("shell's parent = %+v (found=%v), want cron", parent, ok)
	}
	if got := h.detect(at(7 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: the shell's ancestry runs through cron, not nginx", len(got))
	}

	// The same holds when the events arrive in the awkward order: the
	// shell is seen while PID 200 still points at the dead php-fpm.
	h = newHarness(testWindow)
	h.SetPatterns(webShellPattern(4))
	h.start(nginx, at(time.Second))
	h.start(oldMiddle, at(time.Second))
	h.start(shell, at(6*time.Second))
	h.start(newMiddle, at(6*time.Second))
	h.exit(oldMiddle, at(6*time.Second))

	if got := h.detect(at(7 * time.Second)); len(got) != 0 {
		t.Fatalf("out-of-order delivery: findings = %d, want 0", len(got))
	}
}

func TestDescendantRolesStayDistinctAndChainsCompose(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:      "three-deep",
		Processes: []ProcessPattern{named("top", "a"), named("middle", "b"), named("bottom", "b")},
		Relationships: []RelationshipPattern{
			descendant("top", "middle", 3),
			descendant("middle", "bottom", 3),
		},
	}})

	// a → b: one b cannot be both middle and bottom.
	chain := h.lineage(100, at(time.Second), "a", "b")
	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("one process filled two roles: %d finding(s)", len(got))
	}

	// a → b → x → b: now there are two.
	x := proc(110, chain[1].PID, "x", at(2*time.Second))
	bottom := proc(111, 110, "b", at(2*time.Second))
	h.start(x, at(2*time.Second))
	h.start(bottom, at(2*time.Second))

	got := h.detect(at(2 * time.Second))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if bound := got[0].Evidence.Processes; bound[1].PID != chain[1].PID || bound[2].PID != bottom.PID {
		t.Errorf("middle/bottom = %d/%d, want %d/%d", bound[1].PID, bound[2].PID, chain[1].PID, bottom.PID)
	}
}

// Incremental evaluation must find a match whichever end of the relationship
// is the process that changed, and also when the change is to a process in
// between that is bound to no role at all.
func TestDescendantIncrementalEvaluationInBothDirections(t *testing.T) {
	pattern := []BehaviorPattern{{
		Name: "web-shell-connects",
		Processes: []ProcessPattern{
			named("web", "nginx", core.EventNetworkConnect),
			named("shell", "sh", core.EventNetworkConnect),
		},
		Relationships: []RelationshipPattern{descendant("web", "shell", 4)},
	}}

	setup := func() (*harness, []core.Process) {
		h := newHarness(testWindow)
		h.SetPatterns(pattern)
		chain := h.lineage(100, at(time.Second), "nginx", "php-fpm", "worker", "sh")
		if got := h.detect(at(time.Second)); len(got) != 0 {
			t.Fatalf("findings before any connection = %d", len(got))
		}
		return h, chain
	}

	// The descendant changes last: the search walks up from it.
	h, chain := setup()
	h.connect(chain[0], at(2*time.Second))
	if got := h.detect(at(2 * time.Second)); len(got) != 0 {
		t.Fatalf("findings with only the ancestor active = %d", len(got))
	}
	h.connect(chain[3], at(3*time.Second))
	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("descendant changed last: findings = %d, want 1", len(got))
	}

	// The ancestor changes last: the search walks down from it.
	h, chain = setup()
	h.connect(chain[3], at(2*time.Second))
	h.detect(at(2 * time.Second))
	h.connect(chain[0], at(3*time.Second))
	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("ancestor changed last: findings = %d, want 1", len(got))
	}

	// Neither end changes: the link between them is what appears.
	h = newHarness(testWindow)
	h.SetPatterns(pattern)
	nginx := proc(100, 1, "nginx", at(0))
	worker := proc(300, 200, "worker", at(2*time.Second)) // parent 200 not seen yet
	shell := proc(400, 300, "sh", at(3*time.Second))
	for _, p := range []core.Process{nginx, worker, shell} {
		h.start(p, at(4*time.Second))
	}
	h.connect(nginx, at(5*time.Second))
	h.connect(shell, at(5*time.Second))
	if got := h.detect(at(5 * time.Second)); len(got) != 0 {
		t.Fatalf("findings with a gap in the chain = %d", len(got))
	}

	middle := proc(200, 100, "php-fpm", at(time.Second))
	h.start(middle, at(6*time.Second)) // fills the gap; touches neither end
	if got := h.detect(at(6 * time.Second)); len(got) != 1 {
		t.Fatalf("intermediate appeared last: findings = %d, want 1", len(got))
	}
	if h.rescan {
		t.Error("a small subtree should be re-evaluated process by process, not by a full rescan")
	}
}

func TestDescendantWalkIsBoundedAndCounted(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name:          "init-shell",
		Processes:     []ProcessPattern{named("top", "init"), named("shell", "sh")},
		Relationships: []RelationshipPattern{descendant("top", "shell", 2)},
	}})

	// One parent with more children than a single walk visits.
	top := proc(1, 0, "init", at(0))
	children := make([]core.Process, 0, maxDescendantVisits+50)
	for i := 0; i < maxDescendantVisits+50; i++ {
		children = append(children, proc(int32(10+i), 1, "worker", at(time.Second)))
	}
	h.Seed(append([]core.Process{top}, children...))

	if got := h.Metrics().DescendantWalksTruncated; got != 0 {
		t.Fatalf("truncations before any walk = %d", got)
	}

	// Seed asks for everything to be evaluated; that starts from each
	// candidate shell and walks up, which needs no cap.
	h.detect(at(time.Second))
	if got := h.Metrics().DescendantWalksTruncated; got != 0 {
		t.Fatalf("an upward walk was reported as truncated: %d", got)
	}

	// A change to the top process makes the search walk down from it.
	h.connect(top, at(2*time.Second))
	h.detect(at(2 * time.Second))
	if got := h.Metrics().DescendantWalksTruncated; got != 1 {
		t.Fatalf("truncated walks = %d, want 1", got)
	}

	// The cap only limits the downward walk. A shell that changes is still
	// found, by walking up from it.
	shell := proc(99999, children[len(children)-1].PID, "sh", at(3*time.Second))
	h.start(shell, at(3*time.Second))
	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestLargeSubtreeGainingAnAncestorTriggersRescan(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(webShellPattern(3))

	// A parent that is not known yet, with many known children.
	orphans := make([]core.Process, 0, maxSubtreeTouch+10)
	for i := 0; i < maxSubtreeTouch+10; i++ {
		orphans = append(orphans, proc(int32(1000+i), 500, "worker", at(time.Second)))
	}
	middle := proc(600, 500, "mid", at(time.Second))
	shell := proc(601, 600, "sh", at(time.Second))
	h.Seed(append(orphans, middle, shell))
	h.detect(at(time.Second))

	nginx := proc(500, 1, "nginx", at(0))
	h.start(nginx, at(2*time.Second))

	if got := h.detect(at(2 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (nginx → mid → sh)", len(got))
	}
}

func TestDescendantValidation(t *testing.T) {
	roles := []ProcessPattern{{ID: "a"}, {ID: "b"}}

	valid := map[string]RelationshipPattern{
		"default depth": descendant("a", "b", 0),
		"depth 1":       descendant("a", "b", 1),
		"depth limit":   descendant("a", "b", MaxDepthLimit),
		"spawned":       spawned("a", "b"),
	}
	for name, relationship := range valid {
		pattern := BehaviorPattern{Name: "p", Processes: roles, Relationships: []RelationshipPattern{relationship}}
		if err := pattern.Validate(); err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}

	invalid := map[string]struct {
		relationship RelationshipPattern
		want         string
	}{
		"depth too large":       {descendant("a", "b", MaxDepthLimit+1), "relationships[0]: max_depth must be between 1 and 16, got 17"},
		"negative depth":        {descendant("a", "b", -1), "max_depth must be between 1 and 16"},
		"max_depth on SPAWNED":  {RelationshipPattern{Type: RelationshipSpawned, Parent: "a", Child: "b", MaxDepth: 2}, "max_depth applies to DESCENDANT, not SPAWNED"},
		"unknown relationship":  {RelationshipPattern{Type: "ADOPTED", Parent: "a", Child: "b"}, `unknown relationship type "ADOPTED"`},
		"descendant of oneself": {descendant("a", "a", 2), "its own parent"},
	}
	for name, c := range invalid {
		pattern := BehaviorPattern{Name: "p", Processes: roles, Relationships: []RelationshipPattern{c.relationship}}
		err := pattern.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %v, want it to mention %q", name, err, c.want)
		}
	}
}

// Found by the incremental-versus-full comparison: an intermediate whose
// tombstone has expired but has not yet been swept must break the chain
// whichever end the search starts from.
func TestDescendantExpiredIntermediateBreaksChainInBothDirections(t *testing.T) {
	pattern := []BehaviorPattern{{
		Name: "web-shell-connects",
		Processes: []ProcessPattern{
			named("web", "nginx", core.EventNetworkConnect),
			named("shell", "sh", core.EventNetworkConnect),
		},
		Relationships: []RelationshipPattern{descendant("web", "shell", 4)},
	}}

	for _, last := range []string{"ancestor", "descendant"} {
		h := newHarness(testWindow)
		h.SetPatterns(pattern)

		chain := h.lineage(100, at(time.Second), "nginx", "php-fpm", "sh")
		h.exit(chain[1], at(2*time.Second))

		// Evaluate just before the tombstone expires, so the periodic sweep
		// has run and will not run again at the moment it does expire.
		expiry := 2*time.Second + testWindow
		h.detect(at(expiry - time.Second))

		ends := []core.Process{chain[0], chain[2]}
		if last == "ancestor" {
			ends[0], ends[1] = ends[1], ends[0]
		}
		h.connect(ends[0], at(expiry-500*time.Millisecond))
		h.detect(at(expiry - 500*time.Millisecond))
		h.connect(ends[1], at(expiry))

		if _, lingering := h.records[chain[1].Identity()]; !lingering {
			t.Fatalf("%s last: the tombstone was swept; the test no longer covers the unswept case", last)
		}
		if got := h.detect(at(expiry)); len(got) != 0 {
			t.Errorf("%s changed last: findings = %d, want 0 through an expired intermediate", last, len(got))
		}
	}
}
