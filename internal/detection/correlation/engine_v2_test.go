package correlation

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// connectTo delivers a NETWORK_CONNECT with connection details.
func (h *harness) connectTo(p core.Process, addr string, port uint32, ts time.Time) {
	h.clock.set(ts)
	h.Process(core.Event{
		Type:      core.EventNetworkConnect,
		Timestamp: ts,
		Process:   &p,
		Network:   &core.NetworkConnection{RemoteAddress: addr, RemotePort: port, Protocol: "tcp"},
	})
}

func (h *harness) query(p core.Process, domain string, ts time.Time) {
	h.clock.set(ts)
	h.Process(core.Event{
		Type:      core.EventDNSQuery,
		Timestamp: ts,
		Process:   &p,
		DNS:       &core.DNSQuery{Domain: domain, Type: "A"},
	})
}

func block(fields ...FieldPredicate) *MatchBlock { return &MatchBlock{Fields: fields} }

// --- Step 0: process identity -------------------------------------------

// An event can arrive with a PID but no start time, when the OS would not
// say at that moment. It is about the process holding that PID and must be
// correlated with it, not filed under a separate identity.
func TestEventWithoutStartTimeIsAttributedToKnownProcess(t *testing.T) {
	for name, partialStart := range map[string]time.Time{
		"unix epoch, as collectors report a failed read": time.UnixMilli(0),
		"zero time, as a constructed process has":        {},
	} {
		h := newHarness(testWindow)
		parent, child := h.defaultPair()
		h.connect(parent, at(time.Second))

		// The child's network event carries only its PID.
		partial := core.Process{PID: child.PID, StartTime: partialStart}
		h.connect(partial, at(2*time.Second))

		if got := h.detect(at(3 * time.Second)); len(got) != 1 {
			t.Errorf("%s: findings = %d, want 1 (the event belongs to the known child)", name, len(got))
			continue
		}

		if n := len(h.records); n != 2 {
			t.Errorf("%s: %d process records, want 2 (no phantom process)", name, n)
		}
		events := h.chains[child.Identity()][0].Events()
		if last := events[len(events)-1]; last.Type != core.EventNetworkConnect || last.Process.Identity() != child.Identity() {
			t.Errorf("%s: event not stored under the child's identity: %+v", name, last.Process)
		}
		if _, phantom := h.chains[partial.Identity()]; phantom {
			t.Errorf("%s: events stored under an identity with no start time", name)
		}
	}
}

func TestExitWithoutStartTimeEndsTheKnownProcess(t *testing.T) {
	h := newHarness(testWindow)
	parent, _ := h.defaultPair()

	h.exit(core.Process{PID: parent.PID, StartTime: time.UnixMilli(0)}, at(time.Second))

	if h.records[parent.Identity()].exitedAt.IsZero() {
		t.Fatal("exit event without a start time did not mark the known process as exited")
	}
}

// When the first sight of a process lacks a start time, the first full
// description takes over the PID, and later partial events resolve to it.
func TestFullDescriptionReplacesPartialOne(t *testing.T) {
	h := newHarness(testWindow)
	parent := proc(100, 1, "node", at(-time.Hour))
	child := proc(200, 100, "python", at(0))
	partialChild := core.Process{PID: 200, PPID: 100, StartTime: time.UnixMilli(0)}

	h.start(parent, at(0))
	h.connect(parent, at(time.Second))
	h.connect(partialChild, at(2*time.Second)) // first sight of PID 200
	h.start(child, at(3*time.Second))          // now fully described
	h.connect(partialChild, at(4*time.Second)) // resolves to the real child

	if holder := h.pids[200]; holder != child.Identity() {
		t.Fatalf("PID 200 is held by %+v, want the fully described process", holder)
	}
	if got := h.detect(at(5 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestUnknownProcessWithoutStartTimeIsKeptAsIs(t *testing.T) {
	h := newHarness(testWindow)
	stranger := core.Process{PID: 999, Name: "mystery", StartTime: time.UnixMilli(0)}

	h.connect(stranger, at(time.Second))

	if _, ok := h.records[stranger.Identity()]; !ok {
		t.Fatal("a process with no start time and no known holder should still be recorded")
	}
}

// --- Step 1: predicates in the engine -----------------------------------

func TestDefaultPatternMatchesVersionedPythonNames(t *testing.T) {
	for name, want := range map[string]int{
		"python": 1, "python3": 1, "python3.12": 1, "python2.7": 1,
		"pythonw": 0, "ipython": 0, "bash": 0,
	} {
		h := newHarness(testWindow)
		parent := proc(100, 1, "node", at(-time.Hour))
		child := proc(200, 100, name, at(0))
		h.start(parent, at(0))
		h.start(child, at(0))
		h.connect(parent, at(time.Second))
		h.connect(child, at(2*time.Second))

		if got := h.detect(at(3 * time.Second)); len(got) != want {
			t.Errorf("child named %q: findings = %d, want %d", name, len(got), want)
		}
	}
}

func TestConditionsAndMatchBlockAreBothRequired(t *testing.T) {
	role := ProcessPattern{
		ID:         "p",
		Conditions: []Condition{{Type: ConditionProcessUser, Value: "www-data"}},
		Match:      block(fieldIs("name", Predicate{Prefix: sp("py")})),
	}

	for _, c := range []struct {
		process core.Process
		want    bool
	}{
		{core.Process{Name: "python", User: "www-data"}, true},
		{core.Process{Name: "python", User: "root"}, false},
		{core.Process{Name: "bash", User: "www-data"}, false},
	} {
		if got := NewMatcher().MatchProcess(role, c.process); got != c.want {
			t.Errorf("%s/%s: matched = %v, want %v", c.process.Name, c.process.User, got, c.want)
		}
	}
}

func TestEventWhereNeedsOneMatchingEvent(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name: "odd-port",
		Processes: []ProcessPattern{{
			ID: "p",
			Events: []EventPattern{{
				Type: core.EventNetworkConnect,
				Where: block(
					fieldIs("remote_port", Predicate{Not: &Predicate{In: []string{"80", "443", "53"}}}),
					fieldIs("remote_addr", Predicate{Not: &Predicate{CIDR: []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128"}}}),
				),
			}},
		}},
	}})

	p := proc(50, 1, "curl", at(0))
	h.start(p, at(0))

	// Events of the right type that fail the filter do not count...
	h.connectTo(p, "93.184.216.34", 443, at(1*time.Second)) // allowed port
	h.connectTo(p, "10.1.2.3", 4444, at(2*time.Second))     // private address
	h.connectTo(p, "::1", 9000, at(3*time.Second))          // loopback
	if got := h.detect(at(4 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: no single event passes the whole filter", len(got))
	}

	// ...nor does an event with no connection details pass a filter by
	// default, although the not: operators are true for missing values.
	// One event passing every field is what is needed.
	h.connectTo(p, "203.0.113.9", 4444, at(5*time.Second))
	if got := h.detect(at(6 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestEventRequirementsAreIndependent(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name: "lookup-and-odd-port",
		Processes: []ProcessPattern{{
			ID: "p",
			Events: []EventPattern{
				{Type: core.EventDNSQuery, Where: block(fieldIs("domain", Predicate{Regex: sp(`\.(ru|top)$`)}))},
				{Type: core.EventNetworkConnect, Where: block(fieldIs("remote_port", Predicate{Gt: sp("1024")}))},
				{Type: core.EventNetworkConnect}, // any connection at all
			},
		}},
	}})

	p := proc(50, 1, "python", at(0))
	h.start(p, at(0))
	h.query(p, "example.com", at(time.Second))
	h.connectTo(p, "1.1.1.1", 443, at(2*time.Second))
	if got := h.detect(at(3 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}

	h.query(p, "c2.evil.top", at(4*time.Second))
	if got := h.detect(at(4 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0 (no high-port connection yet)", len(got))
	}

	h.connectTo(p, "1.1.1.1", 8443, at(5*time.Second))
	if got := h.detect(at(5 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestFilteredEventStillObeysTheWindow(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name: "odd-port",
		Processes: []ProcessPattern{{
			ID:     "p",
			Events: []EventPattern{{Type: core.EventNetworkConnect, Where: block(fieldIs("remote_port", Predicate{Eq: sp("4444")}))}},
		}},
	}})

	p := proc(50, 1, "nc", at(0))
	h.start(p, at(0))
	h.connectTo(p, "203.0.113.9", 4444, at(time.Second))
	h.SetPatterns(h.patternsForTest()) // evaluate from scratch below

	if got := h.detect(at(time.Second + testWindow)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: the matching event has left the window", len(got))
	}
}

// patternsForTest returns the patterns currently loaded.
func (h *harness) patternsForTest() []BehaviorPattern {
	patterns := make([]BehaviorPattern, len(h.patterns))
	for i, compiled := range h.patterns {
		patterns[i] = compiled.BehaviorPattern
	}
	return patterns
}

func TestPatternValidationNamesRoleAndField(t *testing.T) {
	base := func(role ProcessPattern) BehaviorPattern {
		return BehaviorPattern{Name: "p", Processes: []ProcessPattern{role}}
	}

	cases := map[string]struct {
		pattern BehaviorPattern
		want    []string
	}{
		"unknown process field": {
			base(ProcessPattern{ID: "child", Match: block(fieldIs("colour", Predicate{Eq: sp("x")}))}),
			[]string{`role "child"`, "match.colour", "unknown field"},
		},
		"operator wrong for field": {
			base(ProcessPattern{ID: "child", Match: block(fieldIs("name", Predicate{CIDR: []string{"10.0.0.0/8"}}))}),
			[]string{`role "child"`, "match.name", `"cidr" is not valid for a string field`},
		},
		"bad regex": {
			base(ProcessPattern{ID: "child", Match: block(fieldIs("cmdline", Predicate{Regex: sp("(")}))}),
			[]string{`role "child"`, "match.cmdline", "bad regex"},
		},
		"where field wrong for event type": {
			base(ProcessPattern{ID: "child", Events: []EventPattern{
				{Type: core.EventProcessStart},
				{Type: core.EventDNSQuery, Where: block(fieldIs("remote_port", Predicate{Eq: sp("53")}))},
			}}),
			[]string{`role "child"`, "events[1] (DNS_QUERY)", "where.remote_port", "unknown field"},
		},
		"numeric operator on a path": {
			base(ProcessPattern{ID: "w", Events: []EventPattern{{Type: core.EventFileCreate, Where: block(fieldIs("path", Predicate{Gt: sp("1")}))}}}),
			[]string{`role "w"`, "events[0] (FILE_CREATE)", "where.path", `"gt" is not valid`},
		},
		"empty in list": {
			base(ProcessPattern{ID: "c", Events: []EventPattern{{Type: core.EventNetworkConnect, Where: block(fieldIs("remote_port", Predicate{In: []string{}}))}}}),
			[]string{`role "c"`, "where.remote_port", `"in" needs at least one value`},
		},
		"exclude names an unknown role": {
			BehaviorPattern{Name: "p", Processes: []ProcessPattern{{ID: "a"}}, Exclude: []RoleExclusion{{Role: "ghost", Match: block(fieldIs("name", Predicate{Eq: sp("x")}))}}},
			[]string{"exclude[0]", `unknown role "ghost"`},
		},
		"exclude with a bad match": {
			BehaviorPattern{Name: "p", Processes: []ProcessPattern{{ID: "a"}}, Exclude: []RoleExclusion{{Role: "a", Match: block(fieldIs("exe", Predicate{Glob: sp("[")}))}}},
			[]string{"exclude[0]", `role "a"`, "match.exe", "bad glob"},
		},
		"exclude with nothing to match": {
			BehaviorPattern{Name: "p", Processes: []ProcessPattern{{ID: "a"}}, Exclude: []RoleExclusion{{Role: "a"}}},
			[]string{"exclude[0]", `role "a"`, "must say which processes"},
		},
		"negative rate limit": {
			BehaviorPattern{Name: "p", Processes: []ProcessPattern{{ID: "a"}}, MaxFindingsPerWindow: -1},
			[]string{"max_findings_per_window", "must not be negative"},
		},
	}

	for name, c := range cases {
		err := c.pattern.Validate()
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

// --- Step 2: exclusions, rate limit, drafts -----------------------------

func TestPerPatternExcludeBarsProcessFromRole(t *testing.T) {
	pattern := BehaviorPattern{
		Name:          "spawned-shell",
		Processes:     []ProcessPattern{{ID: "parent"}, named("child", "bash")},
		Relationships: []RelationshipPattern{spawned("parent", "child")},
		Exclude: []RoleExclusion{
			{Role: "parent", Match: block(fieldIs("name", Predicate{In: []string{"sshd", "tmux"}}))},
		},
	}
	if err := pattern.Validate(); err != nil {
		t.Fatal(err)
	}

	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{pattern})

	sshd := proc(10, 1, "sshd", at(0))
	nginx := proc(20, 1, "nginx", at(0))
	h.start(sshd, at(0))
	h.start(nginx, at(0))
	h.start(proc(11, 10, "bash", at(time.Second)), at(time.Second))

	if got := h.detect(at(time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: sshd may not fill the parent role", len(got))
	}

	// The exclusion is about the parent role only: bash spawned by nginx is
	// reported, and a bash is free to be a parent itself.
	h.start(proc(21, 20, "bash", at(2*time.Second)), at(2*time.Second))
	got := h.detect(at(2 * time.Second))
	if len(got) != 1 || got[0].Evidence.Processes[0].Name != "nginx" {
		t.Fatalf("findings = %+v, want one with nginx as the parent", got)
	}

	// Exclusions inside a pattern are not counted as dropped findings: no
	// finding was ever formed.
	if counts := h.ExcludedFindings(); len(counts) != 0 {
		t.Errorf("per-pattern exclude counted as dropped findings: %v", counts)
	}
}

func TestGlobalExclusionDropsFindingAndCounts(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(append(DefaultPatterns(), BehaviorPattern{
		Name:      "any-python",
		Processes: []ProcessPattern{named("p", "python")},
	}))

	err := h.SetExclusions([]Exclusion{
		{Rules: []string{"network-active-parent-spawns-python"}, Match: block(fieldIs("user", Predicate{Eq: sp("deploy")})), Description: "deploy tooling"},
		{Rules: []string{"*"}, Match: block(fieldIs("exe", Predicate{Prefix: sp("/opt/trusted/")}))},
	})
	if err != nil {
		t.Fatal(err)
	}

	pair := func(pid int32, user, exe string) (core.Process, core.Process) {
		parent := core.Process{PID: pid, PPID: 1, Name: "node", User: user, StartTime: at(0)}
		child := core.Process{PID: pid + 1, PPID: pid, Name: "python", User: "app", Executable: exe, StartTime: at(0)}
		h.start(parent, at(time.Second))
		h.start(child, at(time.Second))
		h.connect(parent, at(2*time.Second))
		h.connect(child, at(2*time.Second))
		return parent, child
	}

	pair(100, "deploy", "/usr/bin/python")  // rule-specific exclusion on the parent
	pair(200, "app", "/opt/trusted/python") // wildcard exclusion on the child
	_, reported := pair(300, "app", "/usr/bin/python")

	rules := map[string][]int32{}
	for _, f := range h.detect(at(3 * time.Second)) {
		rules[f.Rule] = append(rules[f.Rule], f.Evidence.Process.PID)
	}

	// The rule-specific exclusion does not apply to the other rule, so the
	// deploy pair's python is still reported by any-python. The wildcard
	// one applies to both.
	if got := fmt.Sprint(rules["network-active-parent-spawns-python"]); got != fmt.Sprint([]int32{reported.PID}) {
		t.Errorf("spawn rule reported children %s, want only %d", got, reported.PID)
	}
	if got := fmt.Sprint(rules["any-python"]); got != fmt.Sprint([]int32{101, 301}) {
		t.Errorf("any-python reported %s, want [101 301]", got)
	}

	counts := h.ExcludedFindings()
	if counts["network-active-parent-spawns-python"] != 2 || counts["any-python"] != 1 {
		t.Errorf("excluded counts = %v, want spawn rule 2 and any-python 1", counts)
	}

	// Re-evaluating does not count the same incidents again.
	h.SetPatterns(h.patternsForTest())
	h.detect(at(4 * time.Second))
	if again := h.ExcludedFindings(); again["network-active-parent-spawns-python"] != 4 {
		// SetPatterns clears suppression, so the two incidents are seen
		// afresh exactly once more.
		t.Errorf("after a reset, excluded count = %d, want 4", again["network-active-parent-spawns-python"])
	}
	for i := 0; i < 5; i++ {
		h.detect(at(5*time.Second + time.Duration(i)*time.Second))
	}
	if again := h.ExcludedFindings(); again["network-active-parent-spawns-python"] != 4 {
		t.Errorf("repeated evaluation recounted excluded findings: %d", again["network-active-parent-spawns-python"])
	}
}

func TestSetExclusionsReportsInvalidOnesAndKeepsTheRest(t *testing.T) {
	h := newHarness(testWindow)

	err := h.SetExclusions([]Exclusion{
		{Rules: []string{"*"}, Match: block(fieldIs("name", Predicate{Regex: sp("(")}))},
		{Rules: []string{"*"}, Match: block(fieldIs("name", Predicate{Eq: sp("python")}))},
		{Match: block(fieldIs("name", Predicate{Eq: sp("x")}))},
		{Rules: []string{"*"}},
	})
	if err == nil || !strings.Contains(err.Error(), "exclusions[0]") || !strings.Contains(err.Error(), "match.name") {
		t.Fatalf("error = %v, want it to name exclusions[0] and match.name", err)
	}
	if len(h.exclusions) != 1 {
		t.Fatalf("%d exclusions applied, want the 1 valid one", len(h.exclusions))
	}

	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(time.Second))
	if got := h.detect(at(2 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: the valid exclusion applies", len(got))
	}
}

// spawnPairs creates n distinct node→python pairs that each match the
// default pattern at ts.
func (h *harness) spawnPairs(firstPID int32, n int, ts time.Time) {
	for i := int32(0); i < int32(n); i++ {
		parent := proc(firstPID+2*i, 1, "node", ts.Add(-time.Minute))
		child := proc(firstPID+2*i+1, firstPID+2*i, "python", ts)
		h.start(parent, ts)
		h.start(child, ts)
		h.connect(parent, ts)
		h.connect(child, ts)
	}
}

func TestRateLimitHoldsBackAndSummarises(t *testing.T) {
	h := newHarness(testWindow)
	pattern := DefaultPatterns()[0]
	pattern.MaxFindingsPerWindow = 3
	h.SetPatterns([]BehaviorPattern{pattern})

	h.spawnPairs(1000, 5, at(time.Second))
	if got := h.detect(at(time.Second)); len(got) != 3 {
		t.Fatalf("first burst: findings = %d, want the limit of 3", len(got))
	}

	// More incidents in the same window are held back too.
	h.spawnPairs(2000, 4, at(10*time.Second))
	if got := h.detect(at(10 * time.Second)); len(got) != 0 {
		t.Fatalf("second burst: findings = %d, want 0", len(got))
	}

	// Nothing is reported until the rule's window, which began with its
	// first finding, rolls over.
	if got := h.detect(at(time.Second + testWindow - time.Millisecond)); len(got) != 0 {
		t.Fatalf("before rollover: findings = %d, want 0", len(got))
	}

	got := h.detect(at(time.Second + testWindow))
	if len(got) != 1 {
		t.Fatalf("at rollover: findings = %d, want the one summary", len(got))
	}
	summary := got[0]
	if summary.Severity != core.SeverityInfo || summary.Rule != pattern.Name {
		t.Errorf("summary = %s/%s, want INFO for rule %s", summary.Severity, summary.Rule, pattern.Name)
	}
	if want := "rule network-active-parent-spawns-python: 6 additional findings suppressed"; summary.Description != want {
		t.Errorf("summary description = %q, want %q", summary.Description, want)
	}
	if !strings.HasPrefix(summary.ID, "finding-") {
		t.Errorf("summary ID = %q", summary.ID)
	}

	// The summary is emitted once, and the next window starts with a full
	// allowance.
	if got := h.detect(at(time.Second + testWindow + time.Second)); len(got) != 0 {
		t.Fatalf("after the summary: findings = %d, want 0", len(got))
	}
	h.spawnPairs(3000, 2, at(2*testWindow))
	if got := h.detect(at(2 * testWindow)); len(got) != 2 {
		t.Fatalf("next window: findings = %d, want 2", len(got))
	}
}

func TestRateLimitDefaultsToTwentyAndIsPerRule(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns(append(DefaultPatterns(), BehaviorPattern{
		Name:      "any-node",
		Processes: []ProcessPattern{named("p", "node", core.EventNetworkConnect)},
	}))

	h.spawnPairs(1000, 25, at(time.Second))

	byRule := map[string]int{}
	for _, f := range h.detect(at(time.Second)) {
		byRule[f.Rule]++
	}
	for rule, got := range byRule {
		if got != DefaultMaxFindingsPerWindow {
			t.Errorf("rule %s: %d findings, want the default limit of %d", rule, got, DefaultMaxFindingsPerWindow)
		}
	}
	if len(byRule) != 2 {
		t.Fatalf("rules that fired = %v, want both", byRule)
	}

	summaries := h.detect(at(time.Second + testWindow))
	if len(summaries) != 2 {
		t.Fatalf("summaries = %d, want one per rule", len(summaries))
	}
	// One summary per rule, in a stable order.
	if summaries[0].Rule != "any-node" || summaries[1].Rule != "network-active-parent-spawns-python" {
		t.Errorf("summary order = %s, %s", summaries[0].Rule, summaries[1].Rule)
	}
	for _, s := range summaries {
		if !strings.HasSuffix(s.Description, ": 5 additional findings suppressed") {
			t.Errorf("summary = %q, want 5 suppressed", s.Description)
		}
	}
}

func TestExcludedFindingsDoNotUseUpTheRateLimit(t *testing.T) {
	h := newHarness(testWindow)
	pattern := DefaultPatterns()[0]
	pattern.MaxFindingsPerWindow = 2
	h.SetPatterns([]BehaviorPattern{pattern})
	if err := h.SetExclusions([]Exclusion{
		{Rules: []string{"*"}, Match: block(fieldIs("name", Predicate{Eq: sp("node")}))},
	}); err != nil {
		t.Fatal(err)
	}

	h.spawnPairs(1000, 5, at(time.Second)) // all excluded: parents are node

	ruby := proc(5000, 1, "ruby", at(0))
	child := proc(5001, 5000, "python", at(time.Second))
	h.start(ruby, at(time.Second))
	h.start(child, at(time.Second))
	h.connect(ruby, at(time.Second))
	h.connect(child, at(time.Second))

	if got := h.detect(at(time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want the 1 that is not excluded", len(got))
	}
	if got := h.detect(at(time.Second + testWindow)); len(got) != 0 {
		t.Fatalf("a summary was emitted although nothing was rate-limited: %+v", got)
	}
}

func TestDraftPatternWithoutRolesNeverMatches(t *testing.T) {
	draft := BehaviorPattern{Name: "new-pattern", Severity: core.SeverityMedium, Title: "New Pattern"}
	if err := draft.Validate(); err != nil {
		t.Fatalf("a draft must stay valid so it can be saved and loaded: %v", err)
	}

	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{draft})
	h.defaultPair()
	h.Seed([]core.Process{proc(1, 0, "launchd", at(-time.Hour))})

	for i := 0; i < 3; i++ {
		if got := h.detect(at(time.Duration(i) * time.Second)); len(got) != 0 {
			t.Fatalf("a pattern with no roles produced findings: %+v", got)
		}
	}
	if got := NewMatcher().FindMatches(draft, nil, nil); len(got) != 0 {
		t.Fatalf("FindMatches on a draft = %d matches", len(got))
	}
}

func TestInvalidPatternIsSkippedNotFatal(t *testing.T) {
	bad := BehaviorPattern{
		Name:      "broken",
		Processes: []ProcessPattern{{ID: "p", Match: block(fieldIs("name", Predicate{Regex: sp("(")}))}},
	}

	h := newHarness(testWindow)
	h.SetPatterns(append([]BehaviorPattern{bad}, DefaultPatterns()...))
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(time.Second))

	got := h.detect(at(2 * time.Second))
	if len(got) != 1 || got[0].Rule != "network-active-parent-spawns-python" {
		t.Fatalf("findings = %+v, want only the valid pattern's", got)
	}
}

// A requirement for an event type Sentinel never produces could never be met,
// so it is rejected rather than loaded as a rule that silently cannot fire.
func TestUnknownEventTypesAreRejected(t *testing.T) {
	requirement := BehaviorPattern{
		Name: "p",
		Processes: []ProcessPattern{{
			ID:     "shell",
			Events: []EventPattern{{Type: core.EventDNSQuery}, {Type: "NETWORK_CONECT"}},
		}},
	}
	err := requirement.Validate()
	for _, want := range []string{`role "shell"`, "events[1]", `unknown event type "NETWORK_CONECT"`, "NETWORK_CONNECT"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("event requirement: error = %v, want it to mention %q", err, want)
		}
	}

	step := BehaviorPattern{
		Name:      "p",
		Processes: []ProcessPattern{{ID: "shell"}},
		Sequence: &SequencePattern{Steps: []SequenceStep{
			{Role: "shell", Type: core.EventFileCreate},
			{Role: "shell", Type: "PROCESS_LAUNCH"},
		}},
	}
	err = step.Validate()
	for _, want := range []string{"sequence", "steps[1]", `unknown event type "PROCESS_LAUNCH"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("sequence step: error = %v, want it to mention %q", err, want)
		}
	}

	for eventType := range knownEventTypes {
		pattern := BehaviorPattern{
			Name:      "p",
			Processes: []ProcessPattern{{ID: "a", Events: []EventPattern{{Type: eventType}}}},
		}
		if err := pattern.Validate(); err != nil {
			t.Errorf("%s: unexpected error: %v", eventType, err)
		}
	}
}
