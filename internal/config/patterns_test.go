package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

const (
	shippedPatterns = "../../configs/patterns.yaml"
	// v1Patterns is the patterns file as it shipped before the predicate
	// schema existed.
	v1Patterns = "testdata/patterns_v1.yaml"
	v2Patterns = "testdata/patterns_v2.yaml"
)

// normalize makes nil and empty slices compare equal: YAML loading produces
// empty slices where hand-written patterns leave them nil.
func normalize(patterns []correlation.BehaviorPattern) []correlation.BehaviorPattern {
	out := make([]correlation.BehaviorPattern, len(patterns))
	for i, p := range patterns {
		p.Processes = append([]correlation.ProcessPattern{}, p.Processes...)
		for j, pp := range p.Processes {
			pp.Conditions = append([]correlation.Condition{}, pp.Conditions...)
			pp.Events = append([]correlation.EventPattern{}, pp.Events...)
			p.Processes[j] = pp
		}
		p.Relationships = append([]correlation.RelationshipPattern{}, p.Relationships...)
		out[i] = p
	}
	return out
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// mustLoad loads a file that is expected to have nothing wrong with it.
func mustLoad(t *testing.T, path string) PatternSet {
	t.Helper()
	set, err := LoadPatterns(path)
	if err != nil {
		t.Fatalf("LoadPatterns(%s): %v", path, err)
	}
	if len(set.Errors) != 0 {
		t.Fatalf("LoadPatterns(%s): unexpected pattern errors: %v", path, set.Errors)
	}
	return set
}

func copyFile(t *testing.T, from string) string {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, string(data))
}

// detects reports how many findings the patterns produce for a node parent
// spawning the named child, both with network activity.
func detects(t *testing.T, patterns []correlation.BehaviorPattern, childName string) int {
	t.Helper()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	parent := core.Process{PID: 100, Name: "node", StartTime: now.Add(-time.Hour)}
	child := core.Process{PID: 200, PPID: 100, Name: childName, StartTime: now}

	engine := correlation.NewEngine(5*time.Minute, correlation.WithClock(func() time.Time { return now }))
	engine.SetPatterns(patterns)

	for _, event := range []core.Event{
		{Type: core.EventProcessStart, Process: &parent},
		{Type: core.EventNetworkConnect, Process: &parent},
		{Type: core.EventProcessStart, Process: &child},
		{Type: core.EventNetworkConnect, Process: &child},
	} {
		now = now.Add(time.Second)
		event.Timestamp = now
		engine.Process(event)
	}

	return len(engine.DetectBehaviors())
}

// --- Defaults -----------------------------------------------------------

func TestShippedPatternsFileLoadsAsDefaults(t *testing.T) {
	loaded := mustLoad(t, shippedPatterns)

	if !reflect.DeepEqual(normalize(loaded.Patterns), normalize(correlation.DefaultPatterns())) {
		t.Fatalf("shipped patterns differ from DefaultPatterns:\n%+v", loaded.Patterns)
	}
}

// Saving the defaults reproduces the shipped file byte for byte.
func TestSavingDefaultsReproducesShippedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := SavePatterns(path, correlation.DefaultPatterns()); err != nil {
		t.Fatalf("SavePatterns: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("saved defaults differ from %s:\n%s", shippedPatterns, got)
	}
}

func TestShippedPatternDetectsVersionedPython(t *testing.T) {
	loaded := mustLoad(t, shippedPatterns)

	for child, want := range map[string]int{"python": 1, "python3": 1, "python3.12": 1, "bash": 0} {
		if got := detects(t, loaded.Patterns, child); got != want {
			t.Errorf("child %q: findings = %d, want %d", child, got, want)
		}
	}
}

// --- v1 compatibility ---------------------------------------------------

func TestV1FileLoadsAndBehavesAsBefore(t *testing.T) {
	loaded := mustLoad(t, v1Patterns)

	if len(loaded.Patterns) != 1 || len(loaded.Exclusions) != 0 {
		t.Fatalf("loaded %d patterns and %d exclusions, want 1 and 0", len(loaded.Patterns), len(loaded.Exclusions))
	}

	// The v1 conditions are carried as conditions, with no predicate added.
	child := loaded.Patterns[0].Processes[1]
	want := []correlation.Condition{{Type: correlation.ConditionProcessName, Value: "python"}}
	if !reflect.DeepEqual(child.Conditions, want) || child.Match != nil {
		t.Fatalf("child role = %+v, want the v1 condition only", child)
	}
	if loaded.Patterns[0].UsesAdvancedFields() {
		t.Error("a v1 pattern is reported as using advanced fields")
	}

	// PROCESS_NAME: python has always meant exactly "python".
	for childName, want := range map[string]int{"python": 1, "python3": 0, "Python": 0, "bash": 0} {
		if got := detects(t, loaded.Patterns, childName); got != want {
			t.Errorf("child %q: findings = %d, want %d", childName, got, want)
		}
	}
}

// A v1 condition is exactly an eq predicate on the same field.
func TestV1ConditionEqualsEqPredicate(t *testing.T) {
	v1 := mustLoad(t, writeFile(t, `patterns:
    - name: p
      processes:
        - id: only
          conditions:
            - {type: PROCESS_NAME, value: python}
            - {type: PROCESS_USER, value: app}
`))
	v2 := mustLoad(t, writeFile(t, `patterns:
    - name: p
      processes:
        - id: only
          match:
            name: {eq: python}
            user: app
`))

	matcher := correlation.NewMatcher()
	for _, process := range []core.Process{
		{Name: "python", User: "app"}, {Name: "python", User: "root"},
		{Name: "python3", User: "app"}, {Name: "", User: "app"}, {},
	} {
		a := matcher.MatchProcess(v1.Patterns[0].Processes[0], process)
		b := matcher.MatchProcess(v2.Patterns[0].Processes[0], process)
		if a != b {
			t.Errorf("%+v: v1 conditions matched = %v, eq predicates matched = %v", process, a, b)
		}
	}
}

func TestV1FileIsRewrittenUnchanged(t *testing.T) {
	loaded := mustLoad(t, v1Patterns)

	path := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := SavePatterns(path, loaded.Patterns); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(path)
	want, _ := os.ReadFile(v1Patterns)
	if !bytes.Equal(got, want) {
		t.Fatalf("a v1 file changed when saved:\n%s", got)
	}
}

func TestRoleMayUseConditionsAndMatchTogether(t *testing.T) {
	loaded := mustLoad(t, v2Patterns)

	shell := loaded.Patterns[0].Processes[1]
	if len(shell.Conditions) != 1 || shell.Match == nil {
		t.Fatalf("shell role = %+v, want both a condition and a match block", shell)
	}

	matcher := correlation.NewMatcher()
	wanted := core.Process{Name: "bash", User: "www-data", CommandLine: "bash -c id", Executable: "/tmp/bash"}
	if !matcher.MatchProcess(shell, wanted) {
		t.Error("process satisfying both forms should match")
	}

	wrongUser := wanted
	wrongUser.User = "root" // fails the v1 condition only
	wrongName := wanted
	wrongName.Name = "python" // fails the match block only
	if matcher.MatchProcess(shell, wrongUser) || matcher.MatchProcess(shell, wrongName) {
		t.Error("conditions and match must both hold")
	}
}

// --- v2 parsing ---------------------------------------------------------

func TestV2FileParses(t *testing.T) {
	loaded := mustLoad(t, v2Patterns)

	if len(loaded.Patterns) != 2 || len(loaded.Exclusions) != 2 {
		t.Fatalf("loaded %d patterns and %d exclusions, want 2 and 2", len(loaded.Patterns), len(loaded.Exclusions))
	}

	pattern := loaded.Patterns[0]
	if pattern.MaxFindingsPerWindow != 5 || len(pattern.Exclude) != 1 || pattern.Exclude[0].Role != "shell" {
		t.Errorf("pattern-level fields: max=%d exclude=%+v", pattern.MaxFindingsPerWindow, pattern.Exclude)
	}
	if !pattern.UsesAdvancedFields() || loaded.Patterns[1].UsesAdvancedFields() {
		t.Error("UsesAdvancedFields should be true for the v2 pattern only")
	}

	server := pattern.Processes[0].Match.Fields[0]
	if server.Field != "name" || !server.Predicate.NoCase || !reflect.DeepEqual(server.Predicate.In, []string{"nginx", "apache2", "httpd"}) {
		t.Errorf("server.name predicate = %+v", server)
	}

	shell := pattern.Processes[1]
	if len(shell.Match.Fields) != 2 || len(shell.Match.AnyOf) != 3 {
		t.Fatalf("shell match = %+v", shell.Match)
	}
	// A bare scalar is eq, and is remembered as shorthand.
	bare := shell.Match.AnyOf[2].Fields[0].Predicate
	if bare.Eq == nil || *bare.Eq != "/bin/sh" || !bare.Shorthand {
		t.Errorf("bare scalar predicate = %+v", bare)
	}

	connect := shell.Events[0]
	if connect.Type != core.EventNetworkConnect || len(connect.Where.Fields) != 3 {
		t.Fatalf("connect event = %+v", connect)
	}
	port := connect.Where.Fields[0].Predicate
	if port.Not == nil || !reflect.DeepEqual(port.Not.In, []string{"80", "443", "53"}) {
		t.Errorf("remote_port predicate = %+v", port)
	}
	addr := connect.Where.Fields[1].Predicate
	if addr.Not == nil || !reflect.DeepEqual(addr.Not.CIDR, []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128"}) {
		t.Errorf("remote_addr predicate = %+v", addr)
	}
	if shell.Events[1].Where != nil {
		t.Error("an event without where should have no filter")
	}
	// A bare list is in.
	paths := shell.Events[2].Where.Fields[0].Predicate
	if !paths.Shorthand || !reflect.DeepEqual(paths.In, []string{"/etc/passwd", "/etc/shadow"}) {
		t.Errorf("bare list predicate = %+v", paths)
	}

	wildcard := loaded.Exclusions[0]
	if !wildcard.AppliesTo("anything") || wildcard.Description != "Monitoring agent" {
		t.Errorf("wildcard exclusion = %+v", wildcard)
	}
	scoped := loaded.Exclusions[1]
	if !scoped.AppliesTo("webshell-outbound") || scoped.AppliesTo("plain-v1-pattern") {
		t.Errorf("scoped exclusion applies to the wrong rules: %+v", scoped.Rules)
	}
}

func TestV2FileRoundTrips(t *testing.T) {
	original := mustLoad(t, v2Patterns)
	path := copyFile(t, v2Patterns)

	// Twice, to show the saved form is itself stable.
	var previous []byte
	for pass := 0; pass < 2; pass++ {
		if err := SavePatterns(path, mustLoad(t, path).Patterns); err != nil {
			t.Fatal(err)
		}

		reloaded := mustLoad(t, path)
		if !reflect.DeepEqual(reloaded, original) {
			t.Fatalf("pass %d: the file changed meaning when saved:\n%+v\n%+v", pass, original, reloaded)
		}

		data, _ := os.ReadFile(path)
		if pass > 0 && !bytes.Equal(data, previous) {
			t.Fatalf("saving a saved file changed it:\n%s", data)
		}
		previous = data
	}

	// Shorthand stays shorthand and operator objects stay objects.
	saved := string(previous)
	for _, want := range []string{
		"exe: /bin/sh",
		"path: [/etc/passwd, /etc/shadow]",
		"user: deploy",
		"{regex: '^(ba|da|z)?sh$'}",
		`{not: {cidr: [10.0.0.0/8, 127.0.0.0/8, '::1/128']}}`,
		"max_findings_per_window: 5",
		// Exclusions are carried over verbatim, original quoting included.
		`rules: ["*"]`,
	} {
		if !strings.Contains(saved, want) {
			t.Errorf("saved file does not contain %q:\n%s", want, saved)
		}
	}
}

func TestOperatorShapesAccepted(t *testing.T) {
	loaded := mustLoad(t, writeFile(t, `patterns:
    - name: shapes
      processes:
        - id: p
          match:
            name: ""                         # bare empty scalar: eq ""
            user: {eq: ""}
            exe: {not: /usr/bin/true}        # shorthand inside not
            cmdline: {not: [a, b]}
          events:
            - type: NETWORK_CONNECT
              where:
                remote_addr: {cidr: 10.0.0.0/8}   # one network without a list
                remote_port: 443
                local_port: {gte: 1024, lt: 65535}
`))

	role := loaded.Patterns[0].Processes[0]
	fields := map[string]correlation.Predicate{}
	for _, f := range role.Match.Fields {
		fields[f.Field] = f.Predicate
	}

	if p := fields["name"]; p.Eq == nil || *p.Eq != "" {
		t.Errorf("name = %+v, want eq empty", p)
	}
	if p := fields["exe"]; p.Not == nil || p.Not.Eq == nil || *p.Not.Eq != "/usr/bin/true" {
		t.Errorf("exe = %+v", p)
	}
	if p := fields["cmdline"]; p.Not == nil || !reflect.DeepEqual(p.Not.In, []string{"a", "b"}) {
		t.Errorf("cmdline = %+v", p)
	}
	if p := role.Events[0].Where.Fields[0].Predicate; !reflect.DeepEqual(p.CIDR, []string{"10.0.0.0/8"}) {
		t.Errorf("remote_addr = %+v", p)
	}

	// And an empty name is what it says: only a process with no name.
	matcher := correlation.NewMatcher()
	if !matcher.MatchProcess(role, core.Process{Executable: "/bin/x", CommandLine: "c"}) {
		t.Error("process with empty name and user should match")
	}
	if matcher.MatchProcess(role, core.Process{Name: "x", Executable: "/bin/x", CommandLine: "c"}) {
		t.Error("process with a name should not match name: \"\"")
	}
}

// --- Validation ---------------------------------------------------------

// role wraps a role body in a one-pattern file named "bad".
func role(body string) string {
	return "patterns:\n    - name: bad\n      processes:\n        - id: child\n" + body
}

func TestLoadPatternsReportsPredicateErrors(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want []string
	}{
		"unknown process field": {
			role("          match:\n            colour: red\n"),
			[]string{`role "child"`, "match.colour", "unknown field"},
		},
		"unknown operator": {
			role("          match:\n            name: {like: py}\n"),
			[]string{`role "child"`, "match.name", `unknown operator "like"`},
		},
		"cidr on name": {
			role("          match:\n            name: {cidr: [10.0.0.0/8]}\n"),
			[]string{`role "child"`, "match.name", `"cidr" is not valid for a string field`},
		},
		"gt on path": {
			role("          events:\n            - type: FILE_CREATE\n              where:\n                path: {gt: 5}\n"),
			[]string{`role "child"`, "events[0] (FILE_CREATE)", "where.path", `"gt" is not valid for a string field`},
		},
		"bad regex": {
			role("          match:\n            cmdline: {regex: '('}\n"),
			[]string{`role "child"`, "match.cmdline", "bad regex"},
		},
		"bad glob": {
			role("          match:\n            exe: {glob: '/tmp/[abc'}\n"),
			[]string{`role "child"`, "match.exe", "bad glob"},
		},
		"bad cidr": {
			role("          events:\n            - type: NETWORK_CONNECT\n              where:\n                remote_addr: {cidr: [10.0.0.0/40]}\n"),
			[]string{`role "child"`, "events[0] (NETWORK_CONNECT)", "where.remote_addr", "bad cidr"},
		},
		"where field wrong for the event type": {
			role("          events:\n            - type: DNS_QUERY\n              where:\n                remote_port: 53\n"),
			[]string{`role "child"`, "events[0] (DNS_QUERY)", "where.remote_port", "unknown field"},
		},
		"where on an event type with no fields": {
			role("          events:\n            - type: SCRIPT_EXECUTION\n              where:\n                path: /x\n"),
			[]string{`role "child"`, "events[0] (SCRIPT_EXECUTION)", "no fields to filter on"},
		},
		"empty in list": {
			role("          match:\n            name: {in: []}\n"),
			[]string{`role "child"`, "match.name", `"in" needs at least one value`},
		},
		"empty bare list": {
			role("          match:\n            name: []\n"),
			[]string{`role "child"`, "match.name", `"in" needs at least one value`},
		},
		"text where a number is needed": {
			role("          events:\n            - type: NETWORK_CONNECT\n              where:\n                remote_port: {eq: https}\n"),
			[]string{`role "child"`, "where.remote_port", "needs an integer"},
		},
		"operator given a list": {
			role("          match:\n            name: {prefix: [a, b]}\n"),
			[]string{`role "child"`, "match.name", `"prefix" needs a single value`},
		},
		"in given a scalar": {
			role("          match:\n            name: {in: python}\n"),
			[]string{`role "child"`, "match.name", `"in" needs a list`},
		},
		"empty operator object": {
			role("          match:\n            name: {}\n"),
			[]string{`role "child"`, "match.name", "no operator given"},
		},
		"match is not a mapping": {
			role("          match: python\n"),
			[]string{`role "child"`, "match", "must be a mapping"},
		},
		"any_of is not a list": {
			role("          match:\n            any_of: {name: x}\n"),
			[]string{`role "child"`, "match.any_of", "must be a list"},
		},
		"empty any_of": {
			role("          match:\n            any_of: []\n"),
			[]string{`role "child"`, "match.any_of", "at least one alternative"},
		},
		"error inside nested any_of": {
			role("          match:\n            any_of:\n              - name: ok\n              - any_of:\n                  - exe: {lt: 3}\n"),
			[]string{`role "child"`, "match.any_of[1].any_of[0].exe", `"lt" is not valid`},
		},
		"error inside not": {
			role("          match:\n            name: {not: {regex: '['}}\n"),
			[]string{`role "child"`, "match.name", "not:", "bad regex"},
		},
		"exclude with unknown role": {
			role("          events: []\n      exclude:\n        - role: ghost\n          match:\n            name: x\n"),
			[]string{"exclude[0]", `unknown role "ghost"`},
		},
		"exclude with bad predicate": {
			role("          events: []\n      exclude:\n        - role: child\n          match:\n            name: {cidr: ['::1/128']}\n"),
			[]string{"exclude[0]", `role "child"`, "match.name", `"cidr" is not valid`},
		},
		"negative rate limit": {
			role("          events: []\n      max_findings_per_window: -3\n"),
			[]string{"max_findings_per_window", "must not be negative"},
		},
	}

	for name, c := range cases {
		set, err := LoadPatterns(writeFile(t, c.yaml))
		if err != nil {
			t.Errorf("%s: the whole file was rejected: %v", name, err)
			continue
		}
		if len(set.Patterns) != 0 || len(set.Errors) != 1 {
			t.Errorf("%s: loaded %d patterns with %d errors, want 0 and 1", name, len(set.Patterns), len(set.Errors))
			continue
		}

		message := set.Errors[0].Error()
		// Every message names the pattern, then says where in it.
		for _, want := range append([]string{`pattern[0] "bad"`}, c.want...) {
			if !strings.Contains(message, want) {
				t.Errorf("%s: error %q does not mention %q", name, message, want)
			}
		}
		if set.Errors[0].Name != "bad" || set.Errors[0].Index != 0 || set.Errors[0].Exclusion {
			t.Errorf("%s: error fields = %+v", name, set.Errors[0])
		}
	}
}

func TestLoadPatternsReportsStructuralErrors(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"two roles and no relationships": {`patterns:
    - name: bad
      processes:
        - id: a
        - id: b
`, "no relationships"},
		"relationship with unknown role": {`patterns:
    - name: bad
      processes:
        - id: a
        - id: b
      relationships:
        - {type: SPAWNED, parent: ghost, child: b}
`, `unknown role "ghost"`},
		"duplicate role ids": {`patterns:
    - name: bad
      processes:
        - id: a
        - id: a
      relationships:
        - {type: SPAWNED, parent: a, child: a}
`, `duplicate role id "a"`},
		"role outside every relationship": {`patterns:
    - name: bad
      processes:
        - id: a
        - id: b
        - id: c
      relationships:
        - {type: SPAWNED, parent: a, child: b}
`, `role "c" is not part of any relationship`},
		"unknown condition type": {`patterns:
    - name: bad
      processes:
        - id: p
          conditions:
            - {type: PROCESS_COLOR, value: blue}
`, `unknown condition type "PROCESS_COLOR"`},
		"unknown relationship type": {`patterns:
    - name: bad
      processes:
        - id: a
        - id: b
      relationships:
        - {type: ADOPTED, parent: a, child: b}
`, `unknown relationship type "ADOPTED"`},
		"wrong YAML type for a field": {`patterns:
    - name: bad
      processes: not-a-list
`, "cannot unmarshal"},
	}

	for name, c := range cases {
		set, err := LoadPatterns(writeFile(t, c.yaml))
		if err != nil {
			t.Errorf("%s: the whole file was rejected: %v", name, err)
			continue
		}
		if len(set.Errors) != 1 {
			t.Errorf("%s: %d errors, want 1", name, len(set.Errors))
			continue
		}
		message := set.Errors[0].Error()
		if !strings.Contains(message, c.want) || !strings.Contains(message, `pattern[0] "bad"`) {
			t.Errorf("%s: error %q does not name the pattern and mention %q", name, message, c.want)
		}
	}
}

func TestLoadPatternsReportsExclusionErrors(t *testing.T) {
	set, err := LoadPatterns(writeFile(t, `patterns: []
exclusions:
    - rules: ["*"]
      match:
        name: python
    - rules: ["*"]
      match:
        name: {cidr: [10.0.0.0/8]}
    - match:
        name: x
    - rules: [some-rule]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Exclusions) != 1 || len(set.Errors) != 3 {
		t.Fatalf("loaded %d exclusions with %d errors, want 1 and 3: %v", len(set.Exclusions), len(set.Errors), set.Errors)
	}

	wants := []string{
		`exclusions[1]: match.name: operator "cidr" is not valid for a string field`,
		"exclusions[2]: rules:",
		"exclusions[3]: match:",
	}
	for i, want := range wants {
		if got := set.Errors[i].Error(); !strings.Contains(got, want) || !set.Errors[i].Exclusion {
			t.Errorf("error %d = %q, want it to contain %q", i, got, want)
		}
	}
}

// --- Partial loading ----------------------------------------------------

const oneBadTwoGood = `patterns:
    - name: first-good
      severity: LOW
      processes:
        - id: only
          match:
            name: python
    - name: broken
      severity: HIGH
      processes:
        - id: only
          match:
            name: {regex: '('}
    - name: second-good
      severity: LOW
      processes:
        - id: parent
          conditions: []
          events: []
        - id: child
          conditions: []
          events: []
      relationships:
        - {type: SPAWNED, parent: parent, child: child}
`

func TestOneBadPatternDoesNotDiscardTheFile(t *testing.T) {
	set, err := LoadPatterns(writeFile(t, oneBadTwoGood))
	if err != nil {
		t.Fatalf("the whole file was rejected: %v", err)
	}

	if len(set.Patterns) != 2 || set.Patterns[0].Name != "first-good" || set.Patterns[1].Name != "second-good" {
		t.Fatalf("loaded %+v, want the two good patterns in order", set.Patterns)
	}
	if len(set.Errors) != 1 {
		t.Fatalf("%d errors, want 1: %v", len(set.Errors), set.Errors)
	}

	bad := set.Errors[0]
	if bad.Index != 1 || bad.Name != "broken" {
		t.Errorf("error is about pattern[%d] %q, want pattern[1] \"broken\"", bad.Index, bad.Name)
	}
	if want := `pattern[1] "broken": role "only": match.name: bad regex`; !strings.Contains(bad.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", bad, want)
	}
}

func TestUnreadableOrMalformedFileIsStillAnError(t *testing.T) {
	if _, err := LoadPatterns(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing file should be an error")
	}

	for name, content := range map[string]string{
		"YAML syntax error":   "patterns: [",
		"patterns not a list": "patterns: 7",
	} {
		set, err := LoadPatterns(writeFile(t, content))
		if err == nil {
			t.Errorf("%s: expected an error, got %+v", name, set)
		}
	}
}

func TestMissingNameIsReportedPerPattern(t *testing.T) {
	set, err := LoadPatterns(writeFile(t, "patterns:\n    - severity: LOW\n    - name: ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Patterns) != 1 || len(set.Errors) != 1 || !strings.Contains(set.Errors[0].Error(), "name is required") {
		t.Fatalf("patterns=%d errors=%v", len(set.Patterns), set.Errors)
	}
}

// --- Saving -------------------------------------------------------------

// The editors hold only the patterns that loaded. Saving from one must not
// delete what it never saw: the rejected pattern and the exclusions.
func TestSaveKeepsRejectedPatternsAndExclusions(t *testing.T) {
	path := writeFile(t, oneBadTwoGood+`exclusions:
    - rules: ["*"]
      match:
        exe: {prefix: /opt/monitoring/}
      description: Monitoring agent
`)

	before, err := LoadPatterns(path)
	if err != nil {
		t.Fatal(err)
	}

	// What an editor does: change something on a pattern it holds, save.
	before.Patterns[0].Title = "Edited"
	if err := SavePatterns(path, before.Patterns); err != nil {
		t.Fatal(err)
	}

	after, err := LoadPatterns(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(after.Patterns) != 2 || after.Patterns[0].Title != "Edited" {
		t.Fatalf("saved patterns = %+v", after.Patterns)
	}
	if !reflect.DeepEqual(after.Exclusions, before.Exclusions) || len(after.Exclusions) != 1 {
		t.Fatalf("exclusions changed: %+v", after.Exclusions)
	}
	if len(after.Errors) != 1 || after.Errors[0].Name != "broken" {
		t.Fatalf("the rejected pattern was not kept in the file: errors = %v", after.Errors)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "regex: '('") {
		t.Errorf("the rejected pattern's content was altered:\n%s", data)
	}

	// Saving again does not multiply it.
	if err := SavePatterns(path, after.Patterns); err != nil {
		t.Fatal(err)
	}
	again, _ := LoadPatterns(path)
	if len(again.Errors) != 1 || len(again.Patterns) != 2 {
		t.Fatalf("after a second save: %d patterns, %d errors", len(again.Patterns), len(again.Errors))
	}
}

func TestSaveToNewFileWritesOnlyPatterns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "patterns.yaml")
	if err := SavePatterns(path, correlation.DefaultPatterns()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "exclusions") {
		t.Errorf("a new file gained an exclusions key:\n%s", data)
	}
}

// A pattern freshly created in the editor has no roles yet. It must stay
// loadable, or one unfinished draft would be reported as an error forever.
func TestDraftPatternWithoutRolesStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.yaml")
	draft := correlation.BehaviorPattern{Name: "new-pattern", Severity: core.SeverityMedium, Title: "New Pattern"}

	if err := SavePatterns(path, append(correlation.DefaultPatterns(), draft)); err != nil {
		t.Fatalf("SavePatterns: %v", err)
	}
	if loaded := mustLoad(t, path); len(loaded.Patterns) != 2 {
		t.Fatalf("loaded %d patterns, want 2", len(loaded.Patterns))
	}
}
