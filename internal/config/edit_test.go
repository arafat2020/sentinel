package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

func editErrors(errs []EditError) string {
	lines := make([]string, len(errs))
	for i, e := range errs {
		lines[i] = e.String()
	}
	return strings.Join(lines, "\n")
}

// What the editor shows is what would be saved, and saving it unchanged
// gives the same pattern back.
func TestPatternYAMLRoundTrips(t *testing.T) {
	patterns := append(correlation.ShippedPatterns(), mustLoad(t, v3Patterns).Patterns...)

	for _, pattern := range patterns {
		text, err := PatternYAML(pattern)
		if err != nil {
			t.Fatalf("%s: %v", pattern.Name, err)
		}
		if !strings.HasPrefix(text, "name: "+pattern.Name+"\n") {
			t.Errorf("%s: YAML does not start with its name:\n%s", pattern.Name, text)
		}

		parsed, problems := ParsePatternYAML(text)
		if len(problems) != 0 {
			t.Fatalf("%s: its own YAML is rejected:\n%s\n%s", pattern.Name, editErrors(problems), text)
		}
		if !reflect.DeepEqual(normalize([]correlation.BehaviorPattern{parsed}), normalize([]correlation.BehaviorPattern{pattern})) {
			t.Errorf("%s: changed by a round trip through its YAML:\n%s", pattern.Name, text)
		}

		// As it appears inside a patterns file, too.
		asItem := "- " + strings.ReplaceAll(strings.TrimRight(text, "\n"), "\n", "\n  ") + "\n"
		if _, problems := ParsePatternYAML(asItem); len(problems) != 0 {
			t.Errorf("%s: rejected in list form:\n%s", pattern.Name, editErrors(problems))
		}
	}
}

// Every unknown key is reported, each with its path and its line.
func TestParsePatternYAMLReportsEveryUnknownKey(t *testing.T) {
	_, problems := ParsePatternYAML(`name: typo-ridden
severty: HIGH
processes:
  - id: parent
  - id: child
    mach:
      name: python
    events:
      - type: NETWORK_CONNECT
        were: { remote_port: 443 }
relationships:
  - { type: SPAWNED, parent: parent, child: child, depth: 2 }
`)

	want := []EditError{
		{Path: "severty", Line: 2},
		{Path: "processes[1].mach", Line: 6},
		{Path: "processes[1].events[0].were", Line: 10},
		{Path: "relationships[0].depth", Line: 12},
	}
	if len(problems) != len(want) {
		t.Fatalf("%d problems, want %d:\n%s", len(problems), len(want), editErrors(problems))
	}
	for i, problem := range problems {
		if problem.Path != want[i].Path || problem.Line != want[i].Line || !strings.Contains(problem.Message, "unknown key (valid keys here: ") {
			t.Errorf("problem %d = %+v, want path %q at line %d", i, problem, want[i].Path, want[i].Line)
		}
	}

	if got := problems[1].String(); !strings.HasPrefix(got, "line 6: processes[1].mach: unknown key (valid keys here: conditions, events, id, match)") {
		t.Errorf("rendered as %q", got)
	}
}

// anyLine stands for "some line": the YAML parser's idea of where a syntax
// error is does not always agree with a reader's.
const anyLine = -1

func TestParsePatternYAMLReportsOtherProblems(t *testing.T) {
	cases := map[string]struct {
		text     string
		wantLine int
		wantText string
	}{
		"syntax error":  {"name: x\nseverity: HIGH\nprocesses: [a, b\n", anyLine, "did not find expected"},
		"wrong type":    {"name: x\nprocesses: not-a-list\n", 2, "cannot unmarshal"},
		"empty":         {"   \n", 0, "the pattern is empty"},
		"two patterns":  {"- name: a\n- name: b\n", 1, "expected one pattern, found a list of 2"},
		"not a mapping": {"just some text\n", 1, "a pattern is a set of keys"},
		"no name":       {"severity: HIGH\n", 0, "name is required"},
		// Well formed, but it cannot be matched: no single line is wrong.
		"unrelated roles": {"name: x\nprocesses:\n  - id: a\n  - id: b\n", 0, "no relationships"},
		"bad operator":    {"name: x\nprocesses:\n  - id: a\n    match:\n      name: { like: py }\n", 0, `role "a": match.name: unknown operator "like"`},
		"unknown event":   {"name: x\nprocesses:\n  - id: a\n    events:\n      - type: DNS_LOOKUP\n", 0, `events[0]: unknown event type "DNS_LOOKUP"`},
	}

	for name, c := range cases {
		pattern, problems := ParsePatternYAML(c.text)
		if len(problems) == 0 {
			t.Errorf("%s: accepted as %+v", name, pattern)
			continue
		}
		if pattern.Name != "" || len(pattern.Processes) != 0 {
			t.Errorf("%s: a pattern was returned along with errors", name)
		}
		lineOK := problems[0].Line == c.wantLine || (c.wantLine == anyLine && problems[0].Line > 0)
		if !lineOK || !strings.Contains(problems[0].String(), c.wantText) {
			t.Errorf("%s: got %q (line %d), want line %d and %q", name, problems[0].String(), problems[0].Line, c.wantLine, c.wantText)
		}
	}
}

func TestPatternTemplateIsAValidPattern(t *testing.T) {
	pattern, problems := ParsePatternYAML(PatternTemplate)
	if len(problems) != 0 {
		t.Fatalf("the template is rejected:\n%s", editErrors(problems))
	}

	// It shows each part of the schema once.
	if pattern.Name != "new-pattern" || len(pattern.Processes) != 2 || len(pattern.Relationships) != 1 ||
		pattern.Sequence == nil || len(pattern.Exclude) != 1 || pattern.Processes[0].Match == nil {
		t.Errorf("template loaded as %+v", pattern)
	}
	events := pattern.Processes[1].Events
	if len(events) != 2 || events[0].Where == nil || events[1].Count != 5 || events[1].Distinct != "domain" {
		t.Errorf("template events = %+v", events)
	}
	for _, topic := range []string{"# A role", "where", "threshold", "relationships", "sequence", "capture", "exclude"} {
		if !strings.Contains(PatternTemplate, topic) {
			t.Errorf("the template does not explain %q", topic)
		}
	}
}

const fileWithExclusions = `patterns:
    - name: good
      severity: LOW
      processes:
        - id: p
    - name: broken
      processes: not-a-list
exclusions:
    - rules: ["*"]
      match:
        user: backup
      description: Nightly backup
`

func TestExclusionsYAMLShowsTheFilesExclusions(t *testing.T) {
	path := writeFile(t, fileWithExclusions)

	text, err := ExclusionsYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exclusions:\n", `- rules: ["*"]`, "user: backup", "description: Nightly backup"} {
		if !strings.Contains(text, want) {
			t.Errorf("exclusions YAML lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "patterns") {
		t.Errorf("exclusions YAML includes the patterns:\n%s", text)
	}

	// What it shows is accepted back unchanged.
	entries, problems := ParseExclusionsYAML(text)
	if len(problems) != 0 || len(entries) != 1 {
		t.Fatalf("%d entries, problems:\n%s", len(entries), editErrors(problems))
	}

	// No file, or a file without any: an empty list to start from.
	for _, empty := range []string{filepath.Join(t.TempDir(), "absent.yaml"), writeFile(t, "patterns: []\n")} {
		text, err := ExclusionsYAML(empty)
		if err != nil || strings.TrimSpace(text) != "exclusions: []" {
			t.Errorf("no exclusions rendered as %q, err %v", text, err)
		}
	}
}

func TestParseExclusionsYAMLReportsProblemsWithPaths(t *testing.T) {
	_, problems := ParseExclusionsYAML(`exclusions:
    - rules: ["*"]
      match: { user: backup }
    - ruls: [a]
      match: { name: x }
    - rules: [a]
      match: { colour: blue }
    - rules: [a]
`)

	rendered := editErrors(problems)
	for _, want := range []string{
		"line 4: exclusions[1].ruls: unknown key (valid keys here: description, match, rules)",
		"exclusions[2]: match.colour: unknown field",
		"line 8: exclusions[3]: ",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("problems lack %q:\n%s", want, rendered)
		}
	}
	if len(problems) != 3 {
		t.Errorf("%d problems, want 3:\n%s", len(problems), rendered)
	}

	if _, problems := ParseExclusionsYAML("exclusions:\n  - rules: [a]\npatterns: []\n"); len(problems) != 1 || problems[0].Path != "patterns" {
		t.Errorf("a stray key: %s", editErrors(problems))
	}
	if _, problems := ParseExclusionsYAML("exclusions: nope\n"); len(problems) != 1 || !strings.Contains(problems[0].Message, "must be a list") {
		t.Errorf("not a list: %s", editErrors(problems))
	}
	if _, problems := ParseExclusionsYAML("exclusions: [\n"); len(problems) == 0 || problems[0].Line == 0 {
		t.Errorf("syntax error: %s", editErrors(problems))
	}

	// Clearing the list is allowed.
	for _, empty := range []string{"", "exclusions: []\n", "exclusions:\n"} {
		if entries, problems := ParseExclusionsYAML(empty); len(entries) != 0 || len(problems) != 0 {
			t.Errorf("%q: %d entries, problems %s", empty, len(entries), editErrors(problems))
		}
	}
}

// Changing the exclusions leaves every pattern in the file as it is written,
// including one that does not load.
func TestSaveAndAppendExclusionsKeepThePatterns(t *testing.T) {
	path := writeFile(t, fileWithExclusions)

	entries, problems := ParseExclusionsYAML(`exclusions:
    - rules: [good]
      match: { exe: { prefix: /opt/tool/ } }
      description: Replaced
`)
	if len(problems) != 0 {
		t.Fatal(editErrors(problems))
	}
	if err := SaveExclusions(path, entries); err != nil {
		t.Fatal(err)
	}

	if err := AppendExclusion(path, correlation.Exclusion{
		Rules:       []string{"*"},
		Description: "Appended",
		Match:       &correlation.MatchBlock{Fields: []correlation.FieldPredicate{{Field: "user", Predicate: correlation.Predicate{Eq: strPtr("svc")}}}},
	}); err != nil {
		t.Fatal(err)
	}

	set, err := LoadPatterns(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Patterns) != 1 || set.Patterns[0].Name != "good" {
		t.Errorf("patterns after saving exclusions: %+v", set.Patterns)
	}
	if len(set.Errors) != 1 || set.Errors[0].Name != "broken" {
		t.Errorf("the pattern that does not load was not kept: %v", set.Errors)
	}
	if len(set.Exclusions) != 2 || set.Exclusions[0].Description != "Replaced" || set.Exclusions[1].Description != "Appended" {
		t.Errorf("exclusions = %+v", set.Exclusions)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "processes: not-a-list") {
		t.Errorf("the broken pattern's text was lost:\n%s", data)
	}

	// An exclusion that would not load is not written.
	before, _ := os.ReadFile(path)
	if err := AppendExclusion(path, correlation.Exclusion{Rules: []string{"*"}}); err == nil {
		t.Error("an exclusion that excludes nothing in particular was appended")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the file changed although the exclusion was rejected")
	}

	// Appending to a file that does not exist yet creates it.
	fresh := filepath.Join(t.TempDir(), "configs", "patterns.yaml")
	if err := AppendExclusion(fresh, correlation.Exclusion{
		Rules: []string{"r"},
		Match: &correlation.MatchBlock{Fields: []correlation.FieldPredicate{{Field: "name", Predicate: correlation.Predicate{Eq: strPtr("x")}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if set := mustLoad(t, fresh); len(set.Exclusions) != 1 || len(set.Patterns) != 0 {
		t.Errorf("fresh file: %+v", set)
	}
}

func TestExclusionPreviews(t *testing.T) {
	match := &correlation.MatchBlock{Fields: []correlation.FieldPredicate{
		{Field: "exe", Predicate: correlation.Predicate{Prefix: strPtr("/opt/backup/")}},
		{Field: "user", Predicate: correlation.Predicate{Eq: strPtr("backup")}},
	}}

	global, err := ExclusionYAML(correlation.Exclusion{Rules: []string{"*"}, Match: match, Description: "Backup agent"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exclusions:", `rules:`, `'*'`, "prefix: /opt/backup/", "user: {eq: backup}", "description: Backup agent"} {
		if !strings.Contains(global, want) {
			t.Errorf("global preview lacks %q:\n%s", want, global)
		}
	}
	if entries, problems := ParseExclusionsYAML(global); len(entries) != 1 || len(problems) != 0 {
		t.Errorf("the global preview is not loadable: %s", editErrors(problems))
	}

	role, err := RoleExclusionYAML(correlation.RoleExclusion{Role: "payload", Match: match})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exclude:", "role: payload", "prefix: /opt/backup/"} {
		if !strings.Contains(role, want) {
			t.Errorf("role preview lacks %q:\n%s", want, role)
		}
	}
}

func TestCheckWritable(t *testing.T) {
	dir := t.TempDir()
	if err := CheckWritable(filepath.Join(dir, "patterns.yaml")); err != nil {
		t.Errorf("a writable directory: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the check left %d file(s) behind", len(entries))
	}

	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	err := CheckWritable(filepath.Join(dir, "patterns.yaml"))
	if err == nil || !strings.Contains(err.Error(), "not allowed to write") || !strings.Contains(err.Error(), "picked up without a restart") {
		t.Errorf("a read-only directory: %v", err)
	}
}

func strPtr(s string) *string { return &s }
