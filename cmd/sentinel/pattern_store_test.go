package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

const storeTestPatterns = `patterns:
    - name: tmp-binary-connects
      severity: HIGH
      title: Binary in /tmp connected out
      description: A program running from /tmp made a network connection.
      processes:
        - id: parent
        - id: payload
          match:
            exe: {prefix: /tmp/}
          events:
            - type: NETWORK_CONNECT
      relationships:
        - {type: SPAWNED, parent: parent, child: payload}
`

// storeHarness is a patterns file, an engine on a clock the test controls,
// and the store that joins them.
type storeHarness struct {
	t      *testing.T
	path   string
	engine *correlation.Engine
	store  *patternStore
	now    time.Time

	mu     sync.Mutex
	states []patternState
}

func newStoreHarness(t *testing.T, content string) *storeHarness {
	t.Helper()

	h := &storeHarness{t: t, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.path = filepath.Join(t.TempDir(), "configs", "patterns.yaml")
	if err := os.MkdirAll(filepath.Dir(h.path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	set, err := loadPatternSet(h.path)
	h.engine = correlation.NewEngine(time.Minute, correlation.WithClock(func() time.Time { return h.now }))
	h.engine.SetPatterns(set.Patterns)
	_ = h.engine.SetExclusions(set.Exclusions)

	h.store = newPatternStore(h.path, h.engine, set, err)
	h.store.OnChange(func(state patternState) {
		h.mu.Lock()
		h.states = append(h.states, state)
		h.mu.Unlock()
	})
	return h
}

func (h *storeHarness) changes() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.states)
}

func (h *storeHarness) file() string {
	h.t.Helper()
	data, err := os.ReadFile(h.path)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(data)
}

// attack plays "a shell starts /tmp/x, which connects out" and returns what
// the engine reports. Each call uses fresh processes, a minute later.
func (h *storeHarness) attack(user string) []core.Finding {
	h.now = h.now.Add(2 * time.Minute)
	pid := int32(h.now.Unix() % 100000)

	shell := core.Process{PID: pid, PPID: 1, Name: "sh", Executable: "/bin/sh", User: user, StartTime: h.now}
	payload := core.Process{PID: pid + 1, PPID: pid, Name: "x", Executable: "/tmp/build/x", CommandLine: "/tmp/build/x --serve 8080", User: user, StartTime: h.now}

	h.engine.Process(core.Event{Type: core.EventProcessStart, Timestamp: h.now, Process: &shell})
	h.engine.Process(core.Event{Type: core.EventProcessStart, Timestamp: h.now, Process: &payload})
	h.engine.Process(core.Event{Type: core.EventNetworkConnect, Timestamp: h.now, Process: &payload,
		Network: &core.NetworkConnection{RemoteAddress: "203.0.113.9", RemotePort: 4444}})

	return h.engine.DetectBehaviors()
}

func mustDraft(t *testing.T, f core.Finding, role string) exclusionDraft {
	t.Helper()
	draft, err := newExclusionDraft(f, role)
	if err != nil {
		t.Fatal(err)
	}
	draft.Description = "Build output, run by CI"
	return draft
}

// --- Exclude from a finding ----------------------------------------------

func TestExclusionDraftIsPrefilledFromTheRole(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	findings := h.attack("ci")
	if len(findings) != 1 {
		t.Fatalf("%d findings", len(findings))
	}

	if roles := findingRoles(findings[0]); strings.Join(roles, ",") != "parent,payload" {
		t.Fatalf("roles = %v", roles)
	}

	draft, err := newExclusionDraft(findings[0], "payload")
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]exclusionField{}
	for _, f := range draft.Fields {
		got[f.Field] = f
	}
	want := map[string]exclusionField{
		"exe":     {Field: "exe", Original: "/tmp/build/x", Keep: true, Mode: modeEq, Value: "/tmp/build/x"},
		"cmdline": {Field: "cmdline", Original: "/tmp/build/x --serve 8080", Keep: false, Mode: modeEq, Value: "/tmp/build/x --serve 8080"},
		"user":    {Field: "user", Original: "ci", Keep: true, Mode: modeEq, Value: "ci"},
		"name":    {Field: "name", Original: "x", Keep: false, Mode: modeEq, Value: "x"},
	}
	for name, field := range want {
		if got[name] != field {
			t.Errorf("%s = %+v, want %+v", name, got[name], field)
		}
	}
	if draft.Rule != "tmp-binary-connects" || draft.Role != "payload" || draft.AllRules {
		t.Errorf("draft = %+v", draft)
	}

	// Nothing can be saved without saying why.
	if err := draft.Validate(); err == nil || !strings.Contains(err.Error(), "description is required") {
		t.Errorf("no description: %v", err)
	}
	draft.Description = "x"
	for i := range draft.Fields {
		draft.Fields[i].Keep = false
	}
	if err := draft.Validate(); err == nil || !strings.Contains(err.Error(), "at least one field") {
		t.Errorf("no fields kept: %v", err)
	}

	if _, err := newExclusionDraft(findings[0], "ghost"); err == nil {
		t.Error("a draft was made for a role the finding does not have")
	}
}

// Each way of loosening a field, in each scope, produces the YAML shown, and
// that YAML is what the strict loader then reads back.
func TestExclusionYAMLForEachChoice(t *testing.T) {
	cases := []struct {
		name     string
		adjust   func(*exclusionDraft)
		wantYAML []string
		// wantLoaded checks the match block the loader ends up with.
		wantLoaded string
	}{
		{
			"exact executable and user, this rule",
			func(d *exclusionDraft) {},
			[]string{`# added to the pattern "tmp-binary-connects"`, "exclude:", "role: payload", "exe: {eq: /tmp/build/x}", "user: {eq: ci}", "description: Build output, run by CI"},
			"exe eq /tmp/build/x; user eq ci",
		},
		{
			"executable loosened to its directory",
			func(d *exclusionDraft) { d.SetMode("exe", modePrefix) },
			[]string{"exe: {prefix: /tmp/build/}", "user: {eq: ci}"},
			"exe prefix /tmp/build/; user eq ci",
		},
		{
			"command line, exact",
			func(d *exclusionDraft) { d.field("cmdline").Keep = true; d.field("exe").Keep = false },
			[]string{"cmdline: {eq: /tmp/build/x --serve 8080}"},
			"cmdline eq /tmp/build/x --serve 8080; user eq ci",
		},
		{
			"command line loosened to contains",
			func(d *exclusionDraft) {
				d.field("cmdline").Keep = true
				d.SetMode("cmdline", modeContains)
				d.field("cmdline").Value = "--serve"
			},
			[]string{"cmdline: {contains: --serve}"},
			"exe eq /tmp/build/x; cmdline contains --serve; user eq ci",
		},
		{
			"command line loosened to its command",
			func(d *exclusionDraft) { d.field("cmdline").Keep = true; d.SetMode("cmdline", modePrefix) },
			[]string{`cmdline: {prefix: '/tmp/build/x '}`},
			"exe eq /tmp/build/x; cmdline prefix /tmp/build/x ; user eq ci",
		},
		{
			"name only",
			func(d *exclusionDraft) {
				d.field("exe").Keep, d.field("user").Keep, d.field("name").Keep = false, false, true
			},
			[]string{"name: {eq: x}"},
			"name eq x",
		},
		{
			"all rules",
			func(d *exclusionDraft) { d.AllRules = true; d.SetMode("exe", modePrefix) },
			[]string{"# added to the top-level exclusions (applies to every rule)", "exclusions:", "rules:", "- '*'", "exe: {prefix: /tmp/build/}", "description: Build output, run by CI"},
			"exe prefix /tmp/build/; user eq ci",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newStoreHarness(t, storeTestPatterns)
			findings := h.attack("ci")
			if len(findings) != 1 {
				t.Fatalf("%d findings before any exclusion", len(findings))
			}

			draft := mustDraft(t, findings[0], "payload")
			c.adjust(&draft)

			preview := draft.Preview()
			for _, want := range c.wantYAML {
				if !strings.Contains(preview, want) {
					t.Errorf("preview lacks %q:\n%s", want, preview)
				}
			}

			if err := h.store.AddExclusion(draft); err != nil {
				t.Fatal(err)
			}

			// What was previewed is in the file, and the strict loader
			// accepts the whole file.
			saved := h.file()
			for _, line := range strings.Split(preview, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || line == "exclude:" || line == "exclusions:" {
					continue
				}
				if !strings.Contains(saved, strings.TrimPrefix(line, "- ")) {
					t.Errorf("the file lacks the previewed line %q:\n%s", line, saved)
				}
			}

			set, err := config.LoadPatterns(h.path)
			if err != nil || len(set.Errors) != 0 || len(set.Patterns) != 1 {
				t.Fatalf("after saving: err %v, errors %v, %d patterns", err, set.Errors, len(set.Patterns))
			}

			var loaded *correlation.MatchBlock
			if draft.AllRules {
				if len(set.Exclusions) != 1 || set.Exclusions[0].Description != "Build output, run by CI" || set.Exclusions[0].Rules[0] != "*" {
					t.Fatalf("top-level exclusions = %+v", set.Exclusions)
				}
				loaded = set.Exclusions[0].Match
			} else {
				exclude := set.Patterns[0].Exclude
				if len(exclude) != 1 || exclude[0].Role != "payload" || exclude[0].Description != "Build output, run by CI" {
					t.Fatalf("pattern exclude = %+v", exclude)
				}
				loaded = exclude[0].Match
			}
			if got := describeMatch(loaded); got != c.wantLoaded {
				t.Errorf("loaded match = %q, want %q", got, c.wantLoaded)
			}

			// The engine no longer reports it, for new processes too...
			if again := h.attack("ci"); len(again) != 0 {
				t.Errorf("still reported after the exclusion: %d finding(s)", len(again))
			}
			// ...but still reports what the exclusion does not cover: the
			// same program run by someone else, when the user was kept.
			want := 0
			if draft.field("user").Keep {
				want = 1
			}
			if other := h.attack("mallory"); len(other) != want {
				t.Errorf("another user's process: %d finding(s), want %d", len(other), want)
			}
		})
	}
}

func describeMatch(block *correlation.MatchBlock) string {
	if block == nil {
		return ""
	}
	parts := make([]string, 0, len(block.Fields))
	for _, f := range block.Fields {
		switch {
		case f.Predicate.Eq != nil:
			parts = append(parts, f.Field+" eq "+*f.Predicate.Eq)
		case f.Predicate.Prefix != nil:
			parts = append(parts, f.Field+" prefix "+*f.Predicate.Prefix)
		case f.Predicate.Contains != nil:
			parts = append(parts, f.Field+" contains "+*f.Predicate.Contains)
		}
	}
	return strings.Join(parts, "; ")
}

// Without the exclusion the same activity is reported every time: the test
// above would pass vacuously if it were not.
func TestAttackIsReportedEachTimeWithoutAnExclusion(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	for i := 0; i < 3; i++ {
		if got := h.attack("ci"); len(got) != 1 {
			t.Fatalf("attack %d: %d findings", i, len(got))
		}
	}
}

func TestExclusionForARuleThatIsNotLoaded(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	findings := h.attack("ci")

	draft := mustDraft(t, findings[0], "payload")
	draft.Rule = "a-rule-from-an-old-finding"
	before := h.file()

	err := h.store.AddExclusion(draft)
	if err == nil || !strings.Contains(err.Error(), "exclude for all rules instead") {
		t.Fatalf("err = %v", err)
	}
	if h.file() != before {
		t.Error("the file changed although nothing could be added")
	}
}

// --- YAML editor -----------------------------------------------------------

func TestPatternYAMLEditorSavesAValidPattern(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)

	text, err := h.store.PatternYAML(0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "name: tmp-binary-connects\n") {
		t.Fatalf("editor text:\n%s", text)
	}

	edited := strings.Replace(text, "prefix: /tmp/", "prefix: /dev/shm/", 1)
	edited = strings.Replace(edited, "severity: HIGH", "severity: CRITICAL", 1)
	if problems := h.store.SavePatternYAML(0, edited); len(problems) != 0 {
		t.Fatalf("a valid edit was rejected: %v", problems)
	}

	state := h.store.State()
	if len(state.Patterns) != 1 || state.Patterns[0].Severity != core.SeverityCritical || state.Source != "saved" {
		t.Errorf("state after save = %+v", state)
	}
	if !strings.Contains(h.file(), "prefix: /dev/shm/") {
		t.Errorf("the file was not updated:\n%s", h.file())
	}
	// The engine has it: /tmp no longer matches.
	if got := h.attack("ci"); len(got) != 0 {
		t.Errorf("the engine still has the old pattern: %d findings", len(got))
	}
	if h.changes() != 1 {
		t.Errorf("listeners were told %d times, want once", h.changes())
	}
}

func TestPatternYAMLEditorRejectsAnInvalidPattern(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	before := h.file()

	text, _ := h.store.PatternYAML(0)
	broken := strings.Replace(text, "match:", "mach:", 1)
	broken = strings.Replace(broken, "relationships:", "relationship:", 1)

	problems := h.store.SavePatternYAML(0, broken)
	if len(problems) != 2 {
		t.Fatalf("%d problems, want both typos: %v", len(problems), problems)
	}
	if problems[0].Path != "processes[1].mach" || problems[0].Line == 0 || problems[1].Path != "relationship" || problems[1].Line == 0 {
		t.Errorf("problems = %+v", problems)
	}
	if !strings.Contains(problems[0].String(), "processes[1].mach: unknown key") {
		t.Errorf("rendered: %s", problems[0])
	}

	// Well formed YAML that is not a usable pattern is rejected too.
	semantic := h.store.SavePatternYAML(0, "name: x\nprocesses:\n  - id: a\n  - id: b\n")
	if len(semantic) != 1 || !strings.Contains(semantic[0].Message, "no relationships") {
		t.Errorf("semantic problem = %v", semantic)
	}

	if h.file() != before {
		t.Error("an invalid pattern reached the file")
	}
	if h.changes() != 0 || len(h.store.State().Patterns) != 1 {
		t.Error("an invalid pattern changed the patterns in force")
	}
	if got := h.attack("ci"); len(got) != 1 {
		t.Errorf("the engine lost its pattern: %d findings", len(got))
	}
}

func TestNewPatternFromTemplate(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)

	if problems := h.store.SavePatternYAML(-1, config.PatternTemplate); len(problems) != 0 {
		t.Fatalf("the template was rejected: %v", problems)
	}
	state := h.store.State()
	if len(state.Patterns) != 2 || state.Patterns[1].Name != "new-pattern" || len(state.Problems()) != 0 {
		t.Fatalf("patterns after adding the template: %+v, problems %v", state.Patterns, state.Problems())
	}

	// A second pattern with the same name would be ambiguous.
	problems := h.store.SavePatternYAML(-1, config.PatternTemplate)
	if len(problems) != 1 || problems[0].Path != "name" || !strings.Contains(problems[0].Message, `already called "new-pattern"`) {
		t.Errorf("duplicate name: %v", problems)
	}
	// Renaming an existing pattern onto another's name, too; saving it
	// under its own name is fine.
	text, _ := h.store.PatternYAML(1)
	if problems := h.store.SavePatternYAML(1, text); len(problems) != 0 {
		t.Errorf("saving a pattern unchanged: %v", problems)
	}
	if problems := h.store.SavePatternYAML(0, text); len(problems) != 1 {
		t.Errorf("renaming onto an existing name: %v", problems)
	}
}

func TestExclusionsYAMLEditor(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)

	text, err := h.store.ExclusionsYAML()
	if err != nil || strings.TrimSpace(text) != "exclusions: []" {
		t.Fatalf("no exclusions yet: %q, %v", text, err)
	}

	before := h.file()
	problems := h.store.SaveExclusionsYAML("exclusions:\n  - rules: [\"*\"]\n    mach: {user: ci}\n")
	if len(problems) != 1 || problems[0].Path != "exclusions[0].mach" || problems[0].Line != 3 {
		t.Fatalf("problems = %+v", problems)
	}
	if h.file() != before {
		t.Error("invalid exclusions reached the file")
	}

	if problems := h.store.SaveExclusionsYAML("exclusions:\n  - rules: [\"*\"]\n    match: {user: ci}\n    description: CI account\n"); len(problems) != 0 {
		t.Fatal(problems)
	}
	if state := h.store.State(); len(state.Exclusions) != 1 || len(state.Patterns) != 1 {
		t.Errorf("state = %+v", state)
	}
	if got := h.attack("ci"); len(got) != 0 {
		t.Errorf("the engine does not have the exclusion: %d findings", len(got))
	}
	if got := h.attack("mallory"); len(got) != 1 {
		t.Errorf("another user: %d findings", len(got))
	}
}

func TestSavingWithoutWriteAccessSaysSo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}

	h := newStoreHarness(t, storeTestPatterns)
	dir := filepath.Dir(h.path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	if err := h.store.Writable(); err == nil {
		t.Fatal("a read-only directory was reported writable")
	}

	text, _ := h.store.PatternYAML(0)
	problems := h.store.SavePatternYAML(0, text)
	if len(problems) != 1 || !strings.Contains(problems[0].Message, "not allowed to write") {
		t.Errorf("pattern save: %v", problems)
	}
	if problems := h.store.SaveExclusionsYAML("exclusions: []\n"); len(problems) != 1 || !strings.Contains(problems[0].Message, "not allowed to write") {
		t.Errorf("exclusions save: %v", problems)
	}

	findings := h.attack("ci")
	if err := h.store.AddExclusion(mustDraft(t, findings[0], "payload")); err == nil || !strings.Contains(err.Error(), "not allowed to write") {
		t.Errorf("exclusion from a finding: %v", err)
	}
}

// --- Watcher ---------------------------------------------------------------

const testDebounce = 60 * time.Millisecond

func (h *storeHarness) watch() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	if err := h.store.Watch(ctx, testDebounce); err != nil {
		h.t.Fatal(err)
	}
}

func (h *storeHarness) awaitReloads(want int64) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.store.externalReloads.Load() < want {
		if time.Now().After(deadline) {
			h.t.Fatalf("%d external reload(s), want %d", h.store.externalReloads.Load(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// settle waits long enough for any pending change to have been acted on.
func settle() { time.Sleep(6 * testDebounce) }

func TestWatcherAppliesAnExternalEdit(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	h.watch()

	// Written in place, as a simple editor or `echo >` does.
	edited := strings.Replace(storeTestPatterns, "prefix: /tmp/", "prefix: /opt/", 1)
	if err := os.WriteFile(h.path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	h.awaitReloads(1)

	state := h.store.State()
	if state.Source != "file changed" || len(state.Problems()) != 0 {
		t.Errorf("state = %+v", state)
	}
	if got := h.attack("ci"); len(got) != 0 {
		t.Errorf("the engine still matches /tmp: %d findings", len(got))
	}
}

// vim, and most editors that care about your data, write a new file and
// rename it over the old one. The file being watched is then gone.
func TestWatcherAppliesAnEditMadeByRename(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	h.watch()

	for round, prefix := range []string{"/opt/", "/srv/"} {
		edited := strings.Replace(storeTestPatterns, "prefix: /tmp/", "prefix: "+prefix, 1)
		swap := filepath.Join(filepath.Dir(h.path), ".patterns.yaml.swp")
		if err := os.WriteFile(swap, []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(swap, h.path); err != nil {
			t.Fatal(err)
		}
		// The second round proves the watch survived the first rename.
		h.awaitReloads(int64(round + 1))

		yaml, _ := h.store.PatternYAML(0)
		if !strings.Contains(yaml, "prefix: "+prefix) {
			t.Errorf("round %d: pattern in force:\n%s", round, yaml)
		}
	}
}

func TestWatcherLoadsWhatIsValidAndReportsTheRest(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	h.watch()

	withABadOne := storeTestPatterns + `    - name: typo
      severity: LOW
      processes:
        - id: p
          mach: {name: x}
`
	if err := os.WriteFile(h.path, []byte(withABadOne), 0o644); err != nil {
		t.Fatal(err)
	}
	h.awaitReloads(1)

	state := h.store.State()
	if len(state.Patterns) != 1 || state.Patterns[0].Name != "tmp-binary-connects" {
		t.Errorf("valid patterns after a partly invalid edit: %+v", state.Patterns)
	}
	problems := state.Problems()
	if len(problems) != 1 || !strings.Contains(problems[0], `pattern[1] "typo": processes[0].mach: unknown key`) {
		t.Errorf("problems = %v", problems)
	}
	if got := h.attack("ci"); len(got) != 1 {
		t.Errorf("the valid pattern stopped working: %d findings", len(got))
	}

	// A file that is not YAML at all: keep what was loaded, and say so.
	if err := os.WriteFile(h.path, []byte("patterns: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.awaitReloads(2)

	state = h.store.State()
	if len(state.Patterns) != 1 || !strings.Contains(state.FileError, "keeping the patterns loaded before") {
		t.Errorf("after an unparseable edit: %d patterns, file error %q", len(state.Patterns), state.FileError)
	}
	if problems := state.Problems(); len(problems) == 0 || !strings.Contains(problems[0], "keeping the patterns loaded before") {
		t.Errorf("problems = %v", problems)
	}
	if got := h.attack("ci"); len(got) != 1 {
		t.Errorf("detection stopped after an unparseable edit: %d findings", len(got))
	}

	// Fixing the file clears the error.
	if err := os.WriteFile(h.path, []byte(storeTestPatterns), 0o644); err != nil {
		t.Fatal(err)
	}
	h.awaitReloads(3)
	if state := h.store.State(); state.FileError != "" || len(state.Problems()) != 0 {
		t.Errorf("after fixing the file: %+v", state)
	}
}

func TestWatcherIgnoresSentinelsOwnSaves(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	h.watch()

	text, _ := h.store.PatternYAML(0)
	if problems := h.store.SavePatternYAML(0, strings.Replace(text, "HIGH", "LOW", 1)); len(problems) != 0 {
		t.Fatal(problems)
	}
	findings := h.attack("ci")
	if err := h.store.AddExclusion(mustDraft(t, findings[0], "payload")); err != nil {
		t.Fatal(err)
	}
	if problems := h.store.SaveExclusionsYAML("exclusions:\n  - rules: [\"*\"]\n    match: {user: svc}\n"); len(problems) != 0 {
		t.Fatal(problems)
	}
	// A save that changes nothing is not a change.
	if problems := h.store.SaveExclusionsYAML(mustText(t, h.store.ExclusionsYAML)); len(problems) != 0 {
		t.Fatal(problems)
	}
	settle()

	if got := h.store.externalReloads.Load(); got != 0 {
		t.Errorf("Sentinel's own saves caused %d reload(s) through the watcher", got)
	}
	// Each save was applied once, by the save itself.
	if got := h.changes(); got != 3 {
		t.Errorf("listeners were told %d times for 3 saves", got)
	}

	// Other files in the directory are none of its business.
	os.WriteFile(filepath.Join(filepath.Dir(h.path), "notes.txt"), []byte("x"), 0o644)
	// Nor is the file being rewritten with the same contents.
	os.WriteFile(h.path, []byte(h.file()), 0o644)
	settle()
	if got := h.store.externalReloads.Load(); got != 0 {
		t.Errorf("%d reload(s) for changes that changed nothing", got)
	}
}

func TestWatcherDebouncesABurstOfWrites(t *testing.T) {
	h := newStoreHarness(t, storeTestPatterns)
	h.watch()

	// An editor writing in several steps, faster than the debounce.
	for i := 0; i < 8; i++ {
		edited := strings.Replace(storeTestPatterns, "prefix: /tmp/", "prefix: /step"+string(rune('0'+i))+"/", 1)
		if err := os.WriteFile(h.path, []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(testDebounce / 6)
	}
	h.awaitReloads(1)
	settle()

	if got := h.store.externalReloads.Load(); got != 1 {
		t.Errorf("%d reloads for one burst of writes, want 1", got)
	}
	yaml, _ := h.store.PatternYAML(0)
	if !strings.Contains(yaml, "prefix: /step7/") {
		t.Errorf("the last write is not the one in force:\n%s", yaml)
	}
}

func mustText(t *testing.T, get func() (string, error)) string {
	t.Helper()
	text, err := get()
	if err != nil {
		t.Fatal(err)
	}
	return text
}
