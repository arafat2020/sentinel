package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/rivo/tview"
)

// v2Fixture uses every part of the pattern schema the editors cannot edit:
// match blocks, event filters, per-pattern exclusions, a rate limit and
// top-level exclusions.
const v2Fixture = "../../internal/config/testdata/patterns_v2.yaml"

// rejectedPattern is a pattern that fails validation, so the editors never
// hold it.
const rejectedPattern = `    - name: broken
      severity: HIGH
      title: Does not load
      description: Kept in the file for the user to fix.
      processes:
        - id: only
          match:
            name: {regex: '('}
`

// fixtureCopy writes the v2 fixture, with a rejected pattern inserted, to a
// temporary file and returns its path.
func fixtureCopy(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(v2Fixture)
	if err != nil {
		t.Fatal(err)
	}

	content := strings.Replace(string(data), "exclusions:\n", rejectedPattern+"exclusions:\n", 1)
	if content == string(data) {
		t.Fatal("fixture has no exclusions section to insert before")
	}

	path := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadSet(t *testing.T, path string) config.PatternSet {
	t.Helper()
	set, err := config.LoadPatterns(path)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// wantAfterTitleEdit is what the file must load as once only the first
// pattern's title has been changed: everything else exactly as before.
func wantAfterTitleEdit(original config.PatternSet, title string) config.PatternSet {
	want := original
	want.Patterns = append([]correlation.BehaviorPattern(nil), original.Patterns...)
	want.Patterns[0].Title = title

	// The rejected pattern is written after the ones the editor holds, so
	// its position in the file, and therefore in the error, moves.
	want.Errors = append([]config.PatternError(nil), original.Errors...)
	for i := range want.Errors {
		if !want.Errors[i].Exclusion {
			want.Errors[i].Index = len(want.Patterns) + i
		}
	}
	return want
}

// normalized returns a deep copy of patterns in which empty slices are nil.
// The editors copy patterns, and a copied empty list is a nil one; that is
// not a difference in content.
func normalized(patterns []correlation.BehaviorPattern) []correlation.BehaviorPattern {
	out := make([]correlation.BehaviorPattern, len(patterns))

	for i, p := range patterns {
		roles := make([]correlation.ProcessPattern, len(p.Processes))
		for j, role := range p.Processes {
			role.Conditions = append([]correlation.Condition(nil), role.Conditions...)
			role.Events = append([]correlation.EventPattern(nil), role.Events...)
			roles[j] = role
		}

		p.Processes = roles
		p.Relationships = append([]correlation.RelationshipPattern(nil), p.Relationships...)
		p.Exclude = append([]correlation.RoleExclusion(nil), p.Exclude...)
		out[i] = p
	}

	return out
}

// clonePatterns gives an editor its own copy to work on, so the test still
// has the original to compare against.
func clonePatterns(patterns []correlation.BehaviorPattern) []correlation.BehaviorPattern {
	return normalized(patterns)
}

func assertSameSet(t *testing.T, got, want config.PatternSet) {
	t.Helper()

	if !reflect.DeepEqual(normalized(got.Patterns), normalized(want.Patterns)) {
		t.Errorf("patterns changed beyond the edit:\n got %+v\nwant %+v", got.Patterns, want.Patterns)
	}
	if !reflect.DeepEqual(got.Exclusions, want.Exclusions) {
		t.Errorf("top-level exclusions changed:\n got %+v\nwant %+v", got.Exclusions, want.Exclusions)
	}
	if len(got.Errors) != len(want.Errors) {
		t.Fatalf("rejected patterns: got %v, want %v", got.Errors, want.Errors)
	}
	for i := range want.Errors {
		if got.Errors[i].Name != want.Errors[i].Name || got.Errors[i].Error() != want.Errors[i].Error() {
			t.Errorf("rejected pattern %d: got %q, want %q", i, got.Errors[i], want.Errors[i])
		}
	}
}

// The TUI editor understands only the original fields. Editing a title
// through it and saving must leave match blocks, event filters, exclusions,
// the rate limit, the top-level exclusions and patterns that failed to load
// exactly as they were.
func TestTUIEditorRoundTripsAdvancedFields(t *testing.T) {
	path := fixtureCopy(t)
	original := loadSet(t, path)
	if len(original.Patterns) != 2 || len(original.Exclusions) != 2 || len(original.Errors) != 1 {
		t.Fatalf("fixture loaded as %d patterns, %d exclusions, %d errors", len(original.Patterns), len(original.Exclusions), len(original.Errors))
	}

	var saved []correlation.BehaviorPattern
	page := NewPatternsPage(tview.NewApplication(), tview.NewPages(), path, clonePatterns(original.Patterns),
		func(updated []correlation.BehaviorPattern) { saved = updated })
	page.SetLoadErrors(original.Errors)

	// The same path a user takes: select the pattern, type in the Title
	// field, press Save.
	page.selectPattern(0)
	title, ok := page.form.GetFormItemByLabel("Title").(*tview.InputField)
	if !ok {
		t.Fatal("the pattern form has no Title field")
	}
	title.SetText("Edited in the TUI")
	page.savePattern()

	if len(saved) != 2 || saved[0].Title != "Edited in the TUI" {
		t.Fatalf("onSave received %+v", saved)
	}

	want := wantAfterTitleEdit(original, "Edited in the TUI")
	assertSameSet(t, loadSet(t, path), want)

	// What reaches the engine is equally intact.
	if !reflect.DeepEqual(normalized(saved), normalized(want.Patterns)) {
		t.Errorf("patterns handed to the engine lost data:\n got %+v\nwant %+v", saved, want.Patterns)
	}
}

func TestTUIEditorPreservesRoleFieldsThroughProcessEdits(t *testing.T) {
	path := fixtureCopy(t)
	original := loadSet(t, path)

	page := NewPatternsPage(tview.NewApplication(), tview.NewPages(), path, clonePatterns(original.Patterns), nil)
	page.selectPattern(0)

	// What the process editor does: change a role's v1 fields in place.
	shell := &page.draft.Processes[1]
	shell.Conditions = append(shell.Conditions, correlation.Condition{Type: correlation.ConditionProcessName, Value: "sh"})
	shell.Events = append(shell.Events, correlation.EventPattern{Type: core.EventFileDelete})
	page.savePattern()

	got := loadSet(t, path).Patterns[0].Processes[1]
	want := original.Patterns[0].Processes[1]

	if !reflect.DeepEqual(got.Match, want.Match) {
		t.Errorf("the role's match block changed:\n got %+v\nwant %+v", got.Match, want.Match)
	}
	if len(got.Events) != len(want.Events)+1 || !reflect.DeepEqual(got.Events[:len(want.Events)], want.Events) {
		t.Errorf("existing event filters changed:\n got %+v\nwant %+v", got.Events, want.Events)
	}
	if len(got.Conditions) != len(want.Conditions)+1 {
		t.Errorf("conditions = %+v", got.Conditions)
	}
}

func TestDesktopEditorRoundTripsAdvancedFields(t *testing.T) {
	path := fixtureCopy(t)
	original := loadSet(t, path)

	var saved []correlation.BehaviorPattern
	ui := &DesktopUI{patternEditIdx: -1}
	ui.SetPatternErrors(original.Errors)
	ui.SetPatterns(path, clonePatterns(original.Patterns),
		func(updated []correlation.BehaviorPattern) { saved = updated })

	// What the Save button does with the form's contents.
	first := original.Patterns[0]
	ui.applyPatternEdit(0, first.Name, "Edited on the desktop", first.Description, first.Severity)
	ui.commitPatterns()

	want := wantAfterTitleEdit(original, "Edited on the desktop")
	assertSameSet(t, loadSet(t, path), want)

	if !reflect.DeepEqual(normalized(saved), normalized(want.Patterns)) {
		t.Errorf("patterns handed to the engine lost data:\n got %+v\nwant %+v", saved, want.Patterns)
	}
}

func TestTUIMarksAdvancedPatternsAndShowsLoadErrors(t *testing.T) {
	path := fixtureCopy(t)
	set := loadSet(t, path)

	page := NewPatternsPage(tview.NewApplication(), tview.NewPages(), path, set.Patterns, nil)

	// Without load errors and with valid patterns there is nothing to show.
	if text := page.problems.GetText(true); text != "" {
		t.Errorf("problems panel shown with nothing wrong: %q", text)
	}

	page.SetLoadErrors(set.Errors)
	problems := page.problems.GetText(true)
	for _, want := range []string{`"broken"`, `role "only"`, "match.name", "bad regex"} {
		if !strings.Contains(problems, want) {
			t.Errorf("problems panel %q does not mention %q", problems, want)
		}
	}

	advanced, _ := page.list.GetItemText(0)
	plain, _ := page.list.GetItemText(1)
	if !strings.Contains(advanced, "⚙") || strings.Contains(plain, "⚙") {
		t.Errorf("list markers: v2 pattern %q, v1 pattern %q", advanced, plain)
	}

	// The form says why the advanced parts cannot be edited here.
	page.selectPattern(0)
	note, ok := page.form.GetFormItemByLabel("Advanced").(*tview.TextView)
	if !ok || !strings.Contains(note.GetText(true), advancedFieldsNote) {
		t.Errorf("the form for a v2 pattern does not carry the %q note", advancedFieldsNote)
	}
	page.selectPattern(1)
	if page.form.GetFormItemByLabel("Advanced") != nil {
		t.Error("the form for a v1 pattern carries the advanced-fields note")
	}
}

func TestPatternProblemsCoversFileAndEditorMistakes(t *testing.T) {
	set := loadSet(t, fixtureCopy(t))

	// An editor can produce a pattern that does not validate: two roles and
	// no relationship.
	unrelated := correlation.BehaviorPattern{
		Name:      "from-editor",
		Processes: []correlation.ProcessPattern{{ID: "a"}, {ID: "b"}},
	}

	problems := patternProblems(set.Errors, append(set.Patterns, unrelated))
	if len(problems) != 2 {
		t.Fatalf("problems = %q, want the rejected file entry and the editor's pattern", problems)
	}
	if !strings.Contains(problems[0], `"broken"`) || !strings.Contains(problems[0], "bad regex") {
		t.Errorf("file problem = %q", problems[0])
	}
	if !strings.Contains(problems[1], `"from-editor"`) || !strings.Contains(problems[1], "no relationships") {
		t.Errorf("editor problem = %q", problems[1])
	}

	if got := patternProblems(nil, correlation.DefaultPatterns()); len(got) != 0 {
		t.Errorf("the default patterns are reported as having problems: %q", got)
	}
}

func TestLoadPatternSetFallsBackOnlyForUnusableFiles(t *testing.T) {
	// A file with one bad entry is used, minus that entry.
	set, err := loadPatternSet(fixtureCopy(t))
	if err != nil || len(set.Patterns) != 2 || len(set.Errors) != 1 {
		t.Fatalf("partial file: %d patterns, %d errors, err=%v", len(set.Patterns), len(set.Errors), err)
	}

	// A file that cannot be parsed at all falls back to the defaults.
	broken := filepath.Join(t.TempDir(), "patterns.yaml")
	if err := os.WriteFile(broken, []byte("patterns: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err = loadPatternSet(broken)
	if err == nil {
		t.Fatal("a malformed file should be reported")
	}
	if !reflect.DeepEqual(set.Patterns, correlation.DefaultPatterns()) {
		t.Errorf("fallback patterns = %+v, want the defaults", set.Patterns)
	}
}

// The same guarantee for the temporal parts of the schema: DESCENDANT with
// its depth, thresholds, and a sequence with a capture.
func TestEditorsRoundTripTemporalFields(t *testing.T) {
	const v3Fixture = "../../internal/config/testdata/patterns_v3.yaml"

	data, err := os.ReadFile(v3Fixture)
	if err != nil {
		t.Fatal(err)
	}

	for name, edit := range map[string]func(path string, patterns []correlation.BehaviorPattern){
		"TUI": func(path string, patterns []correlation.BehaviorPattern) {
			page := NewPatternsPage(tview.NewApplication(), tview.NewPages(), path, patterns, nil)
			page.selectPattern(0)
			page.form.GetFormItemByLabel("Title").(*tview.InputField).SetText("Edited")

			// Opening the relationship editor must not rewrite the type.
			page.openRelationshipDetailEditor("patterns", 0, func() {})
			page.savePattern()
		},
		"desktop": func(path string, patterns []correlation.BehaviorPattern) {
			ui := &DesktopUI{patternEditIdx: -1}
			ui.SetPatterns(path, patterns, nil)
			ui.applyPatternEdit(0, patterns[0].Name, "Edited", patterns[0].Description, patterns[0].Severity)
			ui.commitPatterns()
		},
	} {
		path := filepath.Join(t.TempDir(), "patterns.yaml")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}

		original := loadSet(t, path)
		if len(original.Errors) != 0 || len(original.Patterns) != 2 {
			t.Fatalf("fixture loaded as %d patterns with errors %v", len(original.Patterns), original.Errors)
		}

		edit(path, clonePatterns(original.Patterns))

		want := wantAfterTitleEdit(original, "Edited")
		got := loadSet(t, path)
		if !reflect.DeepEqual(normalized(got.Patterns), normalized(want.Patterns)) {
			t.Errorf("%s editor changed more than the title:\n got %+v\nwant %+v", name, got.Patterns, want.Patterns)
		}

		saved := got.Patterns[0]
		if saved.Relationships[0].Type != correlation.RelationshipDescendant || saved.Relationships[0].MaxDepth != 4 {
			t.Errorf("%s editor: relationship = %+v, want DESCENDANT with max_depth 4", name, saved.Relationships[0])
		}
		if saved.Sequence == nil || len(saved.Sequence.Steps) != 3 || saved.Sequence.Steps[1].Capture != "dropped" {
			t.Errorf("%s editor: sequence = %+v", name, saved.Sequence)
		}
		if event := saved.Processes[1].Events[0]; event.Count != 20 || event.Distinct != "domain" {
			t.Errorf("%s editor: threshold = %+v", name, event)
		}
	}
}
