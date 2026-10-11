package main

import (
	"os"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
)

// These tests drive the desktop widgets through Fyne's test driver: no
// window is shown and nothing is drawn on a real screen. They check what the
// views do, not how they look.

func desktopFixture(t *testing.T) (*findingsModel, *storeHarness) {
	t.Helper()
	test.NewApp()

	h := newStoreHarness(t, uiTestPatterns)
	model := newFindingsModel(nil)
	model.Add(otherFinding(0, core.SeverityLow, "rule-a"))
	model.Add(downloadFinding(1))
	model.Add(otherFinding(2, core.SeverityHigh, "rule-a"))
	return model, h
}

func TestDesktopFindingsListFiltersAndActions(t *testing.T) {
	model, h := desktopFixture(t)

	view := newDesktopFindings(model, h.store)
	var copied []string
	var excluded []findingItem
	view.copyText = func(text string) { copied = append(copied, text) }
	view.exclude = func(item findingItem) { excluded = append(excluded, item) }
	test.NewWindow(view.root)

	if len(view.rows) != 3 || view.count.Text != "3 shown of 3 (3 new)" {
		t.Fatalf("list: %d rows, count %q", len(view.rows), view.count.Text)
	}
	if got := desktopRowText(view.rows[1]); !strings.Contains(got, "CRITICAL") || !strings.Contains(got, "download-and-execute — Downloaded file executed") || !strings.Contains(got, "x(4131)") || !strings.Contains(got, "new") {
		t.Errorf("row text = %q", got)
	}
	if severityImportance(view.rows[1]) != widget.DangerImportance || severityImportance(view.rows[2]) != widget.HighImportance {
		t.Error("rows are not coloured by severity")
	}

	// Nothing selected: nothing to act on.
	if !view.ack.Disabled() || !view.excludeBtn.Disabled() {
		t.Error("actions are enabled with no finding selected")
	}

	// Filters.
	if got := strings.Join(view.rule.Options, ","); got != "All rules,download-and-execute,rule-a" {
		t.Errorf("rule options = %q", got)
	}
	view.severity.SetSelected("CRITICAL")
	if len(view.rows) != 1 || view.rows[0].Key != "finding-b" {
		t.Fatalf("severity filter: %s", keysOf(view.rows))
	}
	view.severity.SetSelected(allSeverities)
	view.rule.SetSelected("rule-a")
	if keysOf(view.rows) != "other-c other-a" {
		t.Fatalf("rule filter: %s", keysOf(view.rows))
	}
	view.oldestFirst.SetChecked(true)
	if keysOf(view.rows) != "other-a other-c" {
		t.Fatalf("oldest first: %s", keysOf(view.rows))
	}
	view.oldestFirst.SetChecked(false)
	view.rule.SetSelected(allRules)

	// Selecting a finding shows everything about it.
	view.list.Select(1)
	if view.selected != "finding-b" {
		t.Fatalf("selected %q", view.selected)
	}
	for _, want := range []string{"CRITICAL  [download-and-execute]", "ROLES", "payload: x  pid 4131", "TIMELINE (4 events)", "$dropped = FILE_CREATE  /tmp/x"} {
		if !strings.Contains(view.detail.Text, want) {
			t.Errorf("detail lacks %q:\n%s", want, view.detail.Text)
		}
	}
	if view.ack.Disabled() || view.excludeBtn.Disabled() {
		t.Error("actions are disabled with a finding selected")
	}

	// Acknowledge, dismiss, and back to new.
	test.Tap(view.ack)
	if item, _ := model.Get("finding-b"); item.Status != core.StatusAcknowledged {
		t.Errorf("status after Acknowledge = %q", item.Status)
	}
	if !strings.Contains(view.detail.Text, "Status: acknowledged") || view.message.Text != "Marked acknowledged." || view.count.Text != "3 shown of 3 (2 new)" {
		t.Errorf("after Acknowledge: message %q, count %q", view.message.Text, view.count.Text)
	}
	test.Tap(view.dismiss)
	if item, _ := model.Get("finding-b"); item.Status != core.StatusDismissed {
		t.Errorf("status after Dismiss = %q", item.Status)
	}
	if severityImportance(view.rows[1]) != widget.LowImportance {
		t.Error("a dismissed finding is not played down")
	}
	view.status.SetSelected("dismissed")
	if keysOf(view.rows) != "finding-b" || view.selected != "finding-b" {
		t.Errorf("status filter: %s (selected %q)", keysOf(view.rows), view.selected)
	}
	view.status.SetSelected(allStatuses)
	test.Tap(view.renew)

	// Copy as JSON, and Exclude.
	test.Tap(view.copyJSON)
	if len(copied) != 1 || !strings.Contains(copied[0], `"rule": "download-and-execute"`) || !strings.Contains(copied[0], `"status": "new"`) {
		t.Errorf("copied = %v", copied)
	}
	test.Tap(view.excludeBtn)
	if len(excluded) != 1 || excluded[0].Key != "finding-b" {
		t.Errorf("exclude was asked for %v", excluded)
	}

	// A finding without evidence can be triaged but not excluded.
	model.Add(core.Finding{ID: "bare", Title: "No evidence", Severity: core.SeverityInfo, Timestamp: findingEpoch.AddDate(0, 0, 1)})
	view.Refresh()
	view.list.Select(0)
	if view.selected != "bare" || view.ack.Disabled() || !view.excludeBtn.Disabled() {
		t.Errorf("finding without evidence: selected %q, ack disabled %v, exclude disabled %v", view.selected, view.ack.Disabled(), view.excludeBtn.Disabled())
	}
}

func TestDesktopExcludeForm(t *testing.T) {
	model, h := desktopFixture(t)
	item, _ := model.Get("finding-b")

	closed := 0
	form, err := newDesktopExclude(item, model, h.store, func() { closed++ })
	if err != nil {
		t.Fatal(err)
	}
	test.NewWindow(form.root)

	// It starts on the finding's primary process, exact matches on the
	// executable and the user, and cannot be saved without a description.
	if form.role.Selected != "payload" || !form.keep["exe"].Checked || form.keep["cmdline"].Checked || form.value["exe"].Text != "/tmp/x" {
		t.Fatalf("form starts as role %q, exe kept %v, value %q", form.role.Selected, form.keep["exe"].Checked, form.value["exe"].Text)
	}
	if !form.saveBtn.Disabled() || !strings.Contains(form.problem.Text, "description is required") {
		t.Errorf("without a description: save disabled %v, problem %q", form.saveBtn.Disabled(), form.problem.Text)
	}
	if !strings.Contains(form.preview.Text, "exe: {eq: /tmp/x}") || !strings.Contains(form.preview.Text, `# added to the pattern "download-and-execute"`) {
		t.Errorf("preview:\n%s", form.preview.Text)
	}

	// Loosen the executable to its directory; the value and the preview
	// follow.
	form.mode["exe"].SetSelected("starts with")
	if form.value["exe"].Text != "/tmp/" || !strings.Contains(form.preview.Text, "exe: {prefix: /tmp/}") {
		t.Errorf("after loosening: value %q, preview:\n%s", form.value["exe"].Text, form.preview.Text)
	}

	// Add the command line as a substring the user types.
	form.keep["cmdline"].SetChecked(true)
	form.mode["cmdline"].SetSelected("contains")
	form.value["cmdline"].SetText("--daemon")
	form.keep["user"].SetChecked(false)
	if !strings.Contains(form.preview.Text, "cmdline: {contains: --daemon}") || strings.Contains(form.preview.Text, "user:") {
		t.Errorf("preview:\n%s", form.preview.Text)
	}

	// Another role offers that role's process instead.
	form.role.SetSelected("downloader")
	if form.value["exe"].Text != "/usr/bin/curl" || !strings.Contains(form.preview.Text, "role: downloader") {
		t.Errorf("after choosing downloader: exe %q, preview:\n%s", form.value["exe"].Text, form.preview.Text)
	}
	form.role.SetSelected("payload")
	form.mode["exe"].SetSelected("starts with")

	// All rules: a top-level exclusion.
	form.scope.SetSelected(scopeAllRules)
	if !strings.Contains(form.preview.Text, "# added to the top-level exclusions") || !strings.Contains(form.preview.Text, "- '*'") {
		t.Errorf("all-rules preview:\n%s", form.preview.Text)
	}
	form.scope.SetSelected(form.scopeThisRule())

	form.description.SetText("Deploy helper")
	if form.saveBtn.Disabled() || form.problem.Text != "" {
		t.Fatalf("with everything filled in: save disabled %v, problem %q", form.saveBtn.Disabled(), form.problem.Text)
	}

	before := h.file()
	if strings.Contains(before, "exclude:") {
		t.Fatal("written before Save")
	}
	test.Tap(form.saveBtn)

	saved := h.file()
	for _, want := range []string{"exclude:", "role: payload", "exe: {prefix: /tmp/}", "description: Deploy helper"} {
		if !strings.Contains(saved, want) {
			t.Errorf("the patterns file lacks %q:\n%s", want, saved)
		}
	}
	if closed != 1 {
		t.Errorf("the form was told it was done %d times", closed)
	}
	if item, _ := model.Get("finding-b"); item.Status != core.StatusDismissed {
		t.Errorf("the finding is %q after its exclusion was saved", item.Status)
	}
	if state := h.store.State(); len(state.Patterns[0].Exclude) != 1 || len(state.Problems()) != 0 {
		t.Errorf("patterns in force: %+v", state.Patterns[0].Exclude)
	}

	// A finding with no processes cannot start the form.
	if _, err := newDesktopExclude(findingItem{Finding: core.Finding{Rule: "r"}}, model, h.store, nil); err == nil {
		t.Error("a form was built for a finding without evidence")
	}
}

func TestDesktopYAMLEditor(t *testing.T) {
	_, h := desktopFixture(t)
	original := h.file()

	text, err := h.store.PatternYAML(0)
	if err != nil {
		t.Fatal(err)
	}

	saved := 0
	editor := newDesktopYAML(text, "", func(edited string) []config.EditError {
		return h.store.SavePatternYAML(0, edited)
	}, func() { saved++ })
	test.NewWindow(editor.root)

	if !editor.entry.TextStyle.Monospace || !strings.HasPrefix(editor.entry.Text, "name: download-and-execute\n") {
		t.Fatalf("editor starts with:\n%s", editor.entry.Text)
	}

	// An invalid edit: every problem listed, nothing written, editor open.
	editor.entry.SetText(strings.Replace(strings.Replace(text, "relationships:", "relationship:", 1), "sequence:", "sequnce:", 1))
	test.Tap(editor.saveBtn)

	for _, want := range []string{"2 problem(s) — nothing was saved:", "relationship: unknown key", "sequnce: unknown key", "✗ line "} {
		if !strings.Contains(editor.problems.Text, want) {
			t.Errorf("problems lack %q:\n%s", want, editor.problems.Text)
		}
	}
	if saved != 0 || h.file() != original {
		t.Fatal("an invalid pattern was saved")
	}

	// A valid edit.
	editor.entry.SetText(strings.Replace(text, "severity: CRITICAL", "severity: MEDIUM", 1))
	test.Tap(editor.saveBtn)
	if saved != 1 || editor.problems.Text != "" {
		t.Fatalf("valid edit: saved %d, problems %q", saved, editor.problems.Text)
	}
	if got := h.store.State().Patterns[0].Severity; got != core.SeverityMedium {
		t.Errorf("severity in force = %s", got)
	}

	// The template, as a new pattern.
	added := newDesktopYAML(config.PatternTemplate, "", func(edited string) []config.EditError {
		return h.store.SavePatternYAML(-1, edited)
	}, nil)
	if !added.trySave() || len(h.store.State().Patterns) != 2 {
		t.Errorf("template: %d patterns, problems %q", len(h.store.State().Patterns), added.problems.Text)
	}

	// The exclusions, with a mistake and then without.
	exclusions := newDesktopYAML("exclusions:\n  - rules: [\"*\"]\n    mach: {user: ci}\n", "", h.store.SaveExclusionsYAML, nil)
	if exclusions.trySave() || !strings.Contains(exclusions.problems.Text, "line 3: exclusions[0].mach: unknown key") {
		t.Errorf("exclusions with a typo: %q", exclusions.problems.Text)
	}
	exclusions.entry.SetText("exclusions:\n  - rules: [\"*\"]\n    match: {user: ci}\n    description: CI\n")
	if !exclusions.trySave() || len(h.store.State().Exclusions) != 1 {
		t.Errorf("valid exclusions: %q", exclusions.problems.Text)
	}

	// A file that cannot be written is announced when the editor opens.
	if os.Geteuid() != 0 {
		notice := "Sentinel is not allowed to write to /etc/sentinel"
		if readOnly := newDesktopYAML(text, notice, nil, nil); readOnly.problems.Text != notice {
			t.Errorf("notice = %q", readOnly.problems.Text)
		}
	}
}
