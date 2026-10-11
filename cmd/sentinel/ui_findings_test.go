package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/eventbus"
	"github.com/arafat2020/sentinel/internal/store"
)

// uiTestPatterns has the rule the test findings come from, so that an
// exclusion can be attached to it and its captures can be shown.
const uiTestPatterns = `patterns:
    - name: download-and-execute
      severity: CRITICAL
      title: Downloaded file executed
      description: A downloaded file was run.
      processes:
        - id: launcher
        - id: downloader
        - id: payload
      relationships:
        - {type: SPAWNED, parent: launcher, child: downloader}
        - {type: SPAWNED, parent: launcher, child: payload}
      sequence:
        within: 1m0s
        steps:
            - {role: downloader, type: NETWORK_CONNECT}
            - role: downloader
              type: FILE_CREATE
              capture: dropped
            - role: payload
              type: PROCESS_START
              where:
                exe: {eq: $dropped.path}
`

// fullHarness is the dashboard as main() assembles it: findings, patterns
// with the pattern-file service, the footer.
type fullHarness struct {
	*uiHarness
	model    *findingsModel
	patterns *patternStore
	path     string
	copied   []string
}

func newFullHarness(t *testing.T) *fullHarness {
	t.Helper()

	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "sentinel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	path := filepath.Join(dir, "configs", "patterns.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(uiTestPatterns), 0o644); err != nil {
		t.Fatal(err)
	}

	set, loadErr := loadPatternSet(path)
	engine := correlation.NewEngine(time.Minute)
	engine.SetPatterns(set.Patterns)
	patterns := newPatternStore(path, engine, set, loadErr)

	model := newFindingsModel(db)
	model.Add(otherFinding(0, core.SeverityLow, "rule-a"))
	model.Add(downloadFinding(1))
	model.Add(otherFinding(2, core.SeverityHigh, "rule-a"))

	ui := NewUI()
	settings := newSettingsPage(ui.app, db, (&fakeSSH{}).ops())
	ui.SetSettingsPage(settings)

	page := NewPatternsPage(ui.app, ui.pages, path, nil, nil)
	page.SetStore(patterns)
	ui.SetPatternsPage(page)

	ui.SetFindings(model, patterns)
	ui.SetStatusLine(func() string {
		total, unhandled := model.Counts()
		return summaryLine("ebpf", patterns.State(), total, unhandled)
	})

	h := &fullHarness{model: model, patterns: patterns, path: path}
	ui.findings.copyText = func(text string) { h.copied = append(h.copied, text) }

	h.uiHarness = &uiHarness{t: t, ui: ui, settings: settings, ssh: &fakeSSH{}, screen: tcell.NewSimulationScreen("UTF-8")}
	h.start(ui.app)
	return h
}

func (h *fullHarness) typeText(text string) {
	h.t.Helper()
	for _, r := range text {
		if r == '\n' {
			h.key(tcell.KeyEnter, 0)
			continue
		}
		h.key(tcell.KeyRune, r)
	}
}

func (h *fullHarness) keys(k tcell.Key, times int) {
	h.t.Helper()
	for i := 0; i < times; i++ {
		h.key(k, 0)
	}
}

func (h *fullHarness) wantNotOnScreen(unwanted string) {
	h.t.Helper()
	if text := h.screenText(); strings.Contains(text, unwanted) {
		h.t.Fatalf("screen shows %q:\n%s", unwanted, text)
	}
}

// fromAnotherGoroutine runs f off the event loop, as a collector or the file
// watcher would, and returns once the loop has caught up with it.
func (h *fullHarness) fromAnotherGoroutine(f func()) {
	h.t.Helper()

	// Forget wake-ups already handled: the one to wait for is f's.
	h.onLoop(func() {})
	for drained := false; !drained; {
		select {
		case <-h.ticks:
		default:
			drained = true
		}
	}

	go f()
	select {
	case <-h.ticks:
	case <-time.After(loopTimeout):
		h.t.Fatal("the change never reached the event loop")
	}
	h.onLoop(func() {})
}

func (h *fullHarness) status(key string) core.FindingStatus {
	item, _ := h.model.Get(key)
	return item.Status
}

// The whole path on an 80x25 terminal: list, filters, detail, actions, JSON.
func TestFindingsListDetailAndActions(t *testing.T) {
	h := newFullHarness(t)

	if w, rows := h.screen.Size(); w != 80 || rows != 25 {
		t.Fatalf("screen is %dx%d, want 80x25", w, rows)
	}

	h.key(tcell.KeyRune, '5')
	h.wantTab(tabFindings)

	// The list: a header, every finding newest first, and a footer.
	for _, want := range []string{
		"TIME", "SEVERITY", "RULE", "TITLE", "PROCESS", "STATUS",
		"3/3 shown, 3 new", "newest first",
		"CRITICAL", "download-and-execute", "x(4131)", "new",
		"[Enter] Details",
		"collector: ebpf   patterns: 1   pattern errors: 0   findings: 3 new / 3",
	} {
		h.wantOnScreen(want)
	}
	screen := h.screenText()
	if strings.Index(screen, "HIGH") > strings.Index(screen, "CRITICAL") || strings.Index(screen, "CRITICAL") > strings.Index(screen, "LOW ") {
		t.Fatalf("the list is not newest first:\n%s", screen)
	}
	for i, line := range strings.Split(strings.TrimRight(screen, "\n"), "\n") {
		if len([]rune(line)) != 80 {
			t.Fatalf("row %d is %d columns wide", i, len([]rune(line)))
		}
	}

	// Filters cycle from the keyboard.
	h.key(tcell.KeyRune, 's')
	h.wantOnScreen("1/3 shown")
	h.wantOnScreen("sev:CRITICAL")
	for i := 0; i < len(filterSeverities)-1; i++ {
		h.key(tcell.KeyRune, 's')
	}
	h.wantOnScreen("3/3 shown")
	h.key(tcell.KeyRune, 'r')
	h.wantOnScreen("rule:download-and-execute")
	h.key(tcell.KeyRune, 'r')
	h.wantOnScreen("rule:rule-a")
	h.wantOnScreen("2/3 shown")
	h.key(tcell.KeyRune, 'r')
	h.key(tcell.KeyRune, 'o')
	h.wantOnScreen("oldest first")
	h.key(tcell.KeyRune, 'o')

	// The selection starts on the newest; the second row is the download.
	h.key(tcell.KeyDown, 0)
	h.key(tcell.KeyEnter, 0)

	// The detail view has the whole screen: header, roles, timeline.
	for _, want := range []string{
		"CRITICAL  [download-and-execute]  Downloaded file executed",
		"Status: new",
		"ROLES",
		"downloader: curl  pid 4125  ppid 4120  user www-data",
		"exe      /usr/bin/curl",
		"E[x]clude",
		"[Esc] Back to list",
	} {
		h.wantOnScreen(want)
	}
	h.wantNotOnScreen("3/3 shown")

	// Further down: the earlier image, the timeline and the capture.
	h.keys(tcell.KeyPgDn, 1)
	for _, want := range []string{"was      sh  (/usr/bin/dash)", "TIMELINE (4 events)", "+1.060s   NETWORK_CONNECT  downloader tcp 203.0.113.9:80"} {
		h.wantOnScreen(want)
	}
	h.keys(tcell.KeyPgDn, 2)
	h.wantOnScreen("$dropped = FILE_CREATE  /tmp/x")

	// Acknowledge from the detail view.
	h.key(tcell.KeyRune, 'a')
	if got := h.status("finding-b"); got != core.StatusAcknowledged {
		t.Fatalf("status after 'a' = %q", got)
	}
	h.keys(tcell.KeyPgUp, 5)
	h.wantOnScreen("Acknowledged.")
	h.wantOnScreen("Status: acknowledged")

	// Copy as JSON.
	h.key(tcell.KeyRune, 'c')
	h.wantOnScreen("Finding as JSON")
	h.wantOnScreen(`"rule": "download-and-execute"`)
	if len(h.copied) != 1 || !strings.Contains(h.copied[0], `"status": "acknowledged"`) || !strings.Contains(h.copied[0], `"command_line"`) {
		t.Fatalf("copied = %v", h.copied)
	}
	h.key(tcell.KeyEscape, 0)
	h.wantOnScreen("Status: acknowledged")

	// Back to the list, which shows the new status and keeps its place.
	h.key(tcell.KeyEscape, 0)
	h.wantOnScreen(" ack ")
	h.wantOnScreen("3/3 shown, 2 new")
	h.wantOnScreen("findings: 2 new / 3")

	// Dismiss from the list, and filter by status.
	h.key(tcell.KeyUp, 0)
	h.key(tcell.KeyRune, 'd')
	if got := h.status("other-c"); got != core.StatusDismissed {
		t.Fatalf("status after 'd' = %q", got)
	}
	h.key(tcell.KeyRune, 't')
	h.wantOnScreen("status:new")
	h.wantOnScreen("1/3 shown")
	h.key(tcell.KeyRune, 'n') // nothing new is selected to change by accident
	for i := 0; i < len(filterStatuses)-1; i++ {
		h.key(tcell.KeyRune, 't')
	}
	h.wantOnScreen("3/3 shown")

	// A finding arriving from the engine appears without a key press.
	h.fromAnotherGoroutine(func() { h.model.Add(otherFinding(5, core.SeverityMedium, "rule-z")) })
	h.wantOnScreen("4/4 shown")
	h.wantOnScreen("MEDIUM")
	h.wantOnScreen("findings: 2 new / 4")

	// The tab keys still work from the list.
	h.key(tcell.KeyRune, '1')
	h.wantTab(tabProcess)
	h.key(tcell.KeyRune, '5')
	h.wantTab(tabFindings)
	h.wantOnScreen("4/4 shown")
}

// "Exclude…" from the detail view, entirely from the keyboard: loosen the
// executable to its directory, describe, preview, save.
func TestExcludeFromFindingInTheTUI(t *testing.T) {
	h := newFullHarness(t)

	h.key(tcell.KeyRune, '5')
	h.key(tcell.KeyDown, 0)
	h.key(tcell.KeyEnter, 0)
	h.key(tcell.KeyRune, 'x')

	// The form starts on the finding's primary process.
	h.wantOnScreen("Exclude findings like this one")
	h.wantOnScreen("Process in role")
	h.wantOnScreen("payload")
	h.wantOnScreen("Match exe")
	h.wantOnScreen("/tmp/x")

	// Role, then "Match exe", then "exe is": open it and take "starts
	// with".
	h.keys(tcell.KeyTab, 2)
	h.key(tcell.KeyEnter, 0)
	h.key(tcell.KeyDown, 0)
	h.key(tcell.KeyEnter, 0)
	h.wantOnScreen("starts with")

	// On to the description: value, then cmdline (3 items), user (2), name
	// (2), scope.
	h.keys(tcell.KeyTab, 10)
	h.typeText("Deploy helper, runs from /tmp")
	h.wantOnScreen("Deploy helper, runs from /tmp")

	// Preview shows exactly what will be written.
	h.key(tcell.KeyTab, 0)
	h.key(tcell.KeyEnter, 0)
	for _, want := range []string{
		"This will be added to the patterns file",
		`# added to the pattern "download-and-execute"`,
		"exclude:",
		"role: payload",
		"exe: {prefix: /tmp/}",
		"user: {eq: www-data}",
		"description: Deploy helper, runs from /tmp",
		"Save exclusion",
	} {
		h.wantOnScreen(want)
	}

	before, _ := os.ReadFile(h.path)
	if strings.Contains(string(before), "exclude:") {
		t.Fatal("the exclusion was written before it was confirmed")
	}

	h.key(tcell.KeyEnter, 0)

	// Saved, applied, and this finding is dealt with.
	h.wantOnScreen("Exclusion saved and applied. This finding is dismissed.")
	h.wantOnScreen("Status: dismissed")
	if got := h.status("finding-b"); got != core.StatusDismissed {
		t.Fatalf("status = %q", got)
	}

	saved, _ := os.ReadFile(h.path)
	for _, want := range []string{"exclude:", "role: payload", "exe: {prefix: /tmp/}", "description: Deploy helper, runs from /tmp"} {
		if !strings.Contains(string(saved), want) {
			t.Errorf("the patterns file lacks %q:\n%s", want, saved)
		}
	}
	state := h.patterns.State()
	if len(state.Patterns) != 1 || len(state.Patterns[0].Exclude) != 1 || len(state.Problems()) != 0 {
		t.Errorf("patterns in force = %+v, problems %v", state.Patterns, state.Problems())
	}

	// Cancelling leaves everything alone.
	h.key(tcell.KeyRune, 'x')
	h.wantOnScreen("Exclude findings like this one")
	h.key(tcell.KeyEscape, 0)
	h.wantOnScreen("Status: dismissed")
	if after, _ := os.ReadFile(h.path); string(after) != string(saved) {
		t.Error("cancelling changed the file")
	}
}

// Nothing can be saved without a description, and the form says so.
func TestExcludeNeedsADescription(t *testing.T) {
	h := newFullHarness(t)

	h.key(tcell.KeyRune, '5')
	h.key(tcell.KeyDown, 0)
	h.key(tcell.KeyRune, 'x') // straight from the list

	h.keys(tcell.KeyTab, 13) // to Preview, leaving the description empty
	h.key(tcell.KeyEnter, 0)

	h.wantOnScreen("a description is required")
	h.wantNotOnScreen("Save exclusion")
	h.key(tcell.KeyEnter, 0) // Back
	h.wantOnScreen("Exclude findings like this one")

	if data, _ := os.ReadFile(h.path); strings.Contains(string(data), "exclude:") {
		t.Error("an exclusion without a description was written")
	}
}

// The YAML editor: an invalid edit is refused with its problems listed and
// the file untouched; a valid one is saved and applied.
func TestPatternYAMLEditorInTheTUI(t *testing.T) {
	h := newFullHarness(t)
	original, _ := os.ReadFile(h.path)

	h.key(tcell.KeyRune, '6')
	h.wantTab(tabPatterns)
	h.wantOnScreen("[Y] Edit YAML")
	h.wantOnScreen("download-and-execute")

	h.key(tcell.KeyRune, 'y')
	h.wantOnScreen("Edit pattern download-and-execute (YAML)")
	h.wantOnScreen("name: download-and-execute")
	h.wantOnScreen("[Ctrl+S] Check and save")

	// Two mistakes at the top of the file.
	h.typeText("severty: HIGH\nprocesess: []\n")
	h.key(tcell.KeyCtrlS, 0)

	for _, want := range []string{
		"2 problem(s) — nothing was saved",
		"line 1: severty: unknown key (valid keys here:",
		"line 2: procesess: unknown key",
	} {
		h.wantOnScreen(want)
	}
	// Still in the editor, with what was typed.
	h.wantOnScreen("severty: HIGH")
	if now, _ := os.ReadFile(h.path); string(now) != string(original) {
		t.Fatal("an invalid pattern was written to disk")
	}

	// Esc with unsaved changes asks first.
	h.key(tcell.KeyEscape, 0)
	h.wantOnScreen("Unsaved changes")
	h.wantOnScreen("severty: HIGH")

	// Remove the mistakes (the cursor was put on line 1) and change the
	// severity for real.
	h.keys(tcell.KeyCtrlK, 1)
	h.keys(tcell.KeyDelete, 1)
	h.keys(tcell.KeyCtrlK, 1)
	h.keys(tcell.KeyDelete, 1)
	h.wantNotOnScreen("severty")
	h.wantNotOnScreen("procesess")
	h.key(tcell.KeyDown, 0)
	h.key(tcell.KeyEnd, 0)
	h.keys(tcell.KeyBackspace2, len("CRITICAL"))
	h.typeText("LOW")
	h.key(tcell.KeyCtrlS, 0)

	h.wantOnScreen("Saved and applied.")
	h.key(tcell.KeyEnter, 0)
	h.wantNotOnScreen("Check and save")

	if state := h.patterns.State(); len(state.Patterns) != 1 || state.Patterns[0].Severity != core.SeverityLow {
		t.Fatalf("pattern in force after the edit: %+v", state.Patterns)
	}
	if now, _ := os.ReadFile(h.path); !strings.Contains(string(now), "severity: LOW") {
		t.Errorf("the file was not updated:\n%s", now)
	}

	// A new pattern from the template.
	h.key(tcell.KeyRune, 't')
	h.wantOnScreen("New pattern (YAML)")
	h.wantOnScreen("# A pattern describes processes (roles)")
	h.key(tcell.KeyCtrlS, 0)
	h.wantOnScreen("Saved and applied.")
	h.key(tcell.KeyEnter, 0)
	h.wantOnScreen("new-pattern")
	if got := len(h.patterns.State().Patterns); got != 2 {
		t.Errorf("%d patterns after adding the template", got)
	}
	h.wantOnScreen("patterns: 2")

	// The top-level exclusions, and leaving without changes.
	h.key(tcell.KeyRune, 'x')
	h.wantOnScreen("Top-level exclusions (YAML)")
	h.wantOnScreen("exclusions: []")
	h.key(tcell.KeyEscape, 0)
	h.wantNotOnScreen("Top-level exclusions")

	// The tab keys work again once the editor is closed; while it was
	// open, arrows moved the cursor.
	h.key(tcell.KeyLeft, 0)
	h.wantTab(tabFindings)
}

// A change made to the patterns file outside Sentinel shows up: the errors in
// the Patterns tab, the count in the footer, and both in Health.
func TestExternalPatternChangeReachesTheTUI(t *testing.T) {
	h := newFullHarness(t)
	h.ui.SetHealth((&health{
		collection: &processCollection{requested: "poll"},
		bus:        newTestBus(),
		engine:     h.patterns.engine,
		patterns:   h.patterns,
	}).Text)

	h.key(tcell.KeyRune, '6')
	h.wantOnScreen("pattern errors: 0")

	broken := uiTestPatterns + `    - name: typo
      processes:
        - id: p
          mach: {name: x}
`
	if err := os.WriteFile(h.path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	h.fromAnotherGoroutine(func() { h.patterns.refresh("file changed") })

	h.wantOnScreen("pattern errors: 1")
	h.wantOnScreen("Pattern errors")
	h.wantOnScreen(`pattern[1] "typo": processes[0].mach: unknown key`)
	h.wantOnScreen("download-and-execute") // the valid pattern is still listed

	h.keys(tcell.KeyRight, 3)
	h.wantTab(tabHealth)
	h.wantOnScreen("ATTENTION pattern errors 1")
	h.wantOnScreen("Patterns  loaded 1   exclusions 0   errors 1")
	h.wantOnScreen("Latency   event to finding: p50")

	// Fixed again.
	if err := os.WriteFile(h.path, []byte(uiTestPatterns), 0o644); err != nil {
		t.Fatal(err)
	}
	h.fromAnotherGoroutine(func() { h.patterns.refresh("file changed") })
	h.wantOnScreen("pattern errors: 0")
}

func TestHealthAlerts(t *testing.T) {
	quiet := healthReport{}
	if alerts := quiet.Alerts(); len(alerts) != 0 {
		t.Errorf("a clean report has alerts: %v", alerts)
	}
	if strings.Contains(strings.Join(quiet.Lines(), "\n"), alertPrefix) {
		t.Error("a clean report has an ATTENTION line")
	}

	bad := sampleHealth()
	bad.HavePatterns, bad.PatternProblems = true, []string{`pattern[1] "typo": bad`}
	alerts := strings.Join(bad.Alerts(), "; ")
	for _, want := range []string{"kernel drops 104", "tracked-process cap hits 115", "bus drops 203", "sequences possibly truncated 305",
		"sequence searches aborted 306", "threshold counter cap hits 304", "descendant walks truncated 301", "full rescans 321", "pattern errors 1"} {
		if !strings.Contains(alerts, want) {
			t.Errorf("alerts lack %q: %s", want, alerts)
		}
	}

	lines := bad.Lines()
	if !strings.HasPrefix(lines[0], alertPrefix+"kernel drops 104") {
		t.Errorf("the alerts are not the first line: %q", lines[0])
	}
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "p50 315µs   p99 316µs") || !strings.Contains(text, `  ✗ pattern[1] "typo": bad`) {
		t.Errorf("report:\n%s", text)
	}
	if !strings.Contains(bad.LogLine(), "pattern_errors=1") || !strings.Contains(bad.LogLine(), "detection_latency_p99_us=316") {
		t.Errorf("log line: %s", bad.LogLine())
	}

	coloured := colourHealth(text)
	if !strings.HasPrefix(coloured, "[red::b]"+alertPrefix) || !strings.Contains(coloured, "[red::b]  ✗ pattern") {
		t.Errorf("coloured report:\n%s", coloured)
	}
	if strings.Count(coloured, "[red::b]") != 2 {
		t.Errorf("%d lines are red, want the alert line and the one pattern error", strings.Count(coloured, "[red::b]"))
	}
}

func newTestBus() *eventbus.Bus { return eventbus.New(4) }
