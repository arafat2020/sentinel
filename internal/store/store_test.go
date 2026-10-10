package store

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// waitFor polls until the asynchronous writer has stored what a test wrote.
func waitFor(t *testing.T, s *Store, tab string, want int) []Event {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := s.Query(QueryFilter{Tab: tab})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) >= want {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatalf("store holds %d %s row(s), want %d", len(events), tab, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sampleEvidence() core.Evidence {
	started := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	dropper := core.Process{PID: 100, PPID: 1, Name: "sh", Executable: "/bin/sh", User: "www-data", StartTime: started}
	payload := core.Process{PID: 200, PPID: 100, Name: "x", Executable: "/tmp/x", CommandLine: "/tmp/x --run", StartTime: started.Add(3 * time.Second)}

	return core.Evidence{
		Process:   &payload,
		Processes: []core.Process{dropper, payload},
		Roles:     map[string]core.Process{"dropper": dropper, "payload": payload},
		Events: []core.Event{
			{
				Type: core.EventNetworkConnect, Timestamp: started.Add(time.Second), Process: &dropper,
				Network: &core.NetworkConnection{RemoteAddress: "203.0.113.9", RemotePort: 4444, Protocol: "tcp"},
			},
			{
				Type: core.EventFileCreate, Timestamp: started.Add(2 * time.Second), Process: &dropper,
				File: &core.FileEvent{Path: "/tmp/x", Operation: core.FileCreate},
			},
			{Type: core.EventProcessStart, Timestamp: started.Add(3 * time.Second), Process: &payload},
			{
				Type: core.EventDNSQuery, Timestamp: started.Add(4 * time.Second), Process: &payload,
				DNS: &core.DNSQuery{Domain: "c2.example", Type: "A", Resolver: "8.8.8.8"},
			},
		},
	}
}

func TestFindingEvidenceRoundTrips(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	want := sampleEvidence()
	s.WriteFinding("[download-and-execute] Dropped file executed", want)

	events := waitFor(t, s, "Findings", 1)
	if len(events) != 1 {
		t.Fatalf("stored %d findings, want 1", len(events))
	}

	got := events[0]
	if got.Line != "[download-and-execute] Dropped file executed" || got.Tab != "Findings" {
		t.Errorf("row = %q in %q", got.Line, got.Tab)
	}
	if got.Evidence == nil {
		t.Fatal("evidence was not stored")
	}

	evidence := *got.Evidence
	if !reflect.DeepEqual(evidence.Roles, want.Roles) {
		t.Errorf("roles:\n got %+v\nwant %+v", evidence.Roles, want.Roles)
	}
	if !reflect.DeepEqual(evidence.Processes, want.Processes) || !reflect.DeepEqual(evidence.Process, want.Process) {
		t.Errorf("processes:\n got %+v / %+v\nwant %+v / %+v", evidence.Processes, evidence.Process, want.Processes, want.Process)
	}
	if !reflect.DeepEqual(evidence.Events, want.Events) {
		t.Errorf("events:\n got %+v\nwant %+v", evidence.Events, want.Events)
	}
}

func TestRowsWithoutEvidenceHaveNone(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Write("Network", "NETWORK_CONNECT PID=1")
	s.Write("Findings", "a finding written the old way")
	s.WriteFinding("a finding with nothing bound", core.Evidence{})

	if events := waitFor(t, s, "Network", 1); events[0].Evidence != nil {
		t.Errorf("a telemetry row has evidence: %+v", events[0].Evidence)
	}

	findings := waitFor(t, s, "Findings", 2)
	if findings[0].Evidence != nil {
		t.Errorf("a finding written without evidence has some: %+v", findings[0].Evidence)
	}
	// Empty evidence is stored and read back as empty, not as missing.
	if findings[1].Evidence == nil || len(findings[1].Evidence.Roles) != 0 {
		t.Errorf("empty evidence read back as %+v", findings[1].Evidence)
	}
}

// testdata/evidence_go_field_names.json is sampleEvidence exactly as it was
// written before the evidence types had JSON tags. A row holding it must read
// back as the same evidence, and be indistinguishable from one written now.
func TestReadsEvidenceStoredWithGoFieldNames(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join("testdata", "evidence_go_field_names.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), `"CommandLine"`) || strings.Contains(string(legacy), `"command_line"`) {
		t.Fatal("the fixture is not in the old format")
	}

	path := filepath.Join(t.TempDir(), "sentinel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.WriteFinding("written now", sampleEvidence())
	waitFor(t, s, "Findings", 1)
	s.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO events(ts,tab,line,evidence) VALUES(?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), "Findings", "written before the tags", strings.TrimSpace(string(legacy)),
	); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	findings := waitFor(t, s, "Findings", 2)
	want := sampleEvidence()
	for _, row := range findings {
		if row.Evidence == nil {
			t.Fatalf("%q: no evidence was read", row.Line)
		}
		if !reflect.DeepEqual(*row.Evidence, want) {
			t.Errorf("%q:\n got %+v\nwant %+v", row.Line, *row.Evidence, want)
		}
	}

	stored, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stored), `"command_line"`) || strings.Contains(string(stored), `"CommandLine"`) {
		t.Errorf("evidence is not written with the tagged keys: %s", stored)
	}
}

// A database created before evidence was stored has no evidence column. It
// must open, keep its rows, and accept findings with evidence from then on.
func TestOpensDatabaseFromBeforeEvidenceWasStored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.db")

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`
		CREATE TABLE events (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			ts   DATETIME NOT NULL,
			tab  TEXT NOT NULL,
			line TEXT NOT NULL
		);
		CREATE INDEX idx_events_tab_ts ON events(tab, ts);
		CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO settings(key, value) VALUES('retention_days', '30');
		INSERT INTO events(ts, tab, line) VALUES('2026-01-01T10:00:00Z', 'Findings', 'old finding');
		INSERT INTO events(ts, tab, line) VALUES('2026-01-01T10:00:01Z', 'Process', 'old process line');
	`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening an older database: %v", err)
	}

	if days := s.GetRetentionDays(); days != 30 {
		t.Errorf("retention = %d, want the stored 30", days)
	}

	findings := waitFor(t, s, "Findings", 1)
	if findings[0].Line != "old finding" || findings[0].Evidence != nil {
		t.Errorf("old row = %q with evidence %+v, want the line and no evidence", findings[0].Line, findings[0].Evidence)
	}

	s.WriteFinding("new finding", sampleEvidence())
	findings = waitFor(t, s, "Findings", 2)
	if findings[1].Line != "new finding" || findings[1].Evidence == nil || len(findings[1].Evidence.Roles) != 2 {
		t.Errorf("new row = %q with evidence %+v", findings[1].Line, findings[1].Evidence)
	}
	if lines, _ := s.Recent("Process", 10); len(lines) != 1 || lines[0] != "old process line" {
		t.Errorf("old telemetry rows = %q", lines)
	}

	// Opening again must not try to add the column twice.
	s.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopening after migration: %v", err)
	}
	again.Close()
}
