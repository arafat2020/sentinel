package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func sampleFinding(n int) core.Finding {
	evidence := sampleEvidence()
	return core.Finding{
		ID:          fmt.Sprintf("finding-%d", n),
		Timestamp:   time.Date(2026, 1, 1, 12, 0, n, 0, time.UTC),
		Severity:    core.SeverityCritical,
		Rule:        "download-and-execute",
		Title:       "Downloaded file executed",
		Description: "A process ran a file that had just been downloaded.",
		Evidence:    evidence,
	}
}

// awaitFindings polls until the asynchronous writer has caught up.
func awaitFindings(t *testing.T, s *Store, done func([]StoredFinding) bool) []StoredFinding {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		found, err := s.RecentFindings(500)
		if err != nil {
			t.Fatal(err)
		}
		if done(found) {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("store never reached the expected state; it holds %d findings: %+v", len(found), found)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFindingIsStoredWholeAndStartsNew(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	want := sampleFinding(1)
	s.SaveFinding("[download-and-execute] Downloaded file executed", want)

	found := awaitFindings(t, s, func(f []StoredFinding) bool { return len(f) == 1 })[0]

	if found.Key != "finding-1" || found.Status != core.StatusNew || found.Line != "[download-and-execute] Downloaded file executed" {
		t.Errorf("stored as %+v", found)
	}
	if !reflect.DeepEqual(found.Finding, want) {
		t.Errorf("finding read back as\n%+v\nwant\n%+v", found.Finding, want)
	}

	// The row is still an ordinary Findings row for --query.
	events, err := s.Query(QueryFilter{Tab: "Findings"})
	if err != nil || len(events) != 1 || events[0].Evidence == nil {
		t.Errorf("query: %d rows, err %v", len(events), err)
	}
}

func TestFindingStatusIsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	for n := 1; n <= 3; n++ {
		s.SaveFinding("line", sampleFinding(n))
	}
	// Straight after saving, before the writer has flushed: the change is
	// queued behind the row it changes.
	if err := s.SetFindingStatus("finding-2", core.StatusAcknowledged); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFindingStatus("finding-3", core.StatusDismissed); err != nil {
		t.Fatal(err)
	}

	statuses := func(found []StoredFinding) []core.FindingStatus {
		out := make([]core.FindingStatus, len(found))
		for i, f := range found {
			out[i] = f.Status
		}
		return out
	}
	want := []core.FindingStatus{core.StatusNew, core.StatusAcknowledged, core.StatusDismissed}
	awaitFindings(t, s, func(f []StoredFinding) bool { return reflect.DeepEqual(statuses(f), want) })

	// A status can be changed again, and survives a restart.
	if err := s.SetFindingStatus("finding-3", core.StatusNew); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	found, err := s.RecentFindings(10)
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses(found); !reflect.DeepEqual(got, []core.FindingStatus{core.StatusNew, core.StatusAcknowledged, core.StatusNew}) {
		t.Errorf("after reopening: statuses = %v", got)
	}

	if err := s.SetFindingStatus("finding-1", "ignored"); err == nil {
		t.Error("an unknown status was accepted")
	}
	if err := s.SetFindingStatus("", core.StatusDismissed); err == nil {
		t.Error("a status for no finding was accepted")
	}
}

func TestRecentFindingsReturnsTheNewestInOrder(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for n := 1; n <= 7; n++ {
		s.SaveFinding("line", sampleFinding(n))
	}
	s.Write("Process", "not a finding")
	awaitFindings(t, s, func(f []StoredFinding) bool { return len(f) == 7 })

	found, err := s.RecentFindings(3)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, f := range found {
		keys = append(keys, f.Key)
	}
	if !reflect.DeepEqual(keys, []string{"finding-5", "finding-6", "finding-7"}) {
		t.Errorf("the 3 most recent, oldest first: got %v", keys)
	}

	if none, err := s.RecentFindings(0); err != nil || len(none) != 0 {
		t.Errorf("limit 0 returned %d findings, err %v", len(none), err)
	}
}

// A database from every earlier version must open, keep its findings, show
// them, and let their status be changed.
func TestFindingsFromOlderDatabases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel.db")

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// As Phase 3 left it: an evidence column, no finding or status. One
	// finding predates evidence too.
	if _, err := old.Exec(`
		CREATE TABLE events (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			ts   DATETIME NOT NULL,
			tab  TEXT NOT NULL,
			line TEXT NOT NULL,
			evidence TEXT
		);
		CREATE INDEX idx_events_tab_ts ON events(tab, ts);
		CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO events(ts, tab, line) VALUES('2026-01-01T10:00:00Z', 'Findings', '[old-rule] line only');
		INSERT INTO events(ts, tab, line) VALUES('2026-01-01T10:00:01Z', 'Process', 'a process line');
		INSERT INTO events(ts, tab, line, evidence) VALUES('2026-01-01T10:00:02.5Z', 'Findings', '[newer-rule] with evidence',
			'{"roles":{"payload":{"pid":200,"ppid":100,"name":"x","executable":"/tmp/x"}}}');
	`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening an older database: %v", err)
	}

	found, err := s.RecentFindings(500)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("%d findings from the old database, want 2", len(found))
	}

	lineOnly, withEvidence := found[0], found[1]
	if lineOnly.Key != "row-1" || lineOnly.Status != core.StatusNew || lineOnly.Finding.Title != "[old-rule] line only" {
		t.Errorf("line-only finding = %+v", lineOnly)
	}
	if !lineOnly.Finding.Timestamp.Equal(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("line-only finding is timed %v, want when it was stored", lineOnly.Finding.Timestamp)
	}
	if withEvidence.Key != "row-3" || withEvidence.Finding.Evidence.Roles["payload"].Executable != "/tmp/x" {
		t.Errorf("finding with evidence = %+v", withEvidence)
	}

	// An old row has no ID; its status is kept by row.
	if err := s.SetFindingStatus("row-1", core.StatusDismissed); err != nil {
		t.Fatal(err)
	}
	// A key for a row that is not a finding changes nothing.
	if err := s.SetFindingStatus("row-2", core.StatusDismissed); err != nil {
		t.Fatal(err)
	}
	// New findings sit beside the old ones.
	s.SaveFinding("line", sampleFinding(9))
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopening after migration: %v", err)
	}
	defer s.Close()

	found, err = s.RecentFindings(500)
	if err != nil || len(found) != 3 {
		t.Fatalf("after migration: %d findings, err %v", len(found), err)
	}
	if found[0].Status != core.StatusDismissed || found[1].Status != core.StatusNew || found[2].Key != "finding-9" {
		t.Errorf("after migration: %+v", found)
	}

	var status sql.NullString
	if err := s.db.QueryRow(`SELECT status FROM events WHERE id=2`).Scan(&status); err != nil || status.Valid {
		t.Errorf("a telemetry row was given a status: %v %v", status, err)
	}
}
