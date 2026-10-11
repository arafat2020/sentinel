package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/arafat2020/sentinel/internal/core"
)

// findingsTab is the tab findings are stored under.
const findingsTab = "Findings"

const (
	DefaultRetentionDays = 7
	batchSize            = 100
	flushInterval        = 200 * time.Millisecond
)

// Store is a SQLite-backed event log with async batch writes.
// All public methods are goroutine-safe.
type Store struct {
	db      *sql.DB
	writeCh chan writeReq
	stopped chan struct{}
}

type writeReq struct {
	ts   time.Time
	tab  string
	line string
	// evidence is a finding's evidence as JSON, or empty for a row that has
	// none.
	evidence string
	// finding is a finding's header (everything but its evidence) as JSON,
	// and findingID its ID; both empty for rows that are not findings.
	finding   string
	findingID string

	// status, when set, makes this a change of a stored finding's status
	// rather than a new row. key says which finding.
	status core.FindingStatus
	key    string
}

// Open opens (or creates) the SQLite database at path and starts the
// background write goroutine. The caller must call Close when done.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, err
	}
	// SQLite allows only one writer at a time; more than one open conn would
	// just queue on the busy-timeout anyway.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store migrate: %w", err)
	}

	s := &Store{
		db:      db,
		writeCh: make(chan writeReq, 2000),
		stopped: make(chan struct{}),
	}
	go s.writeLoop()
	return s, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			ts   DATETIME NOT NULL,
			tab  TEXT NOT NULL,
			line TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_events_tab_ts ON events(tab, ts);
		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		INSERT OR IGNORE INTO settings(key, value) VALUES('retention_days', '7');
	`)
	if err != nil {
		return err
	}

	// Columns added since the table was first created. Each is nullable,
	// so rows written by earlier versions simply lack a value.
	for _, column := range []string{"evidence TEXT", "finding TEXT", "finding_id TEXT", "status TEXT"} {
		if err := addColumn(db, column); err != nil {
			return err
		}
	}

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_finding_id ON events(finding_id)`)
	return err
}

// addColumn gives the events table a column ("name TYPE") if a database
// created by an earlier version does not have it.
func addColumn(db *sql.DB, definition string) error {
	wanted := strings.Fields(definition)[0]

	rows, err := db.Query(`SELECT name FROM pragma_table_info('events')`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == wanted {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	_, err = db.Exec(`ALTER TABLE events ADD COLUMN ` + definition)
	return err
}

// Write queues a raw log line for a named tab. Non-blocking: drops silently
// if the internal buffer is full (burst protection).
func (s *Store) Write(tab, line string) {
	select {
	case s.writeCh <- writeReq{ts: time.Now(), tab: tab, line: line}:
	default:
	}
}

// WriteFinding queues a finding's log line together with its evidence: the
// processes bound to the rule's roles and the events behind the match. Like
// Write it does not block, and drops the row if the buffer is full.
func (s *Store) WriteFinding(line string, evidence core.Evidence) {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		// The line is still worth keeping without its evidence.
		encoded = nil
	}

	select {
	case s.writeCh <- writeReq{ts: time.Now(), tab: findingsTab, line: line, evidence: string(encoded)}:
	default:
	}
}

// SaveFinding queues a finding for storage: its display line, its header and
// its evidence, with the status "new". Like Write it does not block, and
// drops the row if the buffer is full.
func (s *Store) SaveFinding(line string, f core.Finding) {
	evidence, err := json.Marshal(f.Evidence)
	if err != nil {
		evidence = nil
	}

	header := f
	header.Evidence = core.Evidence{}
	encoded, err := json.Marshal(header)
	if err != nil {
		encoded = nil
	}

	ts := f.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	select {
	case s.writeCh <- writeReq{ts: ts, tab: findingsTab, line: line, evidence: string(evidence), finding: string(encoded), findingID: f.ID}:
	default:
	}
}

// rowKeyPrefix begins the key of a stored finding that has no ID of its own:
// one written before findings were stored whole. The rest is its row number.
const rowKeyPrefix = "row-"

// SetFindingStatus records what has been done about a stored finding. key is
// the Key of a StoredFinding. The change is queued behind any finding still
// waiting to be written, so it is safe to call straight after SaveFinding.
func (s *Store) SetFindingStatus(key string, status core.FindingStatus) error {
	if !core.ValidStatus(status) {
		return fmt.Errorf("unknown finding status %q", status)
	}
	if key == "" {
		return errors.New("finding has no key")
	}

	select {
	case s.writeCh <- writeReq{status: status, key: key}:
		return nil
	default:
		return errors.New("store is busy; status not saved")
	}
}

func setStatus(tx *sql.Tx, key string, status core.FindingStatus) {
	if row, isRow := strings.CutPrefix(key, rowKeyPrefix); isRow {
		if id, err := strconv.ParseInt(row, 10, 64); err == nil {
			tx.Exec(`UPDATE events SET status=? WHERE id=? AND tab=?`, string(status), id, findingsTab)
		}
		return
	}
	tx.Exec(`UPDATE events SET status=? WHERE finding_id=?`, string(status), key)
}

// StoredFinding is a finding read back from the store.
type StoredFinding struct {
	// Key identifies the finding to SetFindingStatus.
	Key     string
	Finding core.Finding
	// Line is the one-line form the finding was stored with.
	Line   string
	Status core.FindingStatus
}

// RecentFindings returns the most recent findings, oldest first, at most
// limit of them.
//
// Findings stored by earlier versions are included. One stored before
// findings were kept whole has only its line and perhaps its evidence: its
// line becomes its title, its time is when it was stored, and its rule and
// severity are unknown. One stored before statuses existed is "new".
func (s *Store) RecentFindings(limit int) ([]StoredFinding, error) {
	if limit <= 0 {
		return nil, nil
	}

	rows, err := s.db.Query(
		`SELECT id, ts, line, evidence, finding, finding_id, status FROM events WHERE tab=? ORDER BY id DESC LIMIT ?`,
		findingsTab, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var found []StoredFinding
	for rows.Next() {
		var (
			id                                    int64
			ts, line                              string
			evidence, header, findingID, statusIn sql.NullString
		)
		if err := rows.Scan(&id, &ts, &line, &evidence, &header, &findingID, &statusIn); err != nil {
			continue
		}

		stored := StoredFinding{Line: line, Status: core.StatusNew}
		if status := core.FindingStatus(statusIn.String); core.ValidStatus(status) {
			stored.Status = status
		}

		if header.Valid && json.Unmarshal([]byte(header.String), &stored.Finding) == nil && findingID.String != "" {
			stored.Key = findingID.String
		} else {
			stored.Key = rowKeyPrefix + strconv.FormatInt(id, 10)
			stored.Finding = core.Finding{ID: stored.Key, Title: line}
			stored.Finding.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		}

		if evidence.Valid && evidence.String != "" {
			json.Unmarshal([]byte(evidence.String), &stored.Finding.Evidence)
		}

		found = append(found, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Newest first came out of the query; the caller wants them in order.
	for i, j := 0, len(found)-1; i < j; i, j = i+1, j-1 {
		found[i], found[j] = found[j], found[i]
	}
	return found, nil
}

func (s *Store) writeLoop() {
	defer close(s.stopped)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]writeReq, 0, batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := s.db.Begin()
		if err != nil {
			batch = batch[:0]
			return
		}
		stmt, err := tx.Prepare("INSERT INTO events(ts,tab,line,evidence,finding,finding_id,status) VALUES(?,?,?,?,?,?,?)")
		if err != nil {
			tx.Rollback()
			batch = batch[:0]
			return
		}
		// NULL unless the row has a value.
		orNull := func(s string) any {
			if s == "" {
				return nil
			}
			return s
		}
		for _, r := range batch {
			// Status changes travel through the same queue as the rows
			// they change, so one never overtakes the other.
			if r.status != "" {
				setStatus(tx, r.key, r.status)
				continue
			}

			status := ""
			if r.findingID != "" {
				status = string(core.StatusNew)
			}
			stmt.Exec(r.ts.UTC().Format(time.RFC3339Nano), r.tab, r.line,
				orNull(r.evidence), orNull(r.finding), orNull(r.findingID), orNull(status))
		}
		stmt.Close()
		tx.Commit()
		batch = batch[:0]
	}

	for {
		select {
		case r, ok := <-s.writeCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, r)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Recent returns the last n stored lines for tab, oldest first.
func (s *Store) Recent(tab string, n int) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT line FROM (
			SELECT line, ts FROM events WHERE tab=? ORDER BY ts DESC LIMIT ?
		) ORDER BY ts ASC`, tab, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var l string
		if rows.Scan(&l) == nil {
			lines = append(lines, l)
		}
	}
	return lines, rows.Err()
}

// DeleteOlderThan removes events whose timestamp is older than days ago.
// Returns the number of rows deleted.
func (s *Store) DeleteOlderThan(days int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -days).UTC().Format(time.RFC3339)
	res, err := s.db.Exec("DELETE FROM events WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetRetentionDays reads the persisted retention_days setting (default 7).
func (s *Store) GetRetentionDays() int {
	var v string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE key='retention_days'").Scan(&v); err != nil {
		return DefaultRetentionDays
	}
	var n int
	if _, err := fmt.Sscan(v, &n); err != nil || n <= 0 {
		return DefaultRetentionDays
	}
	return n
}

// SetRetentionDays persists the retention_days setting.
func (s *Store) SetRetentionDays(days int) error {
	_, err := s.db.Exec(`
		INSERT INTO settings(key,value) VALUES('retention_days',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		fmt.Sprintf("%d", days))
	return err
}

// RunRetention runs DeleteOlderThan once at startup and then every 24 hours.
// It reads the retention setting from the DB each time, so changes take effect
// the next daily run (or at restart).
func (s *Store) RunRetention(ctx context.Context) {
	run := func() { s.DeleteOlderThan(s.GetRetentionDays()) }
	run()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// Event is one stored log line with its metadata.
type Event struct {
	ID   int64
	TS   time.Time
	Tab  string
	Line string
	// Evidence is the evidence stored with a finding, or nil for rows that
	// have none: telemetry lines, and findings written before evidence was
	// stored.
	Evidence *core.Evidence
}

// QueryFilter specifies which events to return. Zero values mean "no filter".
type QueryFilter struct {
	Tab   string    // exact tab name; empty = all tabs
	Since time.Time // inclusive lower bound; zero = no lower bound
	Until time.Time // inclusive upper bound; zero = no upper bound
	Limit int       // max rows; 0 = 200
}

// Query returns events matching the filter, ordered oldest first.
func (s *Store) Query(f QueryFilter) ([]Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}

	q := "SELECT id, ts, tab, line, evidence FROM events WHERE 1=1"
	args := []any{}

	if f.Tab != "" {
		q += " AND tab=?"
		args = append(args, f.Tab)
	}
	if !f.Since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if !f.Until.IsZero() {
		q += " AND ts <= ?"
		args = append(args, f.Until.UTC().Format(time.RFC3339))
	}
	// Rows are inserted in the order they were written, so the row id is
	// the order of events. The timestamp column is text with a variable
	// number of fractional digits, which does not sort chronologically.
	q += " ORDER BY id ASC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var tsStr string
		var evidence sql.NullString
		if err := rows.Scan(&e.ID, &tsStr, &e.Tab, &e.Line, &evidence); err != nil {
			continue
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
		if evidence.Valid && evidence.String != "" {
			var decoded core.Evidence
			if json.Unmarshal([]byte(evidence.String), &decoded) == nil {
				e.Evidence = &decoded
			}
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// HasPassword reports whether a password hash has been stored.
func (s *Store) HasPassword() bool {
	var v string
	return s.db.QueryRow("SELECT value FROM settings WHERE key='password_hash'").Scan(&v) == nil
}

// GetPasswordHash returns the stored bcrypt hash, or "" if none is set.
func (s *Store) GetPasswordHash() string {
	var v string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE key='password_hash'").Scan(&v); err != nil {
		return ""
	}
	return v
}

// SetPasswordHash persists a bcrypt hash as the active password.
func (s *Store) SetPasswordHash(hash string) error {
	_, err := s.db.Exec(`
		INSERT INTO settings(key,value) VALUES('password_hash',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		hash)
	return err
}

// Close drains the pending write queue, flushes to disk, and closes the DB.
func (s *Store) Close() error {
	close(s.writeCh)
	<-s.stopped
	return s.db.Close()
}
