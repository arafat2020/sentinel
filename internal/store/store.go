package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

	return addEvidenceColumn(db)
}

// addEvidenceColumn gives the events table its evidence column if a database
// created by an earlier version does not have it. The column is nullable:
// existing rows, and rows that are not findings, simply have no evidence.
func addEvidenceColumn(db *sql.DB) error {
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
		if name == "evidence" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	_, err = db.Exec(`ALTER TABLE events ADD COLUMN evidence TEXT`)
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
		stmt, err := tx.Prepare("INSERT INTO events(ts,tab,line,evidence) VALUES(?,?,?,?)")
		if err != nil {
			tx.Rollback()
			batch = batch[:0]
			return
		}
		for _, r := range batch {
			var evidence any // NULL unless the row has evidence
			if r.evidence != "" {
				evidence = r.evidence
			}
			stmt.Exec(r.ts.UTC().Format(time.RFC3339Nano), r.tab, r.line, evidence)
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
