package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

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
		stmt, err := tx.Prepare("INSERT INTO events(ts,tab,line) VALUES(?,?,?)")
		if err != nil {
			tx.Rollback()
			batch = batch[:0]
			return
		}
		for _, r := range batch {
			stmt.Exec(r.ts.UTC().Format(time.RFC3339Nano), r.tab, r.line)
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

	q := "SELECT id, ts, tab, line FROM events WHERE 1=1"
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
	q += " ORDER BY ts ASC LIMIT ?"
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
		if err := rows.Scan(&e.ID, &tsStr, &e.Tab, &e.Line); err != nil {
			continue
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
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
