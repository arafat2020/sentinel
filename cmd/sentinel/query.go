package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/store"
)

const dbPath = "sentinel.db"

// runQuery opens the local sentinel.db, applies the given filters, prints
// matching events, and exits. No collectors are started.
//
// Usage:
//
//	sentinel --query
//	sentinel --query --tab Findings
//	sentinel --query --since 2026-09-14
//	sentinel --query --since 2026-09-14T08:00 --until 2026-09-14T18:00 --tab Network
//	sentinel --query --tab Findings --limit 50
func runQuery(tab, since, until string, limit int) {
	s, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: cannot open %s: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	f := store.QueryFilter{
		Tab:   tab,
		Limit: limit,
	}

	if since != "" {
		f.Since, err = parseTime(since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: --since %q: %v\n", since, err)
			os.Exit(1)
		}
	}
	if until != "" {
		f.Until, err = parseTime(until)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: --until %q: %v\n", until, err)
			os.Exit(1)
		}
	}

	events, err := s.Query(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: query failed: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Println("(no events match the filter)")
		return
	}

	for _, e := range events {
		fmt.Printf("%s  %-10s  %s\n", e.TS.Local().Format("2006-01-02 15:04:05"), "["+e.Tab+"]", e.Line)
	}
	fmt.Printf("\n%d event(s)\n", len(events))
}

// parseTime accepts several common date/time formats so the user doesn't have
// to remember RFC3339.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.ParseInLocation(f, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised date/time format (try YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
}
