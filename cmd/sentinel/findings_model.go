package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/store"
)

// defaultRecentFindings is how many stored findings are shown again after a
// restart, unless --recent-findings says otherwise.
const defaultRecentFindings = 500

// maxFindingsInMemory bounds the findings an interface holds. Older ones stay
// in the store.
const maxFindingsInMemory = 2000

// findingItem is a finding as the interfaces hold it.
type findingItem struct {
	// Key identifies the finding in the store.
	Key     string
	Finding core.Finding
	Status  core.FindingStatus
}

// findingFilter narrows and orders the findings list. Empty fields do not
// filter.
type findingFilter struct {
	Severity    core.Severity
	Status      core.FindingStatus
	Rule        string
	OldestFirst bool
}

func (f findingFilter) String() string {
	or := func(value, all string) string {
		if value == "" {
			return all
		}
		return value
	}

	// Kept short: it shares one 80-column line with the counts.
	order := "newest"
	if f.OldestFirst {
		order = "oldest"
	}
	return fmt.Sprintf("sev:%s  status:%s  rule:%s  %s first",
		or(string(f.Severity), "all"), or(string(f.Status), "all"), or(f.Rule, "all"), order)
}

// findingsModel is the list of findings behind the Findings view of the TUI
// and of the desktop app. It keeps them, persists them and their statuses,
// and answers what a view asks: which to show, in what order.
type findingsModel struct {
	store *store.Store // nil when events are not persisted

	mu        sync.Mutex
	items     []*findingItem // oldest first
	filter    findingFilter
	listeners []func()
}

func newFindingsModel(s *store.Store) *findingsModel {
	return &findingsModel{store: s}
}

// OnChange registers fn to be called, from whichever goroutine made the
// change, whenever the findings or the filter change. It must not block.
func (m *findingsModel) OnChange(fn func()) {
	m.mu.Lock()
	m.listeners = append(m.listeners, fn)
	m.mu.Unlock()
}

func (m *findingsModel) changed() {
	m.mu.Lock()
	listeners := append([]func(){}, m.listeners...)
	m.mu.Unlock()

	for _, listener := range listeners {
		listener()
	}
}

// LoadRecent fills the model with the latest findings in the store, so that
// the list is not empty after a restart. It returns how many were loaded.
func (m *findingsModel) LoadRecent(limit int) (int, error) {
	if m.store == nil || limit <= 0 {
		return 0, nil
	}

	stored, err := m.store.RecentFindings(limit)
	if err != nil {
		return 0, err
	}

	m.mu.Lock()
	for _, s := range stored {
		m.items = append(m.items, &findingItem{Key: s.Key, Finding: s.Finding, Status: s.Status})
	}
	m.mu.Unlock()

	m.changed()
	return len(stored), nil
}

// Add records a new finding: it is stored, and appears in the list as new.
func (m *findingsModel) Add(f core.Finding) {
	if f.ID == "" {
		f.ID = fmt.Sprintf("finding-%d", time.Now().UnixNano())
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}

	if m.store != nil {
		m.store.SaveFinding(findingLine(&f), f)
	}

	m.mu.Lock()
	m.items = append(m.items, &findingItem{Key: f.ID, Finding: f, Status: core.StatusNew})
	if extra := len(m.items) - maxFindingsInMemory; extra > 0 {
		m.items = append([]*findingItem{}, m.items[extra:]...)
	}
	m.mu.Unlock()

	m.changed()
}

// SetStatus records what has been done about a finding.
func (m *findingsModel) SetStatus(key string, status core.FindingStatus) error {
	if !core.ValidStatus(status) {
		return fmt.Errorf("unknown status %q", status)
	}

	m.mu.Lock()
	var found *findingItem
	for _, item := range m.items {
		if item.Key == key {
			found = item
			break
		}
	}
	if found == nil {
		m.mu.Unlock()
		return fmt.Errorf("no such finding")
	}
	found.Status = status
	m.mu.Unlock()

	var err error
	if m.store != nil {
		err = m.store.SetFindingStatus(key, status)
	}

	m.changed()
	return err
}

// Get returns a copy of the finding with the given key.
func (m *findingsModel) Get(key string) (findingItem, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, item := range m.items {
		if item.Key == key {
			return *item, true
		}
	}
	return findingItem{}, false
}

// Filter returns the current filter; SetFilter replaces it.
func (m *findingsModel) Filter() findingFilter {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filter
}

func (m *findingsModel) SetFilter(filter findingFilter) {
	m.mu.Lock()
	m.filter = filter
	m.mu.Unlock()

	m.changed()
}

// Visible returns copies of the findings that pass the filter, in its order.
func (m *findingsModel) Visible() []findingItem {
	m.mu.Lock()
	defer m.mu.Unlock()

	filter := m.filter
	visible := make([]findingItem, 0, len(m.items))

	for _, item := range m.items {
		if filter.Severity != "" && item.Finding.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && item.Status != filter.Status {
			continue
		}
		if filter.Rule != "" && item.Finding.Rule != filter.Rule {
			continue
		}
		visible = append(visible, *item)
	}

	// Stored order is arrival order; sort by the findings' own times, and
	// keep arrival order between equal ones.
	sort.SliceStable(visible, func(i, j int) bool {
		if filter.OldestFirst {
			return visible[i].Finding.Timestamp.Before(visible[j].Finding.Timestamp)
		}
		return visible[j].Finding.Timestamp.Before(visible[i].Finding.Timestamp)
	})

	return visible
}

// Counts returns how many findings there are, and how many are new.
func (m *findingsModel) Counts() (total, unhandled int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, item := range m.items {
		if item.Status == core.StatusNew {
			unhandled++
		}
	}
	return len(m.items), unhandled
}

// Rules lists the rules that have findings, in name order.
func (m *findingsModel) Rules() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := map[string]bool{}
	var rules []string
	for _, item := range m.items {
		if rule := item.Finding.Rule; rule != "" && !seen[rule] {
			seen[rule] = true
			rules = append(rules, rule)
		}
	}
	sort.Strings(rules)
	return rules
}

// The values the filters step through, "" (all) first.
var (
	filterSeverities = []core.Severity{"", core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}
	filterStatuses   = []core.FindingStatus{"", core.StatusNew, core.StatusAcknowledged, core.StatusDismissed}
)

// next returns the value after current in values, wrapping round.
func next[T comparable](values []T, current T) T {
	for i, value := range values {
		if value == current {
			return values[(i+1)%len(values)]
		}
	}
	return values[0]
}

// --- Rendering -------------------------------------------------------------

// findingRow is one line of the findings list.
type findingRow struct {
	Time, Severity, Rule, Title, Process, Status string
}

func rowOf(item findingItem) findingRow {
	f := item.Finding

	row := findingRow{
		Time:     f.Timestamp.Local().Format("01-02 15:04:05"),
		Severity: string(f.Severity),
		Rule:     f.Rule,
		Title:    f.Title,
		Status:   string(item.Status),
	}
	if len(row.Time) > 14 {
		row.Time = row.Time[:14]
	}
	if row.Severity == "" {
		row.Severity = "-"
	}
	if row.Rule == "" {
		row.Rule = "-"
	}
	if process := f.Evidence.Process; process != nil {
		row.Process = fmt.Sprintf("%s(%d)", orUnknown(process.Name), process.PID)
	}
	return row
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// roleOf returns the role a process filled in the finding, or "".
func roleOf(f core.Finding, process *core.Process) string {
	if process == nil {
		return ""
	}
	for _, role := range findingRoles(f) {
		if f.Evidence.Roles[role].Identity() == process.Identity() {
			return role
		}
	}
	return ""
}

// eventSummary gives the fields of an event that say what happened.
func eventSummary(event core.Event) string {
	switch {
	case event.Network != nil:
		n := event.Network
		summary := fmt.Sprintf("%s:%d", n.RemoteAddress, n.RemotePort)
		if n.Protocol != "" {
			summary = n.Protocol + " " + summary
		}
		return summary
	case event.DNS != nil:
		summary := event.DNS.Domain
		if event.DNS.Type != "" {
			summary += " (" + event.DNS.Type + ")"
		}
		return summary
	case event.File != nil:
		if event.File.OldPath != "" {
			return event.File.OldPath + " -> " + event.File.Path
		}
		return event.File.Path
	case event.Process != nil:
		if event.Process.CommandLine != "" {
			return event.Process.CommandLine
		}
		if event.Process.Executable != "" {
			return event.Process.Executable
		}
		return event.Process.Name
	}
	return ""
}

// timelineOf returns the finding's events in time order.
func timelineOf(f core.Finding) []core.Event {
	events := append([]core.Event{}, f.Evidence.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	return events
}

// capture is an event a sequence step named, so that later steps could refer
// to it.
type capture struct {
	Name  string
	Event core.Event
}

// capturesOf works out which of a finding's events were captured. The
// evidence lists the events of the rule's sequence first, one per step in
// step order, so the rule as currently loaded says which of them had names.
// If the rule has since changed shape, or is gone, nothing is claimed.
func capturesOf(f core.Finding, patterns []correlation.BehaviorPattern) []capture {
	for _, pattern := range patterns {
		if pattern.Name != f.Rule || pattern.Sequence == nil {
			continue
		}

		steps := pattern.Sequence.Steps
		if len(f.Evidence.Events) < len(steps) {
			return nil
		}

		var captures []capture
		for i, step := range steps {
			event := f.Evidence.Events[i]
			if event.Type != step.Type {
				return nil // not the events of this sequence
			}
			if step.Capture != "" {
				captures = append(captures, capture{Name: step.Capture, Event: event})
			}
		}
		return captures
	}
	return nil
}

// detailLines renders everything known about a finding as plain text, at
// most width columns wide where that can be helped. Both interfaces show
// exactly this.
func detailLines(item findingItem, patterns []correlation.BehaviorPattern) []string {
	f := item.Finding
	var lines []string
	add := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	add("%s  [%s]  %s", orDash(string(f.Severity)), orDash(f.Rule), f.Title)
	if f.Description != "" {
		add("%s", f.Description)
	}
	add("Time: %s    Status: %s", f.Timestamp.Local().Format("2006-01-02 15:04:05.000"), item.Status)
	add("")

	roles := findingRoles(f)
	if len(roles) == 0 && f.Evidence.Process == nil {
		add("No evidence was stored with this finding.")
		return lines
	}

	add("ROLES")
	for _, role := range roles {
		process := f.Evidence.Roles[role]
		add("  %s: %s  pid %d  ppid %d  user %s", role, orUnknown(process.Name), process.PID, process.PPID, orDash(process.User))
		add("      exe      %s", orDash(process.Executable))
		add("      cmdline  %s", orDash(process.CommandLine))
		if !process.StartTime.IsZero() && process.StartTime.Unix() > 0 {
			add("      started  %s", process.StartTime.Local().Format("2006-01-02 15:04:05.000"))
		}
		for _, image := range f.Evidence.PreviousImages[role] {
			add("      was      %s  (%s)  until %s", orUnknown(image.Name), orDash(image.Executable), image.ReplacedAt.Local().Format("15:04:05.000"))
			if image.CommandLine != "" {
				add("               %s", image.CommandLine)
			}
		}
	}
	if len(roles) == 0 {
		process := f.Evidence.Process
		add("  %s  pid %d  ppid %d  user %s", orUnknown(process.Name), process.PID, process.PPID, orDash(process.User))
		add("      exe      %s", orDash(process.Executable))
	}

	events := timelineOf(f)
	if len(events) > 0 {
		add("")
		add("TIMELINE (%d events)", len(events))
		first := events[0].Timestamp
		for _, event := range events {
			role := roleOf(f, event.Process)
			if role == "" && event.Process != nil {
				role = fmt.Sprintf("pid %d", event.Process.PID)
			}
			add("  %s  %-9s %-16s %-10s %s",
				event.Timestamp.Local().Format("15:04:05.000"), relative(event.Timestamp.Sub(first)),
				event.Type, role, eventSummary(event))
		}
	}

	if captures := capturesOf(f, patterns); len(captures) > 0 {
		add("")
		add("CAPTURES")
		for _, c := range captures {
			add("  $%s = %s  %s", c.Name, c.Event.Type, eventSummary(c.Event))
		}
	}

	return lines
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// relative renders a time since the first event: "+0", "+2.004s", "+1m03s".
func relative(d time.Duration) string {
	switch {
	case d <= 0:
		return "+0"
	case d < time.Minute:
		return fmt.Sprintf("+%.3fs", d.Seconds())
	default:
		return fmt.Sprintf("+%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

// findingJSON renders a finding, with its status, as indented JSON with the
// stable snake_case keys of the stored form.
func findingJSON(item findingItem) string {
	out := struct {
		core.Finding
		Status core.FindingStatus `json:"status"`
	}{Finding: item.Finding, Status: item.Status}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(data)
}

// summaryLine is the one-line state shown in the TUI footer.
func summaryLine(backend string, patterns patternState, total, unhandled int) string {
	parts := []string{
		"collector: " + backend,
		fmt.Sprintf("patterns: %d", len(patterns.Patterns)),
	}
	if problems := len(patterns.Problems()); problems > 0 {
		parts = append(parts, fmt.Sprintf("pattern errors: %d", problems))
	} else {
		parts = append(parts, "pattern errors: 0")
	}
	parts = append(parts, fmt.Sprintf("findings: %d new / %d", unhandled, total))
	return strings.Join(parts, "   ")
}
