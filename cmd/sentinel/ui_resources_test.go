package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func pids(procs []core.ProcessUsage) []int32 {
	out := make([]int32, len(procs))
	for i, p := range procs {
		out[i] = p.PID
	}
	return out
}

func equalPIDs(a, b []int32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{5 * 1024 * 1024 * 1024 / 2, "2.5 GiB"},
		{1 << 40, "1.0 TiB"},
		{^uint64(0), "16.0 EiB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.in); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatPercent(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0.0"},
		{-3, "0.0"},
		{12.34, "12.3"},
		{99.95, "100.0"},
		{250, "250.0"},
	}
	for _, c := range cases {
		if got := formatPercent(c.in); got != c.want {
			t.Errorf("formatPercent(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatMeter(t *testing.T) {
	cases := []struct {
		percent float64
		filled  int
		color   string
	}{
		{-10, 0, "green"},
		{0, 0, "green"},
		{50, 5, "green"},
		{60, 6, "yellow"},
		{85, 9, "red"},
		{100, 10, "red"},
		{400, 10, "red"},
	}
	for _, c := range cases {
		got := formatMeter(c.percent, 10)
		if n := strings.Count(got, "█"); n != c.filled {
			t.Errorf("formatMeter(%v) filled %d cells, want %d", c.percent, n, c.filled)
		}
		if n := strings.Count(got, "█") + strings.Count(got, "░"); n != 10 {
			t.Errorf("formatMeter(%v) is %d cells wide, want 10", c.percent, n)
		}
		if !strings.HasPrefix(got, "["+c.color+"]") {
			t.Errorf("formatMeter(%v) = %q, want color %s", c.percent, got, c.color)
		}
	}
}

func TestFormatSummary(t *testing.T) {
	snap := &core.ResourceSnapshot{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		System: core.SystemUsage{
			CPUPercent:  25,
			CPUValid:    true,
			MemoryUsed:  4 << 30,
			MemoryTotal: 16 << 30,
			MemoryValid: true,
		},
		Processes: make([]core.ProcessUsage, 3),
	}

	got := formatSummary(snap, sortByMemory)
	for _, want := range []string{"25.0% of all cores", "4.0 GiB used of 16.0 GiB system RAM (25.0%)", "3 processes", "sorted by RSS", "03:04:05"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary missing %q:\n%s", want, got)
		}
	}

	snap.System = core.SystemUsage{}
	got = formatSummary(snap, sortByCPU)
	if strings.Count(got, "n/a") != 2 {
		t.Errorf("unavailable system metrics should both show n/a:\n%s", got)
	}
}

// proc builds a fully measured process.
func proc(pid int32, cpu float64, mem uint64) core.ProcessUsage {
	return core.ProcessUsage{PID: pid, CPUPercent: cpu, CPUValid: true, MemoryBytes: mem, MemoryValid: true}
}

func TestSortProcessUsage(t *testing.T) {
	procs := []core.ProcessUsage{
		proc(30, 5, 100),
		proc(10, 50, 300),
		proc(20, 5, 900),
		proc(5, 0, 300),
	}
	original := pids(procs)

	if got, want := pids(sortProcessUsage(procs, sortByCPU)), []int32{10, 20, 30, 5}; !equalPIDs(got, want) {
		t.Errorf("by CPU = %v, want %v", got, want)
	}
	if got, want := pids(sortProcessUsage(procs, sortByMemory)), []int32{20, 5, 10, 30}; !equalPIDs(got, want) {
		t.Errorf("by memory = %v, want %v", got, want)
	}
	if !equalPIDs(pids(procs), original) {
		t.Error("sortProcessUsage mutated its input")
	}
	if got := sortProcessUsage(nil, sortByCPU); len(got) != 0 {
		t.Errorf("sorting nil = %v, want empty", got)
	}
}

// An unmeasured value is not a low value: it sorts after every real one,
// including a genuine zero.
func TestSortProcessUsageUnavailableLast(t *testing.T) {
	procs := []core.ProcessUsage{
		{PID: 1},                                 // nothing readable
		proc(2, 0, 0),                            // genuinely idle
		{PID: 3, CPUPercent: 80, CPUValid: true}, // memory unreadable
		{PID: 4, MemoryBytes: 500, MemoryValid: true}, // CPU unreadable
		{PID: 0}, // nothing readable
	}

	if got, want := pids(sortProcessUsage(procs, sortByCPU)), []int32{3, 2, 0, 1, 4}; !equalPIDs(got, want) {
		t.Errorf("by CPU = %v, want %v", got, want)
	}
	if got, want := pids(sortProcessUsage(procs, sortByMemory)), []int32{4, 2, 0, 1, 3}; !equalPIDs(got, want) {
		t.Errorf("by memory = %v, want %v", got, want)
	}
}

func TestFormatProcessCells(t *testing.T) {
	measured := core.ProcessUsage{Name: "idle", CPUValid: true, MemoryValid: true}
	if got := formatProcessCPU(measured); got != "0.0" {
		t.Errorf("measured zero CPU = %q, want 0.0", got)
	}
	if got := formatProcessMemory(measured); got != "0 B" {
		t.Errorf("measured zero memory = %q, want 0 B", got)
	}

	// Values on an unavailable metric must never leak onto the screen.
	unreadable := core.ProcessUsage{CPUPercent: 12, MemoryBytes: 4096}
	for name, got := range map[string]string{
		"CPU":    formatProcessCPU(unreadable),
		"memory": formatProcessMemory(unreadable),
		"name":   formatProcessName(unreadable),
	} {
		if got != "—" {
			t.Errorf("unavailable %s = %q, want —", name, got)
		}
	}
}

func TestSelectionRow(t *testing.T) {
	prev := []core.ProcessUsage{{PID: 1}, {PID: 2}, {PID: 3}}

	cases := []struct {
		name      string
		prevIndex int
		next      []core.ProcessUsage
		want      int
	}{
		{"top row stays on top", 0, []core.ProcessUsage{{PID: 3}, {PID: 1}, {PID: 2}}, 0},
		{"follows moved process", 1, []core.ProcessUsage{{PID: 3}, {PID: 1}, {PID: 2}}, 2},
		{"follows process to top", 2, []core.ProcessUsage{{PID: 3}, {PID: 1}}, 0},
		{"exited process keeps row", 1, []core.ProcessUsage{{PID: 1}, {PID: 3}, {PID: 4}}, 1},
		{"exited process clamps to end", 2, []core.ProcessUsage{{PID: 1}, {PID: 2}}, 1},
		{"empty table", 2, nil, 0},
		{"no selection yet", -1, []core.ProcessUsage{{PID: 1}}, 0},
		{"stale index beyond prev", 9, []core.ProcessUsage{{PID: 1}, {PID: 2}}, 1},
	}
	for _, c := range cases {
		if got := selectionRow(c.prevIndex, prev, c.next); got != c.want {
			t.Errorf("%s: selectionRow = %d, want %d", c.name, got, c.want)
		}
	}
}

// The selection follows a process, not a PID: once the PID belongs to a
// different process the highlight must not jump to it.
func TestSelectionRowDoesNotFollowReusedPID(t *testing.T) {
	t0 := time.Unix(1_000, 0)
	t1 := time.Unix(2_000, 0)

	prev := []core.ProcessUsage{{PID: 1, StartTime: t0}, {PID: 2, StartTime: t0}, {PID: 3, StartTime: t0}}

	same := []core.ProcessUsage{{PID: 2, StartTime: t0}, {PID: 9, StartTime: t0}, {PID: 3, StartTime: t0}}
	if got := selectionRow(2, prev, same); got != 2 {
		t.Errorf("same process: selectionRow = %d, want 2", got)
	}

	reused := []core.ProcessUsage{{PID: 3, StartTime: t1}, {PID: 1, StartTime: t0}, {PID: 2, StartTime: t0}}
	if got := selectionRow(2, prev, reused); got != 2 {
		t.Errorf("reused PID: selectionRow = %d, want the cursor to stay on row 2", got)
	}

	// A start time appearing where there was none is not proof of identity.
	unknown := []core.ProcessUsage{{PID: 1}, {PID: 2}, {PID: 3}}
	known := []core.ProcessUsage{{PID: 3, StartTime: t0}, {PID: 2, StartTime: t0}, {PID: 1, StartTime: t0}}
	if got := selectionRow(2, unknown, known); got != 2 {
		t.Errorf("unknown→known start time: selectionRow = %d, want 2", got)
	}
	// With no start time on either side the PID is trusted.
	if got := selectionRow(2, unknown, []core.ProcessUsage{{PID: 3}, {PID: 2}, {PID: 1}}); got != 0 {
		t.Errorf("unknown start times: selectionRow = %d, want 0", got)
	}
}

func tableColumn(rp *ResourcesPage, col int) []string {
	var out []string
	for row := resourceHeaderRows; row < rp.table.GetRowCount(); row++ {
		out = append(out, rp.table.GetCell(row, col).Text)
	}
	return out
}

func pressRune(rp *ResourcesPage, r rune) {
	rp.table.GetInputCapture()(tcell.NewEventKey(tcell.KeyRune, r, tcell.ModNone))
}

func selectedPID(rp *ResourcesPage) string {
	row, _ := rp.table.GetSelection()
	return rp.table.GetCell(row, 0).Text
}

func TestResourcesPageRenderAndSort(t *testing.T) {
	rp := NewResourcesPage()

	if got := rp.table.GetRowCount(); got != resourceHeaderRows {
		t.Fatalf("empty page has %d rows, want header only", got)
	}

	idle, busy, mid := proc(1, 0, 3<<20), proc(2, 90, 1<<20), proc(3, 10, 2<<20)
	idle.Name, busy.Name, mid.Name = "idle", "[busy]", "mid"
	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{idle, busy, mid}})
	rp.Render()

	if got, want := strings.Join(tableColumn(rp, 0), ","), "2,3,1"; got != want {
		t.Errorf("PIDs by CPU = %s, want %s", got, want)
	}
	if got := rp.table.GetCell(1, 2).Text; got != "90.0" {
		t.Errorf("CPU cell = %q, want 90.0", got)
	}
	if got := rp.table.GetCell(1, 3).Text; got != "1.0 MiB" {
		t.Errorf("memory cell = %q, want 1.0 MiB", got)
	}
	// Brackets in a name must be escaped so tview does not read them as a tag.
	if got := rp.table.GetCell(1, 1).Text; got != "[busy[]" {
		t.Errorf("name cell = %q, want escaped [busy[]", got)
	}
	if !strings.Contains(rp.table.GetCell(0, 2).Text, "▼") {
		t.Error("CPU header should carry the sort marker")
	}
	if got := rp.table.GetCell(0, 3).Text; got != "RSS" {
		t.Errorf("memory column header = %q, want RSS", got)
	}

	pressRune(rp, 'm')

	if got, want := strings.Join(tableColumn(rp, 0), ","), "1,3,2"; got != want {
		t.Errorf("PIDs by memory = %s, want %s", got, want)
	}
	if !strings.Contains(rp.table.GetCell(0, 3).Text, "▼") || strings.Contains(rp.table.GetCell(0, 2).Text, "▼") {
		t.Error("sort marker should move to the RSS header")
	}

	pressRune(rp, 'c')
	if got, want := strings.Join(tableColumn(rp, 0), ","), "2,3,1"; got != want {
		t.Errorf("PIDs after switching back to CPU = %s, want %s", got, want)
	}
}

func TestResourcesPageRendersUnavailableAsDash(t *testing.T) {
	rp := NewResourcesPage()

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		{PID: 1, Name: "launchd"},                                     // nothing measurable
		{PID: 2, Name: "idle", CPUValid: true, MemoryValid: true},     // measured zeros
		{PID: 3, CPUPercent: 7, CPUValid: true, MemoryBytes: 1 << 20}, // no name, no memory
	}})
	rp.Render()

	rows := map[string][3]string{}
	for row := resourceHeaderRows; row < rp.table.GetRowCount(); row++ {
		rows[rp.table.GetCell(row, 0).Text] = [3]string{
			rp.table.GetCell(row, 1).Text, rp.table.GetCell(row, 2).Text, rp.table.GetCell(row, 3).Text,
		}
	}

	want := map[string][3]string{
		"1": {"launchd", "—", "—"},
		"2": {"idle", "0.0", "0 B"},
		"3": {"—", "7.0", "—"},
	}
	for pid, w := range want {
		if rows[pid] != w {
			t.Errorf("pid %s cells = %q, want %q", pid, rows[pid], w)
		}
	}
}

// Regression: changing the sort used to leave the cursor on the same row
// index, silently highlighting a different process.
func TestResourcesPageSortResetsSelectionToTop(t *testing.T) {
	rp := NewResourcesPage()

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		proc(1, 50, 10), proc(2, 40, 50), proc(3, 30, 40), proc(4, 20, 30), proc(5, 10, 20),
	}})
	rp.Render()

	for _, c := range []struct {
		key  rune
		want string // PID expected on the first process row
	}{
		{'m', "2"},
		{'c', "1"},
		{'M', "2"},
	} {
		rp.table.Select(4, 0)
		pressRune(rp, c.key)

		row, _ := rp.table.GetSelection()
		if row != resourceHeaderRows {
			t.Errorf("after %q: selection on row %d, want first process row", c.key, row)
		}
		if got := selectedPID(rp); got != c.want {
			t.Errorf("after %q: selected PID %s, want %s", c.key, got, c.want)
		}
		if cell := rp.table.GetCell(0, 0); cell.Text != "PID" {
			t.Errorf("after %q: header row is %q", c.key, cell.Text)
		}
	}

	// Pressing the key for the sort already in effect changes nothing.
	rp.table.Select(3, 0)
	pressRune(rp, 'm')
	if row, _ := rp.table.GetSelection(); row != 3 {
		t.Errorf("re-selecting the active sort moved the cursor to row %d", row)
	}

	// The next refresh must not undo the reset by "following" the old row.
	pressRune(rp, 'c')
	rp.Render()
	if got := selectedPID(rp); got != "1" {
		t.Errorf("after refresh: selected PID %s, want 1", got)
	}
}

func TestResourcesPageHeaderIsNeverSelected(t *testing.T) {
	rp := NewResourcesPage()
	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{proc(1, 3, 3), proc(2, 2, 2), proc(3, 1, 1)}})
	rp.Render()

	handler := rp.table.InputHandler()
	for _, key := range []tcell.Key{tcell.KeyHome, tcell.KeyUp, tcell.KeyPgUp, tcell.KeyEnd, tcell.KeyHome, tcell.KeyUp} {
		handler(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
		if row, _ := rp.table.GetSelection(); row < resourceHeaderRows {
			t.Fatalf("key %v selected the header row", key)
		}
	}
	if rp.table.GetCell(0, 0).NotSelectable != true {
		t.Error("header cells must be unselectable")
	}
}

func TestResourcesPageSelectionFollowsProcess(t *testing.T) {
	rp := NewResourcesPage()

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		proc(1, 30, 0), proc(2, 20, 0), proc(3, 10, 0),
	}})
	rp.Render()

	if row, _ := rp.table.GetSelection(); row != resourceHeaderRows {
		t.Fatalf("initial selection on row %d, want first data row", row)
	}

	rp.table.Select(2, 0) // PID 2

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		proc(1, 30, 0), proc(2, 5, 0), proc(3, 10, 0),
	}})
	rp.Render()

	if row, _ := rp.table.GetSelection(); row != 3 {
		t.Errorf("selection on row %d, want 3 (PID 2 moved down)", row)
	}

	// The selected process exits and the table shrinks beneath the cursor.
	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{proc(1, 30, 0)}})
	rp.Render()

	if got := rp.table.GetRowCount(); got != 2 {
		t.Errorf("table has %d rows, want 2", got)
	}
	if row, _ := rp.table.GetSelection(); row != 1 {
		t.Errorf("selection on row %d, want 1 after shrink", row)
	}

	rp.SetSnapshot(&core.ResourceSnapshot{})
	rp.Render()

	if got := rp.table.GetRowCount(); got != resourceHeaderRows {
		t.Errorf("table has %d rows, want header only", got)
	}
}

// TestResourcesPageConcurrentSnapshots is meaningful under -race: a collector
// goroutine replaces the snapshot while the event loop renders.
func TestResourcesPageConcurrentSnapshots(t *testing.T) {
	rp := NewResourcesPage()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
				{PID: int32(i), CPUPercent: float64(i)},
				{PID: int32(i + 1)},
			}})
		}
	}()

	for i := 0; i < 200; i++ {
		rp.Render()
	}
	wg.Wait()
}

func TestTabBarOffset(t *testing.T) {
	full := 0
	for i := range tabNames {
		full += len(tabLabel(i)) + 1
	}
	throughSettings := full - len(tabLabel(tabResources)) - 1 - len(tabLabel(tabHealth)) - 1

	cases := []struct {
		name   string
		active int
		width  int
		want   int
	}{
		{"width unknown", tabHealth, 0, 0},
		{"wide terminal", tabHealth, full + 20, 0},
		{"first tab never scrolls", tabProcess, 20, 0},
		{"tab that fits exactly", tabSettings, throughSettings, 0},
		{"last tab on 80 columns", tabHealth, 80, full - 80},
		{"settings on 60 columns", tabSettings, 60, throughSettings - 60},
	}
	for _, c := range cases {
		if got := tabBarOffset(c.active, c.width); got != c.want {
			t.Errorf("%s: tabBarOffset(%d, %d) = %d, want %d", c.name, c.active, c.width, got, c.want)
		}
	}
}
