package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/gdamore/tcell/v2"
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
	for _, want := range []string{"25.0%", "4.0 GiB / 16.0 GiB (25.0%)", "3 processes", "sorted by memory", "03:04:05"} {
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

func TestSortProcessUsage(t *testing.T) {
	procs := []core.ProcessUsage{
		{PID: 30, CPUPercent: 5, MemoryBytes: 100},
		{PID: 10, CPUPercent: 50, MemoryBytes: 300},
		{PID: 20, CPUPercent: 5, MemoryBytes: 900},
		{PID: 5, CPUPercent: 0, MemoryBytes: 300},
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

func TestResourcesPageRenderAndSort(t *testing.T) {
	rp := NewResourcesPage()

	if got := rp.table.GetRowCount(); got != resourceHeaderRows {
		t.Fatalf("empty page has %d rows, want header only", got)
	}

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		{PID: 1, Name: "idle", CPUPercent: 0, MemoryBytes: 3 << 20},
		{PID: 2, Name: "[busy]", CPUPercent: 90, MemoryBytes: 1 << 20},
		{PID: 3, Name: "mid", CPUPercent: 10, MemoryBytes: 2 << 20},
	}})
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

	pressRune(rp, 'm')

	if got, want := strings.Join(tableColumn(rp, 0), ","), "1,3,2"; got != want {
		t.Errorf("PIDs by memory = %s, want %s", got, want)
	}
	if !strings.Contains(rp.table.GetCell(0, 3).Text, "▼") || strings.Contains(rp.table.GetCell(0, 2).Text, "▼") {
		t.Error("sort marker should move to the MEM header")
	}

	pressRune(rp, 'c')
	if got, want := strings.Join(tableColumn(rp, 0), ","), "2,3,1"; got != want {
		t.Errorf("PIDs after switching back to CPU = %s, want %s", got, want)
	}
}

func TestResourcesPageSelectionFollowsProcess(t *testing.T) {
	rp := NewResourcesPage()

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		{PID: 1, CPUPercent: 30},
		{PID: 2, CPUPercent: 20},
		{PID: 3, CPUPercent: 10},
	}})
	rp.Render()

	if row, _ := rp.table.GetSelection(); row != resourceHeaderRows {
		t.Fatalf("initial selection on row %d, want first data row", row)
	}

	rp.table.Select(2, 0) // PID 2

	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		{PID: 1, CPUPercent: 30},
		{PID: 2, CPUPercent: 5},
		{PID: 3, CPUPercent: 10},
	}})
	rp.Render()

	if row, _ := rp.table.GetSelection(); row != 3 {
		t.Errorf("selection on row %d, want 3 (PID 2 moved down)", row)
	}

	// The selected process exits and the table shrinks beneath the cursor.
	rp.SetSnapshot(&core.ResourceSnapshot{Processes: []core.ProcessUsage{
		{PID: 1, CPUPercent: 30},
	}})
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
	throughSettings := full - len(tabLabel(tabResources)) - 1

	cases := []struct {
		name   string
		active int
		width  int
		want   int
	}{
		{"width unknown", tabResources, 0, 0},
		{"wide terminal", tabResources, full + 20, 0},
		{"first tab never scrolls", tabProcess, 20, 0},
		{"tab that fits exactly", tabSettings, throughSettings, 0},
		{"last tab on 80 columns", tabResources, 80, full - 80},
		{"settings on 60 columns", tabSettings, 60, throughSettings - 60},
	}
	for _, c := range cases {
		if got := tabBarOffset(c.active, c.width); got != c.want {
			t.Errorf("%s: tabBarOffset(%d, %d) = %d, want %d", c.name, c.active, c.width, got, c.want)
		}
	}
}
