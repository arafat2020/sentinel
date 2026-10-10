package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// resourceSort selects the column the process table is ordered by.
type resourceSort int

const (
	sortByCPU resourceSort = iota
	sortByMemory
)

func (s resourceSort) String() string {
	if s == sortByMemory {
		return "RSS"
	}
	return "CPU"
}

const (
	resourceMeterWidth = 30
	resourceHeaderRows = 1

	// resourceUnavailable stands in for a value that could not be measured,
	// so it is never mistaken for a real zero.
	resourceUnavailable = "—"
)

// ResourcesPage is the live process monitor (tab 8).
//
// Columns: CPU% is relative to one core (so it can exceed 100) and RSS is the
// process's resident set size, i.e. physical memory currently mapped,
// including pages shared with other processes. Snapshots arrive from a
// background goroutine via SetSnapshot; everything else runs on the tview
// event loop.
type ResourcesPage struct {
	root    *tview.Flex
	summary *tview.TextView
	table   *tview.Table

	mu     sync.Mutex // guards latest
	latest *core.ResourceSnapshot

	// Event-loop only.
	sortBy resourceSort
	rows   []core.ProcessUsage // processes in the order currently displayed
}

// NewResourcesPage constructs the resource monitor page.
func NewResourcesPage() *ResourcesPage {
	rp := &ResourcesPage{}

	rp.summary = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	rp.summary.SetBorder(false)

	rp.table = tview.NewTable().
		SetFixed(resourceHeaderRows, 0).
		SetSelectable(true, false).
		SetSelectedStyle(tcell.StyleDefault.
			Background(tcell.ColorAqua).
			Foreground(tcell.ColorBlack).
			Bold(true))
	rp.table.SetBorder(false)

	hint := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[gray]  ↑/↓ PgUp/PgDn Home/End = select    c = sort by CPU    m = sort by RSS (memory)    " +
			resourceUnavailable + " = not readable[-]")
	hint.SetBorder(false)

	rp.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(rp.summary, 3, 0, false).
		AddItem(rp.table, 0, 1, true).
		AddItem(hint, 1, 0, false)

	rp.table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() != tcell.KeyRune {
			return event
		}
		switch event.Rune() {
		case 'c', 'C':
			rp.setSort(sortByCPU)
			return nil
		case 'm', 'M':
			rp.setSort(sortByMemory)
			return nil
		}
		return event
	})

	rp.Render()
	return rp
}

// Root returns the primitive to register with tview.Pages.
func (rp *ResourcesPage) Root() tview.Primitive { return rp.root }

// SetSnapshot stores the newest sample. Goroutine-safe; it does not touch any
// widget, so the caller decides whether a redraw is worth queueing.
func (rp *ResourcesPage) SetSnapshot(s *core.ResourceSnapshot) {
	rp.mu.Lock()
	rp.latest = s
	rp.mu.Unlock()
}

func (rp *ResourcesPage) setSort(by resourceSort) {
	if rp.sortBy == by {
		return
	}
	rp.sortBy = by
	rp.render(true)
	rp.table.ScrollToBeginning()
}

// Render rebuilds the widgets from the latest snapshot, keeping the current
// selection on its process. Must be called on the tview event loop.
func (rp *ResourcesPage) Render() { rp.render(false) }

// render rebuilds the widgets. With selectTop the highlight moves to the
// first process row instead of following the previously selected process.
func (rp *ResourcesPage) render(selectTop bool) {
	rp.mu.Lock()
	snap := rp.latest
	rp.mu.Unlock()

	rp.renderHeader()

	if snap == nil {
		rp.summary.SetText("\n[gray]  Collecting resource usage…[-]")
		return
	}

	rp.summary.SetText(formatSummary(snap, rp.sortBy))

	rows := sortProcessUsage(snap.Processes, rp.sortBy)
	selected := 0
	if !selectTop {
		prevRow, _ := rp.table.GetSelection()
		selected = selectionRow(prevRow-resourceHeaderRows, rp.rows, rows)
	}

	for i, p := range rows {
		row := i + resourceHeaderRows
		rp.table.SetCell(row, 0, tview.NewTableCell(strconv.Itoa(int(p.PID))).
			SetAlign(tview.AlignRight))
		rp.table.SetCell(row, 1, tview.NewTableCell(tview.Escape(formatProcessName(p))).
			SetExpansion(1))
		rp.table.SetCell(row, 2, tview.NewTableCell(formatProcessCPU(p)).
			SetAlign(tview.AlignRight))
		rp.table.SetCell(row, 3, tview.NewTableCell(formatProcessMemory(p)).
			SetAlign(tview.AlignRight))
	}
	for rp.table.GetRowCount() > len(rows)+resourceHeaderRows {
		rp.table.RemoveRow(rp.table.GetRowCount() - 1)
	}

	rp.rows = rows
	if len(rows) > 0 {
		rp.table.Select(selected+resourceHeaderRows, 0)
	}
}

func (rp *ResourcesPage) renderHeader() {
	titles := [...]string{"PID", "NAME", "CPU%", "RSS"}
	sorted := 2
	if rp.sortBy == sortByMemory {
		sorted = 3
	}

	for col, title := range titles {
		if col == sorted {
			title += " ▼"
		}
		cell := tview.NewTableCell(title).
			SetSelectable(false).
			SetTextColor(tcell.ColorYellow).
			SetAttributes(tcell.AttrBold)
		if col != 1 {
			cell.SetAlign(tview.AlignRight)
		} else {
			cell.SetExpansion(1)
		}
		rp.table.SetCell(0, col, cell)
	}
}

// sortProcessUsage returns a copy of procs ordered by the given column,
// highest first. Processes whose value for that column is unavailable go
// last: an unknown figure is not a low one. Ties fall back to PID so equal
// rows do not jump around between refreshes.
func sortProcessUsage(procs []core.ProcessUsage, by resourceSort) []core.ProcessUsage {
	out := make([]core.ProcessUsage, len(procs))
	copy(out, procs)

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch by {
		case sortByMemory:
			if a.MemoryValid != b.MemoryValid {
				return a.MemoryValid
			}
			if a.MemoryValid && a.MemoryBytes != b.MemoryBytes {
				return a.MemoryBytes > b.MemoryBytes
			}
		default:
			if a.CPUValid != b.CPUValid {
				return a.CPUValid
			}
			if a.CPUValid && a.CPUPercent != b.CPUPercent {
				return a.CPUPercent > b.CPUPercent
			}
		}
		return a.PID < b.PID
	})

	return out
}

// selectionRow decides which index of next should be highlighted, given the
// index highlighted in prev. A selection on the first row stays on the first
// row (so the default view keeps showing the top consumer); any other
// selection follows its process to wherever it moved. Processes are matched
// by PID and start time (see core.ProcessUsage.SameProcess), so a recycled
// PID is not mistaken for the process that was selected. If that process is
// gone, the cursor stays where it was, clamped to the new length.
func selectionRow(prevIndex int, prev, next []core.ProcessUsage) int {
	if len(next) == 0 || prevIndex <= 0 {
		return 0
	}
	if prevIndex < len(prev) {
		selected := prev[prevIndex]
		for i, p := range next {
			if p.SameProcess(selected) {
				return i
			}
		}
	}
	if prevIndex >= len(next) {
		return len(next) - 1
	}
	return prevIndex
}

func formatSummary(snap *core.ResourceSnapshot, by resourceSort) string {
	var b strings.Builder

	sys := snap.System

	if sys.CPUValid {
		fmt.Fprintf(&b, "  CPU  %s  %s%% of all cores\n", formatMeter(sys.CPUPercent, resourceMeterWidth), formatPercent(sys.CPUPercent))
	} else {
		b.WriteString("  CPU  [gray]n/a[-]\n")
	}

	if sys.MemoryValid {
		pct := float64(sys.MemoryUsed) / float64(sys.MemoryTotal) * 100
		fmt.Fprintf(&b, "  Mem  %s  %s used of %s system RAM (%s%%)\n",
			formatMeter(pct, resourceMeterWidth),
			formatBytes(sys.MemoryUsed),
			formatBytes(sys.MemoryTotal),
			formatPercent(pct),
		)
	} else {
		b.WriteString("  Mem  [gray]n/a[-]\n")
	}

	fmt.Fprintf(&b, "[gray]  %d processes    sorted by %s    updated %s[-]",
		len(snap.Processes), by, snap.Timestamp.Format("15:04:05"))

	return b.String()
}

// formatMeter draws a fixed-width usage bar, colored by how full it is.
func formatMeter(percent float64, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := int(percent/100*float64(width) + 0.5)

	color := "green"
	switch {
	case percent >= 85:
		color = "red"
	case percent >= 60:
		color = "yellow"
	}

	return fmt.Sprintf("[%s]%s[gray]%s[-]",
		color,
		strings.Repeat("█", filled),
		strings.Repeat("░", width-filled),
	)
}

func formatProcessName(p core.ProcessUsage) string {
	if p.Name == "" {
		return resourceUnavailable
	}
	return p.Name
}

func formatProcessCPU(p core.ProcessUsage) string {
	if !p.CPUValid {
		return resourceUnavailable
	}
	return formatPercent(p.CPUPercent)
}

func formatProcessMemory(p core.ProcessUsage) string {
	if !p.MemoryValid {
		return resourceUnavailable
	}
	return formatBytes(p.MemoryBytes)
}

func formatPercent(p float64) string {
	if p < 0 {
		p = 0
	}
	return strconv.FormatFloat(p, 'f', 1, 64)
}

// formatBytes renders a size using binary units, e.g. "512 B", "1.5 GiB".
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	units := [...]string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	value := float64(n) / unit
	i := 0
	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}

	return fmt.Sprintf("%.1f %s", value, units[i])
}
