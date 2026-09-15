package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// tabIndex maps friendly names to their position in the tabs slice.
const (
	tabProcess  = 0
	tabNetwork  = 1
	tabDNS      = 2
	tabFile     = 3
	tabFindings = 4
	tabPatterns = 5
	tabSettings = 6
	tabCount    = 7
)

var tabNames = [tabCount]string{"Process", "Network", "DNS", "File", "Findings", "Patterns", "Settings"}

// ringCap is the maximum number of formatted lines kept in memory per tab.
// Older lines are evicted and live only in the SQLite store.
const ringCap = 500

// ringBuf is a fixed-capacity circular buffer of pre-formatted display lines.
// Not goroutine-safe on its own; callers hold UI.mu.
type ringBuf struct {
	data [ringCap]string
	head int // next write position
	n    int // items stored (0..ringCap)
}

// push adds a line. Returns true when the buffer is full and an old line was
// overwritten (caller should redraw from scratch rather than appending).
func (r *ringBuf) push(s string) (wrapped bool) {
	r.data[r.head] = s
	r.head = (r.head + 1) % ringCap
	if r.n < ringCap {
		r.n++
		return false
	}
	return true
}

// content joins all stored lines in order (oldest → newest).
func (r *ringBuf) content() string {
	if r.n == 0 {
		return ""
	}
	parts := make([]string, r.n)
	if r.n < ringCap {
		copy(parts, r.data[:r.n])
	} else {
		copy(parts, r.data[r.head:])
		copy(parts[ringCap-r.head:], r.data[:r.head])
	}
	return strings.Join(parts, "")
}

// UI is a tview-based terminal dashboard with one scrolling pane per telemetry
// type. All Add* methods are goroutine-safe.
type UI struct {
	app          *tview.Application
	pages        *tview.Pages
	views        [tabPatterns]*tview.TextView // telemetry text views (indices 0-4)
	tabBar       *tview.TextView
	active       int
	mu           sync.Mutex // guards active + rings
	rings        [tabPatterns]ringBuf
	store        *store.Store
	patternsPage *PatternsPage
	settingsPage *SettingsPage
}

// NewUI constructs the dashboard. Call SetPatternsPage and SetSettingsPage
// before Run to wire the extra tabs.
func NewUI() *UI {
	u := &UI{}
	u.app = tview.NewApplication()

	for i := range u.views {
		tv := tview.NewTextView().
			SetDynamicColors(true).
			SetScrollable(true).
			SetWrap(true).
			SetChangedFunc(func() { u.app.Draw() })
		tv.SetBorder(false)
		u.views[i] = tv
	}

	u.tabBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	u.tabBar.SetBorder(false)
	u.tabBar.SetBackgroundColor(tcell.ColorDarkBlue)

	u.pages = tview.NewPages()
	for i, tv := range u.views {
		u.pages.AddPage(tabNames[i], tv, true, i == tabProcess)
	}

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.tabBar, 1, 0, false).
		AddItem(u.pages, 0, 1, true)

	u.app.SetRoot(root, true).EnableMouse(false)
	u.renderTabBar()

	u.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		u.mu.Lock()
		active := u.active
		u.mu.Unlock()

		// Pass all keys through when focus is on any interactive widget.
		// This covers InputField cursors, modal button navigation (←/→),
		// form dropdowns, and any other widget that needs raw key events.
		if interactiveFocus(u.app.GetFocus()) {
			return event
		}

		switch event.Key() {
		case tcell.KeyLeft:
			u.switchTab((active + tabCount - 1) % tabCount)
			return nil
		case tcell.KeyRight:
			u.switchTab((active + 1) % tabCount)
			return nil
		case tcell.KeyRune:
			// Digit shortcuts only apply on plain telemetry tabs.
			if event.Rune() >= '1' && event.Rune() <= '7' && active < tabPatterns {
				u.switchTab(int(event.Rune() - '1'))
				return nil
			}
		}
		return event
	})

	return u
}

// SetStore attaches the SQLite store. Call before Run.
func (u *UI) SetStore(s *store.Store) { u.store = s }

// SetPatternsPage wires the pattern editor. Call before Run.
func (u *UI) SetPatternsPage(pp *PatternsPage) {
	u.patternsPage = pp
	u.pages.AddPage(tabNames[tabPatterns], pp.Root(), true, false)
}

// SetSettingsPage wires the settings editor. Call before Run.
func (u *UI) SetSettingsPage(sp *SettingsPage) {
	u.settingsPage = sp
	u.pages.AddPage(tabNames[tabSettings], sp.Root(), true, false)
}

// Run starts the tview event loop. Blocks until Stop is called.
func (u *UI) Run() error { return u.app.Run() }

// Stop halts the tview event loop.
func (u *UI) Stop() { u.app.Stop() }

func (u *UI) switchTab(idx int) {
	u.mu.Lock()
	u.active = idx
	u.mu.Unlock()
	u.pages.SwitchToPage(tabNames[idx])
	u.renderTabBar()
}

func (u *UI) renderTabBar() {
	u.mu.Lock()
	active := u.active
	u.mu.Unlock()

	var bar string
	for i, name := range tabNames {
		if i == active {
			bar += fmt.Sprintf("[black:white:b] %d:%s [-:-:-] ", i+1, name)
		} else {
			bar += fmt.Sprintf("[white:darkblue] %d:%s [-:-:-] ", i+1, name)
		}
	}
	bar += "[gray:darkblue]  ←/→ or 1-7 to switch[-:-:-]"
	u.tabBar.SetText(bar)
}

// append writes a line to a telemetry tab. It:
//  1. Persists the raw line to SQLite (if store is wired).
//  2. Pushes the formatted display line to a bounded ring buffer.
//  3. If the ring wrapped (old lines evicted), redraws the TextView from the
//     ring buffer content instead of appending — preventing unbounded RAM use.
func (u *UI) append(tab int, color, rawLine string) {
	ts := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[gray]%s[-]  [%s]%s[-]\n", ts, color, tview.Escape(rawLine))

	if u.store != nil {
		u.store.Write(tabNames[tab], rawLine)
	}

	u.mu.Lock()
	wrapped := u.rings[tab].push(formatted)
	var full string
	if wrapped {
		full = u.rings[tab].content()
	}
	u.mu.Unlock()

	u.app.QueueUpdateDraw(func() {
		tv := u.views[tab]
		if full != "" {
			tv.SetText(full)
		} else {
			fmt.Fprint(tv, formatted)
		}
		tv.ScrollToEnd()
	})
}

// interactiveFocus returns true when p is a widget that needs raw key events
// for its own navigation — input cursors, modal button selection, dropdowns.
// When true, the global tab-switch capture must not steal arrow or digit keys.
func interactiveFocus(p tview.Primitive) bool {
	if p == nil {
		return false
	}
	switch p.(type) {
	case *tview.InputField, *tview.Button, *tview.DropDown, *tview.Checkbox, *tview.Modal:
		return true
	}
	return false
}

// AddProcess logs a process telemetry line.
func (u *UI) AddProcess(line string) { u.append(tabProcess, "green", line) }

// AddNetwork logs a network telemetry line.
func (u *UI) AddNetwork(line string) { u.append(tabNetwork, "cyan", line) }

// AddDNS logs a DNS telemetry line.
func (u *UI) AddDNS(line string) { u.append(tabDNS, "yellow", line) }

// AddFile logs a file telemetry line.
func (u *UI) AddFile(line string) { u.append(tabFile, "orange", line) }

// AddFinding logs a behavioral finding.
func (u *UI) AddFinding(line string) { u.append(tabFindings, "red", line) }
