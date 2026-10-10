package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// tabIndex maps friendly names to their position in the tabs slice.
const (
	tabProcess   = 0
	tabNetwork   = 1
	tabDNS       = 2
	tabFile      = 3
	tabFindings  = 4
	tabPatterns  = 5
	tabSettings  = 6
	tabResources = 7
	tabCount     = 8
)

var tabNames = [tabCount]string{"Process", "Network", "DNS", "File", "Findings", "Patterns", "Settings", "Resources"}

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
	root         *tview.Flex
	pages        *tview.Pages
	views        [tabPatterns]*tview.TextView // telemetry text views (indices 0-4)
	tabBar       *tview.TextView
	tabBarWidth  int // last drawn screen width; event loop only
	active       int
	mu           sync.Mutex // guards active + rings
	rings        [tabPatterns]ringBuf
	store        *store.Store
	patternsPage *PatternsPage
	settingsPage *SettingsPage
	resources    *ResourcesPage

	// Resource snapshots are rendered by waking the event loop, never by
	// waiting on it. resourceTick is the wake-up: an event recognised by
	// pointer identity, so no real keystroke can be mistaken for it.
	resourceTick    *tcell.EventKey
	resourcePending atomic.Bool // a tick is queued and not yet handled
	stopped         atomic.Bool // Stop was called or the event loop exited
}

// NewUI constructs the dashboard. Call SetPatternsPage and SetSettingsPage
// before Run to wire the extra tabs.
func NewUI() *UI {
	u := &UI{}
	u.app = tview.NewApplication()
	u.resourceTick = tcell.NewEventKey(tcell.KeyNUL, 0, tcell.ModNone)

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
		SetWrap(false).
		SetTextAlign(tview.AlignLeft)
	u.tabBar.SetBorder(false)
	u.tabBar.SetBackgroundColor(tcell.ColorDarkBlue)

	u.pages = tview.NewPages()
	for i, tv := range u.views {
		u.pages.AddPage(tabNames[i], tv, true, i == tabProcess)
	}

	u.resources = NewResourcesPage()
	u.pages.AddPage(tabNames[tabResources], u.resources.Root(), true, false)

	u.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.tabBar, 1, 0, false).
		AddItem(u.pages, 0, 1, true)

	u.app.SetRoot(u.root, true).EnableMouse(false)
	u.renderTabBar()

	// The tab bar is wider than a narrow terminal, so it scrolls sideways to
	// keep the active tab on screen. Re-check whenever the width changes.
	u.app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		if w, _ := screen.Size(); w != u.tabBarWidth {
			u.tabBarWidth = w
			u.scrollTabBar()
		}
		if u.settingsPage != nil {
			u.settingsPage.SyncHint()
		}
		return false
	})

	u.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		u.mu.Lock()
		active := u.active
		u.mu.Unlock()

		// Wake-up from UpdateResources. Returning nil makes tview redraw.
		if event == u.resourceTick {
			u.resourcePending.Store(false)
			if active == tabResources {
				u.resources.Render()
			}
			return nil
		}

		// Every focusable widget on the Settings form needs the arrow keys,
		// so the form would otherwise trap the user on that tab. Arriving on
		// Settings therefore leaves focus on the tab bar, where ←/→ and the
		// digits keep working and the page's shortcuts are still honoured.
		// Enter steps into the form; Esc (the form's cancel action) steps
		// back out.
		if active == tabSettings && u.settingsPage != nil && u.app.GetFocus() == u.tabBar {
			switch event.Key() {
			case tcell.KeyEnter, tcell.KeyTab, tcell.KeyDown:
				u.app.SetFocus(u.pages)
				return nil
			}
			if u.settingsPage.HandleShortcut(event) {
				return nil
			}
		}

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
			// Digit shortcuts only apply where digits are not text entry:
			// the plain telemetry tabs, the resource monitor, and Settings
			// while focus is still on the tab bar.
			if event.Rune() >= '1' && event.Rune() < '1'+tabCount &&
				(active < tabPatterns || active == tabResources || u.app.GetFocus() == u.tabBar) {
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
	sp.SetHost(settingsHost{
		restore: u.restoreFromSettingsModal,
		leave:   func() { u.app.SetFocus(u.tabBar) },
	})
	u.pages.AddPage(tabNames[tabSettings], sp.Root(), true, false)
}

// restoreFromSettingsModal puts the dashboard back after a Settings modal
// closes. Focus goes to whichever tab is showing now: a modal reporting the
// result of a background action must not drag focus back into a hidden
// Settings form. Must be called on the event loop.
func (u *UI) restoreFromSettingsModal(toForm bool) {
	// Focusing the root hands focus to the visible page.
	u.app.SetRoot(u.root, true)

	u.mu.Lock()
	active := u.active
	u.mu.Unlock()

	if active == tabSettings && !toForm {
		u.app.SetFocus(u.tabBar)
	}
}

// Run starts the tview event loop. Blocks until Stop is called or the loop
// ends on its own (Ctrl+C, terminal error).
func (u *UI) Run() error {
	err := u.app.Run()
	u.stopped.Store(true)
	return err
}

// Stop halts the tview event loop. Calling it again, or after the loop has
// already ended, does nothing.
func (u *UI) Stop() {
	if u.stopped.Swap(true) {
		return
	}
	u.app.Stop()
}

func (u *UI) switchTab(idx int) {
	u.mu.Lock()
	u.active = idx
	u.mu.Unlock()
	if idx == tabResources {
		// Samples that arrived while the tab was hidden were not rendered.
		u.resources.Render()
	}
	u.pages.SwitchToPage(tabNames[idx])
	if idx == tabSettings {
		u.app.SetFocus(u.tabBar)
	} else {
		u.app.SetFocus(u.pages)
	}
	u.renderTabBar()
}

func (u *UI) renderTabBar() {
	u.mu.Lock()
	active := u.active
	u.mu.Unlock()

	var bar string
	for i := range tabNames {
		if i == active {
			bar += fmt.Sprintf("[black:white:b]%s[-:-:-] ", tabLabel(i))
		} else {
			bar += fmt.Sprintf("[white:darkblue]%s[-:-:-] ", tabLabel(i))
		}
	}
	bar += "[gray:darkblue]  ←/→ or 1-8 to switch[-:-:-]"
	u.tabBar.SetText(bar)
	u.scrollTabBar()
}

func (u *UI) scrollTabBar() {
	u.mu.Lock()
	active := u.active
	u.mu.Unlock()

	u.tabBar.ScrollTo(0, tabBarOffset(active, u.tabBarWidth))
}

func tabLabel(idx int) string {
	return fmt.Sprintf(" %d:%s ", idx+1, tabNames[idx])
}

// tabBarOffset returns how many cells the tab bar must scroll left so the
// active tab is fully visible in a bar of the given width. It is 0 whenever
// the tab already fits (and before the width is known).
func tabBarOffset(active, width int) int {
	end := 0
	for i := 0; i <= active; i++ {
		end += len(tabLabel(i)) + 1 // label plus separator
	}
	if width <= 0 || end <= width {
		return 0
	}
	return end - width
}

// append writes a line to a telemetry tab. It:
//  1. Persists the raw line to SQLite (if store is wired).
//  2. Pushes the formatted display line to a bounded ring buffer.
//  3. If the ring wrapped (old lines evicted), redraws the TextView from the
//     ring buffer content instead of appending — preventing unbounded RAM use.
func (u *UI) append(tab int, color, rawLine string) {
	u.appendPersisting(tab, color, rawLine, func() {
		u.store.Write(tabNames[tab], rawLine)
	})
}

// appendPersisting is append with the caller deciding how the line is
// written to the store, which is only called when a store is wired.
func (u *UI) appendPersisting(tab int, color, rawLine string, persist func()) {
	ts := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[gray]%s[-]  [%s]%s[-]\n", ts, color, tview.Escape(rawLine))

	if u.store != nil {
		persist()
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

// AddFindingWithEvidence logs a finding and stores its evidence with it. The
// Findings tab shows the same line either way.
func (u *UI) AddFindingWithEvidence(line string, evidence core.Evidence) {
	u.appendPersisting(tabFindings, "red", line, func() {
		u.store.WriteFinding(line, evidence)
	})
}

// UpdateResources hands a fresh resource snapshot to the Resources tab.
// Goroutine-safe. Snapshots are display-only: they are neither persisted nor
// kept in a ring buffer.
//
// It never waits for the event loop. tview's QueueUpdate blocks until the
// loop has run the update, which is forever once the loop has exited, so the
// caller's goroutine could not shut down. Instead the snapshot is stored and,
// while the tab is visible, the loop is woken with a single queued event;
// further snapshots that arrive before it is handled ride along with it.
// Once the UI has stopped the snapshot is simply dropped.
func (u *UI) UpdateResources(s *core.ResourceSnapshot) {
	u.resources.SetSnapshot(s)

	u.mu.Lock()
	visible := u.active == tabResources
	u.mu.Unlock()

	if !visible || u.stopped.Load() {
		return
	}

	// At most one tick is ever outstanding, so this send finds room in the
	// event queue unless ~100 real input events are already backed up.
	if u.resourcePending.CompareAndSwap(false, true) {
		u.app.QueueEvent(u.resourceTick)
	}
}
