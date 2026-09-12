package main

import (
	"fmt"
	"sync"
	"time"

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
	tabCount    = 5
)

var tabNames = [tabCount]string{"Process", "Network", "DNS", "File", "Findings"}

// UI is a tview-based terminal dashboard with one scrolling pane per telemetry
// type. All Add* methods are goroutine-safe and can be called from bus
// subscribers while the tview event loop runs on the main goroutine.
type UI struct {
	app     *tview.Application
	pages   *tview.Pages
	views   [tabCount]*tview.TextView
	tabBar  *tview.TextView
	active  int
	mu      sync.Mutex // guards active for cross-goroutine reads
}

func NewUI() *UI {
	u := &UI{}
	u.app = tview.NewApplication()

	// Build one TextView per tab.
	for i := range u.views {
		tv := tview.NewTextView().
			SetDynamicColors(true).
			SetScrollable(true).
			SetWrap(true).
			SetChangedFunc(func() { u.app.Draw() })
		tv.SetBorder(false)
		u.views[i] = tv
	}

	// Tab bar — a single-line TextView we repaint on every switch.
	u.tabBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	u.tabBar.SetBorder(false)
	u.tabBar.SetBackgroundColor(tcell.ColorDarkBlue)

	// Pages holds the content panes.
	u.pages = tview.NewPages()
	for i, tv := range u.views {
		u.pages.AddPage(tabNames[i], tv, true, i == tabProcess)
	}

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.tabBar, 1, 0, false).
		AddItem(u.pages, 0, 1, true)

	u.app.SetRoot(root, true).EnableMouse(false)
	u.renderTabBar()

	// Tab navigation: 1-5 or ←/→ arrows.
	u.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyLeft:
			u.switchTab((u.active + tabCount - 1) % tabCount)
			return nil
		case tcell.KeyRight:
			u.switchTab((u.active + 1) % tabCount)
			return nil
		case tcell.KeyRune:
			if event.Rune() >= '1' && event.Rune() <= '5' {
				u.switchTab(int(event.Rune() - '1'))
				return nil
			}
		}
		return event
	})

	return u
}

// Run starts the tview event loop. It blocks until Stop is called.
func (u *UI) Run() error {
	return u.app.Run()
}

// Stop halts the tview event loop.
func (u *UI) Stop() {
	u.app.Stop()
}

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
	bar += "[gray:darkblue]  ←/→ or 1-5 to switch[-:-:-]"
	u.tabBar.SetText(bar)
}

// append writes a timestamped line to the given tab, thread-safely.
func (u *UI) append(tab int, color, line string) {
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf("[gray]%s[-]  [%s]%s[-]\n", ts, color, tview.Escape(line))
	u.app.QueueUpdateDraw(func() {
		tv := u.views[tab]
		fmt.Fprint(tv, msg)
		tv.ScrollToEnd()
	})
}

// AddProcess logs a process telemetry line.
func (u *UI) AddProcess(line string) { u.append(tabProcess, "green", line) }

// AddNetwork logs a network telemetry line.
func (u *UI) AddNetwork(line string) { u.append(tabNetwork, "cyan", line) }

// AddDNS logs a DNS telemetry line.
func (u *UI) AddDNS(line string) { u.append(tabDNS, "yellow", line) }

// AddFile logs a file telemetry line.
func (u *UI) AddFile(line string) { u.append(tabFile, "orange", line) }

// AddFinding logs a behavioral finding (always high-visibility).
func (u *UI) AddFinding(line string) { u.append(tabFindings, "red", line) }
