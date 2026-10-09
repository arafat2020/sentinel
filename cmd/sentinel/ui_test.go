package main

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// uiHarness runs the real dashboard on an in-memory screen.
type uiHarness struct {
	t      *testing.T
	ui     *UI
	screen tcell.SimulationScreen
	seen   chan struct{} // one signal per key reaching the event loop
}

func newUIHarness(t *testing.T) *uiHarness {
	t.Helper()

	screen := tcell.NewSimulationScreen("UTF-8")
	ui := NewUI()
	ui.SetSettingsPage(NewSettingsPage(ui.app, nil))
	ui.app.SetScreen(screen)

	seen := make(chan struct{}, 16)
	capture := ui.app.GetInputCapture()
	ui.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		seen <- struct{}{}
		return capture(event)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ui.Run()
	}()
	t.Cleanup(func() {
		ui.Stop()
		<-done
	})

	return &uiHarness{t: t, ui: ui, screen: screen, seen: seen}
}

// key sends one keystroke and returns once the event loop has fully handled
// it: the queued no-op can only run after the key's own iteration finishes.
func (h *uiHarness) key(k tcell.Key, r rune) {
	h.t.Helper()
	h.screen.InjectKey(k, r, tcell.ModNone)
	select {
	case <-h.seen:
	case <-time.After(2 * time.Second):
		h.t.Fatal("key never reached the event loop")
	}
	h.ui.app.QueueUpdate(func() {})
}

func (h *uiHarness) activeTab() int {
	h.ui.mu.Lock()
	defer h.ui.mu.Unlock()
	return h.ui.active
}

func (h *uiHarness) focus() (p tview.Primitive) {
	h.ui.app.QueueUpdate(func() { p = h.ui.app.GetFocus() })
	return p
}

func (h *uiHarness) wantTab(want int) {
	h.t.Helper()
	if got := h.activeTab(); got != want {
		h.t.Fatalf("active tab = %s, want %s", tabNames[got], tabNames[want])
	}
}

func TestArrowKeysPassThroughSettingsTab(t *testing.T) {
	h := newUIHarness(t)

	// Walk right across every tab and back to the start.
	for i := 1; i <= tabCount; i++ {
		h.key(tcell.KeyRight, 0)
		h.wantTab(i % tabCount)
	}

	// And left, which enters Settings from the Resources side.
	h.key(tcell.KeyLeft, 0)
	h.wantTab(tabResources)
	h.key(tcell.KeyLeft, 0)
	h.wantTab(tabSettings)
	h.key(tcell.KeyLeft, 0)
	h.wantTab(tabPatterns)
}

func TestSettingsFormEnterAndEscape(t *testing.T) {
	h := newUIHarness(t)

	h.key(tcell.KeyRune, '7')
	h.wantTab(tabSettings)
	if _, ok := h.focus().(*tview.InputField); ok {
		t.Fatal("arriving on Settings must not focus the retention field")
	}

	h.key(tcell.KeyEnter, 0)
	field, ok := h.focus().(*tview.InputField)
	if !ok {
		t.Fatalf("Enter should focus the retention field, got %T", h.focus())
	}
	text := func() (s string) {
		h.ui.app.QueueUpdate(func() { s = field.GetText() })
		return s
	}

	// Inside the field, arrows and digits belong to the text cursor.
	before := text()
	h.key(tcell.KeyLeft, 0)
	h.key(tcell.KeyRight, 0)
	h.key(tcell.KeyRune, '3')
	h.wantTab(tabSettings)
	if got := text(); got != before+"3" {
		t.Errorf("field text = %q, want %q", got, before+"3")
	}

	h.key(tcell.KeyEscape, 0)
	if _, ok := h.focus().(*tview.InputField); ok {
		t.Fatal("Esc should move focus out of the retention field")
	}

	// Digits switch tabs again once focus is back on the tab bar.
	h.key(tcell.KeyRune, '1')
	h.wantTab(tabProcess)
}

func TestSettingsModalRestoresDashboard(t *testing.T) {
	h := newUIHarness(t)

	h.key(tcell.KeyRune, '7')
	h.key(tcell.KeyEnter, 0)

	h.ui.app.QueueUpdateDraw(func() { h.ui.settingsPage.showInfo("saved") })
	h.key(tcell.KeyEnter, 0) // dismiss the modal

	h.ui.app.QueueUpdateDraw(func() {})
	cells, w, _ := h.screen.GetContents()
	var top []rune
	for x := 0; x < w; x++ {
		top = append(top, cells[x].Runes...)
	}
	if got := string(top); len(got) < 10 || got[:10] != " 1:Process" {
		t.Errorf("tab bar missing after modal closed; top line = %q", got)
	}

	h.key(tcell.KeyEscape, 0)
	h.key(tcell.KeyRight, 0)
	h.wantTab(tabResources)
}
