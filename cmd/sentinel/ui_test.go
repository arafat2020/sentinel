package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/monitor"
	"github.com/arafat2020/sentinel/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// loopTimeout bounds every wait on the event loop, so a deadlocked UI fails
// the test instead of hanging the run.
const loopTimeout = 3 * time.Second

// fakeSSH stands in for the real sshd controls: no sockets, no subprocesses.
type fakeSSH struct {
	mu    sync.Mutex
	calls []string
	gate  chan struct{} // when set, enable/disable block until it is closed
	err   error
}

func (f *fakeSSH) ops() sshOps {
	act := func(name string) func() error {
		return func() error {
			f.mu.Lock()
			f.calls = append(f.calls, name)
			gate, err := f.gate, f.err
			f.mu.Unlock()
			if gate != nil {
				<-gate
			}
			return err
		}
	}
	return sshOps{
		status:  func() string { return "enabled" },
		enable:  act("enable"),
		disable: act("disable"),
	}
}

func (f *fakeSSH) hold() chan struct{} {
	gate := make(chan struct{})
	f.mu.Lock()
	f.gate = gate
	f.mu.Unlock()
	return gate
}

func (f *fakeSSH) called() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

// uiHarness runs the real dashboard on an in-memory screen. Every interaction
// goes through the event loop and returns only once the loop has handled it.
type uiHarness struct {
	t        *testing.T
	ui       *UI
	settings *SettingsPage
	ssh      *fakeSSH
	screen   tcell.SimulationScreen
	seen     chan struct{} // one signal per key reaching the event loop
	ticks    chan struct{} // one signal per resource wake-up handled by the loop
}

func newUIHarness(t *testing.T) *uiHarness {
	t.Helper()

	db, err := store.Open(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	ssh := &fakeSSH{}
	screen := tcell.NewSimulationScreen("UTF-8")
	ui := NewUI()
	settings := newSettingsPage(ui.app, db, ssh.ops())
	ui.SetSettingsPage(settings)

	h := &uiHarness{t: t, ui: ui, settings: settings, ssh: ssh, screen: screen}
	h.start(ui.app)

	t.Cleanup(func() { db.Close() })
	return h
}

// start runs app on the harness screen and registers an orderly shutdown:
// background work first (it needs the loop to deliver its result), then the
// loop itself.
func (h *uiHarness) start(app *tview.Application) {
	app.SetScreen(h.screen)

	h.seen = make(chan struct{}, 16)
	h.ticks = make(chan struct{}, 16)
	capture := app.GetInputCapture()
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Resource wake-ups travel the same path as keys but are not
		// keystrokes; keep them out of key()'s accounting.
		if h.ui != nil && event == h.ui.resourceTick {
			defer func() { h.ticks <- struct{}{} }()
			return capture(event)
		}
		h.seen <- struct{}{}
		if capture == nil {
			return event
		}
		return capture(event)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = app.Run()
	}()

	h.t.Cleanup(func() {
		h.waitBackground()
		if h.ui != nil {
			h.ui.Stop() // idempotent: a test may already have stopped it
		} else {
			app.Stop()
		}
		select {
		case <-done:
		case <-time.After(loopTimeout):
			h.t.Error("event loop did not stop (deadlock?)")
		}
	})
}

// await runs f on another goroutine and fails the test if it does not finish.
func (h *uiHarness) await(what string, f func()) {
	h.t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(loopTimeout):
		h.t.Fatalf("%s: event loop is not responding (deadlock?)", what)
	}
}

// onLoop runs f on the event loop and redraws.
func (h *uiHarness) onLoop(f func()) {
	h.t.Helper()
	h.await("queued update", func() { h.settings.app.QueueUpdateDraw(f) })
}

// waitBackground blocks until the settings page has no SSH call in flight,
// including the UI update that call queues when it finishes.
func (h *uiHarness) waitBackground() {
	h.t.Helper()
	h.await("background SSH call", h.settings.bg.Wait)
}

// key sends one keystroke and returns once the event loop has fully handled
// it: the queued no-op can only run after the key's own iteration finishes.
func (h *uiHarness) key(k tcell.Key, r rune) {
	h.t.Helper()
	h.screen.InjectKey(k, r, tcell.ModNone)
	select {
	case <-h.seen:
	case <-time.After(loopTimeout):
		h.t.Fatal("key never reached the event loop (deadlock?)")
	}
	h.onLoop(func() {})
}

// update delivers a snapshot the way the resource monitor does and returns
// once the event loop has rendered it.
func (h *uiHarness) update(s *core.ResourceSnapshot) {
	h.t.Helper()
	h.ui.UpdateResources(s)
	select {
	case <-h.ticks:
	case <-time.After(loopTimeout):
		h.t.Fatal("resource update never reached the event loop")
	}
	h.onLoop(func() {})
}

func (h *uiHarness) resourcePIDs() (pids string) {
	h.t.Helper()
	h.onLoop(func() { pids = strings.Join(tableColumn(h.ui.resources, 0), ",") })
	return pids
}

func (h *uiHarness) activeTab() int {
	h.ui.mu.Lock()
	defer h.ui.mu.Unlock()
	return h.ui.active
}

func (h *uiHarness) focus() (p tview.Primitive) {
	h.t.Helper()
	h.onLoop(func() { p = h.settings.app.GetFocus() })
	return p
}

func (h *uiHarness) hint() (s string) {
	h.t.Helper()
	h.onLoop(func() { s = h.settings.hint.GetText(true) })
	return s
}

// screenText returns everything currently drawn, one line per row.
func (h *uiHarness) screenText() string {
	h.t.Helper()
	h.onLoop(func() {})

	cells, w, _ := h.screen.GetContents()
	var b strings.Builder
	for i, c := range cells {
		if len(c.Runes) == 0 {
			b.WriteByte(' ')
		} else {
			b.WriteString(string(c.Runes))
		}
		if (i+1)%w == 0 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (h *uiHarness) wantTab(want int) {
	h.t.Helper()
	if got := h.activeTab(); got != want {
		h.t.Fatalf("active tab = %s, want %s", tabNames[got], tabNames[want])
	}
}

func (h *uiHarness) wantOnScreen(want string) {
	h.t.Helper()
	if text := h.screenText(); !strings.Contains(text, want) {
		h.t.Fatalf("screen does not show %q:\n%s", want, text)
	}
}

func (h *uiHarness) wantDashboard() {
	h.t.Helper()
	if text := h.screenText(); !strings.HasPrefix(text, " 1:Process") {
		h.t.Fatalf("tab bar is not on screen:\n%s", text)
	}
}

func (h *uiHarness) inField() bool {
	h.t.Helper()
	_, ok := h.focus().(*tview.InputField)
	return ok
}

func (h *uiHarness) onTabBar() bool {
	h.t.Helper()
	return h.focus() == tview.Primitive(h.ui.tabBar)
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
	if !h.onTabBar() {
		t.Fatal("arriving on Settings must leave focus on the tab bar")
	}

	h.key(tcell.KeyEnter, 0)
	field, ok := h.focus().(*tview.InputField)
	if !ok {
		t.Fatalf("Enter should focus the retention field, got %T", h.focus())
	}
	text := func() (s string) {
		h.onLoop(func() { s = field.GetText() })
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
	if !h.onTabBar() {
		t.Fatal("Esc should move focus back to the tab bar")
	}

	// Digits switch tabs again once focus is back on the tab bar.
	h.key(tcell.KeyRune, '1')
	h.wantTab(tabProcess)
}

// Regression (P1): Esc inside the Settings form used to deadlock the event
// loop. Every key() call below fails the test if the loop stops responding.
func TestSettingsEscapeNeverDeadlocks(t *testing.T) {
	h := newUIHarness(t)
	h.key(tcell.KeyRune, '7')

	for round := 0; round < 3; round++ {
		// Out of the text field.
		h.key(tcell.KeyEnter, 0)
		if !h.inField() {
			t.Fatalf("round %d: Enter did not reach the retention field", round)
		}
		h.key(tcell.KeyEscape, 0)
		if !h.onTabBar() {
			t.Fatalf("round %d: Esc in the field left focus on %T", round, h.focus())
		}

		// Out of the SSH status line, the next stop after the field: Tab
		// skips the read-only items in between, the path that used to hang.
		h.key(tcell.KeyEnter, 0)
		h.key(tcell.KeyTab, 0)
		if h.focus() != tview.Primitive(h.settings.sshStatus) {
			t.Fatalf("round %d: Tab should reach the SSH status line, got %T", round, h.focus())
		}
		h.key(tcell.KeyEscape, 0)
		if !h.onTabBar() {
			t.Fatalf("round %d: Esc on the status line left focus on %T", round, h.focus())
		}

		// Out of a button.
		h.key(tcell.KeyEnter, 0)
		h.key(tcell.KeyTab, 0)
		if _, ok := h.focus().(*tview.Button); !ok {
			t.Fatalf("round %d: Tab should reach a button, got %T", round, h.focus())
		}
		h.key(tcell.KeyEscape, 0)
		if !h.onTabBar() {
			t.Fatalf("round %d: Esc on a button left focus on %T", round, h.focus())
		}

		// Back to the field for the next round.
		h.key(tcell.KeyEnter, 0)
		h.key(tcell.KeyBacktab, 0)
		h.key(tcell.KeyBacktab, 0)
		h.key(tcell.KeyEscape, 0)
	}

	// Esc with nothing to leave is harmless too.
	h.key(tcell.KeyEscape, 0)
	h.key(tcell.KeyRight, 0)
	h.wantTab(tabResources)
}

// The fix lives in the form, not in the dashboard's key handling: a settings
// page with no dashboard around it must survive Esc as well.
func TestSettingsEscapeWithoutHostDoesNotDeadlock(t *testing.T) {
	app := tview.NewApplication()
	sp := newSettingsPage(app, nil, (&fakeSSH{}).ops())
	app.SetRoot(sp.Root(), true)

	h := &uiHarness{t: t, settings: sp, screen: tcell.NewSimulationScreen("UTF-8")}
	h.start(app)

	if !h.inField() {
		t.Fatalf("standalone page should focus the retention field, got %T", h.focus())
	}
	h.key(tcell.KeyEscape, 0)
	h.key(tcell.KeyTab, 0)
	h.key(tcell.KeyEscape, 0)
	h.key(tcell.KeyRune, '5')
	h.wantOnScreen("Retention (days)")
}

// Regression (B3): the result of a background SSH action can arrive after the
// user has moved to another tab. Dismissing that pop-up used to put focus on
// the hidden settings form, swallowing every key and deadlocking on Esc.
func TestSettingsDelayedPopupDoesNotStealFocus(t *testing.T) {
	h := newUIHarness(t)
	gate := h.ssh.hold()

	h.key(tcell.KeyRune, '7')
	h.key(tcell.KeyEnter, 0)
	h.key(tcell.KeyCtrlD, 0)
	h.wantOnScreen("disable SSH?")
	h.key(tcell.KeyTab, 0)   // Cancel → Disable
	h.key(tcell.KeyEnter, 0) // confirm; the SSH call is now blocked on gate

	h.wantDashboard()
	if !h.inField() {
		t.Fatalf("closing the confirm dialog should return to the form, got %T", h.focus())
	}

	// The user walks away while the action is still running.
	h.key(tcell.KeyEscape, 0)
	h.key(tcell.KeyRune, '1')
	h.wantTab(tabProcess)

	close(gate)
	h.waitBackground()
	h.wantOnScreen("SSH has been disabled.")
	if got := h.ssh.called(); got != "disable" {
		t.Errorf("SSH calls = %q, want disable", got)
	}

	h.key(tcell.KeyEnter, 0) // dismiss the result

	h.wantDashboard()
	h.wantTab(tabProcess)
	if got := h.focus(); got != tview.Primitive(h.ui.views[tabProcess]) {
		t.Fatalf("focus after dismissing the pop-up = %T, want the Process view", got)
	}
	var formFocused bool
	h.onLoop(func() { formFocused = h.settings.FormHasFocus() })
	if formFocused {
		t.Fatal("hidden settings form has focus")
	}

	// The active tab still owns the keyboard, and Esc is harmless.
	h.key(tcell.KeyEscape, 0)
	h.key(tcell.KeyRight, 0)
	h.wantTab(tabNetwork)
	h.key(tcell.KeyRune, '8')
	h.wantTab(tabResources)
}

func TestSettingsFailedActionPopupRestoresDashboard(t *testing.T) {
	h := newUIHarness(t)
	h.ssh.err = errors.New("permission denied")

	h.key(tcell.KeyRune, '7')
	h.key(tcell.KeyCtrlE, 0) // from the tab bar
	h.wantOnScreen("enable SSH?")
	h.key(tcell.KeyTab, 0)
	h.key(tcell.KeyEnter, 0)

	h.waitBackground()
	h.wantOnScreen("Failed to enable SSH")
	h.key(tcell.KeyEnter, 0)

	h.wantDashboard()
	h.wantTab(tabSettings)
	if !h.onTabBar() {
		t.Fatalf("focus = %T, want the tab bar it started on", h.focus())
	}
}

// Regression (B4): the Settings shortcuts must work as soon as the tab is
// showing, and still work inside the form, without forcing focus anywhere.
func TestSettingsShortcutsInBothFocusStates(t *testing.T) {
	shortcuts := []struct {
		name string
		key  tcell.Key
		want string // text of the dialog the shortcut opens
	}{
		{"Ctrl+S", tcell.KeyCtrlS, "Saved."},
		{"Ctrl+F", tcell.KeyCtrlF, "Deleted 0 event(s)"},
		{"Ctrl+D", tcell.KeyCtrlD, "disable SSH?"},
		{"Ctrl+E", tcell.KeyCtrlE, "enable SSH?"},
	}

	for _, inForm := range []bool{false, true} {
		state := "tab bar"
		if inForm {
			state = "form"
		}

		for _, sc := range shortcuts {
			t.Run(sc.name+" from "+state, func(t *testing.T) {
				h := newUIHarness(t)
				h.t = t
				h.key(tcell.KeyRune, '7')
				if inForm {
					h.key(tcell.KeyEnter, 0)
				}

				h.key(sc.key, 0)
				h.wantOnScreen(sc.want)

				// First button is OK for results and Cancel for confirmations.
				h.key(tcell.KeyEnter, 0)
				h.wantDashboard()
				h.wantTab(tabSettings)

				if inForm {
					if !h.inField() {
						t.Fatalf("focus = %T, want to be back in the form", h.focus())
					}
					h.key(tcell.KeyEscape, 0)
				}
				if !h.onTabBar() {
					t.Fatalf("focus = %T, want the tab bar", h.focus())
				}

				// Tab navigation is intact afterwards.
				h.key(tcell.KeyLeft, 0)
				h.wantTab(tabPatterns)
				h.key(tcell.KeyRight, 0)
				h.key(tcell.KeyRune, '2')
				h.wantTab(tabNetwork)

				if got := h.ssh.called(); got != "" {
					t.Errorf("cancelled or unrelated shortcut ran SSH calls: %q", got)
				}
			})
		}
	}
}

func TestSettingsShortcutsDoNothingOnOtherTabs(t *testing.T) {
	h := newUIHarness(t)

	for _, key := range []tcell.Key{tcell.KeyCtrlS, tcell.KeyCtrlF, tcell.KeyCtrlD, tcell.KeyCtrlE} {
		h.key(key, 0)
	}
	h.wantDashboard()
	if got := h.focus(); got != tview.Primitive(h.ui.views[tabProcess]) {
		t.Fatalf("a Settings shortcut on the Process tab moved focus to %T", got)
	}
}

func TestSettingsHintMatchesFocusState(t *testing.T) {
	h := newUIHarness(t)
	h.key(tcell.KeyRune, '7')

	check := func(state string, want, notWant []string) {
		t.Helper()
		hint := h.hint()
		for _, w := range want {
			if !strings.Contains(hint, w) {
				t.Errorf("%s hint is missing %q: %q", state, w, hint)
			}
		}
		for _, w := range notWant {
			if strings.Contains(hint, w) {
				t.Errorf("%s hint advertises %q, which does nothing there: %q", state, w, hint)
			}
		}
	}
	shortcuts := []string{"Ctrl+S", "Ctrl+F", "Ctrl+D", "Ctrl+E"}

	check("tab bar", append([]string{"switch tab", "Enter = edit settings"}, shortcuts...), []string{"Esc", "next field"})

	h.key(tcell.KeyEnter, 0)
	check("form", append([]string{"Esc = back to tabs", "Tab = next field"}, shortcuts...), []string{"switch tab", "edit settings"})

	h.key(tcell.KeyEscape, 0)
	check("tab bar again", []string{"switch tab", "Enter = edit settings"}, []string{"Esc"})
}

func TestUpdateResourcesRendersVisibleTabOnly(t *testing.T) {
	h := newUIHarness(t)
	first := &core.ResourceSnapshot{Processes: []core.ProcessUsage{proc(1, 9, 1), proc(2, 5, 1)}}
	second := &core.ResourceSnapshot{Processes: []core.ProcessUsage{proc(3, 9, 1)}}

	// Hidden tab: the snapshot is kept but nothing is queued or rendered.
	h.ui.UpdateResources(first)
	if h.ui.resourcePending.Load() {
		t.Fatal("an update for a hidden tab woke the event loop")
	}
	if got := h.resourcePIDs(); got != "" {
		t.Fatalf("hidden tab rendered rows %q", got)
	}

	// Switching to the tab shows what arrived in the meantime.
	h.key(tcell.KeyRune, '8')
	if got := h.resourcePIDs(); got != "1,2" {
		t.Fatalf("after switching: rows %q, want 1,2", got)
	}

	// Visible tab: an update is rendered and drawn without a keypress.
	h.update(second)
	if got := h.resourcePIDs(); got != "3" {
		t.Fatalf("after live update: rows %q, want 3", got)
	}
	h.wantOnScreen("1 processes")
	if h.ui.resourcePending.Load() {
		t.Error("wake-up still marked pending after it was handled")
	}

	// The wake-up is not a keystroke: it must not reach the focused widget.
	h.key(tcell.KeyRune, '7')
	h.key(tcell.KeyEnter, 0)
	h.ui.app.QueueEvent(h.ui.resourceTick)
	<-h.ticks
	if !h.inField() {
		t.Errorf("wake-up moved focus to %T", h.focus())
	}
}

// scriptedSnapshots is a resource collector that counts its calls.
type scriptedSnapshots struct {
	mu    sync.Mutex
	calls int
}

func (c *scriptedSnapshots) Collect(context.Context) (*core.ResourceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return &core.ResourceSnapshot{Processes: []core.ProcessUsage{proc(int32(c.calls), 1, 1)}}, nil
}

func (c *scriptedSnapshots) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// Regression: UpdateResources used to wait for the event loop to run its
// update. If the UI shut down first, the resource monitor's goroutine stayed
// blocked forever. Here the loop is stalled so updates are genuinely pending
// when the UI stops.
func TestResourceMonitorExitsWhenUIStopsWithUpdatePending(t *testing.T) {
	h := newUIHarness(t)
	h.key(tcell.KeyRune, '8')

	// Stall the event loop so nothing queued behind this can run.
	stalled := make(chan struct{})
	release := make(chan struct{})
	unstalled := make(chan struct{})
	go func() {
		defer close(unstalled)
		h.ui.app.QueueUpdate(func() {
			close(stalled)
			<-release
		})
	}()
	<-stalled

	collector := &scriptedSnapshots{}
	ctx, cancel := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		monitor.NewResourceMonitor(collector, time.Millisecond, h.ui.UpdateResources).Run(ctx)
	}()

	// Several deliveries completing proves the handler does not wait on the
	// stalled loop; the first one is still pending there.
	deadline := time.Now().Add(loopTimeout)
	for collector.count() < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("monitor delivered %d snapshots, then blocked on the stalled UI", collector.count())
		}
		time.Sleep(time.Millisecond)
	}
	if !h.ui.resourcePending.Load() {
		t.Fatal("no update is pending; the scenario is not being exercised")
	}

	// Shut down with the update still pending.
	h.ui.Stop()
	cancel()

	select {
	case <-monitorDone:
	case <-time.After(loopTimeout):
		t.Fatal("resource monitor did not exit after the UI stopped")
	}

	// Updates after shutdown are dropped immediately rather than queued.
	h.await("UpdateResources after Stop", func() {
		for i := 0; i < 500; i++ {
			h.ui.UpdateResources(&core.ResourceSnapshot{})
		}
	})

	close(release)
	<-unstalled
}
