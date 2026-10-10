package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/arafat2020/sentinel/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// sshOps are the SSH daemon operations the settings page drives. They block
// on the OS, so the page only ever calls them off the event loop.
type sshOps struct {
	status  func() string
	enable  func() error
	disable func() error
}

// settingsHost is what the settings page needs from the dashboard it is
// embedded in. Both hooks are called on the event loop.
type settingsHost struct {
	// restore puts the dashboard back on screen after one of the page's
	// modals closes. toForm says whether focus was inside the settings form
	// when the modal opened; the host decides where focus belongs now.
	restore func(toForm bool)
	// leave hands keyboard focus back to tab navigation.
	leave func()
}

const (
	settingsShortcutHint = "Ctrl+S = Save    Ctrl+F = Flush    Ctrl+D = Disable SSH    Ctrl+E = Enable SSH"
	settingsHintTabs     = "[gray]  ←/→ 1-9 = switch tab    Enter = edit settings    " + settingsShortcutHint + "[-]"
	settingsHintForm     = "[gray]  Esc = back to tabs    Tab = next field    " + settingsShortcutHint + "[-]"
)

// SettingsPage is the TUI settings editor (tab 7).
type SettingsPage struct {
	app       *tview.Application
	store     *store.Store
	ssh       sshOps
	host      settingsHost
	root      *tview.Flex
	form      *tview.Form
	hint      *tview.TextView
	sshStatus *tview.TextView // live SSH status indicator

	// Event-loop only.
	hintForForm   bool // which hint text is currently shown
	modalFromForm bool // whether the open modal was raised from the form

	bg sync.WaitGroup // background SSH calls still in flight
}

// NewSettingsPage constructs the settings page.
func NewSettingsPage(app *tview.Application, s *store.Store) *SettingsPage {
	return newSettingsPage(app, s, sshOps{
		status:  sshCurrentStatus,
		enable:  sshEnable,
		disable: sshDisable,
	})
}

func newSettingsPage(app *tview.Application, s *store.Store, ssh sshOps) *SettingsPage {
	sp := &SettingsPage{app: app, store: s, ssh: ssh}
	sp.build()
	return sp
}

// Root returns the primitive to register with tview.Pages.
func (sp *SettingsPage) Root() tview.Primitive { return sp.root }

// SetHost wires the page into the dashboard. Without a host the page still
// works standalone: closing a modal shows the page itself.
func (sp *SettingsPage) SetHost(h settingsHost) { sp.host = h }

// FormHasFocus reports whether focus is inside the settings form (as opposed
// to the tab bar or one of the page's modals).
func (sp *SettingsPage) FormHasFocus() bool { return sp.form.HasFocus() }

// HandleShortcut runs the action bound to a settings shortcut and reports
// whether the key was one. The shortcuts work both inside the form and from
// the tab bar while the Settings tab is showing.
func (sp *SettingsPage) HandleShortcut(event *tcell.EventKey) bool {
	switch event.Key() {
	case tcell.KeyCtrlS:
		sp.save()
	case tcell.KeyCtrlF:
		sp.flush()
	case tcell.KeyCtrlD:
		sp.confirmSSHAction(false)
	case tcell.KeyCtrlE:
		sp.confirmSSHAction(true)
	default:
		return false
	}
	return true
}

// SyncHint makes the hint line describe the keys that work in the current
// focus state. Must be called on the event loop; cheap when nothing changed.
func (sp *SettingsPage) SyncHint() {
	if forForm := sp.form.HasFocus(); forForm != sp.hintForForm {
		sp.hintForForm = forForm
		sp.hint.SetText(settingsHint(forForm))
	}
}

func settingsHint(forForm bool) string {
	if forForm {
		return settingsHintForm
	}
	return settingsHintTabs
}

// leaveForm is the form's cancel action (Esc).
func (sp *SettingsPage) leaveForm() {
	if sp.host.leave != nil {
		sp.host.leave()
	}
}

// showModal replaces the screen with a modal, remembering where focus was so
// closeModal can put it back.
func (sp *SettingsPage) showModal(modal *tview.Modal) {
	sp.modalFromForm = sp.form.HasFocus()
	sp.app.SetRoot(modal, false)
}

// closeModal returns from a modal to whatever the dashboard is showing now,
// which is not necessarily this page: results of background SSH calls arrive
// after the user may have moved to another tab.
func (sp *SettingsPage) closeModal() {
	if sp.host.restore == nil {
		sp.app.SetRoot(sp.root, true)
		return
	}
	sp.host.restore(sp.modalFromForm)
}

// async runs fn off the event loop and tracks it until it has finished,
// including any UI update it queues.
func (sp *SettingsPage) async(fn func()) {
	sp.bg.Add(1)
	go func() {
		defer sp.bg.Done()
		fn()
	}()
}

func (sp *SettingsPage) build() {
	sp.form = tview.NewForm()
	sp.form.SetBorder(true).SetTitle(" Settings ").SetTitleAlign(tview.AlignLeft)
	sp.form.SetFieldBackgroundColor(tcell.ColorDarkBlue)

	// Without a cancel function tview's Form answers Esc by refocusing its
	// first item. Here that is a read-only text view, which hands focus
	// straight back while still holding its own lock: the event loop
	// deadlocks. Esc therefore always has an explicit action.
	sp.form.SetCancelFunc(sp.leaveForm)

	sp.hint = tview.NewTextView().
		SetDynamicColors(true).
		SetText(settingsHint(false))
	sp.hint.SetBorder(false)

	sp.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(sp.form, 0, 1, true).
		AddItem(sp.hint, 1, 0, false)

	sp.form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if sp.HandleShortcut(event) {
			return nil
		}
		return event
	})

	sp.reload()
}

func (sp *SettingsPage) reload() {
	sp.form.Clear(true)

	// ── Log retention ──────────────────────────────────────────────────────────

	sp.form.AddTextView("",
		"[yellow]── Log Retention ──────────────────────────────────────────[-]",
		0, 1, true, false)

	days := store.DefaultRetentionDays
	if sp.store != nil {
		days = sp.store.GetRetentionDays()
	}
	sp.form.AddTextView("",
		"[gray]Events older than the retention window are deleted once per day.\n"+
			"Database: sentinel.db in the working directory.[-]",
		0, 3, true, false)

	sp.form.AddInputField("Retention (days)", strconv.Itoa(days), 10, func(text string, _ rune) bool {
		_, err := strconv.Atoi(strings.TrimSpace(text))
		return err == nil || text == ""
	}, nil)

	sp.form.AddButton("Save  (Ctrl+S)", func() { sp.save() })
	sp.form.AddButton("Flush Now  (Ctrl+F)", func() { sp.flush() })

	// ── SSH remote access ──────────────────────────────────────────────────────

	sp.form.AddTextView("", "", 0, 1, false, false) // spacer

	sp.form.AddTextView("",
		"[yellow]── SSH Remote Access ──────────────────────────────────────[-]",
		0, 1, true, false)

	sp.form.AddTextView("",
		"[gray]Use this kill-switch during an incident to cut off remote shell access.\n"+
			"[red]Warning:[-][gray] disabling SSH terminates all active SSH sessions immediately,\n"+
			"including this one if you are connected remotely.[-]",
		0, 4, true, false)

	sp.sshStatus = tview.NewTextView().SetDynamicColors(true)
	sp.refreshSSHStatus()
	sp.form.AddFormItem(sp.sshStatus)

	sp.form.AddButton("Refresh Status", sp.refreshSSHStatus)

	sp.form.AddButton("Disable SSH", func() { sp.confirmSSHAction(false) })
	sp.form.AddButton("Enable SSH", func() { sp.confirmSSHAction(true) })
}

// refreshSSHStatus spawns a goroutine to check SSH status and update the UI.
// Safe to call from the event loop — the OS call happens off it.
func (sp *SettingsPage) refreshSSHStatus() {
	sp.async(func() {
		status := sp.ssh.status()
		sp.app.QueueUpdateDraw(func() { sp.applySSHStatus(status) })
	})
}

// applySSHStatus updates the status TextView. Must be called on the event loop.
func (sp *SettingsPage) applySSHStatus(status string) {
	if sp.sshStatus == nil {
		return
	}
	switch status {
	case "enabled":
		sp.sshStatus.SetText("  Status: [green]ENABLED[-]  (SSH daemon is running)")
	case "disabled":
		sp.sshStatus.SetText("  Status: [red]DISABLED[-]  (SSH daemon is stopped)")
	default:
		sp.sshStatus.SetText("  Status: [yellow]UNKNOWN[-]  (could not determine — run as root?)")
	}
}

// confirmSSHAction shows a confirmation modal before touching sshd.
func (sp *SettingsPage) confirmSSHAction(enable bool) {
	action := "disable"
	warning := "[red]This will TERMINATE all active SSH sessions immediately.\nYou will be disconnected if connected remotely.[-]"
	if enable {
		action = "enable"
		warning = "This will start the SSH daemon and allow remote logins."
	}

	modal := tview.NewModal().
		SetText(fmt.Sprintf("Are you sure you want to %s SSH?\n\n%s", action, warning)).
		AddButtons([]string{"Cancel", strings.ToUpper(action[:1]) + action[1:]}).
		SetDoneFunc(func(idx int, label string) {
			// Return to the settings page first — no extra Draw() call here,
			// tview redraws naturally after the event handler returns.
			sp.closeModal()
			if idx == 0 || label == "Cancel" {
				return
			}

			// All blocking OS calls run in a goroutine.
			// QueueUpdateDraw is the only safe way to touch the UI from here.
			sp.async(func() {
				var cmdErr error
				if enable {
					cmdErr = sp.ssh.enable()
				} else {
					cmdErr = sp.ssh.disable()
				}
				status := sp.ssh.status() // off the event loop
				sp.app.QueueUpdateDraw(func() {
					sp.applySSHStatus(status)
					if cmdErr != nil {
						sp.showError(fmt.Sprintf("Failed to %s SSH: %v", action, cmdErr))
					} else {
						sp.showInfo(fmt.Sprintf("SSH has been %sd.", action))
					}
				})
			})
		})
	sp.showModal(modal)
}

func (sp *SettingsPage) save() {
	if sp.store == nil {
		return
	}
	item := sp.form.GetFormItemByLabel("Retention (days)")
	if item == nil {
		return
	}
	field, ok := item.(*tview.InputField)
	if !ok {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(field.GetText()))
	if err != nil || n <= 0 {
		sp.showError("Retention must be a positive integer.")
		return
	}
	if err := sp.store.SetRetentionDays(n); err != nil {
		sp.showError(fmt.Sprintf("Save failed: %v", err))
		return
	}
	sp.showInfo(fmt.Sprintf("Saved. Events older than %d day(s) will be purged on the next daily run.", n))
}

func (sp *SettingsPage) flush() {
	if sp.store == nil {
		return
	}
	days := sp.store.GetRetentionDays()
	n, err := sp.store.DeleteOlderThan(days)
	if err != nil {
		sp.showError(fmt.Sprintf("Flush failed: %v", err))
		return
	}
	sp.showInfo(fmt.Sprintf("Deleted %d event(s) older than %d day(s).", n, days))
}

func (sp *SettingsPage) showError(msg string) {
	modal := tview.NewModal().
		SetText("[red]" + tview.Escape(msg) + "[-]").
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			sp.closeModal()
		})
	sp.showModal(modal)
}

func (sp *SettingsPage) showInfo(msg string) {
	modal := tview.NewModal().
		SetText(tview.Escape(msg)).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			sp.closeModal()
		})
	sp.showModal(modal)
}
