package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/arafat2020/sentinel/internal/store"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// SettingsPage is the TUI settings editor (tab 7).
type SettingsPage struct {
	app       *tview.Application
	store     *store.Store
	root      *tview.Flex
	form      *tview.Form
	sshStatus *tview.TextView // live SSH status indicator
}

// NewSettingsPage constructs the settings page.
func NewSettingsPage(app *tview.Application, s *store.Store) *SettingsPage {
	sp := &SettingsPage{app: app, store: s}
	sp.build()
	return sp
}

// Root returns the primitive to register with tview.Pages.
func (sp *SettingsPage) Root() tview.Primitive { return sp.root }

func (sp *SettingsPage) build() {
	sp.form = tview.NewForm()
	sp.form.SetBorder(true).SetTitle(" Settings ").SetTitleAlign(tview.AlignLeft)
	sp.form.SetFieldBackgroundColor(tcell.ColorDarkBlue)

	hint := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[gray]  Tab/Enter = navigate    Ctrl+S = Save    Ctrl+F = Flush    Ctrl+D = Disable SSH    Ctrl+E = Enable SSH[-]")
	hint.SetBorder(false)

	sp.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(sp.form, 0, 1, true).
		AddItem(hint, 1, 0, false)

	sp.form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlS:
			sp.save()
			return nil
		case tcell.KeyCtrlF:
			sp.flush()
			return nil
		case tcell.KeyCtrlD:
			sp.confirmSSHAction(false)
			return nil
		case tcell.KeyCtrlE:
			sp.confirmSSHAction(true)
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

	sp.form.AddButton("Refresh Status", func() {
		go func() {
			status := sshCurrentStatus()
			sp.app.QueueUpdateDraw(func() { sp.applySSHStatus(status) })
		}()
	})

	sp.form.AddButton("Disable SSH", func() { sp.confirmSSHAction(false) })
	sp.form.AddButton("Enable SSH", func() { sp.confirmSSHAction(true) })
}

// refreshSSHStatus spawns a goroutine to check SSH status and update the UI.
// Safe to call from the event loop — the OS call happens off it.
func (sp *SettingsPage) refreshSSHStatus() {
	go func() {
		status := sshCurrentStatus()
		sp.app.QueueUpdateDraw(func() { sp.applySSHStatus(status) })
	}()
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
			sp.app.SetRoot(sp.root, true)
			if idx == 0 || label == "Cancel" {
				return
			}

			// All blocking OS calls run in a goroutine.
			// QueueUpdateDraw is the only safe way to touch the UI from here.
			go func() {
				var cmdErr error
				if enable {
					cmdErr = sshEnable()
				} else {
					cmdErr = sshDisable()
				}
				status := sshCurrentStatus() // fast pgrep check, off event loop
				sp.app.QueueUpdateDraw(func() {
					sp.applySSHStatus(status)
					if cmdErr != nil {
						sp.showError(fmt.Sprintf("Failed to %s SSH: %v", action, cmdErr))
					} else {
						sp.showInfo(fmt.Sprintf("SSH has been %sd.", action))
					}
				})
			}()
		})
	sp.app.SetRoot(modal, false)
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
			sp.app.SetRoot(sp.root, true)
		})
	sp.app.SetRoot(modal, false)
}

func (sp *SettingsPage) showInfo(msg string) {
	modal := tview.NewModal().
		SetText(tview.Escape(msg)).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			sp.app.SetRoot(sp.root, true)
		})
	sp.app.SetRoot(modal, false)
}
