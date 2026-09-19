package main

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/arafat2020/sentinel/internal/auth"
	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/store"
)

// ── Sentinel dark theme ───────────────────────────────────────────────────────

type sentinelTheme struct{}

var _ fyne.Theme = (*sentinelTheme)(nil)

func (sentinelTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x0d, G: 0x11, B: 0x17, A: 0xff}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0xc9, G: 0xd1, B: 0xd9, A: 0xff}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x58, G: 0xa6, B: 0xff, A: 0xff}
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 0x3f, G: 0xb9, B: 0x50, A: 0xff}
	case theme.ColorNameWarning:
		return color.NRGBA{R: 0xe3, G: 0xb3, B: 0x41, A: 0xff}
	case theme.ColorNameError:
		return color.NRGBA{R: 0xf8, G: 0x51, B: 0x49, A: 0xff}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x16, G: 0x1b, B: 0x22, A: 0xff}
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 0x16, G: 0x1b, B: 0x22, A: 0xff}
	case theme.ColorNameMenuBackground:
		return color.NRGBA{R: 0x16, G: 0x1b, B: 0x22, A: 0xff}
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0x16, G: 0x1b, B: 0x22, A: 0xff}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x89, G: 0x92, B: 0x9e, A: 0xff}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0x30, G: 0x36, B: 0x3d, A: 0xff}
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x21, G: 0x26, B: 0x2d, A: 0xff}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x1f, G: 0x6f, B: 0xeb, A: 0x22}
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0x58, G: 0xa6, B: 0xff, A: 0x66}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x6e, G: 0x76, B: 0x81, A: 0xff}
	}
	return theme.DarkTheme().Color(n, v)
}

func (sentinelTheme) Font(s fyne.TextStyle) fyne.Resource    { return theme.DarkTheme().Font(s) }
func (sentinelTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DarkTheme().Icon(n) }
func (sentinelTheme) Size(n fyne.ThemeSizeName) float32      { return theme.DarkTheme().Size(n) }

// ── Bounded log list ──────────────────────────────────────────────────────────

const desktopRingCap = 500

type dlogEntry struct {
	ts         string
	text       string
	importance widget.Importance
}

type dlogList struct {
	mu         sync.Mutex
	entries    []dlogEntry
	list       *widget.List
	importance widget.Importance
}

// newDlogList creates a scrollable log list. Each row is a single truncating
// label — "HH:MM:SS  <content>" — so long lines never wrap and overlap.
func newDlogList(imp widget.Importance) *dlogList {
	ll := &dlogList{importance: imp}
	ll.list = widget.NewList(
		func() int {
			ll.mu.Lock()
			defer ll.mu.Unlock()
			return len(ll.entries)
		},
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.TextStyle = fyne.TextStyle{Monospace: true}
			l.Truncation = fyne.TextTruncateEllipsis
			return l
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			ll.mu.Lock()
			if id >= len(ll.entries) {
				ll.mu.Unlock()
				return
			}
			e := ll.entries[id]
			ll.mu.Unlock()

			l := obj.(*widget.Label)
			l.SetText(e.ts + "  " + e.text)
			l.Importance = e.importance
		},
	)
	return ll
}

func (ll *dlogList) push(text string) {
	ts := time.Now().Format("15:04:05")
	ll.mu.Lock()
	ll.entries = append(ll.entries, dlogEntry{ts: ts, text: text, importance: ll.importance})
	if len(ll.entries) > desktopRingCap {
		ll.entries = ll.entries[1:]
	}
	n := len(ll.entries)
	ll.mu.Unlock()
	ll.list.Refresh()
	if n > 0 {
		ll.list.ScrollTo(n - 1)
	}
}

// ── DesktopUI ─────────────────────────────────────────────────────────────────

// DesktopUI is the Fyne-based desktop dashboard. All Add* methods are goroutine-safe.
type DesktopUI struct {
	fyneApp fyne.App
	win     fyne.Window
	store   *store.Store

	process  *dlogList
	network  *dlogList
	dns      *dlogList
	file     *dlogList
	findings *dlogList

	patternsMu    sync.Mutex
	patterns      []correlation.BehaviorPattern
	patternPath   string
	onPatternSave func([]correlation.BehaviorPattern)

	// pattern editor widgets — set in buildPatternsTab
	patternEditIdx   int
	patternListW     *widget.List
	patternNameE     *widget.Entry
	patternSevSelect *widget.Select
	patternTitleE    *widget.Entry
	patternDescE     *widget.Entry

	stopOnce sync.Once
}

// NewDesktopUI constructs the Fyne app and main window. Call SetStore and
// SetPatterns before Run.
func NewDesktopUI() *DesktopUI {
	u := &DesktopUI{patternEditIdx: -1}
	u.fyneApp = app.NewWithID("com.arafat2020.sentinel")
	u.fyneApp.Settings().SetTheme(&sentinelTheme{})

	u.win = u.fyneApp.NewWindow("Sentinel — Security Monitor")
	u.win.Resize(fyne.NewSize(1100, 700))

	u.process = newDlogList(widget.SuccessImportance)
	u.network = newDlogList(widget.HighImportance)
	u.dns = newDlogList(widget.WarningImportance)
	u.file = newDlogList(widget.WarningImportance)
	u.findings = newDlogList(widget.DangerImportance)

	return u
}

// SetStore attaches the SQLite event store.
func (u *DesktopUI) SetStore(s *store.Store) { u.store = s }

// SetPatterns injects pattern data and the on-save callback.
func (u *DesktopUI) SetPatterns(
	path string,
	patterns []correlation.BehaviorPattern,
	onSave func([]correlation.BehaviorPattern),
) {
	u.patternsMu.Lock()
	u.patternPath = path
	u.patterns = patterns
	u.onPatternSave = onSave
	u.patternsMu.Unlock()
}

// Run starts the Fyne event loop. Blocks until Stop is called or window is closed.
func (u *DesktopUI) Run() error {
	if u.store != nil {
		u.win.Resize(fyne.NewSize(420, 300))
		u.win.SetContent(u.buildPasswordGate())
	} else {
		u.win.SetContent(u.buildMainContent())
	}
	u.win.CenterOnScreen()
	u.win.ShowAndRun()
	return nil
}

// Stop closes the Fyne application.
func (u *DesktopUI) Stop() {
	u.stopOnce.Do(func() { u.fyneApp.Quit() })
}

// AddProcess logs a process event line.
func (u *DesktopUI) AddProcess(line string) {
	if u.store != nil {
		u.store.Write("Process", line)
	}
	u.process.push(line)
}

// AddNetwork logs a network event line.
func (u *DesktopUI) AddNetwork(line string) {
	if u.store != nil {
		u.store.Write("Network", line)
	}
	u.network.push(line)
}

// AddDNS logs a DNS event line.
func (u *DesktopUI) AddDNS(line string) {
	if u.store != nil {
		u.store.Write("DNS", line)
	}
	u.dns.push(line)
}

// AddFile logs a file event line.
func (u *DesktopUI) AddFile(line string) {
	if u.store != nil {
		u.store.Write("File", line)
	}
	u.file.push(line)
}

// AddFinding logs a security finding.
func (u *DesktopUI) AddFinding(line string) {
	if u.store != nil {
		u.store.Write("Findings", line)
	}
	u.findings.push(line)
}

// ── Password gate ─────────────────────────────────────────────────────────────

func (u *DesktopUI) buildPasswordGate() fyne.CanvasObject {
	isFirstRun := !u.store.HasPassword()

	title := widget.NewLabel("SENTINEL")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	var subText string
	if isFirstRun {
		subText = "Create a password to protect Sentinel"
	} else {
		subText = "Enter your password to continue"
	}
	sub := widget.NewLabel(subText)
	sub.Alignment = fyne.TextAlignCenter

	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Password")

	var confirmEntry *widget.Entry
	if isFirstRun {
		confirmEntry = widget.NewPasswordEntry()
		confirmEntry.SetPlaceHolder("Confirm password")
	}

	errLabel := widget.NewLabel("")
	errLabel.Alignment = fyne.TextAlignCenter

	var submitFn func()
	submitFn = func() {
		pw := pwEntry.Text
		if pw == "" {
			errLabel.SetText("Password cannot be empty.")
			return
		}

		if isFirstRun {
			if confirmEntry != nil && pw != confirmEntry.Text {
				errLabel.SetText("Passwords do not match.")
				return
			}
			hash, err := auth.Hash(pw)
			if err != nil {
				errLabel.SetText("Error: " + err.Error())
				return
			}
			if err := u.store.SetPasswordHash(hash); err != nil {
				errLabel.SetText("Error: " + err.Error())
				return
			}
		} else {
			hash := u.store.GetPasswordHash()
			if err := auth.Verify(hash, pw); err != nil {
				errLabel.SetText("Incorrect password. Try again.")
				pwEntry.SetText("")
				return
			}
		}

		u.win.Resize(fyne.NewSize(1100, 700))
		u.win.SetContent(u.buildMainContent())
		u.win.CenterOnScreen()
	}

	submitBtn := widget.NewButton("Continue", submitFn)
	submitBtn.Importance = widget.HighImportance
	pwEntry.OnSubmitted = func(_ string) { submitFn() }
	if confirmEntry != nil {
		confirmEntry.OnSubmitted = func(_ string) { submitFn() }
	}

	items := []fyne.CanvasObject{
		title, sub, widget.NewSeparator(), pwEntry,
	}
	if confirmEntry != nil {
		items = append(items, confirmEntry)
	}
	items = append(items, submitBtn, errLabel)

	return container.NewPadded(container.NewCenter(container.NewVBox(items...)))
}

// ── Main content ──────────────────────────────────────────────────────────────

func (u *DesktopUI) buildMainContent() fyne.CanvasObject {
	tabs := container.NewAppTabs(
		container.NewTabItem("Process", container.NewBorder(
			u.tabHeader("Process Events"), nil, nil, nil, u.process.list,
		)),
		container.NewTabItem("Network", container.NewBorder(
			u.tabHeader("Network Events"), nil, nil, nil, u.network.list,
		)),
		container.NewTabItem("DNS", container.NewBorder(
			u.tabHeader("DNS Queries"), nil, nil, nil, u.dns.list,
		)),
		container.NewTabItem("File", container.NewBorder(
			u.tabHeader("File Events"), nil, nil, nil, u.file.list,
		)),
		container.NewTabItem("Findings", container.NewBorder(
			u.tabHeader("Security Findings"), nil, nil, nil, u.findings.list,
		)),
		container.NewTabItem("Query", u.buildQueryTab()),
		container.NewTabItem("Patterns", u.buildPatternsTab()),
		container.NewTabItem("Settings", container.NewScroll(u.buildSettingsTab())),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	return tabs
}

func (u *DesktopUI) tabHeader(title string) fyne.CanvasObject {
	l := widget.NewLabel(title)
	l.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewVBox(container.NewPadded(l), widget.NewSeparator())
}

// ── Settings tab ──────────────────────────────────────────────────────────────

func (u *DesktopUI) buildSettingsTab() fyne.CanvasObject {
	retTitle := widget.NewLabel("Log Retention")
	retTitle.TextStyle = fyne.TextStyle{Bold: true}

	days := store.DefaultRetentionDays
	if u.store != nil {
		days = u.store.GetRetentionDays()
	}
	retEntry := widget.NewEntry()
	retEntry.SetText(strconv.Itoa(days))

	retDesc := widget.NewLabel("Events older than the retention window are deleted once per day.\nDatabase: sentinel.db in the working directory.")
	retDesc.Wrapping = fyne.TextWrapWord

	saveBtn := widget.NewButton("Save", func() {
		n, err := strconv.Atoi(strings.TrimSpace(retEntry.Text))
		if err != nil || n <= 0 {
			dialog.ShowError(fmt.Errorf("retention must be a positive integer"), u.win)
			return
		}
		if u.store != nil {
			if err := u.store.SetRetentionDays(n); err != nil {
				dialog.ShowError(err, u.win)
				return
			}
		}
		dialog.ShowInformation("Saved",
			fmt.Sprintf("Events older than %d day(s) will be purged on the next daily run.", n), u.win)
	})
	saveBtn.Importance = widget.HighImportance

	flushBtn := widget.NewButton("Flush Now", func() {
		if u.store == nil {
			return
		}
		n, err := u.store.DeleteOlderThan(u.store.GetRetentionDays())
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		dialog.ShowInformation("Flushed", fmt.Sprintf("Deleted %d event(s).", n), u.win)
	})

	retSection := container.NewVBox(
		retTitle,
		retDesc,
		widget.NewForm(widget.NewFormItem("Retention (days)", retEntry)),
		container.NewHBox(saveBtn, flushBtn),
	)

	// SSH section
	sshTitle := widget.NewLabel("SSH Remote Access")
	sshTitle.TextStyle = fyne.TextStyle{Bold: true}

	sshDesc := widget.NewLabel("Kill-switch: use during an incident to cut off remote shell access.\nWarning: disabling SSH terminates all active sessions immediately.")
	sshDesc.Wrapping = fyne.TextWrapWord

	sshStatus := widget.NewLabel("Checking status…")

	refreshStatus := func() {
		sshStatus.SetText("Checking…")
		go func() {
			s := sshCurrentStatus()
			switch s {
			case "enabled":
				sshStatus.SetText("● ENABLED  — SSH daemon is running")
			case "disabled":
				sshStatus.SetText("● DISABLED — SSH daemon is stopped")
			default:
				sshStatus.SetText("● UNKNOWN  — run as root for full access")
			}
		}()
	}
	go refreshStatus()

	refreshBtn := widget.NewButton("Refresh", func() { refreshStatus() })

	disableBtn := widget.NewButton("Disable SSH", func() {
		dialog.ShowConfirm("Disable SSH",
			"This will TERMINATE all active SSH sessions immediately.\nContinue?",
			func(ok bool) {
				if !ok {
					return
				}
				go func() {
					if err := sshDisable(); err != nil {
						dialog.ShowError(err, u.win)
						return
					}
					refreshStatus()
					dialog.ShowInformation("Done", "SSH has been disabled.", u.win)
				}()
			}, u.win)
	})

	enableBtn := widget.NewButton("Enable SSH", func() {
		dialog.ShowConfirm("Enable SSH",
			"Start the SSH daemon and allow remote logins?",
			func(ok bool) {
				if !ok {
					return
				}
				go func() {
					if err := sshEnable(); err != nil {
						dialog.ShowError(err, u.win)
						return
					}
					refreshStatus()
					dialog.ShowInformation("Done", "SSH has been enabled.", u.win)
				}()
			}, u.win)
	})

	sshSection := container.NewVBox(
		sshTitle,
		sshDesc,
		sshStatus,
		container.NewHBox(refreshBtn, disableBtn, enableBtn),
	)

	return container.NewVBox(
		container.NewPadded(retSection),
		widget.NewSeparator(),
		container.NewPadded(sshSection),
	)
}

// ── Patterns tab ──────────────────────────────────────────────────────────────

func (u *DesktopUI) buildPatternsTab() fyne.CanvasObject {
	u.patternListW = widget.NewList(
		func() int {
			u.patternsMu.Lock()
			defer u.patternsMu.Unlock()
			return len(u.patterns)
		},
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			u.patternsMu.Lock()
			name := "(unnamed)"
			if id < len(u.patterns) && u.patterns[id].Name != "" {
				name = u.patterns[id].Name
			}
			u.patternsMu.Unlock()
			obj.(*widget.Label).SetText(name)
		},
	)
	u.patternListW.OnSelected = func(id widget.ListItemID) {
		u.patternEditIdx = id
		u.loadPatternIntoForm(id)
	}

	newPatBtn := widget.NewButton("+ New", func() {
		u.patternsMu.Lock()
		u.patterns = append(u.patterns, correlation.BehaviorPattern{
			Name:     "new-pattern",
			Severity: core.SeverityMedium,
			Title:    "New Pattern",
		})
		idx := len(u.patterns) - 1
		u.patternsMu.Unlock()
		u.patternListW.Refresh()
		u.patternListW.Select(idx)
	})

	delPatBtn := widget.NewButton("Delete", func() {
		idx := u.patternEditIdx
		if idx < 0 {
			return
		}
		u.patternsMu.Lock()
		if idx >= len(u.patterns) {
			u.patternsMu.Unlock()
			return
		}
		name := u.patterns[idx].Name
		u.patternsMu.Unlock()

		dialog.ShowConfirm("Delete Pattern",
			fmt.Sprintf("Delete %q?", name),
			func(ok bool) {
				if !ok {
					return
				}
				u.patternsMu.Lock()
				u.patterns = append(u.patterns[:idx], u.patterns[idx+1:]...)
				u.patternsMu.Unlock()
				u.patternEditIdx = -1
				u.patternListW.Refresh()
				u.clearPatternForm()
				u.commitPatterns()
			}, u.win)
	})

	listHeader := widget.NewLabel("Patterns")
	listHeader.TextStyle = fyne.TextStyle{Bold: true}

	leftPanel := container.NewBorder(
		container.NewVBox(listHeader, widget.NewSeparator()),
		container.NewHBox(newPatBtn, delPatBtn),
		nil, nil,
		u.patternListW,
	)

	// Right: edit form
	u.patternNameE = widget.NewEntry()
	u.patternNameE.SetPlaceHolder("pattern-id")

	u.patternSevSelect = widget.NewSelect(
		[]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, nil,
	)
	u.patternSevSelect.SetSelected("MEDIUM")

	u.patternTitleE = widget.NewEntry()
	u.patternTitleE.SetPlaceHolder("Human-readable title")

	u.patternDescE = widget.NewMultiLineEntry()
	u.patternDescE.SetPlaceHolder("Description")
	u.patternDescE.SetMinRowsVisible(4)

	savePatBtn := widget.NewButton("Save Pattern", func() {
		idx := u.patternEditIdx
		if idx < 0 {
			return
		}
		u.patternsMu.Lock()
		if idx < len(u.patterns) {
			u.patterns[idx].Name = strings.TrimSpace(u.patternNameE.Text)
			u.patterns[idx].Title = strings.TrimSpace(u.patternTitleE.Text)
			u.patterns[idx].Description = strings.TrimSpace(u.patternDescE.Text)
			u.patterns[idx].Severity = core.Severity(u.patternSevSelect.Selected)
		}
		u.patternsMu.Unlock()
		u.patternListW.Refresh()
		u.commitPatterns()
		dialog.ShowInformation("Saved", "Pattern saved successfully.", u.win)
	})
	savePatBtn.Importance = widget.HighImportance

	formHeader := widget.NewLabel("Edit Pattern")
	formHeader.TextStyle = fyne.TextStyle{Bold: true}

	placeholder := widget.NewLabel("← Select a pattern or press + New")
	placeholder.Alignment = fyne.TextAlignCenter

	form := widget.NewForm(
		widget.NewFormItem("Name", u.patternNameE),
		widget.NewFormItem("Severity", u.patternSevSelect),
		widget.NewFormItem("Title", u.patternTitleE),
		widget.NewFormItem("Description", u.patternDescE),
	)

	rightPanel := container.NewBorder(
		container.NewVBox(formHeader, widget.NewSeparator()),
		container.NewPadded(savePatBtn),
		nil, nil,
		container.NewScroll(container.NewVBox(
			container.NewPadded(form),
			container.NewCenter(placeholder),
		)),
	)

	split := container.NewHSplit(leftPanel, rightPanel)
	split.SetOffset(0.28)
	return split
}

func (u *DesktopUI) loadPatternIntoForm(idx int) {
	u.patternsMu.Lock()
	if idx < 0 || idx >= len(u.patterns) {
		u.patternsMu.Unlock()
		return
	}
	p := u.patterns[idx]
	u.patternsMu.Unlock()

	u.patternNameE.SetText(p.Name)
	u.patternTitleE.SetText(p.Title)
	u.patternDescE.SetText(p.Description)
	sev := string(p.Severity)
	if sev == "" {
		sev = "MEDIUM"
	}
	u.patternSevSelect.SetSelected(sev)
}

func (u *DesktopUI) clearPatternForm() {
	u.patternNameE.SetText("")
	u.patternTitleE.SetText("")
	u.patternDescE.SetText("")
	u.patternSevSelect.SetSelected("MEDIUM")
}

func (u *DesktopUI) commitPatterns() {
	u.patternsMu.Lock()
	patterns := make([]correlation.BehaviorPattern, len(u.patterns))
	copy(patterns, u.patterns)
	path := u.patternPath
	onSave := u.onPatternSave
	u.patternsMu.Unlock()

	if err := config.SavePatterns(path, patterns); err != nil {
		dialog.ShowError(err, u.win)
		return
	}
	if onSave != nil {
		onSave(patterns)
	}
}

// ── Query tab ─────────────────────────────────────────────────────────────────

// queryResult is one row returned by the interactive query.
type queryResult struct {
	ts   string
	tab  string
	line string
}

// buildQueryTab builds the interactive log-query panel.
//
// Layout:
//
//	┌─ filter bar ──────────────────────────────────────────────┐
//	│  Tab [dropdown]  Since [entry]  Until [entry]  Limit [n]  │
//	│  [Search]  [Clear]                      N result(s)       │
//	└───────────────────────────────────────────────────────────┘
//	┌─ results list ────────────────────────────────────────────┐
//	│  2026-09-19 15:04:05  [Process]  PROCESS_START PID=…      │
//	│  …                                                        │
//	└───────────────────────────────────────────────────────────┘
//	┌─ detail pane (expands on row click) ──────────────────────┐
//	│  Full line text (wrapping)                                │
//	└───────────────────────────────────────────────────────────┘
func (u *DesktopUI) buildQueryTab() fyne.CanvasObject {
	// ── filter bar ────────────────────────────────────────────────────────────
	tabSelect := widget.NewSelect(
		[]string{"All", "Process", "Network", "DNS", "File", "Findings"},
		nil,
	)
	tabSelect.SetSelected("All")

	sinceEntry := widget.NewEntry()
	sinceEntry.SetPlaceHolder("2026-09-19  or  2026-09-19 08:00")
	sincePickBtn := widget.NewButton("📅", func() {
		showDatePicker(u.win, sinceEntry.Text, func(s string) {
			sinceEntry.SetText(s)
		})
	})
	sinceRow := container.NewBorder(nil, nil, nil, sincePickBtn, sinceEntry)

	untilEntry := widget.NewEntry()
	untilEntry.SetPlaceHolder("2026-09-19 18:00  (blank = now)")
	untilPickBtn := widget.NewButton("📅", func() {
		showDatePicker(u.win, untilEntry.Text, func(s string) {
			untilEntry.SetText(s)
		})
	})
	untilRow := container.NewBorder(nil, nil, nil, untilPickBtn, untilEntry)

	limitEntry := widget.NewEntry()
	limitEntry.SetText("200")
	limitEntry.SetPlaceHolder("limit")

	countLabel := widget.NewLabel("")
	countLabel.Alignment = fyne.TextAlignTrailing

	// ── results ───────────────────────────────────────────────────────────────
	var results []queryResult
	var resultsMu sync.Mutex

	// detail pane — shows the full line of the selected row
	detailLabel := widget.NewLabel("")
	detailLabel.Wrapping = fyne.TextWrapWord
	detailLabel.TextStyle = fyne.TextStyle{Monospace: true}
	detailPane := container.NewVBox(widget.NewSeparator(), detailLabel)

	resultList := widget.NewList(
		func() int {
			resultsMu.Lock()
			defer resultsMu.Unlock()
			return len(results)
		},
		func() fyne.CanvasObject {
			// Row layout: [ts  badge] on left, line truncates in center.
			// Using HBox for the left group so Object indices are stable (0=ts, 1=badge).
			// Then NewBorder(nil,nil,leftGroup,nil,line): Objects=[line, leftGroup].
			ts := widget.NewLabel("")
			ts.TextStyle = fyne.TextStyle{Monospace: true}
			ts.Importance = widget.LowImportance

			badge := widget.NewLabel("")
			badge.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}

			line := widget.NewLabel("")
			line.TextStyle = fyne.TextStyle{Monospace: true}
			line.Truncation = fyne.TextTruncateEllipsis

			leftGroup := container.NewHBox(ts, badge)
			return container.NewBorder(nil, nil, leftGroup, nil, line)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			resultsMu.Lock()
			if id >= len(results) {
				resultsMu.Unlock()
				return
			}
			r := results[id]
			resultsMu.Unlock()

			// NewBorder(nil,nil,leftGroup,nil,line) → Objects[0]=line (center), Objects[1]=leftGroup (left)
			// NewHBox(ts, badge) → Objects[0]=ts, Objects[1]=badge
			row := obj.(*fyne.Container)
			line := row.Objects[0].(*widget.Label)
			leftGroup := row.Objects[1].(*fyne.Container)
			ts := leftGroup.Objects[0].(*widget.Label)
			badge := leftGroup.Objects[1].(*widget.Label)

			ts.SetText(r.ts + "  ")
			badge.SetText("[" + r.tab + "]  ")
			badge.Importance = tabImportance(r.tab)
			line.SetText(r.line)
		},
	)

	resultList.OnSelected = func(id widget.ListItemID) {
		resultsMu.Lock()
		if id >= len(results) {
			resultsMu.Unlock()
			return
		}
		r := results[id]
		resultsMu.Unlock()
		detailLabel.SetText(r.ts + "  [" + r.tab + "]  " + r.line)
	}

	// ── search action ─────────────────────────────────────────────────────────
	runSearch := func() {
		if u.store == nil {
			dialog.ShowError(fmt.Errorf("database not available"), u.win)
			return
		}

		f := store.QueryFilter{}

		tab := tabSelect.Selected
		if tab != "All" {
			f.Tab = tab
		}

		limit, err := strconv.Atoi(strings.TrimSpace(limitEntry.Text))
		if err != nil || limit <= 0 {
			limit = 200
		}
		f.Limit = limit

		since := strings.TrimSpace(sinceEntry.Text)
		until := strings.TrimSpace(untilEntry.Text)

		if since != "" {
			t, err := parseTime(since)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Since: %w", err), u.win)
				return
			}
			f.Since = t
		}
		if until != "" {
			t, err := parseTime(until)
			if err != nil {
				dialog.ShowError(fmt.Errorf("Until: %w", err), u.win)
				return
			}
			f.Until = t
		}

		countLabel.SetText("Searching…")
		detailLabel.SetText("")

		go func() {
			events, err := u.store.Query(f)
			if err != nil {
				dialog.ShowError(err, u.win)
				countLabel.SetText("")
				return
			}

			rows := make([]queryResult, len(events))
			for i, e := range events {
				rows[i] = queryResult{
					ts:   e.TS.Local().Format("2006-01-02 15:04:05"),
					tab:  e.Tab,
					line: e.Line,
				}
			}

			resultsMu.Lock()
			results = rows
			resultsMu.Unlock()

			resultList.Refresh()
			resultList.UnselectAll()

			n := len(rows)
			switch n {
			case 0:
				countLabel.SetText("No results")
			case 1:
				countLabel.SetText("1 result")
			default:
				countLabel.SetText(fmt.Sprintf("%d results", n))
			}
		}()
	}

	clearSearch := func() {
		resultsMu.Lock()
		results = nil
		resultsMu.Unlock()
		resultList.Refresh()
		countLabel.SetText("")
		detailLabel.SetText("")
		sinceEntry.SetText("")
		untilEntry.SetText("")
		limitEntry.SetText("200")
		tabSelect.SetSelected("All")
	}

	searchBtn := widget.NewButton("Search", runSearch)
	searchBtn.Importance = widget.HighImportance
	clearBtn := widget.NewButton("Clear", clearSearch)

	// Allow Enter in any filter field to trigger search
	sinceEntry.OnSubmitted = func(_ string) { runSearch() }
	untilEntry.OnSubmitted = func(_ string) { runSearch() }
	limitEntry.OnSubmitted = func(_ string) { runSearch() }

	// ── layout ────────────────────────────────────────────────────────────────
	filterForm := widget.NewForm(
		widget.NewFormItem("Tab", tabSelect),
		widget.NewFormItem("Since", sinceRow),
		widget.NewFormItem("Until", untilRow),
		widget.NewFormItem("Limit", limitEntry),
	)

	actionRow := container.NewBorder(nil, nil,
		container.NewHBox(searchBtn, clearBtn),
		countLabel,
	)

	filterBar := container.NewVBox(
		filterForm,
		actionRow,
		widget.NewSeparator(),
	)

	// Results take most of the space; detail pane is below (fixed height).
	resultsArea := container.NewBorder(nil, nil, nil, nil, resultList)
	bottomPane := container.NewVBox(detailPane)

	return container.NewBorder(
		container.NewVBox(u.tabHeader("Query Saved Logs"), filterBar),
		container.NewPadded(bottomPane),
		nil, nil,
		resultsArea,
	)
}

// tabImportance maps a tab name to a widget.Importance for badge colouring.
func tabImportance(tab string) widget.Importance {
	switch tab {
	case "Process":
		return widget.SuccessImportance
	case "Network":
		return widget.HighImportance
	case "DNS", "File":
		return widget.WarningImportance
	case "Findings":
		return widget.DangerImportance
	}
	return widget.MediumImportance
}
