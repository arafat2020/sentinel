package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// The desktop app's findings view, exclusion form and YAML editor. Each is a
// small type that owns its widgets and does its work in plain methods, so
// that what it does can be tested without a window on screen; the windows and
// dialogs that hold them are created by the callers at the bottom.

const (
	allSeverities = "All severities"
	allStatuses   = "All statuses"
	allRules      = "All rules"
)

// desktopFindings is the Findings tab: filters, the list, and beside it the
// detail of the selected finding with its actions.
type desktopFindings struct {
	model    *findingsModel
	patterns *patternStore
	// copyText puts text on the clipboard; exclude opens the exclusion
	// form. Both are set by the window that holds the view.
	copyText func(string)
	exclude  func(findingItem)

	severity, status, rule *widget.Select
	oldestFirst            *widget.Check
	count                  *widget.Label
	list                   *widget.List
	detail                 *widget.Label
	message                *widget.Label
	ack, dismiss, renew    *widget.Button
	copyJSON, excludeBtn   *widget.Button

	rows     []findingItem
	selected string // key of the finding shown in the detail pane
	root     fyne.CanvasObject
}

func newDesktopFindings(model *findingsModel, patterns *patternStore) *desktopFindings {
	d := &desktopFindings{model: model, patterns: patterns, copyText: func(string) {}, exclude: func(findingItem) {}}

	severities := []string{allSeverities}
	for _, s := range filterSeverities[1:] {
		severities = append(severities, string(s))
	}
	statuses := []string{allStatuses}
	for _, s := range filterStatuses[1:] {
		statuses = append(statuses, string(s))
	}

	d.severity = widget.NewSelect(severities, func(string) { d.applyFilter() })
	d.status = widget.NewSelect(statuses, func(string) { d.applyFilter() })
	d.rule = widget.NewSelect([]string{allRules}, func(string) { d.applyFilter() })
	d.oldestFirst = widget.NewCheck("Oldest first", func(bool) { d.applyFilter() })
	d.count = widget.NewLabel("")

	d.list = widget.NewList(
		func() int { return len(d.rows) },
		func() fyne.CanvasObject {
			label := widget.NewLabel("")
			label.TextStyle = fyne.TextStyle{Monospace: true}
			label.Truncation = fyne.TextTruncateEllipsis
			return label
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id >= len(d.rows) {
				return
			}
			label := object.(*widget.Label)
			label.SetText(desktopRowText(d.rows[id]))
			label.Importance = severityImportance(d.rows[id])
			label.Refresh()
		},
	)
	d.list.OnSelected = func(id widget.ListItemID) {
		if id < len(d.rows) {
			d.selected = d.rows[id].Key
			d.showDetail()
		}
	}

	d.detail = widget.NewLabel("Select a finding to see what it is based on.")
	d.detail.TextStyle = fyne.TextStyle{Monospace: true}
	d.message = widget.NewLabel("")

	d.ack = widget.NewButton("Acknowledge", func() { d.setStatus(core.StatusAcknowledged) })
	d.dismiss = widget.NewButton("Dismiss", func() { d.setStatus(core.StatusDismissed) })
	d.renew = widget.NewButton("Mark new", func() { d.setStatus(core.StatusNew) })
	d.copyJSON = widget.NewButton("Copy as JSON", d.copySelected)
	d.excludeBtn = widget.NewButton("Exclude…", func() {
		if item, ok := d.model.Get(d.selected); ok {
			d.exclude(item)
		}
	})

	// Set without firing the callbacks: nothing is built yet to refresh.
	d.severity.Selected, d.status.Selected, d.rule.Selected = allSeverities, allStatuses, allRules

	filters := container.NewHBox(d.severity, d.status, d.rule, d.oldestFirst, d.count)
	actions := container.NewHBox(d.ack, d.dismiss, d.renew, d.copyJSON, d.excludeBtn)
	right := container.NewBorder(nil, container.NewVBox(d.message, actions), nil, nil, container.NewScroll(d.detail))

	split := container.NewHSplit(d.list, right)
	split.SetOffset(0.45)
	d.root = container.NewBorder(filters, nil, nil, nil, split)

	d.Refresh()
	return d
}

// desktopRowText is one line of the desktop findings list.
func desktopRowText(item findingItem) string {
	row := rowOf(item)
	return fmt.Sprintf("%s  %-8s  %-12s  %s — %s  %s", row.Time, row.Severity, row.Status, row.Rule, row.Title, row.Process)
}

// severityImportance colours a row by severity; a dismissed finding is
// played down whatever its severity.
func severityImportance(item findingItem) widget.Importance {
	if item.Status == core.StatusDismissed {
		return widget.LowImportance
	}
	switch item.Finding.Severity {
	case core.SeverityCritical, core.SeverityHigh:
		return widget.DangerImportance
	case core.SeverityMedium:
		return widget.WarningImportance
	case core.SeverityLow:
		return widget.HighImportance
	default:
		return widget.MediumImportance
	}
}

// filterFromWidgets reads the filter the user has chosen.
func (d *desktopFindings) filterFromWidgets() findingFilter {
	filter := findingFilter{OldestFirst: d.oldestFirst.Checked}
	if d.severity.Selected != allSeverities {
		filter.Severity = core.Severity(d.severity.Selected)
	}
	if d.status.Selected != allStatuses {
		filter.Status = core.FindingStatus(d.status.Selected)
	}
	if d.rule.Selected != allRules {
		filter.Rule = d.rule.Selected
	}
	return filter
}

func (d *desktopFindings) applyFilter() {
	if d.list == nil {
		return // still being built
	}
	d.model.SetFilter(d.filterFromWidgets())
	d.Refresh()
}

// Refresh redraws the list and the detail from the model. It must run on the
// Fyne thread.
func (d *desktopFindings) Refresh() {
	d.rows = d.model.Visible()

	rules := append([]string{allRules}, d.model.Rules()...)
	if strings.Join(rules, "\n") != strings.Join(d.rule.Options, "\n") {
		d.rule.Options = rules
		d.rule.Refresh()
	}

	total, unhandled := d.model.Counts()
	d.count.SetText(fmt.Sprintf("%d shown of %d (%d new)", len(d.rows), total, unhandled))

	d.list.UnselectAll()
	d.list.Refresh()
	for i, item := range d.rows {
		if item.Key == d.selected {
			d.list.Select(i)
			break
		}
	}
	d.showDetail()
}

func (d *desktopFindings) loadedPatterns() []correlation.BehaviorPattern {
	if d.patterns == nil {
		return nil
	}
	return d.patterns.State().Patterns
}

func (d *desktopFindings) showDetail() {
	item, ok := d.model.Get(d.selected)
	for _, button := range []*widget.Button{d.ack, d.dismiss, d.renew, d.copyJSON, d.excludeBtn} {
		if ok {
			button.Enable()
		} else {
			button.Disable()
		}
	}
	if !ok {
		d.detail.SetText("Select a finding to see what it is based on.")
		return
	}

	if len(findingRoles(item.Finding)) == 0 || d.patterns == nil {
		d.excludeBtn.Disable()
	}
	d.detail.SetText(strings.Join(detailLines(item, d.loadedPatterns()), "\n"))
}

func (d *desktopFindings) setStatus(status core.FindingStatus) {
	if d.selected == "" {
		return
	}
	if err := d.model.SetStatus(d.selected, status); err != nil {
		d.message.SetText("Status not saved: " + err.Error())
	} else {
		d.message.SetText("Marked " + string(status) + ".")
	}
	d.Refresh()
}

func (d *desktopFindings) copySelected() {
	item, ok := d.model.Get(d.selected)
	if !ok {
		return
	}
	d.copyText(findingJSON(item))
	d.message.SetText("Copied the finding as JSON.")
}

// --- Exclude ----------------------------------------------------------------

// desktopExclude is the "Exclude…" form: choose the role, which fields of its
// process to match and how, the scope and a description, with the YAML that
// will be added shown as you go.
type desktopExclude struct {
	item     findingItem
	model    *findingsModel
	patterns *patternStore
	// done is called after a successful save.
	done func()

	draft exclusionDraft

	role        *widget.Select
	fields      *fyne.Container
	keep        map[string]*widget.Check
	mode        map[string]*widget.Select
	value       map[string]*widget.Entry
	scope       *widget.RadioGroup
	description *widget.Entry
	preview     *widget.Label
	problem     *widget.Label
	saveBtn     *widget.Button
	root        fyne.CanvasObject
}

const (
	scopeAllRules = "All rules"
)

func (e *desktopExclude) scopeThisRule() string {
	return fmt.Sprintf("This rule only (role %q of %s)", e.draft.Role, e.item.Finding.Rule)
}

func newDesktopExclude(item findingItem, model *findingsModel, patterns *patternStore, done func()) (*desktopExclude, error) {
	roles := findingRoles(item.Finding)
	if len(roles) == 0 {
		return nil, fmt.Errorf("this finding has no stored processes to build an exclusion from")
	}

	start := roles[0]
	if primary := roleOf(item.Finding, item.Finding.Evidence.Process); primary != "" {
		start = primary
	}

	e := &desktopExclude{item: item, model: model, patterns: patterns, done: done}

	e.fields = container.NewVBox()
	e.preview = widget.NewLabel("")
	e.preview.TextStyle = fyne.TextStyle{Monospace: true}
	e.problem = widget.NewLabel("")
	e.problem.Importance = widget.DangerImportance
	e.problem.Wrapping = fyne.TextWrapWord

	e.description = widget.NewEntry()
	e.description.SetPlaceHolder("Why is this safe to ignore? (required)")
	e.description.OnChanged = func(text string) { e.draft.Description = text; e.update() }

	e.scope = widget.NewRadioGroup(nil, func(choice string) {
		e.draft.AllRules = choice == scopeAllRules
		e.update()
	})
	e.saveBtn = widget.NewButton("Save exclusion", func() { e.save() })
	e.saveBtn.Importance = widget.HighImportance

	e.role = widget.NewSelect(roles, func(role string) { e.chooseRole(role) })
	e.role.Selected = start
	if err := e.chooseRole(start); err != nil {
		return nil, err
	}

	e.root = container.NewVBox(
		widget.NewForm(widget.NewFormItem("Process in role", e.role)),
		e.fields,
		widget.NewForm(
			widget.NewFormItem("Applies to", e.scope),
			widget.NewFormItem("Description", e.description),
		),
		widget.NewLabel("This will be added to the patterns file:"),
		e.preview,
		e.problem,
		e.saveBtn,
	)
	return e, nil
}

// chooseRole rebuilds the form for the process bound to role.
func (e *desktopExclude) chooseRole(role string) error {
	draft, err := newExclusionDraft(e.item.Finding, role)
	if err != nil {
		return err
	}
	draft.AllRules = e.draft.AllRules
	draft.Description = e.draft.Description
	e.draft = draft

	e.keep, e.mode, e.value = map[string]*widget.Check{}, map[string]*widget.Select{}, map[string]*widget.Entry{}
	e.fields.RemoveAll()

	for i := range e.draft.Fields {
		field := &e.draft.Fields[i]
		name := field.Field

		value := widget.NewEntry()
		value.SetText(field.Value)
		value.OnChanged = func(text string) { field.Value = text; e.update() }

		keep := widget.NewCheck("Match "+name, func(checked bool) { field.Keep = checked; e.update() })
		keep.Checked = field.Keep

		labels := []string{}
		for _, mode := range field.Modes() {
			labels = append(labels, modeLabels[mode])
		}
		mode := widget.NewSelect(labels, func(label string) {
			for candidate, text := range modeLabels {
				if text == label && candidate != field.Mode {
					e.draft.SetMode(name, candidate)
					value.SetText(field.Value)
				}
			}
			e.update()
		})
		mode.Selected = modeLabels[field.Mode]

		e.keep[name], e.mode[name], e.value[name] = keep, mode, value
		e.fields.Add(container.NewBorder(nil, nil, container.NewHBox(keep, mode), nil, value))
	}

	e.scope.Options = []string{e.scopeThisRule(), scopeAllRules}
	if e.draft.AllRules {
		e.scope.Selected = scopeAllRules
	} else {
		e.scope.Selected = e.scopeThisRule()
	}
	e.scope.Refresh()
	e.fields.Refresh()

	e.update()
	return nil
}

// update redraws the preview and says what, if anything, stops a save.
func (e *desktopExclude) update() {
	if e.preview == nil || e.saveBtn == nil {
		return
	}
	e.preview.SetText(e.draft.Preview())

	problem := e.draft.Validate()
	if problem == nil && e.patterns != nil {
		problem = e.patterns.Writable()
	}
	if problem != nil {
		e.problem.SetText(problem.Error())
		e.saveBtn.Disable()
		return
	}
	e.problem.SetText("")
	e.saveBtn.Enable()
}

// save writes the exclusion, applies it, and marks the finding dismissed.
func (e *desktopExclude) save() error {
	if err := e.patterns.AddExclusion(e.draft); err != nil {
		e.problem.SetText("Not saved: " + err.Error())
		return err
	}

	_ = e.model.SetStatus(e.item.Key, core.StatusDismissed)
	if e.done != nil {
		e.done()
	}
	return nil
}

// --- YAML editor -------------------------------------------------------------

// desktopYAML is a YAML editor with the problems found in the text listed
// under it. Nothing is saved while there are any.
type desktopYAML struct {
	entry    *widget.Entry
	problems *widget.Label
	saveBtn  *widget.Button
	root     fyne.CanvasObject

	save func(string) []config.EditError
	// done is called after a successful save.
	done func()
}

func newDesktopYAML(text, notice string, save func(string) []config.EditError, done func()) *desktopYAML {
	y := &desktopYAML{save: save, done: done}

	y.entry = widget.NewMultiLineEntry()
	y.entry.TextStyle = fyne.TextStyle{Monospace: true}
	y.entry.Wrapping = fyne.TextWrapOff
	y.entry.SetText(text)
	y.entry.SetMinRowsVisible(22)

	y.problems = widget.NewLabel(notice)
	y.problems.Importance = widget.DangerImportance
	y.problems.Wrapping = fyne.TextWrapWord

	y.saveBtn = widget.NewButton("Check and save", func() { y.trySave() })
	y.saveBtn.Importance = widget.HighImportance

	y.root = container.NewBorder(nil, container.NewVBox(y.problems, y.saveBtn), nil, nil, y.entry)
	return y
}

// trySave checks the text and saves it if nothing is wrong. It reports
// whether it was saved.
func (y *desktopYAML) trySave() bool {
	problems := y.save(y.entry.Text)
	if len(problems) == 0 {
		y.problems.SetText("")
		if y.done != nil {
			y.done()
		}
		return true
	}

	lines := make([]string, 0, len(problems)+1)
	lines = append(lines, fmt.Sprintf("%d problem(s) — nothing was saved:", len(problems)))
	for _, problem := range problems {
		lines = append(lines, "✗ "+problem.String())
	}
	y.problems.SetText(strings.Join(lines, "\n"))
	return false
}

// --- Windows -----------------------------------------------------------------

// openExcludeDialog shows the exclusion form for a finding.
func (u *DesktopUI) openExcludeDialog(item findingItem) {
	var shown dialog.Dialog

	form, err := newDesktopExclude(item, u.findingsModel, u.patternStore, func() {
		if shown != nil {
			shown.Hide()
		}
		u.findingsView.message.SetText("Exclusion saved and applied. This finding is dismissed.")
		u.findingsView.Refresh()
	})
	if err != nil {
		dialog.ShowError(err, u.win)
		return
	}

	shown = dialog.NewCustom("Exclude findings like this one — rule "+item.Finding.Rule, "Cancel", container.NewScroll(form.root), u.win)
	shown.Resize(fyne.NewSize(760, 620))
	shown.Show()
}

// openYAMLWindow shows a YAML editor in a window of its own.
func (u *DesktopUI) openYAMLWindow(title, text string, save func(string) []config.EditError) {
	notice := ""
	if u.patternStore != nil {
		if err := u.patternStore.Writable(); err != nil {
			notice = err.Error()
		}
	}

	window := u.fyneApp.NewWindow(title)
	editor := newDesktopYAML(text, notice, save, func() {
		window.Close()
		u.syncPatternsFromStore()
		dialog.ShowInformation("Saved", "Saved and applied.", u.win)
	})
	window.SetContent(editor.root)
	window.Resize(fyne.NewSize(820, 640))
	window.Show()
}
