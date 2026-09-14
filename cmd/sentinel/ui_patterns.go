package main

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// severityOptions lists valid severity values shown in the dropdown.
var severityOptions = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// eventTypeOptions lists valid event types shown in dropdowns.
var eventTypeOptions = []string{
	"PROCESS_START", "PROCESS_EXIT", "NETWORK_CONNECT", "NETWORK_CLOSE",
	"FILE_CREATE", "FILE_MODIFY", "FILE_DELETE", "FILE_RENAME",
	"PERSISTENCE_CHANGE", "DNS_QUERY", "SCRIPT_EXECUTION",
}

// conditionTypeOptions lists valid condition types.
var conditionTypeOptions = []string{"PROCESS_NAME", "PROCESS_USER"}

// PatternsPage is the full-screen pattern manager embedded in the TUI.
// It owns:
//   - a list panel on the left showing pattern names
//   - a form panel on the right for editing the selected pattern
//
// Sub-editors for processes and relationships are pushed as additional
// pages onto the parent tview.Pages so they overlay the main view.
type PatternsPage struct {
	app         *tview.Application
	pages       *tview.Pages // the root Pages of the main UI
	patterns    []correlation.BehaviorPattern
	patternPath string
	onSave      func([]correlation.BehaviorPattern)

	// root is the layout returned by Root() and registered as a page.
	root *tview.Flex

	// left panel
	list *tview.List

	// right panel widgets (rebuilt on selection change)
	rightPanel  *tview.Pages
	form        *tview.Form
	placeholder *tview.TextView

	// editing state: index in patterns of the item currently shown in the form,
	// -1 when nothing is selected.
	editingIdx int

	// draft holds in-progress edits to the currently selected pattern.
	// It is applied to patterns[editingIdx] only when the user presses Save.
	draft correlation.BehaviorPattern
}

// NewPatternsPage constructs the page. app and pages are the main UI's
// tview.Application and tview.Pages, needed to push modal sub-editors.
func NewPatternsPage(
	app *tview.Application,
	pages *tview.Pages,
	patternPath string,
	patterns []correlation.BehaviorPattern,
	onSave func([]correlation.BehaviorPattern),
) *PatternsPage {
	pp := &PatternsPage{
		app:         app,
		pages:       pages,
		patterns:    patterns,
		patternPath: patternPath,
		onSave:      onSave,
		editingIdx:  -1,
	}
	pp.build()
	return pp
}

// Root returns the tview primitive to register as a page.
func (pp *PatternsPage) Root() tview.Primitive {
	return pp.root
}

// build constructs all tview widgets.
func (pp *PatternsPage) build() {
	pp.list = tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorDarkBlue).
		SetSelectedTextColor(tcell.ColorWhite)
	pp.list.SetBorder(true).SetTitle(" Patterns ").SetTitleAlign(tview.AlignLeft)
	pp.list.SetChangedFunc(func(idx int, _ string, _ string, _ rune) {
		pp.selectPattern(idx)
	})

	// List key bindings: N=new, D=delete
	pp.list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'n', 'N':
			pp.newPattern()
			return nil
		case 'd', 'D':
			pp.deleteSelected()
			return nil
		}
		return event
	})

	pp.placeholder = tview.NewTextView().
		SetText("\n  Select a pattern from the list\n  or press [N] to create one.").
		SetDynamicColors(true)
	pp.placeholder.SetBorder(true).SetTitle(" Edit Pattern ").SetTitleAlign(tview.AlignLeft)

	pp.form = tview.NewForm()
	pp.form.SetBorder(true).SetTitle(" Edit Pattern ").SetTitleAlign(tview.AlignLeft)

	pp.rightPanel = tview.NewPages()
	pp.rightPanel.AddPage("placeholder", pp.placeholder, true, true)
	pp.rightPanel.AddPage("form", pp.form, true, false)

	hint := tview.NewTextView().
		SetText("  [N] New  [D] Delete  [Tab] Switch panel  [←/→] Switch tab  [Esc] Main view").
		SetDynamicColors(true)
	hint.SetBackgroundColor(tcell.ColorDarkBlue)

	body := tview.NewFlex().
		AddItem(pp.list, 30, 0, true).
		AddItem(pp.rightPanel, 0, 1, false)

	pp.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(hint, 1, 0, false)

	pp.reloadList()
}

// reloadList repopulates the list from pp.patterns without changing selection.
func (pp *PatternsPage) reloadList() {
	pp.list.Clear()
	for _, p := range pp.patterns {
		name := p.Name
		if name == "" {
			name = "(unnamed)"
		}
		pp.list.AddItem(name, "", 0, nil)
	}
	if pp.editingIdx >= 0 && pp.editingIdx < len(pp.patterns) {
		pp.list.SetCurrentItem(pp.editingIdx)
	}
}

// selectPattern loads the pattern at idx into the right-side form.
func (pp *PatternsPage) selectPattern(idx int) {
	if idx < 0 || idx >= len(pp.patterns) {
		pp.rightPanel.SwitchToPage("placeholder")
		pp.editingIdx = -1
		return
	}
	pp.editingIdx = idx
	pp.draft = deepCopyPattern(pp.patterns[idx])
	pp.rebuildForm()
	pp.rightPanel.SwitchToPage("form")
}

// rebuildForm recreates all form fields from pp.draft.
func (pp *PatternsPage) rebuildForm() {
	pp.form.Clear(true)

	pp.form.AddInputField("Name", pp.draft.Name, 40, nil, func(v string) {
		pp.draft.Name = v
	})

	sevIdx := 0
	for i, s := range severityOptions {
		if s == string(pp.draft.Severity) {
			sevIdx = i
			break
		}
	}
	pp.form.AddDropDown("Severity", severityOptions, sevIdx, func(_ string, optIdx int) {
		if optIdx >= 0 {
			pp.draft.Severity = core.Severity(severityOptions[optIdx])
		}
	})

	pp.form.AddInputField("Title", pp.draft.Title, 40, nil, func(v string) {
		pp.draft.Title = v
	})

	pp.form.AddInputField("Description", pp.draft.Description, 60, nil, func(v string) {
		pp.draft.Description = v
	})

	// Processes summary + edit button
	pp.form.AddTextView("Processes", pp.processSummary(), 40, 1, true, false)
	pp.form.AddButton("Edit Processes", func() {
		pp.openProcessEditor()
	})

	// Relationships summary + edit button
	pp.form.AddTextView("Relationships", pp.relationshipSummary(), 40, 1, true, false)
	pp.form.AddButton("Edit Relationships", func() {
		pp.openRelationshipEditor()
	})

	pp.form.AddButton("Save", func() {
		pp.savePattern()
	})
	pp.form.AddButton("Cancel", func() {
		pp.selectPattern(pp.editingIdx)
	})

	// Esc in the form goes back to the list
	pp.form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			pp.app.SetFocus(pp.list)
			return nil
		}
		return event
	})
}

func (pp *PatternsPage) processSummary() string {
	if len(pp.draft.Processes) == 0 {
		return "(none)"
	}
	ids := make([]string, len(pp.draft.Processes))
	for i, p := range pp.draft.Processes {
		ids[i] = p.ID
	}
	return strings.Join(ids, ", ")
}

func (pp *PatternsPage) relationshipSummary() string {
	if len(pp.draft.Relationships) == 0 {
		return "(none)"
	}
	parts := make([]string, len(pp.draft.Relationships))
	for i, r := range pp.draft.Relationships {
		parts[i] = fmt.Sprintf("%s→%s", r.Parent, r.Child)
	}
	return strings.Join(parts, "  ")
}

// savePattern validates pp.draft and, if valid, saves to YAML and calls onSave.
func (pp *PatternsPage) savePattern() {
	if pp.draft.Name == "" {
		pp.showModal("Validation", "Pattern name cannot be empty.", nil)
		return
	}
	if pp.editingIdx < 0 || pp.editingIdx >= len(pp.patterns) {
		return
	}
	pp.patterns[pp.editingIdx] = deepCopyPattern(pp.draft)
	pp.reloadList()

	if err := config.SavePatterns(pp.patternPath, pp.patterns); err != nil {
		pp.showModal("Save Error", err.Error(), nil)
		return
	}
	if pp.onSave != nil {
		pp.onSave(pp.patterns)
	}
	pp.showModal("Saved", fmt.Sprintf("Pattern %q saved.", pp.draft.Name), nil)
}

// newPattern inserts a blank pattern and selects it.
func (pp *PatternsPage) newPattern() {
	blank := correlation.BehaviorPattern{
		Name:     "new-pattern",
		Severity: core.SeverityMedium,
		Title:    "New Pattern",
	}
	pp.patterns = append(pp.patterns, blank)
	pp.reloadList()
	newIdx := len(pp.patterns) - 1
	pp.list.SetCurrentItem(newIdx)
	pp.selectPattern(newIdx)
	pp.app.SetFocus(pp.form)
}

// deleteSelected removes the currently selected pattern after confirmation.
func (pp *PatternsPage) deleteSelected() {
	idx := pp.list.GetCurrentItem()
	if idx < 0 || idx >= len(pp.patterns) {
		return
	}
	name := pp.patterns[idx].Name
	pp.showModal(
		"Confirm Delete",
		fmt.Sprintf("Delete pattern %q?  [S]ave changes afterwards.", name),
		func() {
			pp.patterns = append(pp.patterns[:idx], pp.patterns[idx+1:]...)
			pp.editingIdx = -1
			pp.reloadList()
			pp.rightPanel.SwitchToPage("placeholder")
			if err := config.SavePatterns(pp.patternPath, pp.patterns); err == nil && pp.onSave != nil {
				pp.onSave(pp.patterns)
			}
		},
	)
}

// showModal displays a simple OK modal. If onConfirm is non-nil, two buttons
// are shown: OK (runs onConfirm) and Cancel.
func (pp *PatternsPage) showModal(title, msg string, onConfirm func()) {
	modal := tview.NewModal().SetText(msg)
	if onConfirm != nil {
		modal.AddButtons([]string{"OK", "Cancel"}).
			SetDoneFunc(func(idx int, _ string) {
				pp.pages.RemovePage("modal")
				if idx == 0 {
					onConfirm()
				}
			})
	} else {
		modal.AddButtons([]string{"OK"}).
			SetDoneFunc(func(_ int, _ string) {
				pp.pages.RemovePage("modal")
			})
	}
	pp.pages.AddPage("modal", modal, false, true)
}

// ── Process editor ────────────────────────────────────────────────────────────

// openProcessEditor pushes a full-screen process list editor onto pp.pages.
func (pp *PatternsPage) openProcessEditor() {
	pageName := "proc-editor"
	var procList *tview.List
	var statusBar *tview.TextView

	rebuild := func() {
		procList.Clear()
		for _, p := range pp.draft.Processes {
			conds := fmt.Sprintf("conditions:%d", len(p.Conditions))
			evts := make([]string, len(p.Events))
			for i, e := range p.Events {
				evts[i] = string(e.Type)
			}
			evtStr := strings.Join(evts, ",")
			if evtStr == "" {
				evtStr = "none"
			}
			secondary := fmt.Sprintf("  %s  events:[%s]", conds, evtStr)
			procList.AddItem(p.ID, secondary, 0, nil)
		}
	}

	procList = tview.NewList().SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorDarkBlue).
		SetSelectedTextColor(tcell.ColorWhite)
	procList.SetBorder(true).
		SetTitle(fmt.Sprintf(" Processes — %s ", pp.draft.Name)).
		SetTitleAlign(tview.AlignLeft)

	rebuild()

	statusBar = tview.NewTextView().
		SetText("  [A] Add  [E] Edit  [D] Delete  [Esc] Back").
		SetDynamicColors(true)
	statusBar.SetBackgroundColor(tcell.ColorDarkBlue)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(procList, 0, 1, true).
		AddItem(statusBar, 1, 0, false)

	procList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			pp.pages.RemovePage(pageName)
			pp.rebuildForm()
			pp.app.SetFocus(pp.form)
			return nil
		}
		switch event.Rune() {
		case 'a', 'A':
			pp.draft.Processes = append(pp.draft.Processes, correlation.ProcessPattern{
				ID: fmt.Sprintf("proc%d", len(pp.draft.Processes)+1),
			})
			rebuild()
			procList.SetCurrentItem(len(pp.draft.Processes) - 1)
			pp.openProcessDetailEditor(pageName, len(pp.draft.Processes)-1, rebuild)
			return nil
		case 'e', 'E':
			idx := procList.GetCurrentItem()
			if idx >= 0 && idx < len(pp.draft.Processes) {
				pp.openProcessDetailEditor(pageName, idx, rebuild)
			}
			return nil
		case 'd', 'D':
			idx := procList.GetCurrentItem()
			if idx >= 0 && idx < len(pp.draft.Processes) {
				pp.draft.Processes = append(pp.draft.Processes[:idx], pp.draft.Processes[idx+1:]...)
				rebuild()
			}
			return nil
		}
		return event
	})

	pp.pages.AddPage(pageName, layout, true, true)
}

// openProcessDetailEditor pushes an editor for a single ProcessPattern.
func (pp *PatternsPage) openProcessDetailEditor(parentPage string, procIdx int, onReturn func()) {
	pageName := fmt.Sprintf("proc-detail-%d", procIdx)
	proc := &pp.draft.Processes[procIdx]

	form := tview.NewForm()
	form.SetBorder(true).
		SetTitle(fmt.Sprintf(" Edit Process: %s ", proc.ID)).
		SetTitleAlign(tview.AlignLeft)

	form.AddInputField("ID", proc.ID, 30, nil, func(v string) { proc.ID = v })

	rebuildCondList := func() {}
	rebuildEvtList := func() {}

	// Conditions list
	condView := tview.NewTextView().SetDynamicColors(true)
	refreshCondView := func() {
		if len(proc.Conditions) == 0 {
			condView.SetText("  (none)")
			return
		}
		var sb strings.Builder
		for i, c := range proc.Conditions {
			sb.WriteString(fmt.Sprintf("  [%d] %s = %s\n", i, c.Type, c.Value))
		}
		condView.SetText(sb.String())
	}
	refreshCondView()

	form.AddFormItem(condView)

	form.AddButton("Add Condition", func() {
		proc.Conditions = append(proc.Conditions, correlation.Condition{
			Type:  correlation.ConditionProcessName,
			Value: "",
		})
		refreshCondView()
		pp.openConditionEditor(pageName, proc, len(proc.Conditions)-1, func() {
			refreshCondView()
			rebuildCondList()
		})
	})

	form.AddButton("Remove Last Condition", func() {
		if len(proc.Conditions) > 0 {
			proc.Conditions = proc.Conditions[:len(proc.Conditions)-1]
			refreshCondView()
		}
	})

	// Events list
	evtView := tview.NewTextView().SetDynamicColors(true)
	refreshEvtView := func() {
		if len(proc.Events) == 0 {
			evtView.SetText("  (none)")
			return
		}
		var sb strings.Builder
		for i, e := range proc.Events {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i, e.Type))
		}
		evtView.SetText(sb.String())
	}
	refreshEvtView()

	form.AddFormItem(evtView)

	evtDropdown := tview.NewDropDown().SetLabel("Add Event Type").SetOptions(eventTypeOptions, nil)
	form.AddFormItem(evtDropdown)

	form.AddButton("Add Event", func() {
		_, evtVal := evtDropdown.GetCurrentOption()
		proc.Events = append(proc.Events, correlation.EventPattern{
			Type: core.EventType(evtVal),
		})
		refreshEvtView()
	})

	form.AddButton("Remove Last Event", func() {
		if len(proc.Events) > 0 {
			proc.Events = proc.Events[:len(proc.Events)-1]
			refreshEvtView()
		}
	})

	form.AddButton("Done", func() {
		pp.pages.RemovePage(pageName)
		onReturn()
		pp.app.SetFocus(pp.pages)
	})

	rebuildCondList = refreshCondView
	rebuildEvtList = refreshEvtView
	_ = rebuildEvtList

	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			pp.pages.RemovePage(pageName)
			onReturn()
			pp.app.SetFocus(pp.pages)
			return nil
		}
		return event
	})

	pp.pages.AddPage(pageName, form, true, true)
}

// openConditionEditor edits a single Condition on a modal form.
func (pp *PatternsPage) openConditionEditor(parentPage string, proc *correlation.ProcessPattern, condIdx int, onDone func()) {
	pageName := fmt.Sprintf("cond-%s-%d", parentPage, condIdx)
	cond := &proc.Conditions[condIdx]

	form := tview.NewForm()
	form.SetBorder(true).SetTitle(" Edit Condition ").SetTitleAlign(tview.AlignLeft)

	ctIdx := 0
	for i, s := range conditionTypeOptions {
		if s == string(cond.Type) {
			ctIdx = i
			break
		}
	}
	form.AddDropDown("Type", conditionTypeOptions, ctIdx, func(_ string, optIdx int) {
		if optIdx >= 0 {
			cond.Type = correlation.ConditionType(conditionTypeOptions[optIdx])
		}
	})
	form.AddInputField("Value", cond.Value, 40, nil, func(v string) { cond.Value = v })
	form.AddButton("Done", func() {
		pp.pages.RemovePage(pageName)
		onDone()
	})
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			pp.pages.RemovePage(pageName)
			onDone()
			return nil
		}
		return event
	})

	pp.pages.AddPage(pageName, form, false, true)
}

// ── Relationship editor ───────────────────────────────────────────────────────

// openRelationshipEditor pushes a full-screen relationship list editor.
func (pp *PatternsPage) openRelationshipEditor() {
	pageName := "rel-editor"
	var relList *tview.List

	rebuild := func() {
		relList.Clear()
		for _, r := range pp.draft.Relationships {
			relList.AddItem(
				fmt.Sprintf("%s  %s → %s", r.Type, r.Parent, r.Child),
				"", 0, nil,
			)
		}
	}

	relList = tview.NewList().SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorDarkBlue).
		SetSelectedTextColor(tcell.ColorWhite)
	relList.SetBorder(true).
		SetTitle(fmt.Sprintf(" Relationships — %s ", pp.draft.Name)).
		SetTitleAlign(tview.AlignLeft)
	rebuild()

	hint := tview.NewTextView().
		SetText("  [A] Add  [E] Edit  [D] Delete  [Esc] Back").
		SetDynamicColors(true)
	hint.SetBackgroundColor(tcell.ColorDarkBlue)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(relList, 0, 1, true).
		AddItem(hint, 1, 0, false)

	relList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			pp.pages.RemovePage(pageName)
			pp.rebuildForm()
			pp.app.SetFocus(pp.form)
			return nil
		}
		switch event.Rune() {
		case 'a', 'A':
			pp.draft.Relationships = append(pp.draft.Relationships, correlation.RelationshipPattern{
				Type: correlation.RelationshipSpawned,
			})
			rebuild()
			pp.openRelationshipDetailEditor(pageName, len(pp.draft.Relationships)-1, rebuild)
			return nil
		case 'e', 'E':
			idx := relList.GetCurrentItem()
			if idx >= 0 && idx < len(pp.draft.Relationships) {
				pp.openRelationshipDetailEditor(pageName, idx, rebuild)
			}
			return nil
		case 'd', 'D':
			idx := relList.GetCurrentItem()
			if idx >= 0 && idx < len(pp.draft.Relationships) {
				pp.draft.Relationships = append(pp.draft.Relationships[:idx], pp.draft.Relationships[idx+1:]...)
				rebuild()
			}
			return nil
		}
		return event
	})

	pp.pages.AddPage(pageName, layout, true, true)
}

// openRelationshipDetailEditor edits a single RelationshipPattern.
func (pp *PatternsPage) openRelationshipDetailEditor(parentPage string, relIdx int, onReturn func()) {
	pageName := fmt.Sprintf("rel-detail-%d", relIdx)
	rel := &pp.draft.Relationships[relIdx]

	// Collect process IDs for parent/child dropdowns.
	processIDs := make([]string, len(pp.draft.Processes))
	for i, p := range pp.draft.Processes {
		processIDs[i] = p.ID
	}
	if len(processIDs) == 0 {
		processIDs = []string{"(no processes)"}
	}

	form := tview.NewForm()
	form.SetBorder(true).SetTitle(" Edit Relationship ").SetTitleAlign(tview.AlignLeft)

	form.AddDropDown("Type", []string{"SPAWNED"}, 0, func(_ string, _ int) {
		rel.Type = correlation.RelationshipSpawned
	})

	parentIdx := 0
	for i, id := range processIDs {
		if id == rel.Parent {
			parentIdx = i
			break
		}
	}
	form.AddDropDown("Parent", processIDs, parentIdx, func(_ string, optIdx int) {
		if optIdx >= 0 && optIdx < len(processIDs) {
			rel.Parent = processIDs[optIdx]
		}
	})

	childIdx := 0
	for i, id := range processIDs {
		if id == rel.Child {
			childIdx = i
			break
		}
	}
	form.AddDropDown("Child", processIDs, childIdx, func(_ string, optIdx int) {
		if optIdx >= 0 && optIdx < len(processIDs) {
			rel.Child = processIDs[optIdx]
		}
	})

	form.AddButton("Done", func() {
		pp.pages.RemovePage(pageName)
		onReturn()
		pp.app.SetFocus(pp.pages)
	})
	form.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			pp.pages.RemovePage(pageName)
			onReturn()
			pp.app.SetFocus(pp.pages)
			return nil
		}
		return event
	})

	pp.pages.AddPage(pageName, form, false, true)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func deepCopyPattern(src correlation.BehaviorPattern) correlation.BehaviorPattern {
	dst := src
	dst.Processes = make([]correlation.ProcessPattern, len(src.Processes))
	for i, p := range src.Processes {
		pp2 := p
		pp2.Conditions = append([]correlation.Condition(nil), p.Conditions...)
		pp2.Events = append([]correlation.EventPattern(nil), p.Events...)
		dst.Processes[i] = pp2
	}
	dst.Relationships = append([]correlation.RelationshipPattern(nil), src.Relationships...)
	return dst
}
