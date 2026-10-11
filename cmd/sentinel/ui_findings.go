package main

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// FindingsPage is the Findings tab: a list of findings, and for the selected
// one a detail view, its JSON, and a form to exclude it from now on. Each of
// those is a page of its own, so that all of them fit an 80x25 terminal.
type FindingsPage struct {
	app      *tview.Application
	model    *findingsModel
	patterns *patternStore // nil in tests that do not need exclusions
	// copyText puts text on the clipboard, where the terminal allows.
	copyText func(string)

	pages  *tview.Pages
	root   *tview.Flex
	table  *tview.Table
	bar    *tview.TextView
	hint   *tview.TextView
	detail *tview.TextView

	rows []findingItem // what the table shows
	// open is the key of the finding in the detail view.
	open string
	// message is shown once in the bar: the result of the last action.
	message string
	// width is the table width the columns were last laid out for.
	width int
}

// Resized lays the list out again if the terminal's width has changed since
// the columns were sized.
func (fp *FindingsPage) Resized() {
	if _, _, width, _ := fp.table.GetInnerRect(); width > 0 && width != fp.width {
		fp.Refresh()
	}
}

const (
	findingsListHint   = " [Enter] Details [A]ck [D]ismiss [N]ew E[x]clude | [S]ev s[T]atus [R]ule [O]rder"
	findingsDetailHint = " [A]ck [D]ismiss [N]ew [C]opy JSON E[x]clude… [↑/↓] Scroll [Esc] Back to list"
)

func NewFindingsPage(app *tview.Application, model *findingsModel, patterns *patternStore) *FindingsPage {
	fp := &FindingsPage{app: app, model: model, patterns: patterns, copyText: func(string) {}}

	fp.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	fp.table.SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorDarkBlue).Foreground(tcell.ColorWhite))
	fp.table.SetInputCapture(fp.listKeys)

	fp.bar = tview.NewTextView().SetDynamicColors(true)
	// Hints are plain text: with colour tags on, "[A]" would be read as one.
	fp.hint = tview.NewTextView().SetText(findingsListHint)
	fp.hint.SetBackgroundColor(tcell.ColorDarkBlue)

	list := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(fp.bar, 1, 0, false).
		AddItem(fp.table, 0, 1, true).
		AddItem(fp.hint, 1, 0, false)

	fp.detail = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true).SetWordWrap(false)
	fp.detail.SetBorder(true).SetTitle(" Finding ").SetTitleAlign(tview.AlignLeft)
	fp.detail.SetInputCapture(fp.detailKeys)

	detailHint := tview.NewTextView().SetText(findingsDetailHint)
	detailHint.SetBackgroundColor(tcell.ColorDarkBlue)
	detail := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(fp.detail, 0, 1, true).
		AddItem(detailHint, 1, 0, false)

	fp.pages = tview.NewPages()
	fp.pages.AddPage("list", list, true, true)
	fp.pages.AddPage("detail", detail, true, false)

	fp.root = tview.NewFlex().AddItem(fp.pages, 0, 1, true)
	fp.Refresh()

	return fp
}

func (fp *FindingsPage) Root() tview.Primitive { return fp.root }

// severityColor is how a severity is coloured in the list and the detail.
func severityColor(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical:
		return "red"
	case core.SeverityHigh:
		return "orange"
	case core.SeverityMedium:
		return "yellow"
	case core.SeverityLow:
		return "blue"
	default:
		return "gray"
	}
}

// shortStatus is a status as the list shows it, where width is scarce.
func shortStatus(status core.FindingStatus) string {
	if status == core.StatusAcknowledged {
		return "ack"
	}
	return string(status)
}

func statusColor(status core.FindingStatus) string {
	switch status {
	case core.StatusNew:
		return "white"
	case core.StatusAcknowledged:
		return "green"
	default:
		return "gray"
	}
}

// Refresh redraws the list from the model, keeping the selection on the same
// finding where it still shows. It must be called on the event loop.
func (fp *FindingsPage) Refresh() {
	selected := fp.selectedKey()
	fp.rows = fp.model.Visible()

	// Six columns have to fit the terminal, or the table drops the last
	// ones. Time, severity and status have fixed widths; rule and process
	// are capped; the title takes what is left and is cut to it.
	const timeWidth, severityWidth, ruleWidth, processWidth, statusWidth = 14, 8, 20, 12, 9
	_, _, width, _ := fp.table.GetInnerRect()
	if width <= 0 {
		width = 80 // not drawn yet
	}
	fp.width = width
	titleWidth := width - (timeWidth + severityWidth + ruleWidth + processWidth + statusWidth) - 5
	if titleWidth < 8 {
		titleWidth = 8
	}

	fp.table.Clear()
	for column, title := range []string{"TIME", "SEVERITY", "RULE", "TITLE", "PROCESS", "STATUS"} {
		cell := tview.NewTableCell(title).SetSelectable(false).SetTextColor(tcell.ColorYellow)
		if column == 3 {
			cell.SetExpansion(1).SetMaxWidth(titleWidth)
		}
		fp.table.SetCell(0, column, cell)
	}

	keep := 1
	for i, item := range fp.rows {
		row := rowOf(item)
		dim := item.Status == core.StatusDismissed

		text := func(value string, max int) *tview.TableCell {
			cell := tview.NewTableCell(tview.Escape(value)).SetMaxWidth(max)
			if dim {
				cell.SetTextColor(tcell.ColorGray)
			}
			return cell
		}

		fp.table.SetCell(i+1, 0, text(row.Time, timeWidth))
		fp.table.SetCell(i+1, 1, tview.NewTableCell("["+severityColor(item.Finding.Severity)+"]"+row.Severity+"[-]"))
		fp.table.SetCell(i+1, 2, text(row.Rule, ruleWidth))
		fp.table.SetCell(i+1, 3, text(row.Title, titleWidth).SetExpansion(1))
		fp.table.SetCell(i+1, 4, text(row.Process, processWidth))
		fp.table.SetCell(i+1, 5, tview.NewTableCell("["+statusColor(item.Status)+"]"+shortStatus(item.Status)+"[-]"))

		if item.Key == selected {
			keep = i + 1
		}
	}

	if len(fp.rows) > 0 {
		fp.table.Select(keep, 0)
	}

	total, unhandled := fp.model.Counts()
	bar := fmt.Sprintf(" [yellow]%d/%d shown[-], %d new  %s", len(fp.rows), total, unhandled, fp.model.Filter())
	if fp.message != "" {
		bar = " [green]" + tview.Escape(fp.message) + "[-]"
	}
	fp.bar.SetText(bar)

	if fp.open != "" {
		fp.renderDetail()
	}
}

func (fp *FindingsPage) selectedKey() string {
	row, _ := fp.table.GetSelection()
	if row >= 1 && row <= len(fp.rows) {
		return fp.rows[row-1].Key
	}
	return ""
}

func (fp *FindingsPage) listKeys(event *tcell.EventKey) *tcell.EventKey {
	// The result of the last action stays on screen until the next key.
	fp.message = ""

	if event.Key() == tcell.KeyEnter {
		fp.openDetail(fp.selectedKey())
		return nil
	}
	if event.Key() != tcell.KeyRune {
		return event
	}

	filter := fp.model.Filter()

	switch event.Rune() {
	case 's', 'S':
		filter.Severity = next(filterSeverities, filter.Severity)
	case 't', 'T':
		filter.Status = next(filterStatuses, filter.Status)
	case 'r', 'R':
		filter.Rule = next(append([]string{""}, fp.model.Rules()...), filter.Rule)
	case 'o', 'O':
		filter.OldestFirst = !filter.OldestFirst
	case 'a', 'A':
		fp.setStatus(fp.selectedKey(), core.StatusAcknowledged)
		return nil
	case 'd', 'D':
		fp.setStatus(fp.selectedKey(), core.StatusDismissed)
		return nil
	case 'n', 'N':
		fp.setStatus(fp.selectedKey(), core.StatusNew)
		return nil
	case 'x', 'X':
		fp.openExclude(fp.selectedKey())
		return nil
	case 'c', 'C':
		fp.openJSON(fp.selectedKey())
		return nil
	default:
		return event
	}

	fp.model.SetFilter(filter)
	fp.Refresh()
	return nil
}

func (fp *FindingsPage) setStatus(key string, status core.FindingStatus) {
	if key == "" {
		return
	}
	if err := fp.model.SetStatus(key, status); err != nil {
		fp.message = "Status not saved: " + err.Error()
	}
	fp.Refresh()
}

// --- Detail ---------------------------------------------------------------

func (fp *FindingsPage) loadedPatterns() []correlation.BehaviorPattern {
	if fp.patterns == nil {
		return nil
	}
	return fp.patterns.State().Patterns
}

func (fp *FindingsPage) openDetail(key string) {
	if _, ok := fp.model.Get(key); !ok {
		return
	}
	fp.open = key
	fp.renderDetail()
	fp.detail.ScrollToBeginning()
	fp.pages.SwitchToPage("detail")
	fp.app.SetFocus(fp.detail)
}

func (fp *FindingsPage) renderDetail() {
	item, ok := fp.model.Get(fp.open)
	if !ok {
		return
	}

	lines := detailLines(item, fp.loadedPatterns())
	for i, line := range lines {
		escaped := tview.Escape(line)
		switch {
		case i == 0:
			escaped = "[" + severityColor(item.Finding.Severity) + "::b]" + escaped + "[-::-]"
		case line == "ROLES" || strings.HasPrefix(line, "TIMELINE") || line == "CAPTURES":
			escaped = "[yellow]" + escaped + "[-]"
		}
		lines[i] = escaped
	}
	if fp.message != "" {
		lines = append([]string{"[green]" + tview.Escape(fp.message) + "[-]", ""}, lines...)
	}

	fp.detail.SetText(strings.Join(lines, "\n"))
}

func (fp *FindingsPage) closeDetail() {
	fp.open = ""
	fp.pages.SwitchToPage("list")
	fp.app.SetFocus(fp.table)
	fp.Refresh()
}

func (fp *FindingsPage) detailKeys(event *tcell.EventKey) *tcell.EventKey {
	fp.message = ""

	if event.Key() == tcell.KeyEscape {
		fp.closeDetail()
		return nil
	}
	if event.Key() != tcell.KeyRune {
		return event
	}

	switch event.Rune() {
	case 'a', 'A':
		fp.message = "Acknowledged."
		fp.setStatus(fp.open, core.StatusAcknowledged)
	case 'd', 'D':
		fp.message = "Dismissed."
		fp.setStatus(fp.open, core.StatusDismissed)
	case 'n', 'N':
		fp.message = "Marked new."
		fp.setStatus(fp.open, core.StatusNew)
	case 'c', 'C':
		fp.openJSON(fp.open)
	case 'x', 'X':
		fp.openExclude(fp.open)
	case 'q', 'Q':
		fp.closeDetail()
	default:
		return event
	}
	return nil
}

// back returns from a sub-page to the detail view if one is open, and
// otherwise to the list.
func (fp *FindingsPage) back(pagesToDrop ...string) {
	for _, page := range pagesToDrop {
		fp.pages.RemovePage(page)
	}
	if fp.open != "" {
		fp.renderDetail()
		fp.pages.SwitchToPage("detail")
		fp.app.SetFocus(fp.detail)
		return
	}
	fp.pages.SwitchToPage("list")
	fp.app.SetFocus(fp.table)
	fp.Refresh()
}

// --- JSON -----------------------------------------------------------------

func (fp *FindingsPage) openJSON(key string) {
	item, ok := fp.model.Get(key)
	if !ok {
		return
	}

	text := findingJSON(item)
	fp.copyText(text)

	view := tview.NewTextView().SetScrollable(true).SetWrap(false).SetText(text)
	view.SetBorder(true).SetTitleAlign(tview.AlignLeft).
		SetTitle(" Finding as JSON — sent to the clipboard, if your terminal allows it (OSC 52) ")
	view.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Rune() == 'q' {
			fp.back("json")
			return nil
		}
		return event
	})

	hint := tview.NewTextView().SetText("  [↑/↓] Scroll  [Esc] Back")
	hint.SetBackgroundColor(tcell.ColorDarkBlue)

	fp.pages.AddPage("json", tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(view, 0, 1, true).AddItem(hint, 1, 0, false), true, true)
	fp.app.SetFocus(view)
}

// --- Exclude ----------------------------------------------------------------

// What the "is" drop-down of a field offers, by mode.
var modeLabels = map[string]string{modeEq: "exactly", modePrefix: "starts with", modeContains: "contains"}

func (fp *FindingsPage) openExclude(key string) {
	item, ok := fp.model.Get(key)
	if !ok {
		return
	}

	roles := findingRoles(item.Finding)
	if len(roles) == 0 {
		fp.message = "This finding has no stored processes to build an exclusion from."
		fp.Refresh()
		return
	}
	if fp.patterns == nil {
		return
	}

	// Start from the process the rule leads up to: the last role listed is
	// usually it, and it is the finding's primary process.
	start := roles[0]
	if primary := roleOf(item.Finding, item.Finding.Evidence.Process); primary != "" {
		start = primary
	}

	fp.excludeForm(item, roles, start, false, "")
}

// excludeForm shows the exclusion form for one role. It is rebuilt when the
// role changes, because the fields on offer are those of that role's
// process.
func (fp *FindingsPage) excludeForm(item findingItem, roles []string, role string, allRules bool, description string) {
	draft, err := newExclusionDraft(item.Finding, role)
	if err != nil {
		fp.message = err.Error()
		fp.back("exclude")
		return
	}
	draft.AllRules = allRules
	draft.Description = description

	// One row per item, so that the whole form fits 25 rows.
	form := tview.NewForm().SetItemPadding(0)
	form.SetBorder(true).SetTitleAlign(tview.AlignLeft).
		SetTitle(fmt.Sprintf(" Exclude findings like this one — rule %s ", item.Finding.Rule))
	form.SetFieldBackgroundColor(tcell.ColorDarkBlue)

	roleIndex := 0
	for i, name := range roles {
		if name == role {
			roleIndex = i
		}
	}
	rebuilding := false
	form.AddDropDown("Process in role", roles, roleIndex, func(chosen string, _ int) {
		if chosen != "" && chosen != role && !rebuilding {
			rebuilding = true
			fp.excludeForm(item, roles, chosen, draft.AllRules, draft.Description)
		}
	})

	for i := range draft.Fields {
		field := &draft.Fields[i]

		modes := field.Modes()
		labels := make([]string, len(modes))
		current := 0
		for j, mode := range modes {
			labels[j] = modeLabels[mode]
			if mode == field.Mode {
				current = j
			}
		}

		form.AddCheckbox("Match "+field.Field, field.Keep, func(checked bool) { field.Keep = checked })

		value := tview.NewInputField().SetLabel("  value").SetText(field.Value).SetFieldWidth(0)
		value.SetChangedFunc(func(text string) { field.Value = text })

		if len(modes) > 1 {
			name := field.Field
			form.AddDropDown("  "+field.Field+" is", labels, current, func(_ string, index int) {
				if index < 0 || modes[index] == field.Mode {
					return
				}
				draft.SetMode(name, modes[index])
				value.SetText(field.Value)
			})
		}
		form.AddFormItem(value)
	}

	scopes := []string{fmt.Sprintf("this rule only (role %q of %s)", role, item.Finding.Rule), "all rules"}
	scope := 0
	if draft.AllRules {
		scope = 1
	}
	form.AddDropDown("Applies to", scopes, scope, func(_ string, index int) { draft.AllRules = index == 1 })
	form.AddInputField("Description", draft.Description, 0, nil, func(text string) { draft.Description = text })

	form.AddButton("Preview", func() { fp.previewExclusion(item, &draft) })
	form.AddButton("Cancel", func() { fp.back("exclude") })
	form.SetCancelFunc(func() { fp.back("exclude") })

	hint := tview.NewTextView().SetText("  [Tab] Next field  [Space] Tick  [Enter] Open list / press button  [Esc] Cancel")
	hint.SetBackgroundColor(tcell.ColorDarkBlue)

	fp.pages.AddPage("exclude", tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).AddItem(hint, 1, 0, false), true, true)
	fp.app.SetFocus(form)
}

// previewExclusion shows the exact YAML that will be added and asks before
// writing it.
func (fp *FindingsPage) previewExclusion(item findingItem, draft *exclusionDraft) {
	text := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	text.SetBorder(true).SetTitleAlign(tview.AlignLeft).SetTitle(" This will be added to the patterns file ")

	buttons := tview.NewForm()
	leave := func() {
		fp.pages.RemovePage("preview")
		fp.pages.SwitchToPage("exclude")
		fp.app.SetFocus(fp.pages)
	}

	problem := draft.Validate()
	if problem == nil {
		problem = fp.patterns.Writable()
	}

	if problem != nil {
		text.SetText("[red]" + tview.Escape(problem.Error()) + "[-]\n\n" + tview.Escape(draft.Preview()))
		buttons.AddButton("Back", leave)
	} else {
		text.SetText(tview.Escape(draft.Preview()))
		buttons.AddButton("Save exclusion", func() {
			if err := fp.patterns.AddExclusion(*draft); err != nil {
				text.SetText("[red]Not saved: " + tview.Escape(err.Error()) + "[-]\n\n" + tview.Escape(draft.Preview()))
				return
			}

			// It will not be reported again; this one is dealt with.
			_ = fp.model.SetStatus(item.Key, core.StatusDismissed)
			fp.message = "Exclusion saved and applied. This finding is dismissed."
			fp.pages.RemovePage("preview")
			fp.back("exclude")
		})
		buttons.AddButton("Back", leave)
	}
	buttons.SetCancelFunc(leave)

	fp.pages.AddPage("preview", tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(text, 0, 1, false).AddItem(buttons, 3, 0, true), true, true)
	fp.app.SetFocus(buttons)
}
