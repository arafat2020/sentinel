package main

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/arafat2020/sentinel/internal/config"
)

// yamlEditor is a full-screen YAML editor with the problems found in the
// text shown beneath it. It is used for one pattern and for the list of
// exclusions; what "save" means is up to whoever opened it.
type yamlEditor struct {
	root   *tview.Flex
	area   *tview.TextArea
	errors *tview.TextView
	hint   *tview.TextView

	original string
	// save checks and stores the text. It returns what is wrong with it;
	// with nothing wrong, the text has been saved.
	save func(text string) []config.EditError
	// done is called when the editor should close.
	done func(saved bool)
	// discard is set after one Esc with unsaved changes; a second closes.
	discard bool
}

const yamlEditorHint = " [Ctrl+S] Check and save  [Esc] Close  [Ctrl+K] Delete to end of line"

// newYAMLEditor builds an editor. notice, if not empty, is shown straight
// away, for example to say that the file cannot be written.
func newYAMLEditor(title, text, notice string, save func(string) []config.EditError, done func(saved bool)) *yamlEditor {
	e := &yamlEditor{original: text, save: save, done: done}

	e.area = tview.NewTextArea().SetWrap(false)
	e.area.SetText(text, false)
	e.area.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)

	e.errors = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true)
	e.errors.SetBorder(true).SetTitleAlign(tview.AlignLeft)

	e.hint = tview.NewTextView().SetText(yamlEditorHint)
	e.hint.SetBackgroundColor(tcell.ColorDarkBlue)

	e.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(e.area, 0, 1, true).
		AddItem(e.errors, 0, 0, false).
		AddItem(e.hint, 1, 0, false)

	if notice != "" {
		e.show(" Cannot save ", []string{notice})
	}

	e.area.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlS:
			e.trySave()
			return nil
		case tcell.KeyEscape:
			e.tryClose()
			return nil
		}
		e.discard = false
		return event
	})

	return e
}

// show puts lines in the panel under the editor, or hides it for none.
func (e *yamlEditor) show(title string, lines []string) {
	if len(lines) == 0 {
		e.errors.SetText("")
		e.root.ResizeItem(e.errors, 0, 0)
		return
	}

	e.errors.SetTitle(title)
	e.errors.SetText(strings.Join(lines, "\n"))
	e.errors.ScrollToBeginning()

	// Room for the lines as they will wrap, up to eight rows and the
	// border; the rest scroll. The editor keeps half of an 80x25 screen.
	_, _, width, _ := e.root.GetInnerRect()
	if width < 20 {
		width = 80
	}
	height := 0
	for _, line := range lines {
		height += 1 + tview.TaggedStringWidth(line)/(width-2)
	}
	if height > 8 {
		height = 8
	}
	e.root.ResizeItem(e.errors, height+2, 0)
}

func (e *yamlEditor) trySave() {
	problems := e.save(e.area.GetText())
	if len(problems) == 0 {
		e.done(true)
		return
	}

	lines := make([]string, len(problems))
	for i, problem := range problems {
		lines[i] = " [red]✗[-] " + tview.Escape(problem.String())
	}
	title := fmt.Sprintf(" %d problem(s) — nothing was saved ", len(problems))
	e.show(title, lines)

	// Put the cursor on the first problem that has a line.
	for _, problem := range problems {
		if problem.Line > 0 {
			e.gotoLine(problem.Line)
			break
		}
	}
}

// gotoLine moves the cursor to the start of a 1-based line.
func (e *yamlEditor) gotoLine(line int) {
	text := e.area.GetText()
	offset := 0
	for current := 1; current < line; current++ {
		next := strings.IndexByte(text[offset:], '\n')
		if next < 0 {
			break
		}
		offset += next + 1
	}
	e.area.Select(offset, offset)
}

func (e *yamlEditor) tryClose() {
	if e.area.GetText() != e.original && !e.discard {
		e.discard = true
		e.show(" Unsaved changes ", []string{" Press [yellow]Esc[-] again to discard them, or [yellow]Ctrl+S[-] to save."})
		return
	}
	e.done(false)
}
