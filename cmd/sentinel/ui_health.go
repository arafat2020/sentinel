package main

import (
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// healthView is the Health tab: read-only text that is fetched when it is
// drawn, so it is current whenever it is on screen and costs nothing when it
// is not.
type healthView struct {
	*tview.TextView
	text func() string

	shown  string
	asOf   time.Time
	maxAge time.Duration
}

func newHealthView() *healthView {
	view := &healthView{TextView: tview.NewTextView(), maxAge: time.Second}
	view.SetBorder(true).SetTitle(" Health ").SetTitleAlign(tview.AlignLeft)
	view.SetScrollable(true).SetWrap(true).SetDynamicColors(true)
	view.SetText("Collector health is not available.")
	return view
}

// Draw refreshes the text first, at most once per maxAge: the screen can be
// redrawn many times a second, and the report takes a lock on the
// correlation engine.
func (h *healthView) Draw(screen tcell.Screen) {
	if h.text != nil && time.Since(h.asOf) >= h.maxAge {
		if text := h.text(); text != h.shown {
			h.shown = text
			h.SetText(colourHealth(text))
		}
		h.asOf = time.Now()
	}

	h.TextView.Draw(screen)
}

// colourHealth prepares a health report for a view with colour: the line
// that lists what needs attention, and each pattern error, in red.
func colourHealth(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		escaped := tview.Escape(line)
		if strings.HasPrefix(line, alertPrefix) || strings.HasPrefix(line, "  ✗ ") {
			escaped = "[red::b]" + escaped + "[-::-]"
		}
		lines[i] = escaped
	}
	return strings.Join(lines, "\n")
}
