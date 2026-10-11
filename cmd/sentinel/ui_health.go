package main

import (
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// healthView is the Health tab: a report fetched when it is drawn, so it is
// current whenever it is on screen and costs nothing when it is not, and
// laid out for the width it is drawn at.
type healthView struct {
	*tview.TextView
	// report produces the report. text is the older, plain form, used when
	// no report is set.
	report func() healthReport
	text   func() string

	shown  string
	asOf   time.Time
	maxAge time.Duration
	width  int
	latest healthReport
	have   bool
}

func newHealthView() *healthView {
	view := &healthView{TextView: tview.NewTextView(), maxAge: time.Second}
	view.SetBorder(true).SetTitle(" Health ").SetTitleAlign(tview.AlignLeft)
	view.SetScrollable(true).SetWrap(false).SetDynamicColors(true)
	view.SetText("Collector health is not available.")
	return view
}

// Draw refreshes the report first, at most once per maxAge: the screen can
// be redrawn many times a second, and the report takes a lock on the
// correlation engine. A change of width lays the same report out again.
func (h *healthView) Draw(screen tcell.Screen) {
	_, _, width, _ := h.GetInnerRect()
	stale := time.Since(h.asOf) >= h.maxAge

	switch {
	case h.report != nil:
		if stale || !h.have {
			h.latest, h.have = h.report(), true
			h.asOf = time.Now()
		}
		if stale || width != h.width {
			h.show(strings.Join(layoutHealth(h.latest, width, colourHealth), "\n"))
		}

	case h.text != nil && stale:
		h.show(tview.Escape(h.text()))
		h.asOf = time.Now()
	}
	h.width = width

	h.TextView.Draw(screen)
}

func (h *healthView) show(text string) {
	if text != h.shown {
		h.shown = text
		h.SetText(text)
	}
}

// colourHealth gives each piece of the report its colour: section titles
// stand out, labels and zeros recede, values that mean loss are red.
func colourHealth(text, kind string) string {
	escaped := tview.Escape(text)

	switch kind {
	case "alert", "bad":
		return "[red::b]" + escaped + "[-::-]"
	case "title":
		return "[yellow::b]" + escaped + "[-::-]"
	case "label", "zero":
		return "[gray]" + escaped + "[-]"
	case "value":
		return "[white::b]" + escaped + "[-::-]"
	default:
		return escaped
	}
}
