package main

import (
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
	view.SetScrollable(true).SetWrap(true)
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
			h.SetText(text)
		}
		h.asOf = time.Now()
	}

	h.TextView.Draw(screen)
}
