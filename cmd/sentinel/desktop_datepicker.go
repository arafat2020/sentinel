package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// showDatePicker presents a calendar dialog and calls onPick with the chosen
// date/time string in "2006-01-02 15:04" format when the user presses Select.
// If initial is a parseable date/time, the calendar opens on that date.
func showDatePicker(parent fyne.Window, initial string, onPick func(string)) {
	now := time.Now()
	selected := now

	if initial != "" {
		if t, err := parseTime(strings.TrimSpace(initial)); err == nil {
			selected = t
		}
	}

	// viewing is always the 1st of the displayed month.
	viewing := time.Date(selected.Year(), selected.Month(), 1, 0, 0, 0, 0, time.Local)

	// ── time fields ───────────────────────────────────────────────────────────

	hourEntry := widget.NewEntry()
	hourEntry.SetText(fmt.Sprintf("%02d", selected.Hour()))
	hourEntry.Validator = func(s string) error {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 0 || n > 23 {
			return fmt.Errorf("must be 0–23")
		}
		return nil
	}

	minEntry := widget.NewEntry()
	minEntry.SetText(fmt.Sprintf("%02d", selected.Minute()))
	minEntry.Validator = func(s string) error {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 0 || n > 59 {
			return fmt.Errorf("must be 0–59")
		}
		return nil
	}

	// ── calendar grid ─────────────────────────────────────────────────────────

	monthLabel := widget.NewLabel("")
	monthLabel.TextStyle = fyne.TextStyle{Bold: true}
	monthLabel.Alignment = fyne.TextAlignCenter

	dayGrid := container.NewGridWithColumns(7)

	// rebuild redraws the day grid for the current viewing month.
	// All mutations happen on the Fyne event thread (button callbacks), so
	// no extra locking is needed here.
	var rebuild func()
	rebuild = func() {
		monthLabel.SetText(viewing.Format("January 2006"))

		dayGrid.Objects = nil

		// Day-of-week header row (Monday first)
		for _, h := range []string{"Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"} {
			l := widget.NewLabel(h)
			l.Alignment = fyne.TextAlignCenter
			l.TextStyle = fyne.TextStyle{Bold: true}
			l.Importance = widget.LowImportance
			dayGrid.Add(l)
		}

		// Weekday offset for the 1st: Mon=0 … Sun=6
		offset := int(viewing.Weekday()) - 1
		if offset < 0 {
			offset = 6
		}
		for i := 0; i < offset; i++ {
			dayGrid.Add(widget.NewLabel(""))
		}

		// Day buttons
		daysInMonth := daysIn(viewing.Year(), viewing.Month())
		today := time.Now()

		for d := 1; d <= daysInMonth; d++ {
			day := d // capture loop variable

			isSelected := selected.Year() == viewing.Year() &&
				selected.Month() == viewing.Month() &&
				selected.Day() == day

			isToday := today.Year() == viewing.Year() &&
				today.Month() == viewing.Month() &&
				today.Day() == day

			btn := widget.NewButton(fmt.Sprintf("%d", day), func() {
				selected = time.Date(
					viewing.Year(), viewing.Month(), day,
					selected.Hour(), selected.Minute(), 0, 0, time.Local,
				)
				rebuild()
			})

			switch {
			case isSelected:
				btn.Importance = widget.HighImportance
			case isToday:
				btn.Importance = widget.WarningImportance
			default:
				btn.Importance = widget.LowImportance
			}

			dayGrid.Add(btn)
		}

		dayGrid.Refresh()
	}

	rebuild()

	// ── navigation ────────────────────────────────────────────────────────────

	prevMonth := widget.NewButton("◀", func() {
		viewing = viewing.AddDate(0, -1, 0)
		rebuild()
	})
	nextMonth := widget.NewButton("▶", func() {
		viewing = viewing.AddDate(0, 1, 0)
		rebuild()
	})

	prevYear := widget.NewButton("《", func() {
		viewing = viewing.AddDate(-1, 0, 0)
		rebuild()
	})
	nextYear := widget.NewButton("》", func() {
		viewing = viewing.AddDate(1, 0, 0)
		rebuild()
	})

	nav := container.NewBorder(nil, nil,
		container.NewHBox(prevYear, prevMonth),
		container.NewHBox(nextMonth, nextYear),
		container.NewCenter(monthLabel),
	)

	// "Today" shortcut
	todayBtn := widget.NewButton("Today", func() {
		t := time.Now()
		selected = t
		viewing = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.Local)
		hourEntry.SetText(fmt.Sprintf("%02d", t.Hour()))
		minEntry.SetText(fmt.Sprintf("%02d", t.Minute()))
		rebuild()
	})
	todayBtn.Importance = widget.LowImportance

	// ── time row ──────────────────────────────────────────────────────────────

	hourEntry.Resize(fyne.NewSize(48, hourEntry.MinSize().Height))
	minEntry.Resize(fyne.NewSize(48, minEntry.MinSize().Height))

	timeRow := container.NewHBox(
		widget.NewLabel("Time (HH:MM):"),
		hourEntry,
		widget.NewLabel(":"),
		minEntry,
		widget.NewLabel("     "),
		todayBtn,
	)

	// ── assemble ──────────────────────────────────────────────────────────────

	content := container.NewVBox(
		nav,
		dayGrid,
		widget.NewSeparator(),
		container.NewPadded(timeRow),
	)

	dialog.ShowCustomConfirm("Pick Date & Time", "Select", "Cancel", content,
		func(ok bool) {
			if !ok {
				return
			}
			h, m := 0, 0
			fmt.Sscanf(strings.TrimSpace(hourEntry.Text), "%d", &h)
			fmt.Sscanf(strings.TrimSpace(minEntry.Text), "%d", &m)
			h = clamp(h, 0, 23)
			m = clamp(m, 0, 59)
			result := time.Date(
				selected.Year(), selected.Month(), selected.Day(),
				h, m, 0, 0, time.Local,
			)
			onPick(result.Format("2006-01-02 15:04"))
		}, parent)
}

// daysIn returns the number of days in the given month/year.
func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.Local).Day()
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
