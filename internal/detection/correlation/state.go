package correlation

import (
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type State struct {
	events map[core.ProcessIdentity][]core.Event
	window time.Duration
}

func NewState() *State {
	return NewStateWithWindow(30 * time.Second)
}

func NewStateWithWindow(window time.Duration) *State {
	return &State{
		events: make(map[core.ProcessIdentity][]core.Event),
		window: window,
	}
}

func (s *State) Add(event core.Event) {
	if event.Process == nil {
		return
	}

	identity := event.Process.Identity()

	s.events[identity] = append(
		s.events[identity],
		event,
	)
}

func (s *State) EventsForProcess(
	identity core.ProcessIdentity,
) []core.Event {
	return s.EventsForProcessAt(identity, time.Now())
}

func (s *State) EventsForProcessAt(
	identity core.ProcessIdentity,
	now time.Time,
) []core.Event {
	events := s.events[identity]

	if len(events) == 0 {
		return nil
	}

	cutoff := now.Add(-s.window)

	firstValid := 0

	for firstValid < len(events) &&
		events[firstValid].Timestamp.Before(cutoff) {
		firstValid++
	}

	if firstValid == len(events) {
		delete(s.events, identity)
		return nil
	}

	events = events[firstValid:]
	s.events[identity] = events

	return events
}
