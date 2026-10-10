package correlation

import (
	"sort"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// MaxEventsPerType is the most events of any one type a chain retains. When
// a process produces more, the oldest of that type are discarded. The cap is
// per type so that a flood of one kind of event cannot push out a rare event
// of another kind that a pattern is waiting for.
const MaxEventsPerType = 64

// Chain is the bounded, time-ordered sequence of events for one process.
// Events are sorted by timestamp; events with equal timestamps stay in the
// order they were added.
type Chain struct {
	identity core.ProcessIdentity
	events   []core.Event
}

func NewChain(event core.Event) *Chain {
	var identity core.ProcessIdentity

	if event.Process != nil {
		identity = event.Process.Identity()
	}

	return &Chain{
		identity: identity,
		events:   []core.Event{event},
	}
}

// Add inserts event at its place in time order and reports whether it
// belongs to this chain's process.
func (c *Chain) Add(event core.Event) bool {
	if event.Process == nil {
		return false
	}

	if event.Process.Identity() != c.identity {
		return false
	}

	// First position holding a strictly later event: equal timestamps stay
	// in arrival order, and the usual in-order event is a plain append.
	at := sort.Search(len(c.events), func(i int) bool {
		return c.events[i].Timestamp.After(event.Timestamp)
	})

	c.events = append(c.events, core.Event{})
	copy(c.events[at+1:], c.events[at:])
	c.events[at] = event

	c.enforceTypeCap(event.Type)

	return true
}

// enforceTypeCap drops the oldest event of the given type while the chain
// holds more than MaxEventsPerType of them.
func (c *Chain) enforceTypeCap(eventType core.EventType) {
	count := 0
	for _, event := range c.events {
		if event.Type == eventType {
			count++
		}
	}

	for i := 0; count > MaxEventsPerType && i < len(c.events); {
		if c.events[i].Type != eventType {
			i++
			continue
		}
		c.events = append(c.events[:i], c.events[i+1:]...)
		count--
	}
}

func (c *Chain) Events() []core.Event {
	return c.events
}

// EventsAfter returns the events whose timestamp is strictly after cutoff,
// oldest first.
func (c *Chain) EventsAfter(cutoff time.Time) []core.Event {
	return c.events[c.firstAfter(cutoff):]
}

// Prune discards every event whose timestamp is not after cutoff and returns
// how many events remain.
func (c *Chain) Prune(cutoff time.Time) int {
	first := c.firstAfter(cutoff)
	if first > 0 {
		// Copy down so the discarded events can be collected.
		n := copy(c.events, c.events[first:])
		clear(c.events[n:])
		c.events = c.events[:n]
	}

	return len(c.events)
}

func (c *Chain) firstAfter(cutoff time.Time) int {
	return sort.Search(len(c.events), func(i int) bool {
		return c.events[i].Timestamp.After(cutoff)
	})
}
