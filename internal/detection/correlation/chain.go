package correlation

import "github.com/arafat2020/sentinel/internal/core"

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

func (c *Chain) Add(event core.Event) bool {
	if event.Process == nil {
		return false
	}

	if event.Process.Identity() != c.identity {
		return false
	}

	c.events = append(c.events, event)

	return true
}

func (c *Chain) Events() []core.Event {
	return c.events
}
