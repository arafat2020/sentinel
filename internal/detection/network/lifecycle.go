package network

import (
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type LifecycleDetector struct {
	previous    map[core.NetworkConnectionIdentity]core.NetworkConnection
	initialized bool
}

func NewLifecycleDetector() *LifecycleDetector {
	return &LifecycleDetector{
		previous: make(
			map[core.NetworkConnectionIdentity]core.NetworkConnection,
		),
	}
}

func (d *LifecycleDetector) Detect(
	current []core.NetworkConnection,
) []core.Event {
	currentConnections := make(
		map[core.NetworkConnectionIdentity]core.NetworkConnection,
	)

	for _, connection := range current {
		currentConnections[connection.Identity()] = connection
	}

	if !d.initialized {
		d.previous = currentConnections
		d.initialized = true
		return nil
	}

	events := make([]core.Event, 0)

	for identity, connection := range currentConnections {
		if _, exists := d.previous[identity]; !exists {
			c := connection

			events = append(events, core.Event{
				Timestamp: time.Now(),
				Type:      core.EventNetworkConnect,
				Process:   c.Process,
				Network:   &c,
			})
		}
	}

	for identity, connection := range d.previous {
		if _, exists := currentConnections[identity]; !exists {
			c := connection

			events = append(events, core.Event{
				Timestamp: time.Now(),
				Type:      core.EventNetworkClose,
				Process:   c.Process,
				Network:   &c,
			})
		}
	}

	d.previous = currentConnections

	return events
}
