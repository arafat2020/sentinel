package monitor

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

// ProcessEventSource is an event-driven process collector: it reports each
// process start, exec and exit as it happens, instead of being polled.
type ProcessEventSource interface {
	Run(ctx context.Context, seed []core.Process, emit func(core.Event)) error
}

// ProcessEventMonitor publishes an event-driven collector's events on the
// bus. It is the counterpart of ProcessMonitor, which polls.
type ProcessEventMonitor struct {
	source ProcessEventSource
	bus    *eventbus.Bus
}

func NewProcessEventMonitor(source ProcessEventSource, bus *eventbus.Bus) *ProcessEventMonitor {
	return &ProcessEventMonitor{source: source, bus: bus}
}

// Run blocks until ctx is cancelled or the collector fails. seed is the set
// of processes that were already running.
//
// Publishing waits when the bus is full. That holds the collector's reader
// back, so the backlog builds up in the collector's kernel buffer, which is
// sized for it and counts what it cannot hold.
func (m *ProcessEventMonitor) Run(ctx context.Context, seed []core.Process) error {
	return m.source.Run(ctx, seed, func(event core.Event) {
		m.bus.Publish(event)
	})
}
