package monitor

import (
	"context"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type NetworkCollector interface {
	Collect(context.Context) ([]core.NetworkConnection, error)
}

type NetworkDetector interface {
	Detect([]core.NetworkConnection) []core.Event
}

type NetworkMonitor struct {
	collector NetworkCollector
	detector  NetworkDetector
	interval  time.Duration
	bus       *eventbus.Bus
}

func NewNetworkMonitor(
	collector NetworkCollector,
	detector NetworkDetector,
	interval time.Duration,
	bus *eventbus.Bus,
) *NetworkMonitor {
	return &NetworkMonitor{
		collector: collector,
		detector:  detector,
		interval:  interval,
		bus:       bus,
	}
}

func (m *NetworkMonitor) collectAndDetect(ctx context.Context) {
	connections, err := m.collector.Collect(ctx)
	if err != nil {
		return
	}

	events := m.detector.Detect(connections)

	for _, event := range events {
		m.bus.Publish(event)
	}
}

func (m *NetworkMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	m.collectAndDetect(ctx)

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			m.collectAndDetect(ctx)
		}
	}
}
