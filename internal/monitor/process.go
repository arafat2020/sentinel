package monitor

import (
	"context"

	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type ProcessMonitor struct {
	collector   ProcessCollector
	detector    ProcessDetector
	interval    time.Duration
	bus         *eventbus.Bus
	coordinator ProcessCoordinator
}

type ProcessCoordinator interface {
	UpdateSnapshot(*core.ProcessSnapshot)
}

type ProcessCollector interface {
	Collect(context.Context) (*core.ProcessSnapshot, error)
}

type ProcessDetector interface {
	Detect(*core.ProcessSnapshot) []core.Event
}

func NewProcessMonitor(
	collector ProcessCollector,
	detector ProcessDetector,
	interval time.Duration,
	bus *eventbus.Bus,
	coordinator ProcessCoordinator,
) *ProcessMonitor {
	return &ProcessMonitor{
		collector:   collector,
		detector:    detector,
		interval:    interval,
		bus:         bus,
		coordinator: coordinator,
	}
}

func (m *ProcessMonitor) Run(ctx context.Context) {
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

func (m *ProcessMonitor) collectAndDetect(ctx context.Context) {
	snapshot, err := m.collector.Collect(ctx)
	if err != nil {
		return
	}

	m.coordinator.UpdateSnapshot(snapshot)

	events := m.detector.Detect(snapshot)

	for _, event := range events {
		m.bus.Publish(event)
	}
}
