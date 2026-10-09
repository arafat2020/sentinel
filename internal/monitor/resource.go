package monitor

import (
	"context"

	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// ResourceMonitor polls resource usage and hands each snapshot straight to a
// handler. Unlike the other monitors it does not use the event bus: samples
// are high-volume display data, not security events.
type ResourceMonitor struct {
	collector ResourceCollector
	interval  time.Duration
	handler   func(*core.ResourceSnapshot)
}

type ResourceCollector interface {
	Collect(context.Context) (*core.ResourceSnapshot, error)
}

// NewResourceMonitor returns a monitor that calls handler from its own
// goroutine, one snapshot at a time. A slow handler delays the next sample
// rather than queueing work.
func NewResourceMonitor(
	collector ResourceCollector,
	interval time.Duration,
	handler func(*core.ResourceSnapshot),
) *ResourceMonitor {
	return &ResourceMonitor{
		collector: collector,
		interval:  interval,
		handler:   handler,
	}
}

func (m *ResourceMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)

	defer ticker.Stop()

	m.collect(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.collect(ctx)
		}
	}
}

func (m *ResourceMonitor) collect(ctx context.Context) {
	snapshot, err := m.collector.Collect(ctx)
	if err != nil || ctx.Err() != nil {
		return
	}

	m.handler(snapshot)
}
