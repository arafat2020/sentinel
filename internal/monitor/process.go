package monitor

import (
	"context"
	"fmt"
	"time"

	processCollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/core"
	processDetector "github.com/arafat2020/sentinel/internal/detection/process"
)

type ProcessMonitor struct {
	collector *processCollector.Collector
	detector  *processDetector.LifecycleDetector
	interval  time.Duration
}

func NewProcessMonitor(collector *processCollector.Collector,
	detector *processDetector.LifecycleDetector,
	interval time.Duration) *ProcessMonitor {
	return &ProcessMonitor{
		collector: collector,
		detector:  detector,
		interval:  interval,
	}
}

func (m *ProcessMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)

	defer ticker.Stop()

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

	events := m.detector.Detect(snapshot)

	for _, event := range events {
		printEvent(event)
	}
}

func printEvent(event core.Event) {
	if event.Process == nil {
		return
	}

	fmt.Printf(
		"[%s] PID=%d NAME=%s EXE=%s\n",
		event.Type,
		event.Process.PID,
		event.Process.Name,
		event.Process.Executable,
	)
}
