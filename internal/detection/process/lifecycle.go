package process

import (
	"time"

	"github.com/arafatmannan/sentinel/internal/core"
)

type LifecycleDetector struct {
	previous    map[int32]core.Process
	initialized bool
}

func NewLifecycleDetector() *LifecycleDetector {
	return &LifecycleDetector{
		previous: make(map[int32]core.Process),
	}
}

func (d *LifecycleDetector) Detect(
	current *core.ProcessSnapshot,
) []core.Event {
	currentProcesses := make(map[int32]core.Process)

	// Build the current process state.
	for _, process := range current.Processes {
		currentProcesses[process.PID] = process
	}

	// First snapshot establishes the baseline.
	if !d.initialized {
		d.previous = currentProcesses
		d.initialized = true

		return nil
	}

	events := make([]core.Event, 0)

	// Detect new processes.
	for pid, process := range currentProcesses {
		if _, exists := d.previous[pid]; !exists {
			p := process

			events = append(events, core.Event{
				Timestamp: time.Now(),
				Type:      core.EventProcessStart,
				Process:   &p,
			})
		}
	}

	// Detect exited processes.
	for pid, process := range d.previous {
		if _, exists := currentProcesses[pid]; !exists {
			p := process

			events = append(events, core.Event{
				Timestamp: time.Now(),
				Type:      core.EventProcessExit,
				Process:   &p,
			})
		}
	}

	// Current state becomes previous state.
	d.previous = currentProcesses

	return events
}
