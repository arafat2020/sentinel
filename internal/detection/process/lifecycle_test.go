package process

import (
	"testing"
	"time"

	"github.com/arafatmannan/sentinel/internal/core"
)

func TestLifecycleDetector(t *testing.T) {
	detector := NewLifecycleDetector()

	firstSnapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:  100,
				Name: "launchd",
			},
			{
				PID:  200,
				Name: "node",
			},
		},
	}

	// First snapshot establishes baseline.
	events := detector.Detect(firstSnapshot)

	if len(events) != 0 {
		t.Fatalf(
			"expected no events on first snapshot, got %d",
			len(events),
		)
	}
}

func TestDetectPIDReuse(t *testing.T) {
	detector := NewLifecycleDetector()

	firstSnapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				StartTime: time.Unix(1000, 0),
				Name:      "node",
			},
		},
	}

	detector.Detect(firstSnapshot)

	secondSnapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				StartTime: time.Unix(2000, 0),
				Name:      "python",
			},
		},
	}

	events := detector.Detect(secondSnapshot)

	if len(events) != 2 {
		t.Fatalf(
			"expected 2 events, got %d",
			len(events),
		)
	}
}
