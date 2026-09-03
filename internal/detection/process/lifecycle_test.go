package process

import (
	"testing"

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
