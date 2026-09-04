package core

import (
	"testing"
	"time"
)

func TestEvidenceContainsProcess(t *testing.T) {
	process := Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "python",
	}

	evidence := Evidence{
		Process: &process,
	}

	if evidence.Process == nil {
		t.Fatal("expected evidence to contain process")
	}

	if evidence.Process.Identity() != process.Identity() {
		t.Fatal("expected evidence to reference the correct process")
	}
}

func TestEvidenceContainsMultipleProcesses(t *testing.T) {
	parent := Process{
		PID:  100,
		Name: "node",
	}

	child := Process{
		PID:  200,
		PPID: 100,
		Name: "python",
	}

	evidence := Evidence{
		Processes: []Process{
			parent,
			child,
		},
	}

	if len(evidence.Processes) != 2 {
		t.Fatalf(
			"expected 2 processes, got %d",
			len(evidence.Processes),
		)
	}

	if evidence.Processes[0].PID != parent.PID {
		t.Fatalf("expected parent PID %d", parent.PID)
	}

	if evidence.Processes[1].PID != child.PID {
		t.Fatalf("expected child PID %d", child.PID)
	}
}
