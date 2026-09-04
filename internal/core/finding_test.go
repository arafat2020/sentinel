package core

import (
	"testing"
	"time"
)

func TestFindingContainsEvidence(t *testing.T) {
	process := Process{
		PID:  200,
		PPID: 100,
		Name: "python",
	}

	finding := Finding{
		ID:          "finding-1",
		Timestamp:   time.Now(),
		Severity:    SeverityHigh,
		Rule:        "suspicious-child-process",
		Title:       "Suspicious child process",
		Description: "python was spawned by node",
		Evidence: Evidence{
			Process: &process,
		},
	}

	if finding.Evidence.Process == nil {
		t.Fatal("expected finding to contain evidence")
	}

	if finding.Severity != SeverityHigh {
		t.Fatalf(
			"expected severity %s, got %s",
			SeverityHigh,
			finding.Severity,
		)
	}

	if finding.Rule != "suspicious-child-process" {
		t.Fatalf("unexpected rule: %s", finding.Rule)
	}
}
