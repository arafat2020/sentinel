package finding

import (
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestConsoleSinkImplementsSink(t *testing.T) {
	var _ Sink = (*ConsoleSink)(nil)
}

func TestFormatFindingShowsRolesAndEventCount(t *testing.T) {
	f := &core.Finding{
		Severity:    core.SeverityHigh,
		Rule:        "download-and-execute",
		Title:       "Dropped file executed",
		Description: "A process ran a file it had just written.",
		Evidence: core.Evidence{
			Roles: map[string]core.Process{
				"payload": {PID: 200, Name: "x"},
				"dropper": {PID: 100, Name: "sh"},
				"unnamed": {PID: 7},
			},
			Events: make([]core.Event, 3),
		},
	}

	got := FormatFinding(f)

	// Roles in name order, each as role=name(pid), then the event count.
	want := "[FINDING] severity=HIGH rule=download-and-execute title=Dropped file executed " +
		"description=A process ran a file it had just written. " +
		"roles=[dropper=sh(100) payload=x(200) unnamed=?(7)] events=3"
	if got != want {
		t.Errorf("FormatFinding:\n got %s\nwant %s", got, want)
	}
}

func TestFormatFindingWithoutEvidenceIsUnchanged(t *testing.T) {
	f := &core.Finding{Severity: core.SeverityInfo, Rule: "r", Title: "t", Description: "d"}

	if got, want := FormatFinding(f), "[FINDING] severity=INFO rule=r title=t description=d"; got != want {
		t.Errorf("FormatFinding = %q, want %q", got, want)
	}
	if got := FormatRoles(core.Evidence{}); got != "" {
		t.Errorf("FormatRoles of empty evidence = %q", got)
	}

	// A nil finding is still ignored.
	NewConsoleSink().Handle(nil)
}
