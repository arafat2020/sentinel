package finding

import (
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeSink struct {
	findings []*core.Finding
}

func (f *fakeSink) Handle(finding *core.Finding) {
	f.findings = append(f.findings, finding)
}

func TestSinkReceivesFinding(t *testing.T) {
	sink := &fakeSink{}

	finding := &core.Finding{
		ID:       "finding-1",
		Severity: core.SeverityHigh,
		Rule:     "suspicious-child-process",
		Title:    "Suspicious child process",
	}

	sink.Handle(finding)

	if len(sink.findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(sink.findings),
		)
	}

	if sink.findings[0].ID != "finding-1" {
		t.Fatalf(
			"expected finding-1, got %s",
			sink.findings[0].ID,
		)
	}
}
