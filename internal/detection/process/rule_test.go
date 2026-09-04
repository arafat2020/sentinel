package process

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestSuspiciousChildProcessRule(t *testing.T) {
	parent := core.Process{
		PID:       100,
		PPID:      1,
		StartTime: time.Unix(1000, 0),
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "python",
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			parent,
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	rule := NewSuspiciousChildProcessRule()

	ctx := &RuleContext{
		Tree: tree,
	}

	finding := rule.Evaluate(ctx, child.Identity())

	if finding == nil {
		t.Fatal("expected finding")
	}

	if finding.Rule != "suspicious-child-process" {
		t.Fatalf("unexpected rule: %s", finding.Rule)
	}

	if finding.Severity != core.SeverityHigh {
		t.Fatalf(
			"expected severity %s, got %s",
			core.SeverityHigh,
			finding.Severity,
		)
	}

	if finding.Evidence.Process == nil {
		t.Fatal("expected child process evidence")
	}

	if finding.Evidence.Process.Identity() != child.Identity() {
		t.Fatal("expected child process in evidence")
	}

	if len(finding.Evidence.Processes) != 2 {
		t.Fatalf(
			"expected 2 evidence processes, got %d",
			len(finding.Evidence.Processes),
		)
	}
}

func TestSuspiciousChildProcessRuleIgnoresNormalProcess(t *testing.T) {
	parent := core.Process{
		PID:       100,
		PPID:      1,
		StartTime: time.Unix(1000, 0),
		Name:      "launchd",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: time.Unix(2000, 0),
		Name:      "Terminal",
	}

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			parent,
			child,
		},
	}

	tree := NewProcessTree(snapshot)

	rule := NewSuspiciousChildProcessRule()

	ctx := &RuleContext{
		Tree: tree,
	}

	finding := rule.Evaluate(ctx, child.Identity())

	if finding != nil {
		t.Fatal("expected no finding for normal process relationship")
	}
}
