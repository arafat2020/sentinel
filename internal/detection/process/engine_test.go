package process

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type trackingRule struct {
	evaluated int
}

type contextRule struct {
	received bool
}

func (r *contextRule) Evaluate(
	ctx *RuleContext,
	identity core.ProcessIdentity,
) *core.Finding {
	r.received = ctx != nil && ctx.Tree != nil
	return nil
}

func (r *trackingRule) Evaluate(
	ctx *RuleContext,
	identity core.ProcessIdentity,
) *core.Finding {
	r.evaluated++
	return nil
}

func TestEngineProvidesRuleContext(t *testing.T) {
	registry := NewRegistry()

	rule := &contextRule{}
	registry.Register(rule)

	engine := NewEngine(registry)

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				PPID:      1,
				StartTime: unixTime(1000),
				Name:      "node",
			},
		},
	}

	tree := NewProcessTree(snapshot)

	engine.Evaluate(tree)

	if !rule.received {
		t.Fatal("expected rule to receive context")
	}
}

func TestEngineEvaluatesRegisteredRules(t *testing.T) {
	registry := NewRegistry()

	rule := &trackingRule{}
	registry.Register(rule)

	engine := NewEngine(registry)

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				PPID:      1,
				StartTime: unixTime(1000),
				Name:      "node",
			},
			{
				PID:       200,
				PPID:      100,
				StartTime: unixTime(2000),
				Name:      "python",
			},
		},
	}

	tree := NewProcessTree(snapshot)

	engine.Evaluate(tree)

	if rule.evaluated != 2 {
		t.Fatalf(
			"expected rule to be evaluated 2 times, got %d",
			rule.evaluated,
		)
	}
}

func unixTime(seconds int64) time.Time {
	return time.Unix(seconds, 0)
}

type findingRule struct{}

func (r *findingRule) Evaluate(
	ctx *RuleContext,
	identity core.ProcessIdentity,
) *core.Finding {
	return &core.Finding{
		Rule:     "test-rule",
		Severity: core.SeverityLow,
		Title:    "Test finding",
	}
}

func TestEngineReturnsFindings(t *testing.T) {
	registry := NewRegistry()

	rule := &findingRule{}
	registry.Register(rule)

	engine := NewEngine(registry)

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				PPID:      1,
				StartTime: unixTime(1000),
				Name:      "node",
			},
		},
	}

	tree := NewProcessTree(snapshot)

	findings := engine.Evaluate(tree)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	if findings[0].Rule != "test-rule" {
		t.Fatalf(
			"expected rule test-rule, got %q",
			findings[0].Rule,
		)
	}
}

func TestEngineEvaluatesSuspiciousChildProcessRule(t *testing.T) {
	registry := NewRegistry()

	rule := NewSuspiciousChildProcessRule()
	registry.Register(rule)

	engine := NewEngine(registry)

	snapshot := &core.ProcessSnapshot{
		Processes: []core.Process{
			{
				PID:       100,
				PPID:      1,
				StartTime: unixTime(1000),
				Name:      "node",
			},
			{
				PID:       200,
				PPID:      100,
				StartTime: unixTime(2000),
				Name:      "python",
			},
		},
	}

	tree := NewProcessTree(snapshot)

	findings := engine.Evaluate(tree)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	finding := findings[0]

	if finding.Rule != "suspicious-child-process" {
		t.Fatalf(
			"expected suspicious-child-process, got %q",
			finding.Rule,
		)
	}

	if finding.Severity != core.SeverityHigh {
		t.Fatalf(
			"expected HIGH severity, got %s",
			finding.Severity,
		)
	}
}
