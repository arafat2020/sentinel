package process

import (
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

type mockRule struct{}

func (m mockRule) Evaluate(
	ctx *RuleContext,
	identity core.ProcessIdentity,
) *core.Finding {
	return nil
}

func TestRegistryStartsEmpty(t *testing.T) {
	registry := NewRegistry()

	if len(registry.Rules()) != 0 {
		t.Fatalf(
			"expected empty registry, got %d rules",
			len(registry.Rules()),
		)
	}
}

func TestRegistryRegistersRule(t *testing.T) {
	registry := NewRegistry()
	rule := mockRule{}

	registry.Register(rule)

	rules := registry.Rules()

	if len(rules) != 1 {
		t.Fatalf(
			"expected 1 rule, got %d",
			len(rules),
		)
	}
}

func TestRegistryRegistersMultipleRules(t *testing.T) {
	registry := NewRegistry()

	rule1 := mockRule{}
	rule2 := mockRule{}

	registry.Register(rule1)
	registry.Register(rule2)

	rules := registry.Rules()

	if len(rules) != 2 {
		t.Fatalf(
			"expected 2 rules, got %d",
			len(rules),
		)
	}
}
