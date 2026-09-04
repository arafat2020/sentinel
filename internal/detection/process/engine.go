package process

import "github.com/arafat2020/sentinel/internal/core"

type Engine struct {
	registry *Registry
}

func NewEngine(registry *Registry) *Engine {
	return &Engine{
		registry: registry,
	}
}

func (e *Engine) Evaluate(tree *ProcessTree) []*core.Finding {
	findings := make([]*core.Finding, 0)

	for _, process := range tree.Processes() {
		for _, rule := range e.registry.Rules() {
			ctx := &RuleContext{
				Tree: tree,
			}
			finding := rule.Evaluate(ctx, process.Identity())

			if finding != nil {
				findings = append(findings, finding)
			}
		}
	}

	return findings
}
