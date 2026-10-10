package process

import "github.com/arafat2020/sentinel/internal/core"

// RuleContext is what a rule may consult when judging a process.
type RuleContext struct {
	Tree *ProcessTree
}

// Rule is a detection written in Go and evaluated for one process at a time.
//
// None is registered by default. Behavior that can be described as processes,
// their relationships and their events belongs in the YAML patterns
// (docs/behavioral-patterns.md), which need no rebuild to change; the rule
// that used to live here, a node process spawning Python, is now the
// suspicious-child-process pattern in the default patterns file. This
// interface remains for detections a pattern cannot express.
type Rule interface {
	Evaluate(ctx *RuleContext, identity core.ProcessIdentity) *core.Finding
}
