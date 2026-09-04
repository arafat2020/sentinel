package process

import (
	"fmt"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type SuspiciousChildProcessRule struct {
	ParentName string
	ChildName  string
}
type RuleContext struct {
	Tree *ProcessTree
}

type Rule interface {
	Evaluate(ctx *RuleContext, identity core.ProcessIdentity) *core.Finding
}

func NewSuspiciousChildProcessRule() *SuspiciousChildProcessRule {
	return &SuspiciousChildProcessRule{
		ParentName: "node",
		ChildName:  "python",
	}
}

func (r *SuspiciousChildProcessRule) Evaluate(
	ctx *RuleContext,
	identity core.ProcessIdentity,
) *core.Finding {
	child, ok := ctx.Tree.Process(identity)
	if !ok {
		return nil
	}

	parent, ok := ctx.Tree.Parent(identity)
	if !ok {
		return nil
	}

	if parent.Name != r.ParentName || child.Name != r.ChildName {
		return nil
	}

	return &core.Finding{
		ID:        fmt.Sprintf("finding-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Severity:  core.SeverityHigh,
		Rule:      "suspicious-child-process",
		Title:     "Suspicious child process",
		Description: fmt.Sprintf(
			"%s was spawned by %s",
			child.Name,
			parent.Name,
		),
		Evidence: core.Evidence{
			Process: &child,
			Processes: []core.Process{
				parent,
				child,
			},
		},
	}
}
