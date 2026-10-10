package process

import (
	"fmt"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// parentChildRule is a rule for tests: it reports a process with a given name
// whose parent has another given name.
type parentChildRule struct {
	parent, child string
}

// nodeSpawnsPython is the pair the tests in this package use.
func nodeSpawnsPython() *parentChildRule {
	return &parentChildRule{parent: "node", child: "python"}
}

func (r *parentChildRule) Evaluate(ctx *RuleContext, identity core.ProcessIdentity) *core.Finding {
	child, ok := ctx.Tree.Process(identity)
	if !ok {
		return nil
	}

	parent, ok := ctx.Tree.Parent(identity)
	if !ok || parent.Name != r.parent || child.Name != r.child {
		return nil
	}

	return &core.Finding{
		ID:          fmt.Sprintf("finding-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Severity:    core.SeverityHigh,
		Rule:        "parent-child",
		Title:       "Parent and child",
		Description: fmt.Sprintf("%s was spawned by %s", child.Name, parent.Name),
		Evidence: core.Evidence{
			Process:   &child,
			Processes: []core.Process{parent, child},
		},
	}
}
