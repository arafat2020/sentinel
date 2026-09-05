package process

import (
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/finding"
)

type Coordinator struct {
	engine   *Engine
	snapshot *core.ProcessSnapshot
	sink     finding.Sink
}

func (c *Coordinator) UpdateSnapshot(
	snapshot *core.ProcessSnapshot,
) {
	c.snapshot = snapshot
}

func NewCoordinator(
	engine *Engine,
	sink finding.Sink,
) *Coordinator {
	return &Coordinator{
		engine: engine,
		sink:   sink,
	}
}

func (c *Coordinator) Handle(
	event core.Event,
) []*core.Finding {
	if event.Type != core.EventProcessStart {
		return nil
	}

	if c.snapshot == nil {
		return nil
	}

	tree := NewProcessTree(c.snapshot)

	findings := c.engine.Evaluate(tree)

	for _, finding := range findings {
		c.sink.Handle(finding)
	}

	return findings
}
