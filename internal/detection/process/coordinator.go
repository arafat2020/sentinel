package process

import "github.com/arafat2020/sentinel/internal/core"

type Coordinator struct {
	engine *Engine
}

func NewCoordinator(engine *Engine) *Coordinator {
	return &Coordinator{
		engine: engine,
	}
}

func (c *Coordinator) Handle(
	event core.Event,
	snapshot *core.ProcessSnapshot,
) []*core.Finding {

	if event.Type != core.EventProcessStart {
		return nil
	}

	tree := NewProcessTree(snapshot)

	return c.engine.Evaluate(tree)
}
