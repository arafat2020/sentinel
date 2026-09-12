package finding

import "github.com/arafat2020/sentinel/internal/core"

type Sink interface {
	Handle(*core.Finding)
}

// SinkFunc adapts any function to the Sink interface.
type SinkFunc func(*core.Finding)

func (f SinkFunc) Handle(finding *core.Finding) { f(finding) }

// NewSinkFunc wraps fn as a Sink.
func NewSinkFunc(fn func(*core.Finding)) Sink { return SinkFunc(fn) }
