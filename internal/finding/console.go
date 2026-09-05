package finding

import (
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
)

type ConsoleSink struct{}

func NewConsoleSink() *ConsoleSink {
	return &ConsoleSink{}
}

func (s *ConsoleSink) Handle(finding *core.Finding) {
	if finding == nil {
		return
	}

	fmt.Printf(
		"[FINDING] severity=%s rule=%s title=%s description=%s\n",
		finding.Severity,
		finding.Rule,
		finding.Title,
		finding.Description,
	)
}
