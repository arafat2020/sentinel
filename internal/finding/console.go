package finding

import (
	"fmt"
	"sort"
	"strings"

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

	fmt.Println(FormatFinding(finding))
}

// FormatFinding renders a finding as one line: what fired, which process
// filled each of the rule's roles, and how many events back it up.
func FormatFinding(finding *core.Finding) string {
	line := fmt.Sprintf(
		"[FINDING] severity=%s rule=%s title=%s description=%s",
		finding.Severity,
		finding.Rule,
		finding.Title,
		finding.Description,
	)

	if roles := FormatRoles(finding.Evidence); roles != "" {
		line += " roles=[" + roles + "]"
	}
	if n := len(finding.Evidence.Events); n > 0 {
		line += fmt.Sprintf(" events=%d", n)
	}

	return line
}

// FormatRoles renders the role bindings of a finding's evidence as
// "role=name(pid)" pairs, in role-name order. It is empty when the evidence
// names no roles.
func FormatRoles(evidence core.Evidence) string {
	names := make([]string, 0, len(evidence.Roles))
	for role := range evidence.Roles {
		names = append(names, role)
	}
	sort.Strings(names)

	parts := make([]string, len(names))
	for i, role := range names {
		process := evidence.Roles[role]

		name := process.Name
		if name == "" {
			name = "?"
		}
		parts[i] = fmt.Sprintf("%s=%s(%d)", role, name, process.PID)
	}

	return strings.Join(parts, " ")
}
