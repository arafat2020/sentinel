package main

import (
	"fmt"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
	"github.com/arafat2020/sentinel/internal/finding"
)

// advancedFieldsNote marks a pattern or role that uses parts of the pattern
// schema the editors show but cannot change: match blocks, event filters,
// exclusions and the rate limit. Saving from an editor keeps them as they
// are.
const advancedFieldsNote = "advanced fields — edit in YAML"

// patternProblems describes everything wrong with the current patterns, for
// display: entries of the patterns file that were rejected when it was
// loaded, and patterns held in memory that would not validate (an editor can
// produce those, for example two roles with no relationship). A pattern with
// a problem never fires.
func patternProblems(loadErrors []config.PatternError, patterns []correlation.BehaviorPattern) []string {
	problems := make([]string, 0, len(loadErrors))

	for _, loadError := range loadErrors {
		problems = append(problems, loadError.Error())
	}

	for _, pattern := range patterns {
		if err := pattern.Validate(); err != nil {
			problems = append(problems, fmt.Sprintf("pattern %q: %v", pattern.Name, err))
		}
	}

	return problems
}

// findingLine is how a finding is shown and stored: the rule, what it
// means, and which process filled each of the rule's roles.
func findingLine(f *core.Finding) string {
	line := fmt.Sprintf("[%s] %s — %s", f.Rule, f.Title, f.Description)

	if roles := finding.FormatRoles(f.Evidence); roles != "" {
		line += "  (" + roles + ")"
	}

	return line
}

// loadPatternSet reads the patterns file, falling back to the built-in
// defaults when the file as a whole cannot be used. The second result
// reports that fallback.
func loadPatternSet(path string) (config.PatternSet, error) {
	set, err := config.LoadPatterns(path)
	if err != nil {
		return config.PatternSet{Patterns: correlation.DefaultPatterns()}, err
	}

	return set, nil
}
