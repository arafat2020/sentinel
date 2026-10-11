package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/arafat2020/sentinel/internal/config"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// How a field of the exclusion is compared with a process.
const (
	modeEq       = "eq"
	modePrefix   = "prefix"
	modeContains = "contains"
)

// exclusionField is one process field the exclusion may test.
type exclusionField struct {
	// Field is name, exe, cmdline or user.
	Field string
	// Original is the value the process in the finding had.
	Original string
	// Keep says whether the exclusion tests this field at all.
	Keep bool
	// Mode is how it is tested, and Value against what. They start as an
	// exact match on Original and can be loosened.
	Mode  string
	Value string
}

// Modes lists the ways this field can be compared, strictest first.
func (f exclusionField) Modes() []string {
	switch f.Field {
	case "exe":
		return []string{modeEq, modePrefix}
	case "cmdline":
		return []string{modeEq, modePrefix, modeContains}
	default:
		return []string{modeEq}
	}
}

// exclusionDraft is an exclusion being built from a finding: "do not report
// this again when the process in this role looks like that".
type exclusionDraft struct {
	// Rule and Role are the finding's rule and the role whose process the
	// exclusion describes.
	Rule string
	Role string
	// AllRules widens the exclusion from this role of this rule to any
	// process in any rule.
	AllRules    bool
	Description string
	Fields      []exclusionField
}

// findingRoles lists the roles a finding bound, in name order.
func findingRoles(f core.Finding) []string {
	roles := make([]string, 0, len(f.Evidence.Roles))
	for role := range f.Evidence.Roles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}

// newExclusionDraft starts an exclusion from the process a finding bound to
// role. Every field the process has is offered as an exact match. The
// executable and the user are kept to begin with, as the pair that most often
// identifies "this program, run by this account"; the name stands in for a
// missing executable. The command line is offered but not kept, because an
// exact command line rarely recurs.
func newExclusionDraft(f core.Finding, role string) (exclusionDraft, error) {
	process, bound := f.Evidence.Roles[role]
	if !bound {
		return exclusionDraft{}, fmt.Errorf("this finding has no process for the role %q", role)
	}

	draft := exclusionDraft{Rule: f.Rule, Role: role}

	for _, field := range []struct{ name, value string }{
		{"exe", process.Executable},
		{"cmdline", process.CommandLine},
		{"user", process.User},
		{"name", process.Name},
	} {
		if field.value == "" {
			continue
		}

		keep := field.name == "exe" || field.name == "user" || (field.name == "name" && process.Executable == "")
		draft.Fields = append(draft.Fields, exclusionField{
			Field: field.name, Original: field.value, Keep: keep, Mode: modeEq, Value: field.value,
		})
	}

	if len(draft.Fields) == 0 {
		return exclusionDraft{}, fmt.Errorf("nothing is known about the process in the role %q, so there is nothing to exclude by", role)
	}
	return draft, nil
}

// field returns the draft's entry for a process field, or nil.
func (d *exclusionDraft) field(name string) *exclusionField {
	for i := range d.Fields {
		if d.Fields[i].Field == name {
			return &d.Fields[i]
		}
	}
	return nil
}

// SetMode changes how a field is compared and resets its value to the
// natural one for that comparison: the whole original for an exact match or
// a "contains" (which the user then trims), and for a prefix the directory
// of an executable, or the command without its arguments.
func (d *exclusionDraft) SetMode(name, mode string) {
	f := d.field(name)
	if f == nil {
		return
	}

	allowed := false
	for _, candidate := range f.Modes() {
		allowed = allowed || candidate == mode
	}
	if !allowed {
		return
	}

	f.Mode = mode
	f.Value = f.Original

	if mode == modePrefix {
		switch name {
		case "exe":
			if dir := filepath.Dir(f.Original); dir != "." && dir != "/" {
				f.Value = dir + "/"
			}
		case "cmdline":
			if first, _, found := strings.Cut(f.Original, " "); found {
				f.Value = first + " "
			}
		}
	}
}

// Match is the match block the draft describes.
func (d exclusionDraft) Match() *correlation.MatchBlock {
	block := &correlation.MatchBlock{}

	for _, f := range d.Fields {
		if !f.Keep {
			continue
		}

		value := f.Value
		var predicate correlation.Predicate
		switch f.Mode {
		case modePrefix:
			predicate.Prefix = &value
		case modeContains:
			predicate.Contains = &value
		default:
			predicate.Eq = &value
		}
		block.Fields = append(block.Fields, correlation.FieldPredicate{Field: f.Field, Predicate: predicate})
	}

	return block
}

// Global is the draft as a top-level exclusion for every rule.
func (d exclusionDraft) Global() correlation.Exclusion {
	return correlation.Exclusion{Rules: []string{"*"}, Match: d.Match(), Description: strings.TrimSpace(d.Description)}
}

// ForRole is the draft as an exclusion on its role of its rule.
func (d exclusionDraft) ForRole() correlation.RoleExclusion {
	return correlation.RoleExclusion{Role: d.Role, Match: d.Match(), Description: strings.TrimSpace(d.Description)}
}

// Validate reports what is missing before the draft can be saved.
func (d exclusionDraft) Validate() error {
	if strings.TrimSpace(d.Description) == "" {
		return errors.New("a description is required: say why this is safe to ignore")
	}

	kept := 0
	for _, f := range d.Fields {
		if !f.Keep {
			continue
		}
		kept++
		if strings.TrimSpace(f.Value) == "" {
			return fmt.Errorf("%s is kept but has no value", f.Field)
		}
	}
	if kept == 0 {
		return errors.New("keep at least one field, or the exclusion would cover every process")
	}

	if !d.AllRules && (d.Rule == "" || d.Role == "") {
		return errors.New("this finding names no rule and role to attach the exclusion to; exclude for all rules instead")
	}

	return d.Global().Validate()
}

// Preview is the exact YAML that saving the draft adds to the patterns file,
// with a line saying where it goes.
func (d exclusionDraft) Preview() string {
	if d.AllRules {
		text, err := config.ExclusionYAML(d.Global())
		if err != nil {
			return err.Error()
		}
		return "# added to the top-level exclusions (applies to every rule)\n" + text
	}

	text, err := config.RoleExclusionYAML(d.ForRole())
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("# added to the pattern %q\n%s", d.Rule, text)
}
