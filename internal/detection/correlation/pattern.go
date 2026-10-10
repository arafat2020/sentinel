package correlation

import (
	"fmt"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// DefaultWindow is the correlation window Sentinel runs with. Patterns are
// validated against it: a span longer than the window could never be
// observed.
const DefaultWindow = 5 * time.Minute

// DefaultMaxFindingsPerWindow is how many findings a rule may produce in one
// window when the pattern does not set its own limit.
const DefaultMaxFindingsPerWindow = 20

type BehaviorPattern struct {
	Name          string
	Severity      core.Severity
	Title         string
	Description   string
	Processes     []ProcessPattern
	Relationships []RelationshipPattern
	// Exclude lists processes that may not fill particular roles.
	Exclude []RoleExclusion
	// MaxFindingsPerWindow caps the findings this rule produces in one
	// window; further ones are counted and summarised. Zero means
	// DefaultMaxFindingsPerWindow.
	MaxFindingsPerWindow int
	// Sequence, when set, also requires events to have happened in order
	// on the processes bound to the roles.
	Sequence *SequencePattern
}

// RoleExclusion bars any process matching Match from filling Role.
type RoleExclusion struct {
	Role  string
	Match *MatchBlock
}

// Exclusion drops findings: a finding of one of the named rules is discarded
// if any of the processes bound to it matches Match.
type Exclusion struct {
	// Rules names the rules the exclusion applies to; "*" means every rule.
	Rules       []string
	Match       *MatchBlock
	Description string
}

// AppliesTo reports whether the exclusion covers the named rule.
func (x Exclusion) AppliesTo(rule string) bool {
	for _, name := range x.Rules {
		if name == "*" || name == rule {
			return true
		}
	}
	return false
}

// Validate reports whether the exclusion can be applied.
func (x Exclusion) Validate() error {
	if len(x.Rules) == 0 {
		return fmt.Errorf(`rules: list the rules it applies to, or "*" for all`)
	}
	if x.Match.IsEmpty() {
		return fmt.Errorf("match: an exclusion must say which processes it excludes")
	}

	_, err := compileProcessMatch(x.Match, "match")
	return err
}

// UsesAdvancedFields reports whether the pattern uses anything beyond the
// original schema of exact-match conditions and bare event types.
func (p BehaviorPattern) UsesAdvancedFields() bool {
	if len(p.Exclude) > 0 || p.MaxFindingsPerWindow != 0 || p.Sequence != nil {
		return true
	}
	for _, relationship := range p.Relationships {
		if relationship.Type != RelationshipSpawned {
			return true
		}
	}
	for _, role := range p.Processes {
		if role.UsesAdvancedFields() {
			return true
		}
	}
	return false
}

// Validate reports whether the pattern can be used: whether its roles and
// relationships describe something that can be matched without ambiguity,
// and whether every predicate in it compiles. It does not check that the
// pattern is useful. Errors name the role and field at fault.
//
// A pattern with a single role and no relationships is valid and matches one
// process. With two or more roles, every role must take part in at least one
// relationship; otherwise the roles would be unrelated and any combination
// of processes would do. A pattern with no roles is valid, and never matches.
func (p BehaviorPattern) Validate() error {
	return p.ValidateFor(DefaultWindow)
}

// ValidateFor is Validate for an engine with the given correlation window,
// which bounds the spans a pattern may ask for.
func (p BehaviorPattern) ValidateFor(window time.Duration) error {
	_, err := compilePattern(p, window)
	return err
}

// validateStructure checks the roles and relationships of a pattern.
func (p BehaviorPattern) validateStructure() error {
	roles := make(map[string]bool, len(p.Processes))
	for _, process := range p.Processes {
		if roles[process.ID] {
			return fmt.Errorf("duplicate role id %q", process.ID)
		}
		roles[process.ID] = true
	}

	related := make(map[string]bool, len(p.Processes))
	for _, relationship := range p.Relationships {
		for _, id := range []string{relationship.Parent, relationship.Child} {
			if !roles[id] {
				return fmt.Errorf("relationship references unknown role %q", id)
			}
			related[id] = true
		}
		if relationship.Parent == relationship.Child {
			return fmt.Errorf("relationship makes role %q its own parent", relationship.Parent)
		}
	}

	for i, relationship := range p.Relationships {
		switch relationship.Type {
		case RelationshipSpawned:
			if relationship.MaxDepth != 0 {
				return fmt.Errorf("relationships[%d]: max_depth applies to DESCENDANT, not SPAWNED", i)
			}
		case RelationshipDescendant:
			if relationship.MaxDepth != 0 && (relationship.MaxDepth < 1 || relationship.MaxDepth > MaxDepthLimit) {
				return fmt.Errorf("relationships[%d]: max_depth must be between 1 and %d, got %d", i, MaxDepthLimit, relationship.MaxDepth)
			}
		default:
			return fmt.Errorf("relationships[%d]: unknown relationship type %q", i, relationship.Type)
		}
	}

	for i, exclusion := range p.Exclude {
		if !roles[exclusion.Role] {
			return fmt.Errorf("exclude[%d]: unknown role %q", i, exclusion.Role)
		}
	}

	if p.MaxFindingsPerWindow < 0 {
		return fmt.Errorf("max_findings_per_window: must not be negative, got %d", p.MaxFindingsPerWindow)
	}

	if len(p.Processes) < 2 {
		return nil
	}

	if len(p.Relationships) == 0 {
		return fmt.Errorf("%d roles but no relationships: roles must be related to each other", len(p.Processes))
	}

	for _, process := range p.Processes {
		if !related[process.ID] {
			return fmt.Errorf("role %q is not part of any relationship", process.ID)
		}
	}

	return nil
}

type ProcessPattern struct {
	ID string
	// Conditions are the original exact-match conditions. They are still
	// honoured; each is equivalent to an eq predicate in Match.
	Conditions []Condition
	// Match holds field predicates on the process. Conditions and Match
	// must both hold.
	Match  *MatchBlock
	Events []EventPattern
}

// UsesAdvancedFields reports whether the role uses a match block or event
// filters, which the pattern editors display but cannot edit.
func (p ProcessPattern) UsesAdvancedFields() bool {
	if p.Match != nil {
		return true
	}
	for _, event := range p.Events {
		if event.Where != nil || event.isThreshold() {
			return true
		}
	}
	return false
}

// EventPattern requires at least one in-window event of Type that satisfies
// Where. A nil Where accepts any event of the type.
//
// With Count, Within or Distinct set the requirement is a threshold: the
// process must have produced Count events satisfying Where (or events with
// Count distinct values of the Distinct field) inside some span of length
// Within that ends in the correlation window.
type EventPattern struct {
	Type  core.EventType
	Where *MatchBlock
	// Count is how many events are required. Zero means one.
	Count int
	// Within is the length of the span the events must fall in. Zero means
	// the whole correlation window.
	Within time.Duration
	// Distinct names a field of the event; events are then counted by the
	// number of different values it takes.
	Distinct string
}

// isThreshold reports whether the requirement needs counting rather than a
// single matching event.
func (e EventPattern) isThreshold() bool {
	return e.Count > 1 || e.Within != 0 || e.Distinct != ""
}

type RelationshipPattern struct {
	Type   RelationshipType
	Parent string
	Child  string
	// MaxDepth is how many generations may separate parent and child in a
	// DESCENDANT relationship. Zero means DefaultMaxDepth. It must be left
	// zero for SPAWNED, which is always one generation.
	MaxDepth int
}

// depth returns how many generations the relationship may span.
func (r RelationshipPattern) depth() int {
	if r.Type != RelationshipDescendant {
		return 1
	}
	if r.MaxDepth == 0 {
		return DefaultMaxDepth
	}
	return r.MaxDepth
}

type ConditionType string

const (
	ConditionProcessName ConditionType = "PROCESS_NAME"
	ConditionProcessUser ConditionType = "PROCESS_USER"
)

type Condition struct {
	Type  ConditionType
	Value string
}

func DefaultPatterns() []BehaviorPattern {
	return []BehaviorPattern{
		{
			Name:        "network-active-parent-spawns-python",
			Severity:    core.SeverityMedium,
			Title:       "Network-active process spawned Python",
			Description: "A process with network activity spawned a Python process that also established a network connection.",

			Processes: []ProcessPattern{
				{
					ID: "parent",
					Events: []EventPattern{
						{
							Type: core.EventNetworkConnect,
						},
					},
				},
				{
					ID: "child",
					// python, python3, python3.12, ...
					Match: &MatchBlock{
						Fields: []FieldPredicate{
							{
								Field:     "name",
								Predicate: Predicate{Regex: stringPtr(`^python[0-9.]*$`)},
							},
						},
					},
					Events: []EventPattern{
						{
							Type: core.EventNetworkConnect,
						},
					},
				},
			},

			Relationships: []RelationshipPattern{
				{
					Type:   RelationshipSpawned,
					Parent: "parent",
					Child:  "child",
				},
			},
		},
		// This was a rule written in Go until it could be said here.
		{
			Name:        "suspicious-child-process",
			Severity:    core.SeverityHigh,
			Title:       "Suspicious child process",
			Description: "A node process spawned a Python interpreter.",

			Processes: []ProcessPattern{
				{
					ID: "parent",
					Match: &MatchBlock{
						Fields: []FieldPredicate{
							{Field: "name", Predicate: Predicate{Eq: stringPtr("node")}},
						},
					},
				},
				{
					ID: "child",
					Match: &MatchBlock{
						Fields: []FieldPredicate{
							{Field: "name", Predicate: Predicate{Regex: stringPtr(`^python[0-9.]*$`)}},
						},
					},
				},
			},

			Relationships: []RelationshipPattern{
				{
					Type:   RelationshipSpawned,
					Parent: "parent",
					Child:  "child",
				},
			},
		},
	}
}

func stringPtr(s string) *string { return &s }
