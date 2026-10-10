package correlation

import (
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
)

type BehaviorPattern struct {
	Name          string
	Severity      core.Severity
	Title         string
	Description   string
	Processes     []ProcessPattern
	Relationships []RelationshipPattern
}

// Validate reports whether the pattern is structurally sound: whether its
// roles and relationships describe something that can be matched without
// ambiguity. It does not check that the pattern is useful.
//
// A pattern with a single role and no relationships is valid and matches one
// process. With two or more roles, every role must take part in at least one
// relationship; otherwise the roles would be unrelated and any combination
// of processes would do.
func (p BehaviorPattern) Validate() error {
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
	ID         string
	Conditions []Condition
	Events     []EventPattern
}

type EventPattern struct {
	Type core.EventType
}

type RelationshipPattern struct {
	Type   RelationshipType
	Parent string
	Child  string
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
					Conditions: []Condition{
						{
							Type:  ConditionProcessName,
							Value: "python",
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
	}
}
