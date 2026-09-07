package correlation

import "github.com/arafat2020/sentinel/internal/core"

type BehaviorPattern struct {
	Name          string
	Severity      core.Severity
	Title         string
	Description   string
	Processes     []ProcessPattern
	Relationships []RelationshipPattern
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
