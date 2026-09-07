package correlation

import (
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestBehaviorPatternDescribesNetworkActiveParentSpawningPython(t *testing.T) {
	pattern := BehaviorPattern{
		Name:     "network-active-parent-spawns-python",
		Severity: core.SeverityMedium,

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
	}

	if pattern.Name == "" {
		t.Fatal("expected pattern name")
	}

	if len(pattern.Processes) != 2 {
		t.Fatalf("expected 2 process patterns, got %d", len(pattern.Processes))
	}

	if len(pattern.Relationships) != 1 {
		t.Fatalf(
			"expected 1 relationship pattern, got %d",
			len(pattern.Relationships),
		)
	}
}
