package correlation

import (
	"strings"
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

func TestBehaviorPatternValidate(t *testing.T) {
	rel := func(parent, child string) RelationshipPattern {
		return RelationshipPattern{Type: RelationshipSpawned, Parent: parent, Child: child}
	}
	roles := func(ids ...string) []ProcessPattern {
		out := make([]ProcessPattern, len(ids))
		for i, id := range ids {
			out[i] = ProcessPattern{ID: id}
		}
		return out
	}

	valid := map[string]BehaviorPattern{
		"default pattern":            DefaultPatterns()[0],
		"single role":                {Processes: roles("only")},
		"no roles yet (new draft)":   {},
		"chain":                      {Processes: roles("a", "b", "c"), Relationships: []RelationshipPattern{rel("a", "b"), rel("b", "c")}},
		"two children of one role":   {Processes: roles("a", "b", "c"), Relationships: []RelationshipPattern{rel("a", "b"), rel("a", "c")}},
		"same relationship twice":    {Processes: roles("a", "b"), Relationships: []RelationshipPattern{rel("a", "b"), rel("a", "b")}},
		"two separate related pairs": {Processes: roles("a", "b", "c", "d"), Relationships: []RelationshipPattern{rel("a", "b"), rel("c", "d")}},
	}
	for name, pattern := range valid {
		if err := pattern.Validate(); err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}

	invalid := map[string]struct {
		pattern BehaviorPattern
		want    string
	}{
		"two roles, no relationships": {BehaviorPattern{Processes: roles("a", "b")}, "no relationships"},
		"unknown parent role":         {BehaviorPattern{Processes: roles("a", "b"), Relationships: []RelationshipPattern{rel("ghost", "b")}}, `unknown role "ghost"`},
		"unknown child role":          {BehaviorPattern{Processes: roles("a", "b"), Relationships: []RelationshipPattern{rel("a", "ghost")}}, `unknown role "ghost"`},
		"duplicate role id":           {BehaviorPattern{Processes: roles("a", "a"), Relationships: []RelationshipPattern{rel("a", "a")}}, `duplicate role id "a"`},
		"role left unrelated":         {BehaviorPattern{Processes: roles("a", "b", "c"), Relationships: []RelationshipPattern{rel("a", "b")}}, `role "c" is not part of any relationship`},
		"role is its own parent":      {BehaviorPattern{Processes: roles("a", "b"), Relationships: []RelationshipPattern{rel("a", "b"), rel("b", "b")}}, "its own parent"},
	}
	for name, c := range invalid {
		err := c.pattern.Validate()
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", name, err, c.want)
		}
	}
}
