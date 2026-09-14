package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// PatternFile is the top-level YAML document.
type PatternFile struct {
	Patterns []PatternDef `yaml:"patterns"`
}

// PatternDef is the YAML representation of a single BehaviorPattern.
type PatternDef struct {
	Name          string              `yaml:"name"`
	Severity      string              `yaml:"severity"`
	Title         string              `yaml:"title"`
	Description   string              `yaml:"description"`
	Processes     []ProcessPatternDef `yaml:"processes"`
	Relationships []RelationshipDef   `yaml:"relationships"`
}

// ProcessPatternDef is the YAML representation of a ProcessPattern.
type ProcessPatternDef struct {
	ID         string         `yaml:"id"`
	Conditions []ConditionDef `yaml:"conditions"`
	Events     []EventDef     `yaml:"events"`
}

// ConditionDef is the YAML representation of a Condition.
type ConditionDef struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// EventDef is the YAML representation of an EventPattern.
type EventDef struct {
	Type string `yaml:"type"`
}

// RelationshipDef is the YAML representation of a RelationshipPattern.
type RelationshipDef struct {
	Type   string `yaml:"type"`
	Parent string `yaml:"parent"`
	Child  string `yaml:"child"`
}

// LoadPatterns reads the YAML file at path and converts it to correlation
// engine types. Returns an error if the file cannot be read or is malformed.
func LoadPatterns(path string) ([]correlation.BehaviorPattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var pf PatternFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	patterns := make([]correlation.BehaviorPattern, 0, len(pf.Patterns))
	for i, def := range pf.Patterns {
		p, err := convertPattern(def)
		if err != nil {
			return nil, fmt.Errorf("config: pattern[%d] %q: %w", i, def.Name, err)
		}
		patterns = append(patterns, p)
	}
	return patterns, nil
}

// SavePatterns serialises the given patterns to YAML and writes them
// atomically to path (write to a temp file, then rename).
func SavePatterns(path string, patterns []correlation.BehaviorPattern) error {
	defs := make([]PatternDef, len(patterns))
	for i, p := range patterns {
		defs[i] = unconvertPattern(p)
	}

	pf := PatternFile{Patterns: defs}
	data, err := yaml.Marshal(&pf)
	if err != nil {
		return fmt.Errorf("config: marshal patterns: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: create dir %s: %w", dir, err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("config: write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: rename to %s: %w", path, err)
	}
	return nil
}

// EnsureDefaultFile writes DefaultPatterns to path if the file does not exist.
func EnsureDefaultFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	return SavePatterns(path, correlation.DefaultPatterns())
}

func convertPattern(def PatternDef) (correlation.BehaviorPattern, error) {
	if def.Name == "" {
		return correlation.BehaviorPattern{}, fmt.Errorf("name is required")
	}

	procs := make([]correlation.ProcessPattern, 0, len(def.Processes))
	for _, pd := range def.Processes {
		pp, err := convertProcessPattern(pd)
		if err != nil {
			return correlation.BehaviorPattern{}, fmt.Errorf("process %q: %w", pd.ID, err)
		}
		procs = append(procs, pp)
	}

	rels := make([]correlation.RelationshipPattern, 0, len(def.Relationships))
	for _, rd := range def.Relationships {
		rp, err := convertRelationship(rd)
		if err != nil {
			return correlation.BehaviorPattern{}, err
		}
		rels = append(rels, rp)
	}

	return correlation.BehaviorPattern{
		Name:          def.Name,
		Severity:      core.Severity(def.Severity),
		Title:         def.Title,
		Description:   def.Description,
		Processes:     procs,
		Relationships: rels,
	}, nil
}

func convertProcessPattern(def ProcessPatternDef) (correlation.ProcessPattern, error) {
	if def.ID == "" {
		return correlation.ProcessPattern{}, fmt.Errorf("id is required")
	}

	conds := make([]correlation.Condition, 0, len(def.Conditions))
	for _, cd := range def.Conditions {
		ct := correlation.ConditionType(cd.Type)
		if ct != correlation.ConditionProcessName && ct != correlation.ConditionProcessUser {
			return correlation.ProcessPattern{}, fmt.Errorf("unknown condition type %q", cd.Type)
		}
		conds = append(conds, correlation.Condition{Type: ct, Value: cd.Value})
	}

	events := make([]correlation.EventPattern, 0, len(def.Events))
	for _, ed := range def.Events {
		events = append(events, correlation.EventPattern{Type: core.EventType(ed.Type)})
	}

	return correlation.ProcessPattern{
		ID:         def.ID,
		Conditions: conds,
		Events:     events,
	}, nil
}

func convertRelationship(def RelationshipDef) (correlation.RelationshipPattern, error) {
	rt := correlation.RelationshipType(def.Type)
	if rt != correlation.RelationshipSpawned {
		return correlation.RelationshipPattern{}, fmt.Errorf("unknown relationship type %q", def.Type)
	}
	return correlation.RelationshipPattern{
		Type:   rt,
		Parent: def.Parent,
		Child:  def.Child,
	}, nil
}

func unconvertPattern(p correlation.BehaviorPattern) PatternDef {
	procs := make([]ProcessPatternDef, len(p.Processes))
	for i, pp := range p.Processes {
		conds := make([]ConditionDef, len(pp.Conditions))
		for j, c := range pp.Conditions {
			conds[j] = ConditionDef{Type: string(c.Type), Value: c.Value}
		}
		events := make([]EventDef, len(pp.Events))
		for j, e := range pp.Events {
			events[j] = EventDef{Type: string(e.Type)}
		}
		procs[i] = ProcessPatternDef{ID: pp.ID, Conditions: conds, Events: events}
	}

	rels := make([]RelationshipDef, len(p.Relationships))
	for i, r := range p.Relationships {
		rels[i] = RelationshipDef{
			Type:   string(r.Type),
			Parent: r.Parent,
			Child:  r.Child,
		}
	}

	return PatternDef{
		Name:          p.Name,
		Severity:      string(p.Severity),
		Title:         p.Title,
		Description:   p.Description,
		Processes:     procs,
		Relationships: rels,
	}
}
