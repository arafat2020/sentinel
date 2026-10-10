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
	Patterns   []PatternDef   `yaml:"patterns"`
	Exclusions []ExclusionDef `yaml:"exclusions,omitempty"`
}

// PatternDef is the YAML representation of a single BehaviorPattern.
type PatternDef struct {
	Name                 string              `yaml:"name"`
	Severity             string              `yaml:"severity"`
	Title                string              `yaml:"title"`
	Description          string              `yaml:"description"`
	Processes            []ProcessPatternDef `yaml:"processes"`
	Relationships        []RelationshipDef   `yaml:"relationships"`
	Exclude              []RoleExclusionDef  `yaml:"exclude,omitempty"`
	MaxFindingsPerWindow int                 `yaml:"max_findings_per_window,omitempty"`
}

// ProcessPatternDef is the YAML representation of a ProcessPattern.
//
// Conditions is the original exact-match form and Match the predicate form;
// a role may use either or both. Conditions is a pointer so that a role
// written with only a match block is saved without an empty conditions list,
// while roles in the original form are saved exactly as they always were.
type ProcessPatternDef struct {
	ID         string          `yaml:"id"`
	Conditions *[]ConditionDef `yaml:"conditions,omitempty"`
	Match      yaml.Node       `yaml:"match,omitempty"`
	Events     []EventDef      `yaml:"events"`
}

// ConditionDef is the YAML representation of a Condition.
type ConditionDef struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// EventDef is the YAML representation of an EventPattern.
type EventDef struct {
	Type  string    `yaml:"type"`
	Where yaml.Node `yaml:"where,omitempty"`
}

// RelationshipDef is the YAML representation of a RelationshipPattern.
type RelationshipDef struct {
	Type   string `yaml:"type"`
	Parent string `yaml:"parent"`
	Child  string `yaml:"child"`
}

// RoleExclusionDef is the YAML representation of a RoleExclusion.
type RoleExclusionDef struct {
	Role  string    `yaml:"role"`
	Match yaml.Node `yaml:"match"`
}

// ExclusionDef is the YAML representation of a top-level Exclusion.
type ExclusionDef struct {
	Rules       []string  `yaml:"rules"`
	Match       yaml.Node `yaml:"match"`
	Description string    `yaml:"description,omitempty"`
}

// PatternSet is what a patterns file yields: everything in it that is
// usable, and an explanation for everything that is not.
type PatternSet struct {
	Patterns   []correlation.BehaviorPattern
	Exclusions []correlation.Exclusion
	// Errors has one entry per pattern or exclusion that was left out.
	Errors []PatternError
	// Warnings describe things in the file that were ignored without
	// leaving anything out, such as an unknown top-level key.
	Warnings []string
}

// PatternError explains why one pattern or exclusion in a file was rejected.
type PatternError struct {
	// Index is the entry's position in the file's patterns or exclusions
	// list.
	Index int
	// Name is the pattern's name, when it has one.
	Name string
	// Exclusion is true when the entry is a top-level exclusion rather than
	// a pattern.
	Exclusion bool
	Err       error
}

func (e PatternError) Error() string {
	if e.Exclusion {
		return fmt.Sprintf("exclusions[%d]: %v", e.Index, e.Err)
	}
	return fmt.Sprintf("pattern[%d] %q: %v", e.Index, e.Name, e.Err)
}

func (e PatternError) Unwrap() error { return e.Err }

// rawFile is a patterns file with each entry left undecoded, so that one bad
// entry can be reported without giving up on the others.
type rawFile struct {
	Patterns   []yaml.Node `yaml:"patterns"`
	Exclusions []yaml.Node `yaml:"exclusions"`
}

// LoadPatterns reads the YAML file at path and converts it to correlation
// engine types.
//
// It returns an error only when nothing can be made of the file: it cannot
// be read, or it is not valid YAML. A pattern or exclusion that is wrong in
// itself is left out and described in the returned set's Errors; the rest
// of the file is still loaded.
func LoadPatterns(path string) (PatternSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PatternSet{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	set, err := parsePatterns(data)
	if err != nil {
		return PatternSet{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	return set, nil
}

func parsePatterns(data []byte) (PatternSet, error) {
	var raw rawFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return PatternSet{}, err
	}

	set := PatternSet{
		Patterns: make([]correlation.BehaviorPattern, 0, len(raw.Patterns)),
		Warnings: topLevelWarnings(data),
	}

	for i := range raw.Patterns {
		pattern, name, err := decodePattern(&raw.Patterns[i])
		if err != nil {
			set.Errors = append(set.Errors, PatternError{Index: i, Name: name, Err: err})
			continue
		}
		set.Patterns = append(set.Patterns, pattern)
	}

	for i := range raw.Exclusions {
		exclusion, err := decodeExclusion(&raw.Exclusions[i])
		if err != nil {
			set.Errors = append(set.Errors, PatternError{Index: i, Exclusion: true, Err: err})
			continue
		}
		set.Exclusions = append(set.Exclusions, exclusion)
	}

	return set, nil
}

// decodePattern converts one entry of the patterns list. The name is
// returned even on failure, when it could be read, for the error report.
func decodePattern(node *yaml.Node) (correlation.BehaviorPattern, string, error) {
	// A misspelt key would otherwise be dropped in silence, and the pattern
	// would load meaning something other than what was written.
	if err := checkKeys(node, patternKeys, ""); err != nil {
		return correlation.BehaviorPattern{}, nameOf(node), err
	}

	var def PatternDef
	if err := node.Decode(&def); err != nil {
		return correlation.BehaviorPattern{}, nameOf(node), err
	}

	pattern, err := convertPattern(def)
	return pattern, def.Name, err
}

// nameOf reads the name key of a pattern that could not be decoded as a
// whole.
func nameOf(node *yaml.Node) string {
	var named struct {
		Name string `yaml:"name"`
	}
	_ = node.Decode(&named)

	return named.Name
}

func decodeExclusion(node *yaml.Node) (correlation.Exclusion, error) {
	if err := checkKeys(node, exclusionKeys, ""); err != nil {
		return correlation.Exclusion{}, err
	}

	var def ExclusionDef
	if err := node.Decode(&def); err != nil {
		return correlation.Exclusion{}, err
	}

	match, err := decodeMatchBlock(&def.Match, "match")
	if err != nil {
		return correlation.Exclusion{}, err
	}

	exclusion := correlation.Exclusion{
		Rules:       def.Rules,
		Match:       match,
		Description: def.Description,
	}

	return exclusion, exclusion.Validate()
}

// SavePatterns serialises the given patterns to YAML and writes them
// atomically to path (write to a temp file, then rename).
//
// The patterns are the ones a pattern editor holds, which is not everything
// a file can contain. What the editors never see is carried over from the
// file being replaced: its top-level exclusions, and any pattern in it that
// failed to load. Saving from an editor therefore cannot delete either.
func SavePatterns(path string, patterns []correlation.BehaviorPattern) error {
	out := struct {
		Patterns   []yaml.Node `yaml:"patterns"`
		Exclusions []yaml.Node `yaml:"exclusions,omitempty"`
	}{
		Patterns: make([]yaml.Node, 0, len(patterns)),
	}

	for _, p := range patterns {
		var node yaml.Node
		if err := node.Encode(unconvertPattern(p)); err != nil {
			return fmt.Errorf("config: marshal pattern %q: %w", p.Name, err)
		}
		out.Patterns = append(out.Patterns, node)
	}

	rejected, exclusions := carriedOver(path)
	out.Patterns = append(out.Patterns, rejected...)
	out.Exclusions = exclusions

	data, err := yaml.Marshal(&out)
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

// carriedOver returns the parts of the existing file at path that a save
// must keep as they are: the patterns that do not load, and the exclusions.
// A file that is missing or unreadable has nothing to carry over.
func carriedOver(path string) (rejected, exclusions []yaml.Node) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	var raw rawFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil
	}

	for i := range raw.Patterns {
		if _, _, err := decodePattern(&raw.Patterns[i]); err != nil {
			rejected = append(rejected, raw.Patterns[i])
		}
	}

	return rejected, raw.Exclusions
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
			return correlation.BehaviorPattern{}, fmt.Errorf("role %q: %w", pd.ID, err)
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

	var exclude []correlation.RoleExclusion
	for i, xd := range def.Exclude {
		match, err := decodeMatchBlock(&xd.Match, "match")
		if err != nil {
			return correlation.BehaviorPattern{}, fmt.Errorf("exclude[%d] (role %q): %w", i, xd.Role, err)
		}
		exclude = append(exclude, correlation.RoleExclusion{Role: xd.Role, Match: match})
	}

	pattern := correlation.BehaviorPattern{
		Name:                 def.Name,
		Severity:             core.Severity(def.Severity),
		Title:                def.Title,
		Description:          def.Description,
		Processes:            procs,
		Relationships:        rels,
		Exclude:              exclude,
		MaxFindingsPerWindow: def.MaxFindingsPerWindow,
	}

	// Reject patterns that cannot be matched as written, rather than
	// loading a rule that silently never fires or fires on unrelated
	// processes. The error names the role and field at fault.
	if err := pattern.Validate(); err != nil {
		return correlation.BehaviorPattern{}, err
	}

	return pattern, nil
}

func convertProcessPattern(def ProcessPatternDef) (correlation.ProcessPattern, error) {
	if def.ID == "" {
		return correlation.ProcessPattern{}, fmt.Errorf("id is required")
	}

	conds := []correlation.Condition{}
	if def.Conditions != nil {
		for _, cd := range *def.Conditions {
			ct := correlation.ConditionType(cd.Type)
			if ct != correlation.ConditionProcessName && ct != correlation.ConditionProcessUser {
				return correlation.ProcessPattern{}, fmt.Errorf("unknown condition type %q", cd.Type)
			}
			conds = append(conds, correlation.Condition{Type: ct, Value: cd.Value})
		}
	}

	match, err := decodeMatchBlock(&def.Match, "match")
	if err != nil {
		return correlation.ProcessPattern{}, err
	}

	events := make([]correlation.EventPattern, 0, len(def.Events))
	for i, ed := range def.Events {
		where, err := decodeMatchBlock(&ed.Where, "where")
		if err != nil {
			return correlation.ProcessPattern{}, fmt.Errorf("events[%d] (%s): %w", i, ed.Type, err)
		}
		events = append(events, correlation.EventPattern{Type: core.EventType(ed.Type), Where: where})
	}

	return correlation.ProcessPattern{
		ID:         def.ID,
		Conditions: conds,
		Match:      match,
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
		def := ProcessPatternDef{ID: pp.ID, Match: encodeMatchBlock(pp.Match)}

		// The conditions list has always been written, even when empty. Keep
		// that for roles in the original form; leave it out only where a
		// match block makes an empty list pure noise.
		if len(pp.Conditions) > 0 || pp.Match == nil {
			conds := make([]ConditionDef, len(pp.Conditions))
			for j, c := range pp.Conditions {
				conds[j] = ConditionDef{Type: string(c.Type), Value: c.Value}
			}
			def.Conditions = &conds
		}

		def.Events = make([]EventDef, len(pp.Events))
		for j, e := range pp.Events {
			def.Events[j] = EventDef{Type: string(e.Type), Where: encodeMatchBlock(e.Where)}
		}

		procs[i] = def
	}

	rels := make([]RelationshipDef, len(p.Relationships))
	for i, r := range p.Relationships {
		rels[i] = RelationshipDef{
			Type:   string(r.Type),
			Parent: r.Parent,
			Child:  r.Child,
		}
	}

	var exclude []RoleExclusionDef
	for _, x := range p.Exclude {
		exclude = append(exclude, RoleExclusionDef{Role: x.Role, Match: encodeMatchBlock(x.Match)})
	}

	return PatternDef{
		Name:                 p.Name,
		Severity:             string(p.Severity),
		Title:                p.Title,
		Description:          p.Description,
		Processes:            procs,
		Relationships:        rels,
		Exclude:              exclude,
		MaxFindingsPerWindow: p.MaxFindingsPerWindow,
	}
}
