package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// This file is what the editors in the interfaces use: one pattern, or the
// list of exclusions, as YAML text, checked exactly as the patterns file is
// checked when Sentinel starts, with every problem reported and nothing
// written unless there are none.

// EditError is one thing wrong with YAML a user is editing.
type EditError struct {
	// Path is where in the document the problem is, for example
	// "processes[1].mach"; empty when the problem is not at one place.
	Path string
	// Line is the 1-based line of the text, or 0 when it is not known. The
	// YAML parser knows it for syntax errors, wrong types and unknown
	// keys; a pattern that is well formed but does not make sense (two
	// roles with no relationship, say) is not wrong on any one line.
	Line    int
	Message string
}

func (e EditError) String() string {
	var b strings.Builder
	if e.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", e.Line)
	}
	if e.Path != "" {
		b.WriteString(e.Path + ": ")
	}
	b.WriteString(e.Message)
	return b.String()
}

var yamlLine = regexp.MustCompile(`line (\d+): `)

// yamlErrors splits what the YAML library reports into one EditError per
// problem, with its line.
func yamlErrors(err error) []EditError {
	messages := []string{strings.TrimPrefix(err.Error(), "yaml: ")}

	var typed *yaml.TypeError
	if errors.As(err, &typed) {
		messages = typed.Errors
	}

	out := make([]EditError, 0, len(messages))
	for _, message := range messages {
		edit := EditError{Message: message}
		if found := yamlLine.FindStringSubmatchIndex(message); found != nil {
			edit.Line, _ = strconv.Atoi(message[found[2]:found[3]])
			edit.Message = message[:found[0]] + message[found[1]:]
		}
		out = append(out, edit)
	}
	return out
}

// unknownKeys reports every key in node, at any depth, that allowed does not
// provide for. checkKeys stops at the first; an editor shows them all.
func unknownKeys(node *yaml.Node, allowed keys, path string, out *[]EditError) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]

		here := key.Value
		if path != "" {
			here = path + "." + key.Value
		}

		nested, known := allowed[key.Value]
		if !known {
			*out = append(*out, EditError{
				Path:    here,
				Line:    key.Line,
				Message: "unknown key (valid keys here: " + strings.Join(sortedKeys(allowed), ", ") + ")",
			})
			continue
		}
		if nested == nil {
			continue
		}

		switch value.Kind {
		case yaml.MappingNode:
			unknownKeys(value, nested, here, out)
		case yaml.SequenceNode:
			for j, item := range value.Content {
				unknownKeys(item, nested, fmt.Sprintf("%s[%d]", here, j), out)
			}
		}
	}
}

// PatternYAML renders one pattern exactly as SavePatterns would write it.
func PatternYAML(pattern correlation.BehaviorPattern) (string, error) {
	data, err := yaml.Marshal(unconvertPattern(pattern))
	if err != nil {
		return "", fmt.Errorf("config: marshal pattern %q: %w", pattern.Name, err)
	}
	return string(data), nil
}

// ParsePatternYAML reads one pattern from text an editor holds, with the
// checks LoadPatterns applies to each pattern of a file. It returns either
// the pattern or everything that is wrong with the text, never both.
//
// The text is the pattern's own mapping ("name: ..."). A one-element list
// ("- name: ..."), as a pattern appears inside a patterns file, is accepted
// too.
func ParsePatternYAML(text string) (correlation.BehaviorPattern, []EditError) {
	var none correlation.BehaviorPattern

	var document yaml.Node
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		return none, yamlErrors(err)
	}
	if len(document.Content) == 0 {
		return none, []EditError{{Message: "the pattern is empty"}}
	}

	node := document.Content[0]
	if node.Kind == yaml.SequenceNode {
		if len(node.Content) != 1 {
			return none, []EditError{{Line: node.Line, Message: fmt.Sprintf("expected one pattern, found a list of %d", len(node.Content))}}
		}
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return none, []EditError{{Line: node.Line, Message: "a pattern is a set of keys (name, severity, processes, ...)"}}
	}

	var problems []EditError
	unknownKeys(node, patternKeys, "", &problems)

	var def PatternDef
	if err := node.Decode(&def); err != nil {
		problems = append(problems, yamlErrors(err)...)
	}
	if len(problems) > 0 {
		return none, problems
	}

	pattern, err := convertPattern(def)
	if err != nil {
		return none, []EditError{{Message: err.Error()}}
	}
	return pattern, nil
}

// ExclusionsYAML returns the top-level exclusions of the patterns file at
// path as an "exclusions:" list, as they are written there, including any
// that do not load.
func ExclusionsYAML(path string) (string, error) {
	out := struct {
		Exclusions []yaml.Node `yaml:"exclusions"`
	}{Exclusions: []yaml.Node{}}

	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return "", fmt.Errorf("config: read %s: %w", path, err)
	default:
		var raw rawFile
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return "", fmt.Errorf("config: parse %s: %w", path, err)
		}
		if raw.Exclusions != nil {
			out.Exclusions = raw.Exclusions
		}
	}

	encoded, err := yaml.Marshal(&out)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// ParseExclusionsYAML reads an "exclusions:" list from text an editor holds
// and checks each entry as LoadPatterns does. It returns the entries, ready
// for SaveExclusions, or everything that is wrong.
func ParseExclusionsYAML(text string) ([]yaml.Node, []EditError) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		return nil, yamlErrors(err)
	}
	if len(document.Content) == 0 {
		return nil, nil // an empty document: no exclusions
	}

	root := document.Content[0]
	list := root

	if root.Kind == yaml.MappingNode {
		list = nil
		var problems []EditError
		for i := 0; i+1 < len(root.Content); i += 2 {
			if key := root.Content[i]; key.Value != "exclusions" {
				problems = append(problems, EditError{Path: key.Value, Line: key.Line, Message: `unknown key (only "exclusions" belongs here)`})
			} else {
				list = root.Content[i+1]
			}
		}
		if len(problems) > 0 {
			return nil, problems
		}
		if list == nil || isNull(list) {
			return nil, nil
		}
	}
	if list.Kind != yaml.SequenceNode {
		return nil, []EditError{{Path: "exclusions", Line: list.Line, Message: "must be a list"}}
	}

	var problems []EditError
	entries := make([]yaml.Node, 0, len(list.Content))

	for i, item := range list.Content {
		path := fmt.Sprintf("exclusions[%d]", i)

		before := len(problems)
		unknownKeys(item, exclusionKeys, path, &problems)
		if len(problems) > before {
			continue
		}

		if _, err := decodeExclusion(item); err != nil {
			var typed *yaml.TypeError
			if errors.As(err, &typed) {
				for _, problem := range yamlErrors(err) {
					problem.Path = path
					problems = append(problems, problem)
				}
			} else {
				problems = append(problems, EditError{Path: path, Line: item.Line, Message: err.Error()})
			}
			continue
		}
		entries = append(entries, *item)
	}

	if len(problems) > 0 {
		return nil, problems
	}
	return entries, nil
}

// SaveExclusions replaces the top-level exclusions of the patterns file at
// path, leaving its patterns exactly as they are written, including any that
// do not load.
func SaveExclusions(path string, exclusions []yaml.Node) error {
	return rewrite(path, func(raw *rawFile) error {
		raw.Exclusions = exclusions
		return nil
	})
}

// AppendExclusion adds one top-level exclusion to the patterns file at path,
// leaving everything else in it as it is.
func AppendExclusion(path string, exclusion correlation.Exclusion) error {
	if err := exclusion.Validate(); err != nil {
		return err
	}

	return rewrite(path, func(raw *rawFile) error {
		var node yaml.Node
		if err := node.Encode(exclusionDef(exclusion)); err != nil {
			return err
		}
		raw.Exclusions = append(raw.Exclusions, node)
		return nil
	})
}

func exclusionDef(exclusion correlation.Exclusion) ExclusionDef {
	return ExclusionDef{
		Rules:       exclusion.Rules,
		Match:       encodeMatchBlock(exclusion.Match),
		Description: exclusion.Description,
	}
}

// ExclusionYAML renders a top-level exclusion as it would be added to the
// "exclusions:" list of a patterns file.
func ExclusionYAML(exclusion correlation.Exclusion) (string, error) {
	out := struct {
		Exclusions []ExclusionDef `yaml:"exclusions"`
	}{Exclusions: []ExclusionDef{exclusionDef(exclusion)}}

	data, err := yaml.Marshal(&out)
	return string(data), err
}

// RoleExclusionYAML renders a per-pattern exclusion as it would be added to
// the "exclude:" list of its pattern.
func RoleExclusionYAML(exclusion correlation.RoleExclusion) (string, error) {
	out := struct {
		Exclude []RoleExclusionDef `yaml:"exclude"`
	}{Exclude: []RoleExclusionDef{{Role: exclusion.Role, Match: encodeMatchBlock(exclusion.Match)}}}

	data, err := yaml.Marshal(&out)
	return string(data), err
}

// rewrite applies change to the patterns file at path with every entry kept
// as written, and writes the result atomically. A missing file is treated as
// an empty one.
func rewrite(path string, change func(*rawFile) error) error {
	var raw rawFile

	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return fmt.Errorf("config: read %s: %w", path, err)
	default:
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	if err := change(&raw); err != nil {
		return err
	}

	out := struct {
		Patterns   []yaml.Node `yaml:"patterns"`
		Exclusions []yaml.Node `yaml:"exclusions,omitempty"`
	}{Patterns: raw.Patterns, Exclusions: raw.Exclusions}
	if out.Patterns == nil {
		out.Patterns = []yaml.Node{}
	}

	var encoded bytes.Buffer
	encoder := yaml.NewEncoder(&encoded)
	if err := encoder.Encode(&out); err != nil {
		return fmt.Errorf("config: marshal patterns: %w", err)
	}
	encoder.Close()

	return writeAtomically(path, encoded.Bytes())
}

func writeAtomically(path string, data []byte) error {
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

// CheckWritable reports whether the patterns file at path can be replaced by
// this process, with an explanation fit to show a user when it cannot.
// Saving writes a new file beside the old one and renames it into place, so
// what is needed is permission to create files in the directory.
func CheckWritable(path string) error {
	dir := filepath.Dir(path)

	probe, err := os.CreateTemp(dir, ".sentinel-write-test-*")
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("Sentinel is not allowed to write to %s, so patterns cannot be saved from here. "+
				"Run Sentinel as a user who owns that directory (it is usually root's), or edit %s by hand; "+
				"changes to the file are picked up without a restart", dir, path)
		}
		return fmt.Errorf("patterns cannot be saved to %s: %w", dir, err)
	}
	probe.Close()
	os.Remove(probe.Name())

	// The directory may be writable while an existing file is not ours to
	// replace on some filesystems; the rename would still succeed on the
	// usual ones, so that is not checked here.
	return nil
}

// PatternTemplate is the starting point for "New pattern from YAML". It is a
// complete, valid pattern that uses each part of the schema once, with the
// meaning of each part beside it.
const PatternTemplate = `# A pattern describes processes (roles), how they are related, and what
# they did. Change the name, then keep what you need and delete the rest.
# The full guide is docs/behavioral-patterns.md.
name: new-pattern
severity: MEDIUM            # INFO, LOW, MEDIUM, HIGH or CRITICAL
title: Short headline shown in the findings list
description: One sentence saying what happened and why it matters.

processes:
  # A role. "match" says which processes may fill it: name, exe, cmdline, user.
  - id: parent
    match:
      name: { in: [bash, sh, zsh] }
      user: { not: root }

  - id: child
    match:
      exe: { prefix: /tmp/ }
    # "events" says what the process must have done. "where" filters the
    # event: remote_addr, remote_port, domain, path, ... depending on type.
    events:
      - type: NETWORK_CONNECT
        where:
          remote_port: { not: { in: [80, 443] } }
      # A threshold: at least "count" matching events within "within",
      # optionally counting distinct values of one field.
      - type: DNS_QUERY
        count: 5
        within: 30s
        distinct: domain

# How the roles are related: SPAWNED (direct child) or DESCENDANT
# (within max_depth generations).
relationships:
  - { type: SPAWNED, parent: parent, child: child }

# Optional: events that must happen in this order. "capture" names an event
# so that a later step can compare against it with $name.field.
sequence:
  within: 60s
  steps:
    - { role: child, type: FILE_CREATE, capture: dropped }
    - role: child
      type: NETWORK_CONNECT

# Optional: never report when this role is filled by a process like this.
exclude:
  - role: child
    match:
      exe: /tmp/known-good-tool

max_findings_per_window: 20
`
