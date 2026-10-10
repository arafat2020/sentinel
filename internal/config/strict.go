package config

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// keys describes the keys a YAML mapping may have. A nil value marks a key
// whose content is not checked here: either it is a plain value, or (match
// and where blocks) its keys are field names, which are validated against
// the fields of the thing being matched when the pattern is compiled.
//
// A non-nil value describes the mapping under that key, or each mapping in
// the list under it.
type keys map[string]keys

var (
	matchKeys keys // field names; see above

	eventKeys = keys{"type": nil, "where": matchKeys, "count": nil, "within": nil, "distinct": nil}

	patternKeys = keys{
		"name":                    nil,
		"severity":                nil,
		"title":                   nil,
		"description":             nil,
		"max_findings_per_window": nil,
		"processes": {
			"id":         nil,
			"conditions": {"type": nil, "value": nil},
			"match":      matchKeys,
			"events":     eventKeys,
		},
		"relationships": {"type": nil, "parent": nil, "child": nil, "max_depth": nil},
		"exclude":       {"role": nil, "match": matchKeys},
		"sequence": {
			"within":          nil,
			"order_tolerance": nil,
			"steps":           {"role": nil, "type": nil, "where": matchKeys, "capture": nil},
		},
	}

	exclusionKeys = keys{"rules": nil, "match": matchKeys, "description": nil}

	topLevelKeys = keys{"patterns": nil, "exclusions": nil}
)

// checkKeys reports the first key in node, or in anything nested under it,
// that allowed does not provide for. The error gives the path to the key,
// for example "processes[1].mach".
func checkKeys(node *yaml.Node, allowed keys, path string) error {
	if node.Kind != yaml.MappingNode {
		return nil // the wrong shape is reported when the node is decoded
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]

		here := key
		if path != "" {
			here = path + "." + key
		}

		nested, known := allowed[key]
		if !known {
			return fmt.Errorf("%s: unknown key (valid keys here: %s)", here, strings.Join(sortedKeys(allowed), ", "))
		}
		if nested == nil {
			continue
		}

		switch value.Kind {
		case yaml.MappingNode:
			if err := checkKeys(value, nested, here); err != nil {
				return err
			}
		case yaml.SequenceNode:
			for j, item := range value.Content {
				if err := checkKeys(item, nested, fmt.Sprintf("%s[%d]", here, j)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// topLevelWarnings names the top-level keys of a patterns file that Sentinel
// does not use. They are warnings, not errors: nothing a pattern says is
// lost by ignoring them.
func topLevelWarnings(data []byte) []string {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) == 0 {
		return nil
	}

	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}

	var warnings []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		if key := root.Content[i].Value; !has(topLevelKeys, key) {
			warnings = append(warnings, fmt.Sprintf(
				"unknown top-level key %q ignored (valid keys: %s)", key, strings.Join(sortedKeys(topLevelKeys), ", ")))
		}
	}

	return warnings
}

func has(allowed keys, key string) bool {
	_, ok := allowed[key]
	return ok
}

func sortedKeys(allowed keys) []string {
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}
