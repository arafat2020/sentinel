package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/arafat2020/sentinel/internal/detection/correlation"
)

// This file converts match and where blocks between YAML and the
// correlation package's MatchBlock. The conversion is purely about shape:
// which operators a field accepts, and whether a regex or CIDR is
// well-formed, is decided when the pattern is validated.

const anyOfKey = "any_of"

// decodeMatchBlock converts a match or where mapping. A zero node, which is
// what an absent key decodes to, is an absent block. path prefixes error
// messages, for example "match".
func decodeMatchBlock(node *yaml.Node, path string) (*correlation.MatchBlock, error) {
	if node == nil || node.IsZero() || isNull(node) {
		return nil, nil
	}

	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: must be a mapping of field names to predicates", path)
	}

	block := &correlation.MatchBlock{}

	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]

		if key == anyOfKey {
			if value.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s.any_of: must be a list of match blocks", path)
			}

			// Written but empty is kept as such, so validation can say so.
			block.AnyOf = []correlation.MatchBlock{}
			for j, item := range value.Content {
				alternative, err := decodeMatchBlock(item, fmt.Sprintf("%s.any_of[%d]", path, j))
				if err != nil {
					return nil, err
				}
				if alternative == nil {
					alternative = &correlation.MatchBlock{}
				}
				block.AnyOf = append(block.AnyOf, *alternative)
			}
			continue
		}

		predicate, err := decodePredicate(value)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", path, key, err)
		}
		block.Fields = append(block.Fields, correlation.FieldPredicate{Field: key, Predicate: predicate})
	}

	return block, nil
}

// decodePredicate converts one field's value: an operator object, or the
// shorthand of a bare scalar (eq) or a bare list (in).
func decodePredicate(node *yaml.Node) (correlation.Predicate, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		value := scalarText(node)
		return correlation.Predicate{Eq: &value, Shorthand: true}, nil

	case yaml.SequenceNode:
		values, err := scalarList(node)
		if err != nil {
			return correlation.Predicate{}, err
		}
		return correlation.Predicate{In: values, Shorthand: true}, nil

	case yaml.MappingNode:
		return decodeOperators(node)

	default:
		return correlation.Predicate{}, fmt.Errorf("must be a value, a list, or an operator object")
	}
}

func decodeOperators(node *yaml.Node) (correlation.Predicate, error) {
	var p correlation.Predicate

	for i := 0; i+1 < len(node.Content); i += 2 {
		operator, value := node.Content[i].Value, node.Content[i+1]

		var target **string

		switch operator {
		case "eq":
			target = &p.Eq
		case "contains":
			target = &p.Contains
		case "prefix":
			target = &p.Prefix
		case "suffix":
			target = &p.Suffix
		case "glob":
			target = &p.Glob
		case "regex":
			target = &p.Regex
		case "gt":
			target = &p.Gt
		case "gte":
			target = &p.Gte
		case "lt":
			target = &p.Lt
		case "lte":
			target = &p.Lte

		case "in":
			values, err := listOf(operator, value)
			if err != nil {
				return p, err
			}
			p.In = values
			continue

		case "cidr":
			// One network may be written without the list.
			if value.Kind == yaml.ScalarNode {
				p.CIDR = []string{scalarText(value)}
				continue
			}
			values, err := listOf(operator, value)
			if err != nil {
				return p, err
			}
			p.CIDR = values
			continue

		case "not":
			inner, err := decodePredicate(value)
			if err != nil {
				return p, fmt.Errorf("not: %w", err)
			}
			p.Not = &inner
			continue

		case "nocase":
			if err := value.Decode(&p.NoCase); err != nil {
				return p, fmt.Errorf(`"nocase" must be true or false`)
			}
			continue

		default:
			return p, fmt.Errorf("unknown operator %q", operator)
		}

		if value.Kind != yaml.ScalarNode {
			return p, fmt.Errorf("%q needs a single value", operator)
		}
		text := scalarText(value)
		*target = &text
	}

	return p, nil
}

func listOf(operator string, node *yaml.Node) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%q needs a list", operator)
	}
	return scalarList(node)
}

// scalarList reads a list of scalars. The result is non-nil even when the
// list is empty, which is how "written but empty" is told from "absent".
func scalarList(node *yaml.Node) ([]string, error) {
	values := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("list entries must be plain values")
		}
		values = append(values, scalarText(item))
	}
	return values, nil
}

func isNull(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

// scalarText returns a scalar as written. A null (an empty value) is the
// empty string.
func scalarText(node *yaml.Node) string {
	if isNull(node) {
		return ""
	}
	return node.Value
}

// encodeMatchBlock converts a block back to YAML, in the shape it was
// written: shorthand stays shorthand, operator objects stay objects. A nil
// block encodes to the zero node, which is left out of the output.
func encodeMatchBlock(block *correlation.MatchBlock) yaml.Node {
	if block == nil {
		return yaml.Node{}
	}

	node := yaml.Node{Kind: yaml.MappingNode}

	for _, fp := range block.Fields {
		node.Content = append(node.Content, scalarNode(fp.Field), encodePredicate(fp.Predicate))
	}

	if block.AnyOf != nil {
		alternatives := &yaml.Node{Kind: yaml.SequenceNode}
		for i := range block.AnyOf {
			alternative := encodeMatchBlock(&block.AnyOf[i])
			alternatives.Content = append(alternatives.Content, &alternative)
		}
		node.Content = append(node.Content, scalarNode(anyOfKey), alternatives)
	}

	return node
}

func encodePredicate(p correlation.Predicate) *yaml.Node {
	if p.Shorthand && isShorthand(p) {
		if p.Eq != nil {
			return scalarNode(*p.Eq)
		}
		return listNode(p.In)
	}

	// Operator objects are short; one line each reads best.
	node := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
	add := func(key string, value *yaml.Node) {
		node.Content = append(node.Content, scalarNode(key), value)
	}

	for _, scalar := range []struct {
		key   string
		value *string
	}{
		{"eq", p.Eq}, {"contains", p.Contains}, {"prefix", p.Prefix}, {"suffix", p.Suffix},
		{"glob", p.Glob}, {"regex", p.Regex},
		{"gt", p.Gt}, {"gte", p.Gte}, {"lt", p.Lt}, {"lte", p.Lte},
	} {
		if scalar.value != nil {
			add(scalar.key, scalarNode(*scalar.value))
		}
	}

	if p.In != nil {
		add("in", listNode(p.In))
	}
	if p.CIDR != nil {
		add("cidr", listNode(p.CIDR))
	}
	if p.Not != nil {
		add("not", encodePredicate(*p.Not))
	}
	if p.NoCase {
		add("nocase", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}

	return node
}

// isShorthand reports whether a predicate is exactly what the shorthand can
// express: eq alone, or in alone.
func isShorthand(p correlation.Predicate) bool {
	others := p.Contains != nil || p.Prefix != nil || p.Suffix != nil || p.Glob != nil ||
		p.Regex != nil || p.CIDR != nil || p.Gt != nil || p.Gte != nil || p.Lt != nil ||
		p.Lte != nil || p.Not != nil || p.NoCase

	return !others && ((p.Eq != nil) != (p.In != nil))
}

func scalarNode(value string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: value}
	if value == "" {
		// Without a tag an empty scalar is written as nothing at all.
		node.Tag = "!!str"
		node.Style = yaml.DoubleQuotedStyle
	}
	return node
}

func listNode(values []string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, value := range values {
		node.Content = append(node.Content, scalarNode(value))
	}
	return node
}
