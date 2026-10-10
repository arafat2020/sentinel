package correlation

import (
	"fmt"

	"github.com/arafat2020/sentinel/internal/core"
)

// processPredicate decides whether a process satisfies a match block.
type processPredicate func(*core.Process) bool

// eventPredicate decides whether an event satisfies a where block.
type eventPredicate func(*core.Event) bool

// field describes one matchable field of a T: what kind it is and how to
// read it. Exactly one of text and number is set, according to kind.
type field[T any] struct {
	kind fieldKind
	// text reads a string or address field. An empty result means the
	// value is missing.
	text func(*T) string
	// number reads a numeric field; ok is false when the part of the event
	// that carries it is absent.
	number func(*T) (value int64, ok bool)
}

// processFields are the fields a process match block may use.
var processFields = map[string]field[core.Process]{
	"name":    {kind: kindString, text: func(p *core.Process) string { return p.Name }},
	"exe":     {kind: kindString, text: func(p *core.Process) string { return p.Executable }},
	"cmdline": {kind: kindString, text: func(p *core.Process) string { return p.CommandLine }},
	"user":    {kind: kindString, text: func(p *core.Process) string { return p.User }},
}

var networkFields = map[string]field[core.Event]{
	"remote_addr": {kind: kindAddress, text: func(e *core.Event) string {
		if e.Network == nil {
			return ""
		}
		return e.Network.RemoteAddress
	}},
	"remote_port": {kind: kindNumber, number: func(e *core.Event) (int64, bool) {
		if e.Network == nil {
			return 0, false
		}
		return int64(e.Network.RemotePort), true
	}},
	"local_port": {kind: kindNumber, number: func(e *core.Event) (int64, bool) {
		if e.Network == nil {
			return 0, false
		}
		return int64(e.Network.LocalPort), true
	}},
	"protocol": {kind: kindString, text: func(e *core.Event) string {
		if e.Network == nil {
			return ""
		}
		return e.Network.Protocol
	}},
	"state": {kind: kindString, text: func(e *core.Event) string {
		if e.Network == nil {
			return ""
		}
		return e.Network.State
	}},
}

var dnsFields = map[string]field[core.Event]{
	"domain": {kind: kindString, text: func(e *core.Event) string {
		if e.DNS == nil {
			return ""
		}
		return e.DNS.Domain
	}},
	"query_type": {kind: kindString, text: func(e *core.Event) string {
		if e.DNS == nil {
			return ""
		}
		return e.DNS.Type
	}},
	"resolver": {kind: kindAddress, text: func(e *core.Event) string {
		if e.DNS == nil {
			return ""
		}
		return e.DNS.Resolver
	}},
}

var fileFields = map[string]field[core.Event]{
	"path": {kind: kindString, text: func(e *core.Event) string {
		if e.File == nil {
			return ""
		}
		return e.File.Path
	}},
	"old_path": {kind: kindString, text: func(e *core.Event) string {
		if e.File == nil {
			return ""
		}
		return e.File.OldPath
	}},
}

// eventFields returns the fields a where block may use for an event type, or
// nil for an event type that carries nothing to filter on.
func eventFields(eventType core.EventType) map[string]field[core.Event] {
	switch eventType {
	case core.EventNetworkConnect, core.EventNetworkClose:
		return networkFields
	case core.EventDNSQuery:
		return dnsFields
	case core.EventFileCreate, core.EventFileModify, core.EventFileDelete, core.EventFileRename:
		return fileFields
	default:
		return nil
	}
}

// compileProcessMatch compiles a process match block. path prefixes error
// messages, for example "match".
func compileProcessMatch(block *MatchBlock, path string) (processPredicate, error) {
	return compileBlock(block, processFields, path)
}

// compileEventWhere compiles a where block for events of the given type.
func compileEventWhere(block *MatchBlock, eventType core.EventType, path string) (eventPredicate, error) {
	fields := eventFields(eventType)
	if fields == nil && !block.IsEmpty() {
		return nil, fmt.Errorf("%s: %s events have no fields to filter on", path, eventType)
	}

	return compileBlock(block, fields, path)
}

// compileBlock compiles a match block against a field table. Every field
// predicate must hold, and if there are alternatives at least one of them
// must.
func compileBlock[T any](block *MatchBlock, fields map[string]field[T], path string) (func(*T) bool, error) {
	if block.IsEmpty() {
		return func(*T) bool { return true }, nil
	}

	var tests []func(*T) bool

	for _, fp := range block.Fields {
		where := path + "." + fp.Field

		f, known := fields[fp.Field]
		if !known {
			return nil, fmt.Errorf("%s: unknown field (valid fields: %s)", where, fieldNames(fields))
		}

		test, err := compileField(f, fp.Predicate)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		tests = append(tests, test)
	}

	if block.AnyOf != nil {
		if len(block.AnyOf) == 0 {
			return nil, fmt.Errorf("%s.any_of: needs at least one alternative", path)
		}

		alternatives := make([]func(*T) bool, len(block.AnyOf))
		for i := range block.AnyOf {
			alternative, err := compileBlock(&block.AnyOf[i], fields, fmt.Sprintf("%s.any_of[%d]", path, i))
			if err != nil {
				return nil, err
			}
			alternatives[i] = alternative
		}

		tests = append(tests, func(subject *T) bool {
			for _, alternative := range alternatives {
				if alternative(subject) {
					return true
				}
			}
			return false
		})
	}

	if len(tests) == 1 {
		return tests[0], nil
	}

	return func(subject *T) bool {
		for _, test := range tests {
			if !test(subject) {
				return false
			}
		}
		return true
	}, nil
}

func compileField[T any](f field[T], predicate Predicate) (func(*T) bool, error) {
	if f.kind == kindNumber {
		test, err := compileNumberPredicate(predicate)
		if err != nil {
			return nil, err
		}

		read := f.number
		return func(subject *T) bool {
			value, ok := read(subject)
			return test(value, ok)
		}, nil
	}

	test, err := compileStringPredicate(predicate, f.kind)
	if err != nil {
		return nil, err
	}

	read := f.text
	return func(subject *T) bool {
		value := read(subject)
		return test(value, value != "")
	}, nil
}
