package correlation

import (
	"strings"
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

func whereMatches(t *testing.T, eventType core.EventType, event core.Event, fields ...FieldPredicate) bool {
	t.Helper()
	test, err := compileEventWhere(block(fields...), eventType, "where")
	if err != nil {
		t.Fatalf("compile %v: %v", fields, err)
	}
	return test(&event)
}

// direction, result and the transfer figures are fields of network events.
// A collector that cannot tell leaves them unset, and they then behave as any
// missing value does.
func TestNetworkDirectionResultAndTransferFields(t *testing.T) {
	failed := core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{
		RemoteAddress: "203.0.113.9", RemotePort: 4444, Direction: core.DirectionOutbound, Result: core.ResultRefused,
	}}
	accepted := core.Event{Type: core.EventNetworkConnect, Network: &core.NetworkConnection{
		RemoteAddress: "198.51.100.7", RemotePort: 51000, LocalPort: 22, Direction: core.DirectionInbound, Result: core.ResultOK,
	}}
	closed := core.Event{Type: core.EventNetworkClose, Network: &core.NetworkConnection{
		RemoteAddress: "203.0.113.9", RemotePort: 443, Direction: core.DirectionOutbound, Result: core.ResultOK,
		Transfer: &core.NetworkTransfer{BytesSent: 5_000_000, BytesReceived: 1200, DurationMs: 42_000},
	}}
	// As the poll collector reports a connection: nothing about how it came
	// to be or what it carried.
	polled := core.Event{Type: core.EventNetworkClose, Network: &core.NetworkConnection{RemoteAddress: "203.0.113.9", RemotePort: 443}}

	cases := []struct {
		name   string
		event  core.Event
		fields []FieldPredicate
		want   bool
	}{
		{"outbound", failed, []FieldPredicate{fieldIs("direction", Predicate{Eq: sp("outbound")})}, true},
		{"inbound is not outbound", accepted, []FieldPredicate{fieldIs("direction", Predicate{Eq: sp("outbound")})}, false},
		{"refused", failed, []FieldPredicate{fieldIs("result", Predicate{Eq: sp("refused")})}, true},
		{"any failure", failed, []FieldPredicate{fieldIs("result", Predicate{Not: &Predicate{Eq: sp("ok")}})}, true},
		{"result in a list", accepted, []FieldPredicate{fieldIs("result", Predicate{In: []string{"refused", "timeout", "unreachable"}})}, false},
		{"inbound to ssh", accepted, []FieldPredicate{fieldIs("direction", Predicate{Eq: sp("inbound")}), fieldIs("local_port", Predicate{Eq: sp("22")})}, true},

		{"large upload", closed, []FieldPredicate{fieldIs("bytes_sent", Predicate{Gte: sp("1000000")})}, true},
		{"small download", closed, []FieldPredicate{fieldIs("bytes_received", Predicate{Lt: sp("4096")})}, true},
		{"long lived", closed, []FieldPredicate{fieldIs("duration_ms", Predicate{Gt: sp("30000")})}, true},
		{"not that long", closed, []FieldPredicate{fieldIs("duration_ms", Predicate{Gt: sp("60000")})}, false},
		{"exfiltration shape", closed, []FieldPredicate{
			fieldIs("direction", Predicate{Eq: sp("outbound")}),
			fieldIs("bytes_sent", Predicate{Gt: sp("1000000")}),
			fieldIs("bytes_received", Predicate{Lt: sp("100000")}),
		}, true},
		// A connect event has no transfer figures yet.
		{"bytes on a connect event", failed, []FieldPredicate{fieldIs("bytes_sent", Predicate{Gte: sp("0")})}, false},

		// Missing values: every positive operator is false, eq "" is true,
		// and so is the negation of a positive operator.
		{"polled: direction eq", polled, []FieldPredicate{fieldIs("direction", Predicate{Eq: sp("outbound")})}, false},
		{"polled: direction is missing", polled, []FieldPredicate{fieldIs("direction", Predicate{Eq: sp("")})}, true},
		{"polled: result not ok", polled, []FieldPredicate{fieldIs("result", Predicate{Not: &Predicate{Eq: sp("ok")}})}, true},
		{"polled: bytes gt", polled, []FieldPredicate{fieldIs("bytes_sent", Predicate{Gt: sp("0")})}, false},
		{"polled: bytes lt", polled, []FieldPredicate{fieldIs("bytes_sent", Predicate{Lt: sp("10")})}, false},
		{"polled: not bytes gt", polled, []FieldPredicate{fieldIs("bytes_sent", Predicate{Not: &Predicate{Gt: sp("0")}})}, true},
		{"polled: duration", polled, []FieldPredicate{fieldIs("duration_ms", Predicate{Lte: sp("5")})}, false},
	}

	for _, c := range cases {
		if got := whereMatches(t, c.event.Type, c.event, c.fields...); got != c.want {
			t.Errorf("%s: matched = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNetworkFieldValidation(t *testing.T) {
	cases := map[string]struct {
		field FieldPredicate
		want  string
	}{
		"number operator on direction": {fieldIs("direction", Predicate{Gt: sp("1")}), `operator "gt" is not valid for a string field`},
		"text where bytes are wanted":  {fieldIs("bytes_sent", Predicate{Eq: sp("lots")}), `needs an integer`},
		"string operator on duration":  {fieldIs("duration_ms", Predicate{Prefix: sp("1")}), `is not valid for a numeric field`},
		"misspelt field": {fieldIs("bytes_recieved", Predicate{Gt: sp("1")}),
			"unknown field (valid fields: bytes_received, bytes_sent, direction, duration_ms, local_port, protocol, remote_addr, remote_port, result, state)"},
	}

	for name, c := range cases {
		for _, eventType := range []core.EventType{core.EventNetworkConnect, core.EventNetworkClose} {
			_, err := compileEventWhere(block(c.field), eventType, "where")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s (%s): error = %v, want it to mention %q", name, eventType, err, c.want)
			}
		}
	}

	// The new fields belong to network events only.
	if _, err := compileEventWhere(block(fieldIs("direction", Predicate{Eq: sp("outbound")})), core.EventDNSQuery, "where"); err == nil {
		t.Error("direction was accepted on a DNS_QUERY")
	}

	// A sequence step can capture a connection and a later step compare
	// against what it carried.
	pattern := BehaviorPattern{
		Name:      "p",
		Processes: []ProcessPattern{{ID: "p"}},
		Sequence: &SequencePattern{Steps: []SequenceStep{
			{Role: "p", Type: core.EventNetworkClose, Capture: "first", Where: block(fieldIs("direction", Predicate{Eq: sp("outbound")}))},
			{Role: "p", Type: core.EventNetworkConnect, Where: block(fieldIs("remote_addr", Predicate{Eq: sp("$first.remote_addr")}), fieldIs("result", Predicate{Eq: sp("ok")}))},
		}},
	}
	if err := pattern.ValidateFor(testWindow); err != nil {
		t.Errorf("a sequence using the new fields is rejected: %v", err)
	}
}
