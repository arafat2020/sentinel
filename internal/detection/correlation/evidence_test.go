package correlation

import (
	"fmt"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func eventTypes(events []core.Event) string {
	out := ""
	for i, e := range events {
		if i > 0 {
			out += ","
		}
		out += string(e.Type)
	}
	return out
}

func TestEvidenceNamesTheProcessInEachRole(t *testing.T) {
	h := newHarness(testWindow)
	parent, child := h.defaultPair()
	h.connect(parent, at(time.Second))
	h.connect(child, at(2*time.Second))

	findings := h.detect(at(3 * time.Second))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	evidence := findings[0].Evidence

	if len(evidence.Roles) != 2 ||
		evidence.Roles["parent"].Identity() != parent.Identity() ||
		evidence.Roles["child"].Identity() != child.Identity() {
		t.Fatalf("roles = %+v, want parent and child bound to their processes", evidence.Roles)
	}

	// The Phase 1 fields are unchanged.
	if len(evidence.Processes) != 2 || evidence.Processes[0].PID != parent.PID || evidence.Processes[1].PID != child.PID {
		t.Errorf("Processes = %+v", evidence.Processes)
	}
	if evidence.Process == nil || evidence.Process.PID != child.PID {
		t.Errorf("Process = %+v, want the last role", evidence.Process)
	}

	// One example event for each of the two requirements, in role order.
	if len(evidence.Events) != 2 ||
		evidence.Events[0].Process.PID != parent.PID || evidence.Events[1].Process.PID != child.PID ||
		eventTypes(evidence.Events) != "NETWORK_CONNECT,NETWORK_CONNECT" {
		t.Errorf("events = %s by %+v", eventTypes(evidence.Events), evidence.Events)
	}
}

func TestEvidenceEventsAreSequenceThenExamplesThenThresholds(t *testing.T) {
	h := newHarness(testWindow)

	pattern := BehaviorPattern{
		Name: "everything",
		Processes: []ProcessPattern{{
			ID:    "p",
			Match: block(fieldIs("name", Predicate{Eq: sp("tool")})),
			Events: []EventPattern{
				{Type: core.EventFileModify},                             // an ordinary requirement
				{Type: core.EventDNSQuery, Count: 3, Distinct: "domain"}, // a threshold
				{Type: core.EventNetworkClose},                           // another ordinary one
			},
		}},
		Sequence: &SequencePattern{Steps: []SequenceStep{
			step("p", core.EventNetworkConnect),
			step("p", core.EventFileCreate),
		}},
	}
	if err := pattern.ValidateFor(testWindow); err != nil {
		t.Fatal(err)
	}
	h.SetPatterns([]BehaviorPattern{pattern})

	p := proc(50, 1, "tool", at(0))
	h.start(p, at(0))
	for i := 0; i < 5; i++ {
		h.query(p, fmt.Sprintf("h%d.example", i), at(time.Second+time.Duration(i)*100*time.Millisecond))
	}
	h.feed(core.EventNetworkClose, p, at(2*time.Second))
	h.feed(core.EventFileModify, p, at(3*time.Second))
	h.connect(p, at(4*time.Second))
	h.fileCreate(p, "/tmp/x", at(5*time.Second))

	findings := h.detect(at(6 * time.Second))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}

	// Sequence steps in step order; then an example per ordinary
	// requirement in the order written; then the threshold's events, oldest
	// first.
	want := "NETWORK_CONNECT,FILE_CREATE," + "FILE_MODIFY,NETWORK_CLOSE," +
		"DNS_QUERY,DNS_QUERY,DNS_QUERY,DNS_QUERY,DNS_QUERY"
	events := findings[0].Evidence.Events
	if got := eventTypes(events); got != want {
		t.Fatalf("events = %s\n    want %s", got, want)
	}
	if events[4].DNS.Domain != "h0.example" || events[8].DNS.Domain != "h4.example" {
		t.Errorf("threshold events not oldest first: %s … %s", events[4].DNS.Domain, events[8].DNS.Domain)
	}
}

func TestEvidenceKeepsTenMostRecentThresholdEvents(t *testing.T) {
	h, p := newThresholdHarness(t, EventPattern{Type: core.EventDNSQuery, Count: 25})

	for i := 0; i < 40; i++ {
		h.query(p, fmt.Sprintf("q%02d.example", i), at(time.Second+time.Duration(i)*10*time.Millisecond))
	}

	findings := h.detect(at(2 * time.Second))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}

	events := findings[0].Evidence.Events
	if len(events) != thresholdEvidenceEvents {
		t.Fatalf("threshold evidence = %d events, want %d", len(events), thresholdEvidenceEvents)
	}
	if events[0].DNS.Domain != "q30.example" || events[9].DNS.Domain != "q39.example" {
		t.Errorf("evidence is %s … %s, want the ten most recent, oldest first", events[0].DNS.Domain, events[9].DNS.Domain)
	}
}

func TestEvidenceEventsAreCapped(t *testing.T) {
	h := newHarness(testWindow)

	// Eight thresholds of ten events each would be eighty.
	types := []core.EventType{
		core.EventDNSQuery, core.EventNetworkConnect, core.EventNetworkClose, core.EventFileCreate,
		core.EventFileModify, core.EventFileDelete, core.EventFileRename, core.EventProcessStart,
	}
	role := ProcessPattern{ID: "p", Match: block(fieldIs("name", Predicate{Eq: sp("busy")}))}
	for _, eventType := range types {
		role.Events = append(role.Events, EventPattern{Type: eventType, Count: 12})
	}
	h.SetPatterns([]BehaviorPattern{{Name: "busy", Processes: []ProcessPattern{role}}})

	p := proc(50, 1, "busy", at(0))
	for i := 0; i < 12; i++ {
		for _, eventType := range types {
			h.feed(eventType, p, at(time.Second+time.Duration(i)*time.Millisecond))
		}
	}

	findings := h.detect(at(2 * time.Second))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := len(findings[0].Evidence.Events); got != MaxEvidenceEvents {
		t.Fatalf("evidence holds %d events, want the cap of %d", got, MaxEvidenceEvents)
	}
}

func TestRateLimitSummaryHasNoRoleEvidence(t *testing.T) {
	h := newHarness(testWindow)
	pattern := DefaultPatterns()[0]
	pattern.MaxFindingsPerWindow = 1
	h.SetPatterns([]BehaviorPattern{pattern})

	h.spawnPairs(1000, 3, at(time.Second))
	h.detect(at(time.Second))

	summaries := h.detect(at(time.Second + testWindow))
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}
	if e := summaries[0].Evidence; len(e.Roles) != 0 || len(e.Events) != 0 || e.Process != nil {
		t.Errorf("summary carries evidence: %+v", e)
	}
}
