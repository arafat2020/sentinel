package correlation

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// thresholdPattern is one role whose process must meet one counting
// requirement.
func thresholdPattern(event EventPattern) []BehaviorPattern {
	return []BehaviorPattern{{
		Name:      "threshold",
		Processes: []ProcessPattern{{ID: "p", Match: block(fieldIs("name", Predicate{Eq: sp("dig")})), Events: []EventPattern{event}}},
	}}
}

func newThresholdHarness(t *testing.T, event EventPattern) (*harness, core.Process) {
	t.Helper()

	patterns := thresholdPattern(event)
	if err := patterns[0].ValidateFor(testWindow); err != nil {
		t.Fatalf("pattern does not validate: %v", err)
	}

	h := newHarness(testWindow)
	h.SetPatterns(patterns)

	p := proc(50, 1, "dig", at(0))
	h.start(p, at(0))
	return h, p
}

func TestThresholdCountBoundary(t *testing.T) {
	const count = 5

	for sent, want := range map[int]int{count - 1: 0, count: 1, count + 3: 1} {
		h, p := newThresholdHarness(t, EventPattern{Type: core.EventDNSQuery, Count: count})

		for i := 0; i < sent; i++ {
			h.query(p, "example.com", at(time.Duration(i+1)*time.Second))
		}

		if got := h.detect(at(10 * time.Second)); len(got) != want {
			t.Errorf("%d of %d events: findings = %d, want %d", sent, count, len(got), want)
		}
	}
}

func TestThresholdOnlyCountsEventsPassingWhere(t *testing.T) {
	h, p := newThresholdHarness(t, EventPattern{
		Type:  core.EventDNSQuery,
		Count: 3,
		Where: block(fieldIs("domain", Predicate{Suffix: sp(".example")})),
	})

	// Plenty of queries, but only two that pass the filter.
	for i := 0; i < 20; i++ {
		h.query(p, "other.org", at(time.Duration(i)*100*time.Millisecond))
	}
	h.query(p, "a.example", at(3*time.Second))
	h.query(p, "b.example", at(4*time.Second))
	if got := h.detect(at(5 * time.Second)); len(got) != 0 {
		t.Fatalf("findings with two matching events = %d, want 0", len(got))
	}

	h.query(p, "c.example", at(6*time.Second))
	if got := h.detect(at(6 * time.Second)); len(got) != 1 {
		t.Fatalf("findings with three matching events = %d, want 1", len(got))
	}
}

// within is a sliding span, not a fixed bucket: the events must be close
// together, wherever in the window that happens.
func TestThresholdWithinSlides(t *testing.T) {
	requirement := EventPattern{Type: core.EventDNSQuery, Count: 3, Within: 5 * time.Second}

	cases := []struct {
		name  string
		times []time.Duration
		want  int
	}{
		{"three inside the span", []time.Duration{1 * time.Second, 3 * time.Second, 5 * time.Second}, 1},
		{"exactly the span apart is outside it", []time.Duration{1 * time.Second, 3 * time.Second, 6 * time.Second}, 0},
		{"just inside", []time.Duration{1 * time.Second, 3 * time.Second, 6*time.Second - time.Nanosecond}, 1},
		{"spread too thin", []time.Duration{1 * time.Second, 5 * time.Second, 9 * time.Second, 13 * time.Second}, 0},
		{"a late burst qualifies", []time.Duration{1 * time.Second, 9 * time.Second, 15 * time.Second, 16 * time.Second, 17 * time.Second}, 1},
		{"a burst straddling a bucket boundary", []time.Duration{4 * time.Second, 5 * time.Second, 6 * time.Second}, 1},
	}

	for _, c := range cases {
		h, p := newThresholdHarness(t, requirement)
		for _, ts := range c.times {
			h.query(p, "example.com", at(ts))
		}
		if got := h.detect(at(20 * time.Second)); len(got) != c.want {
			t.Errorf("%s: findings = %d, want %d", c.name, len(got), c.want)
		}
	}
}

// A span that met the requirement keeps it met while the span's end is in
// the correlation window, even if later events are sparse.
func TestThresholdStaysMetUntilItsSpanLeavesTheWindow(t *testing.T) {
	h, p := newThresholdHarness(t, EventPattern{Type: core.EventDNSQuery, Count: 3, Within: 2 * time.Second})

	for _, ts := range []time.Duration{1 * time.Second, 2 * time.Second, 2500 * time.Millisecond} {
		h.query(p, "example.com", at(ts))
	}
	// Sparse events afterwards replace the burst in the counter.
	h.query(p, "example.com", at(10*time.Second))
	h.query(p, "example.com", at(18*time.Second))

	if got := h.detect(at(20 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1: the burst ended inside the window", len(got))
	}

	// The burst ended at 2.5s; one window later it no longer counts.
	h.SetPatterns(h.patternsForTest())
	h.query(p, "example.com", at(2500*time.Millisecond+testWindow))
	if got := h.detect(at(2500*time.Millisecond + testWindow)); len(got) != 0 {
		t.Fatalf("findings after the burst left the window = %d, want 0", len(got))
	}
}

func TestThresholdDistinctIgnoresRepeats(t *testing.T) {
	requirement := EventPattern{Type: core.EventDNSQuery, Count: 4, Distinct: "domain", Within: 20 * time.Second}

	h, p := newThresholdHarness(t, requirement)

	// Many queries, three distinct domains.
	for i := 0; i < 30; i++ {
		h.query(p, fmt.Sprintf("host%d.example", i%3), at(time.Duration(i)*100*time.Millisecond))
	}
	if got := h.detect(at(4 * time.Second)); len(got) != 0 {
		t.Fatalf("findings with 3 distinct domains = %d, want 0", len(got))
	}

	h.query(p, "host3.example", at(5*time.Second))
	if got := h.detect(at(5 * time.Second)); len(got) != 1 {
		t.Fatalf("findings with 4 distinct domains = %d, want 1", len(got))
	}
}

func TestThresholdDistinctNeedsValuesInsideTheSpan(t *testing.T) {
	requirement := EventPattern{Type: core.EventDNSQuery, Count: 3, Distinct: "domain", Within: 5 * time.Second}

	// Three distinct domains, but the first was last seen too long ago.
	h, p := newThresholdHarness(t, requirement)
	h.query(p, "a.example", at(1*time.Second))
	h.query(p, "b.example", at(8*time.Second))
	h.query(p, "c.example", at(9*time.Second))
	if got := h.detect(at(10 * time.Second)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0: a.example is outside the span", len(got))
	}

	// Seeing it again brings it back into the span.
	h.query(p, "a.example", at(11*time.Second))
	if got := h.detect(at(11 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestThresholdDistinctOnNumericField(t *testing.T) {
	h, p := newThresholdHarness(t, EventPattern{Type: core.EventNetworkConnect, Count: 3, Distinct: "remote_port"})

	for i, port := range []uint32{22, 22, 23, 23, 22} {
		h.connectTo(p, "203.0.113.9", port, at(time.Duration(i+1)*time.Second))
	}
	if got := h.detect(at(6 * time.Second)); len(got) != 0 {
		t.Fatalf("findings with 2 distinct ports = %d, want 0", len(got))
	}

	h.connectTo(p, "203.0.113.9", 0, at(7*time.Second)) // port 0 is a value like any other
	if got := h.detect(at(7 * time.Second)); len(got) != 1 {
		t.Fatalf("findings with 3 distinct ports = %d, want 1", len(got))
	}
}

// A threshold must not depend on how many events a chain retains: it counts
// far more events than the per-type cap.
func TestThresholdCountsBeyondTheChainCap(t *testing.T) {
	const count = 5 * MaxEventsPerType

	h, p := newThresholdHarness(t, EventPattern{Type: core.EventDNSQuery, Count: count, Distinct: "domain"})

	for i := 0; i < count; i++ {
		h.query(p, fmt.Sprintf("x%d.tunnel.example", i), at(time.Second+time.Duration(i)*time.Millisecond))
	}

	if n := len(h.chains[p.Identity()][0].Events()); n > MaxEventsPerType+1 {
		t.Fatalf("chain holds %d events; the cap should have applied", n)
	}
	if got := h.detect(at(3 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestThresholdCountersOnlyForProcessesThatCouldFillTheRole(t *testing.T) {
	h, p := newThresholdHarness(t, EventPattern{Type: core.EventDNSQuery, Count: 3})

	other := proc(60, 1, "curl", at(0)) // does not satisfy the role's match
	h.start(other, at(0))
	for i := 0; i < 10; i++ {
		h.query(other, "example.com", at(time.Duration(i+1)*100*time.Millisecond))
	}
	if n := h.Metrics().ThresholdCounters; n != 0 {
		t.Fatalf("%d counter(s) created for a process that cannot fill the role", n)
	}

	h.query(p, "example.com", at(2*time.Second))
	if n := h.Metrics().ThresholdCounters; n != 1 {
		t.Fatalf("counters = %d, want 1", n)
	}

	// Other event types never touch the counter either.
	h.connect(p, at(3*time.Second))
	if n := h.Metrics().ThresholdCounters; n != 1 {
		t.Fatalf("counters = %d, want 1", n)
	}
}

func TestThresholdCountersAreEvictedByTheSweep(t *testing.T) {
	h, p := newThresholdHarness(t, EventPattern{Type: core.EventDNSQuery, Count: 3})

	h.query(p, "example.com", at(time.Second))
	h.query(p, "example.com", at(2*time.Second))
	if m := h.Metrics(); m.ThresholdCounters != 1 || m.ThresholdCountersEvicted != 0 {
		t.Fatalf("metrics = %+v, want one live counter", m)
	}

	// Still inside the window: kept.
	h.detect(at(20 * time.Second))
	if m := h.Metrics(); m.ThresholdCounters != 1 {
		t.Fatalf("counter evicted while its events were in the window: %+v", m)
	}

	// A full window after its last event: released.
	h.detect(at(2*time.Second + 2*testWindow))
	if m := h.Metrics(); m.ThresholdCounters != 0 || m.ThresholdCountersEvicted != 1 {
		t.Fatalf("metrics = %+v, want the counter evicted", m)
	}

	// And it starts from nothing: the two old events do not count.
	later := 2*time.Second + 2*testWindow + time.Second
	h.query(p, "example.com", at(later))
	if got := h.detect(at(later)); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestThresholdCounterCapIsEnforcedAndCounted(t *testing.T) {
	h := newHarness(time.Hour)
	patterns := []BehaviorPattern{{
		Name:      "many",
		Processes: []ProcessPattern{{ID: "p", Events: []EventPattern{{Type: core.EventDNSQuery, Count: 2}}}},
	}}
	h.SetPatterns(patterns)

	// One more process than there may be counters, each with one event.
	for i := 0; i <= maxThresholdCounters; i++ {
		p := proc(int32(1000+i), 1, "any", at(0))
		h.query(p, "example.com", at(time.Second+time.Duration(i)*time.Microsecond))
	}

	m := h.Metrics()
	if m.ThresholdCounters != maxThresholdCounters {
		t.Fatalf("counters = %d, want the cap of %d", m.ThresholdCounters, maxThresholdCounters)
	}
	if m.ThresholdCounterCapHits != 1 {
		t.Fatalf("cap hits = %d, want 1", m.ThresholdCounterCapHits)
	}

	// A process that already has a counter is unaffected by the cap.
	first := proc(1000, 1, "any", at(0))
	h.query(first, "example.com", at(2*time.Second))
	if got := h.detect(at(2 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if after := h.Metrics().ThresholdCounterCapHits; after != 1 {
		t.Fatalf("cap hits = %d, want still 1", after)
	}
}

func TestThresholdAlongsidePlainRequirementAndRelationship(t *testing.T) {
	h := newHarness(testWindow)
	h.SetPatterns([]BehaviorPattern{{
		Name: "beaconing-child",
		Processes: []ProcessPattern{
			named("parent", "node"),
			{
				ID:    "child",
				Match: block(fieldIs("name", Predicate{Eq: sp("python")})),
				Events: []EventPattern{
					{Type: core.EventNetworkConnect, Count: 3, Within: 10 * time.Second},
					{Type: core.EventDNSQuery}, // and at least one lookup
				},
			},
		},
		Relationships: []RelationshipPattern{spawned("parent", "child")},
	}})

	_, child := h.defaultPair()
	for i := 0; i < 3; i++ {
		h.connect(child, at(time.Duration(i+1)*time.Second))
	}
	if got := h.detect(at(4 * time.Second)); len(got) != 0 {
		t.Fatalf("findings without the DNS query = %d, want 0", len(got))
	}

	h.query(child, "example.com", at(5*time.Second))
	if got := h.detect(at(5 * time.Second)); len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
}

func TestThresholdWorksWithoutAnEngine(t *testing.T) {
	base := at(0)
	p := core.Process{PID: 1, StartTime: base, Name: "dig"}

	var chain *Chain
	for i := 0; i < 4; i++ {
		event := core.Event{
			Type: core.EventDNSQuery, Timestamp: base.Add(time.Duration(i) * time.Second), Process: &p,
			DNS: &core.DNSQuery{Domain: fmt.Sprintf("h%d.example", i%2)},
		}
		if chain == nil {
			chain = NewChain(event)
		} else {
			chain.Add(event)
		}
	}

	matcher := NewMatcher()
	four := ProcessPattern{ID: "p", Events: []EventPattern{{Type: core.EventDNSQuery, Count: 4}}}
	five := ProcessPattern{ID: "p", Events: []EventPattern{{Type: core.EventDNSQuery, Count: 5}}}
	threeDistinct := ProcessPattern{ID: "p", Events: []EventPattern{{Type: core.EventDNSQuery, Count: 3, Distinct: "domain"}}}

	if !matcher.MatchEvents(four, chain) || matcher.MatchEvents(five, chain) || matcher.MatchEvents(threeDistinct, chain) {
		t.Errorf("MatchEvents: four=%v five=%v threeDistinct=%v, want true false false",
			matcher.MatchEvents(four, chain), matcher.MatchEvents(five, chain), matcher.MatchEvents(threeDistinct, chain))
	}
	if matcher.MatchEventsAfter(four, chain, base.Add(500*time.Millisecond)) {
		t.Error("MatchEventsAfter counted an event before the cutoff")
	}
}

func TestThresholdValidation(t *testing.T) {
	role := func(event EventPattern) BehaviorPattern {
		return BehaviorPattern{Name: "p", Processes: []ProcessPattern{{ID: "r", Events: []EventPattern{event}}}}
	}

	valid := map[string]EventPattern{
		"count only":             {Type: core.EventDNSQuery, Count: 100},
		"count and within":       {Type: core.EventDNSQuery, Count: 100, Within: time.Minute},
		"distinct only":          {Type: core.EventDNSQuery, Distinct: "domain"},
		"distinct and within":    {Type: core.EventDNSQuery, Distinct: "domain", Within: time.Minute},
		"within the full window": {Type: core.EventDNSQuery, Count: 2, Within: DefaultWindow},
		"count of one":           {Type: core.EventDNSQuery, Count: 1},
		"largest count":          {Type: core.EventDNSQuery, Count: MaxThresholdCount},
		"distinct numeric field": {Type: core.EventNetworkConnect, Count: 5, Distinct: "remote_port"},
		"distinct address field": {Type: core.EventNetworkConnect, Count: 5, Distinct: "remote_addr"},
		"distinct process field": {Type: core.EventProcessStart, Count: 2, Distinct: "exe"},
	}
	for name, event := range valid {
		if err := role(event).Validate(); err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
		}
	}

	invalid := map[string]struct {
		event EventPattern
		want  []string
	}{
		"negative count":                 {EventPattern{Type: core.EventDNSQuery, Count: -1}, []string{`role "r"`, "events[0] (DNS_QUERY)", "count must be at least 1"}},
		"count too large":                {EventPattern{Type: core.EventDNSQuery, Count: MaxThresholdCount + 1}, []string{"events[0] (DNS_QUERY)", "count must be at most 1000"}},
		"within longer than window":      {EventPattern{Type: core.EventDNSQuery, Count: 2, Within: DefaultWindow + time.Second}, []string{"events[0] (DNS_QUERY)", "within must be more than 0 and at most the correlation window (5m0s)"}},
		"negative within":                {EventPattern{Type: core.EventDNSQuery, Count: 2, Within: -time.Second}, []string{"within must be more than 0"}},
		"within without count":           {EventPattern{Type: core.EventDNSQuery, Within: time.Minute}, []string{"events[0] (DNS_QUERY)", "within needs a count above 1 or distinct"}},
		"within with count of one":       {EventPattern{Type: core.EventDNSQuery, Count: 1, Within: time.Minute}, []string{"within needs a count above 1 or distinct"}},
		"distinct field of another type": {EventPattern{Type: core.EventDNSQuery, Count: 2, Distinct: "remote_port"}, []string{"events[0] (DNS_QUERY)", `distinct: "remote_port" is not a field of DNS_QUERY events`, "domain"}},
		"distinct unknown field":         {EventPattern{Type: core.EventNetworkConnect, Count: 2, Distinct: "colour"}, []string{`distinct: "colour" is not a field of NETWORK_CONNECT events`}},
	}
	for name, c := range invalid {
		err := role(c.event).Validate()
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		for _, want := range c.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q does not mention %q", name, err, want)
			}
		}
	}

	// The limit on within follows the engine's own window.
	tight := role(EventPattern{Type: core.EventDNSQuery, Count: 2, Within: time.Minute})
	if err := tight.ValidateFor(30 * time.Second); err == nil || !strings.Contains(err.Error(), "(30s)") {
		t.Errorf("ValidateFor(30s) error = %v, want within rejected against a 30s window", err)
	}
}
