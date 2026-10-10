package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestChainBuildsFromProcessEvents(t *testing.T) {
	now := time.Now()

	process := core.Process{
		PID:        100,
		StartTime:  now,
		Name:       "node",
		Executable: "/usr/local/bin/node",
	}

	processStart := core.Event{
		Timestamp: now,
		Type:      core.EventProcessStart,
		Process:   &process,
	}

	networkConnect := core.Event{
		Timestamp: now.Add(5 * time.Second),
		Type:      core.EventNetworkConnect,
		Process:   &process,
	}

	chain := NewChain(processStart)

	chain.Add(networkConnect)

	if len(chain.Events()) != 2 {
		t.Fatalf(
			"expected 2 events in chain, got %d",
			len(chain.Events()),
		)
	}

	if chain.Events()[0].Type != core.EventProcessStart {
		t.Fatalf(
			"expected first event to be PROCESS_START, got %s",
			chain.Events()[0].Type,
		)
	}

	if chain.Events()[1].Type != core.EventNetworkConnect {
		t.Fatalf(
			"expected second event to be NETWORK_CONNECT, got %s",
			chain.Events()[1].Type,
		)
	}
}

func TestChainRejectsEventFromDifferentProcess(t *testing.T) {
	now := time.Now()

	processA := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	processB := core.Process{
		PID:       200,
		StartTime: now,
		Name:      "python",
	}

	startEvent := core.Event{
		Timestamp: now,
		Type:      core.EventProcessStart,
		Process:   &processA,
	}

	otherEvent := core.Event{
		Timestamp: now.Add(time.Second),
		Type:      core.EventNetworkConnect,
		Process:   &processB,
	}

	chain := NewChain(startEvent)

	added := chain.Add(otherEvent)

	if added {
		t.Fatal("expected event from different process to be rejected")
	}

	if len(chain.Events()) != 1 {
		t.Fatalf(
			"expected chain to contain 1 event, got %d",
			len(chain.Events()),
		)
	}
}

func chainTypes(events []core.Event) []core.EventType {
	types := make([]core.EventType, len(events))
	for i, event := range events {
		types[i] = event.Type
	}
	return types
}

func sameTypes(got []core.EventType, want ...core.EventType) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestChainKeepsEventsInTimestampOrder(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	process := core.Process{PID: 100, StartTime: base}
	event := func(eventType core.EventType, offset time.Duration) core.Event {
		return core.Event{Type: eventType, Timestamp: base.Add(offset), Process: &process}
	}

	chain := NewChain(event(core.EventNetworkConnect, 5*time.Second))

	// Earlier than everything, in the middle, and two ties with an
	// existing timestamp.
	chain.Add(event(core.EventProcessStart, 0))
	chain.Add(event(core.EventDNSQuery, 3*time.Second))
	chain.Add(event(core.EventFileCreate, 5*time.Second))
	chain.Add(event(core.EventFileModify, 5*time.Second))
	chain.Add(event(core.EventProcessExit, 9*time.Second))

	got := chainTypes(chain.Events())
	if !sameTypes(got,
		core.EventProcessStart,
		core.EventDNSQuery,
		core.EventNetworkConnect, // ties keep arrival order
		core.EventFileCreate,
		core.EventFileModify,
		core.EventProcessExit,
	) {
		t.Fatalf("event order = %v", got)
	}
}

func TestChainEventsAfterAndPrune(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	process := core.Process{PID: 100, StartTime: base}

	chain := NewChain(core.Event{Type: core.EventProcessStart, Timestamp: base, Process: &process})
	for i := 1; i <= 4; i++ {
		chain.Add(core.Event{
			Type:      core.EventNetworkConnect,
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Process:   &process,
		})
	}

	// The cutoff itself is excluded.
	if got := len(chain.EventsAfter(base.Add(2 * time.Second))); got != 2 {
		t.Errorf("EventsAfter(+2s) = %d events, want 2", got)
	}
	if got := len(chain.EventsAfter(base.Add(-time.Second))); got != 5 {
		t.Errorf("EventsAfter(before all) = %d events, want 5", got)
	}
	if got := len(chain.EventsAfter(base.Add(time.Minute))); got != 0 {
		t.Errorf("EventsAfter(after all) = %d events, want 0", got)
	}
	if got := len(chain.Events()); got != 5 {
		t.Errorf("EventsAfter modified the chain: %d events", got)
	}

	if remaining := chain.Prune(base.Add(2 * time.Second)); remaining != 2 {
		t.Errorf("Prune(+2s) left %d events, want 2", remaining)
	}
	if first := chain.Events()[0].Timestamp; !first.Equal(base.Add(3 * time.Second)) {
		t.Errorf("oldest event after prune = %v", first)
	}
	if remaining := chain.Prune(base.Add(time.Minute)); remaining != 0 {
		t.Errorf("Prune(after all) left %d events, want 0", remaining)
	}
}

func TestChainCapsEachEventTypeSeparately(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	process := core.Process{PID: 100, StartTime: base}

	chain := NewChain(core.Event{Type: core.EventDNSQuery, Timestamp: base, Process: &process})
	for i := 1; i <= 3*MaxEventsPerType; i++ {
		chain.Add(core.Event{
			Type:      core.EventNetworkConnect,
			Timestamp: base.Add(time.Duration(i) * time.Millisecond),
			Process:   &process,
		})
	}

	events := chain.Events()
	if len(events) != MaxEventsPerType+1 {
		t.Fatalf("chain holds %d events, want %d", len(events), MaxEventsPerType+1)
	}
	if events[0].Type != core.EventDNSQuery {
		t.Fatal("the lone event of another type was evicted")
	}

	// The newest connects are the ones kept.
	oldestKept := base.Add(time.Duration(2*MaxEventsPerType+1) * time.Millisecond)
	if got := events[1].Timestamp; !got.Equal(oldestKept) {
		t.Errorf("oldest retained connect = %v, want %v", got, oldestKept)
	}
}
