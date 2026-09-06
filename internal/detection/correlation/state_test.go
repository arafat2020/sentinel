package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestStateStoresEventsByProcess(t *testing.T) {
	state := NewState()

	process := core.Process{
		PID:        100,
		StartTime:  time.Now(),
		Name:       "node",
		Executable: "/usr/local/bin/node",
	}

	event := core.Event{
		Timestamp: time.Now(),
		Type:      core.EventProcessStart,
		Process:   &process,
	}

	state.Add(event)

	events := state.EventsForProcess(process.Identity())

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Type != core.EventProcessStart {
		t.Fatalf(
			"expected PROCESS_START, got %s",
			events[0].Type,
		)
	}
}

func TestStateExpiresOldEvents(t *testing.T) {
	now := time.Date(
		2026,
		1,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	state := NewStateWithWindow(30 * time.Second)

	process := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	oldEvent := core.Event{
		Timestamp: now,
		Type:      core.EventProcessStart,
		Process:   &process,
	}

	recentEvent := core.Event{
		Timestamp: now.Add(15 * time.Second),
		Type:      core.EventNetworkConnect,
		Process:   &process,
	}

	state.Add(oldEvent)
	state.Add(recentEvent)

	events := state.EventsForProcessAt(
		process.Identity(),
		now.Add(40*time.Second),
	)

	if len(events) != 1 {
		t.Fatalf(
			"expected 1 recent event, got %d",
			len(events),
		)
	}

	if events[0].Type != core.EventNetworkConnect {
		t.Fatalf(
			"expected NETWORK_CONNECT, got %s",
			events[0].Type,
		)
	}
}
