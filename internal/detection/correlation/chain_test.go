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
