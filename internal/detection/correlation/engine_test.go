package correlation

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestEngineCorrelatesEventsForSameProcess(t *testing.T) {
	now := time.Now()

	process := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
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

	engine := NewEngine(30 * time.Second)

	engine.Process(processStart)
	engine.Process(networkConnect)

	chains := engine.ChainsForProcess(process.Identity())

	if len(chains) != 1 {
		t.Fatalf(
			"expected 1 chain, got %d",
			len(chains),
		)
	}

	events := chains[0].Events()

	if len(events) != 2 {
		t.Fatalf(
			"expected chain to contain 2 events, got %d",
			len(events),
		)
	}

	if events[0].Type != core.EventProcessStart {
		t.Fatalf(
			"expected first event to be PROCESS_START, got %s",
			events[0].Type,
		)
	}

	if events[1].Type != core.EventNetworkConnect {
		t.Fatalf(
			"expected second event to be NETWORK_CONNECT, got %s",
			events[1].Type,
		)
	}
}

func TestEngineKeepsDifferentProcessesInSeparateChains(t *testing.T) {
	now := time.Now()

	parent := core.Process{
		PID:       100,
		StartTime: now,
		Name:      "node",
	}

	child := core.Process{
		PID:       200,
		PPID:      100,
		StartTime: now.Add(time.Second),
		Name:      "python",
	}

	parentStart := core.Event{
		Timestamp: now,
		Type:      core.EventProcessStart,
		Process:   &parent,
	}

	childStart := core.Event{
		Timestamp: now.Add(2 * time.Second),
		Type:      core.EventProcessStart,
		Process:   &child,
	}

	engine := NewEngine(30 * time.Second)

	engine.Process(parentStart)
	engine.Process(childStart)

	parentChains := engine.ChainsForProcess(parent.Identity())
	childChains := engine.ChainsForProcess(child.Identity())

	if len(parentChains) != 1 {
		t.Fatalf(
			"expected 1 parent chain, got %d",
			len(parentChains),
		)
	}

	if len(childChains) != 1 {
		t.Fatalf(
			"expected 1 child chain, got %d",
			len(childChains),
		)
	}

	if len(parentChains[0].Events()) != 1 {
		t.Fatalf(
			"expected parent chain to contain 1 event, got %d",
			len(parentChains[0].Events()),
		)
	}

	if len(childChains[0].Events()) != 1 {
		t.Fatalf(
			"expected child chain to contain 1 event, got %d",
			len(childChains[0].Events()),
		)
	}
}
