package network

import (
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestLifecycleDetectorIgnoresInitialSnapshot(
	t *testing.T,
) {
	detector := NewLifecycleDetector()

	connections := []core.NetworkConnection{
		{
			PID:           123,
			Protocol:      "tcp",
			LocalAddress:  "127.0.0.1",
			LocalPort:     50000,
			RemoteAddress: "8.8.8.8",
			RemotePort:    443,
		},
	}

	events := detector.Detect(connections)

	if len(events) != 0 {
		t.Fatalf(
			"expected 0 events, got %d",
			len(events),
		)
	}
}

func TestLifecycleDetectorDetectsNewConnection(
	t *testing.T,
) {
	detector := NewLifecycleDetector()

	initial := []core.NetworkConnection{
		{
			PID:           123,
			Protocol:      "tcp",
			LocalAddress:  "127.0.0.1",
			LocalPort:     50000,
			RemoteAddress: "8.8.8.8",
			RemotePort:    443,
		},
	}

	detector.Detect(initial)

	current := append(
		initial,
		core.NetworkConnection{
			PID:           123,
			Protocol:      "tcp",
			LocalAddress:  "127.0.0.1",
			LocalPort:     50001,
			RemoteAddress: "1.1.1.1",
			RemotePort:    443,
		},
	)

	events := detector.Detect(current)

	if len(events) != 1 {
		t.Fatalf(
			"expected 1 event, got %d",
			len(events),
		)
	}

	if events[0].Type != core.EventNetworkConnect {
		t.Fatalf(
			"expected NETWORK_CONNECT, got %s",
			events[0].Type,
		)
	}

	if events[0].Network == nil {
		t.Fatal("expected network connection in event")
	}

	if events[0].Network.RemoteAddress != "1.1.1.1" {
		t.Fatalf(
			"expected remote address 1.1.1.1, got %s",
			events[0].Network.RemoteAddress,
		)
	}
}

func TestLifecycleDetectorDetectsClosedConnection(t *testing.T) {
	detector := NewLifecycleDetector()

	connection := core.NetworkConnection{
		PID:           123,
		Protocol:      "tcp",
		LocalAddress:  "127.0.0.1",
		LocalPort:     50000,
		RemoteAddress: "8.8.8.8",
		RemotePort:    443,
	}

	detector.Detect([]core.NetworkConnection{connection})

	events := detector.Detect(nil)

	if len(events) != 1 {
		t.Fatalf(
			"expected 1 event, got %d",
			len(events),
		)
	}

	if events[0].Type != core.EventNetworkClose {
		t.Fatalf(
			"expected NETWORK_CLOSE, got %s",
			events[0].Type,
		)
	}

	if events[0].Network == nil {
		t.Fatal("expected network connection in event")
	}

	if events[0].Network.RemoteAddress != "8.8.8.8" {
		t.Fatalf(
			"expected remote address 8.8.8.8, got %s",
			events[0].Network.RemoteAddress,
		)
	}
}
