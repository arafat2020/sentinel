package core

import (
	"testing"
	"time"
)

func TestNetworkConnectionPreservesMetadata(t *testing.T) {
	timestamp := time.Now()

	connection := NetworkConnection{
		Timestamp:     timestamp,
		PID:           123,
		PPID:          100,
		Protocol:      "tcp",
		LocalAddress:  "127.0.0.1",
		LocalPort:     54321,
		RemoteAddress: "8.8.8.8",
		RemotePort:    443,
		State:         "ESTABLISHED",
	}

	if connection.PID != 123 {
		t.Fatalf("expected PID 123, got %d", connection.PID)
	}

	if connection.PPID != 100 {
		t.Fatalf("expected PPID 100, got %d", connection.PPID)
	}

	if connection.Protocol != "tcp" {
		t.Fatalf("expected protocol tcp, got %s", connection.Protocol)
	}

	if connection.RemoteAddress != "8.8.8.8" {
		t.Fatalf(
			"expected remote address 8.8.8.8, got %s",
			connection.RemoteAddress,
		)
	}

	if connection.RemotePort != 443 {
		t.Fatalf(
			"expected remote port 443, got %d",
			connection.RemotePort,
		)
	}

	if connection.Timestamp.IsZero() {
		t.Fatal("expected timestamp")
	}
}
