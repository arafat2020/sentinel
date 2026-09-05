package network

import (
	"context"
	"testing"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestBuildConnectionPreservesMetadata(t *testing.T) {
	process := core.Process{
		PID:         123,
		PPID:        100,
		Name:        "python",
		Executable:  "/usr/bin/python3",
		CommandLine: "python3 test.py",
		User:        "test-user",
	}

	connection := gopsnet.ConnectionStat{
		Fd:     42,
		Family: 2,
		Type:   1,
		Laddr: gopsnet.Addr{
			IP:   "127.0.0.1",
			Port: 54321,
		},
		Raddr: gopsnet.Addr{
			IP:   "8.8.8.8",
			Port: 443,
		},
		Status: "ESTABLISHED",
		Pid:    123,
	}

	result := buildConnection(connection, process)

	if result.PID != 123 {
		t.Fatalf("expected PID 123, got %d", result.PID)
	}

	if result.PPID != 100 {
		t.Fatalf("expected PPID 100, got %d", result.PPID)
	}

	if result.Protocol != "tcp" {
		t.Fatalf(
			"expected protocol tcp, got %s",
			result.Protocol,
		)
	}

	if result.LocalAddress != "127.0.0.1" {
		t.Fatalf(
			"expected local address 127.0.0.1, got %s",
			result.LocalAddress,
		)
	}

	if result.LocalPort != 54321 {
		t.Fatalf(
			"expected local port 54321, got %d",
			result.LocalPort,
		)
	}

	if result.RemoteAddress != "8.8.8.8" {
		t.Fatalf(
			"expected remote address 8.8.8.8, got %s",
			result.RemoteAddress,
		)
	}

	if result.RemotePort != 443 {
		t.Fatalf(
			"expected remote port 443, got %d",
			result.RemotePort,
		)
	}

	if result.State != "ESTABLISHED" {
		t.Fatalf(
			"expected state ESTABLISHED, got %s",
			result.State,
		)
	}

	if result.Process == nil {
		t.Fatal("expected process metadata")
	}

	if result.Process.Name != "python" {
		t.Fatalf(
			"expected process name python, got %s",
			result.Process.Name,
		)
	}

	if result.Timestamp.IsZero() {
		t.Fatal("expected timestamp")
	}

	if result.Timestamp.After(time.Now()) {
		t.Fatal("timestamp cannot be in the future")
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		socketType uint32
		expected   string
	}{
		{1, "tcp"},
		{2, "udp"},
		{999, "unknown"},
	}

	for _, tt := range tests {
		result := protocolName(tt.socketType)

		if result != tt.expected {
			t.Fatalf(
				"expected %s, got %s",
				tt.expected,
				result,
			)
		}
	}
}

func TestCollectorCollectsConnections(t *testing.T) {
	ctx := context.Background()

	collector := NewCollector()

	connections, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect connections: %v", err)
	}

	t.Logf("collected %d network connections", len(connections))

	for _, connection := range connections {
		if connection.PID <= 0 {
			t.Fatalf("expected valid PID, got %d", connection.PID)
		}

		if connection.Protocol == "" {
			t.Fatal("expected protocol")
		}

		if connection.Process == nil {
			t.Fatal("expected process attribution")
		}

		if connection.Process.PID != connection.PID {
			t.Fatalf(
				"process PID %d does not match connection PID %d",
				connection.Process.PID,
				connection.PID,
			)
		}

		if connection.Timestamp.IsZero() {
			t.Fatal("expected connection timestamp")
		}
	}
}
