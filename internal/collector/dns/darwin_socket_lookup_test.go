//go:build darwin

package dns

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestDarwinSocketLookup_FindsOwner(t *testing.T) {
	conn, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 0,
		},
	)
	if err != nil {
		t.Fatalf("failed to create UDP socket: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr().(*net.UDPAddr)

	owner, found, err := findSocketInProcess(
		os.Getpid(),
		addr.IP,
		uint32(addr.Port),
	)

	if err != nil {
		t.Fatalf("socket lookup failed: %v", err)
	}

	if !found {
		t.Fatal("expected socket to be found")
	}

	if owner == nil {
		t.Fatal("expected owner, got nil")
	}

	if int(owner.PID) != os.Getpid() {
		t.Fatalf(
			"expected PID %d, got %d",
			os.Getpid(),
			owner.PID,
		)
	}
}

func TestDarwinSocketLookup_InvalidIP(t *testing.T) {
	lookup := NewDarwinSocketLookup()

	_, err := lookup.FindOwner(
		context.Background(),
		"not-an-ip",
		12345,
	)

	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestDarwinSocketLookup_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	cancel()

	lookup := NewDarwinSocketLookup()

	_, err := lookup.FindOwner(
		ctx,
		"127.0.0.1",
		12345,
	)

	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}
