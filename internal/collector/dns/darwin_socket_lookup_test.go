//go:build darwin

package dns

import (
	"fmt"
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
		t.Fatal(err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"expected *net.UDPAddr, got %T",
			conn.LocalAddr(),
		)
	}

	pid := os.Getpid()

	fmt.Printf(
		"TEST PID=%d SOCKET=%s:%d\n",
		pid,
		addr.IP.String(),
		addr.Port,
	)

	// Directly test the process that we KNOW owns the socket.
	owner, found, err := findSocketInProcess(
		pid,
		addr.IP,
		uint32(addr.Port),
	)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf(
		"direct lookup: owner=%+v found=%v\n",
		owner,
		found,
	)

	if !found {
		t.Fatal("direct socket lookup failed")
	}

	if owner == nil {
		t.Fatal("expected owner, got nil")
	}

	if owner.PID != uint32(pid) {
		t.Fatalf(
			"expected PID %d, got %d",
			pid,
			owner.PID,
		)
	}
}
