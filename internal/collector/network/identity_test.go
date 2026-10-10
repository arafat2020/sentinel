package network

import (
	"context"
	"net"
	"os"
	"testing"

	processcollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/core"
)

// A process's identity is its PID and start time, and the correlation engine
// joins a process's network activity to the rest of what it does by that
// identity. So the process attached to a connection must be identical, to
// the millisecond, to what the process collector and the resolver (used for
// DNS and file events) report for the same live process.
//
// This checks it against the running system, using this test process: it
// opens a connection so the network collector has something to report for
// it.
func TestConnectionProcessHasSameIdentityAsProcessCollector(t *testing.T) {
	ctx := context.Background()
	self := int32(os.Getpid())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open a listener here: %v", err)
	}
	defer listener.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Skipf("cannot connect to the listener: %v", err)
	}
	defer conn.Close()

	connections, err := NewCollector().Collect(ctx)
	if err != nil {
		t.Fatalf("network Collect: %v", err)
	}

	var fromNetwork *core.Process
	for i := range connections {
		if connections[i].PID == self && connections[i].Process != nil {
			fromNetwork = connections[i].Process
			break
		}
	}
	if fromNetwork == nil {
		t.Skip("the network collector reported no connection for this process (no permission to list sockets?)")
	}

	fromResolver, err := processcollector.NewResolver().Resolve(ctx, self)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	snapshot, err := processcollector.NewCollector().Collect(ctx)
	if err != nil {
		t.Fatalf("process Collect: %v", err)
	}
	var fromCollector *core.Process
	for i := range snapshot.Processes {
		if snapshot.Processes[i].PID == self {
			fromCollector = &snapshot.Processes[i]
		}
	}
	if fromCollector == nil {
		t.Fatal("the process collector did not report this process")
	}

	want := fromCollector.Identity()
	if want.StartTime.Unix() <= 0 {
		t.Fatalf("process collector reported no start time for this process: %v", want.StartTime)
	}

	for source, got := range map[string]core.ProcessIdentity{
		"network collector": fromNetwork.Identity(),
		"resolver":          fromResolver.Identity(),
	} {
		if got != want {
			t.Errorf("%s identity = {%d %v}, process collector = {%d %v}",
				source, got.PID, got.StartTime, want.PID, want.StartTime)
		}
	}

	// Asking again must give the same answer: a start time that drifted
	// between reads would make one process look like two.
	again, err := processcollector.NewResolver().Resolve(ctx, self)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if again.Identity() != want {
		t.Errorf("identity changed between reads: {%v} then {%v}", want.StartTime, again.StartTime)
	}
}
