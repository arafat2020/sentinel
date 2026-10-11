//go:build linux && integration

package netevents

// These tests load eBPF programs and make real connections, so they need a
// real Linux kernel and root:
//
//	sudo go test -tags integration ./internal/collector/network/...

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"

	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	processcollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/collector/process/procevents"
	"github.com/arafat2020/sentinel/internal/core"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
)

// The test binary doubles as the client: started with this variable set, it
// makes connections and exits, so that connections come from real, separate,
// short-lived processes whose PIDs the test knows.
const helperEnv = "SENTINEL_NET_HELPER"

func TestMain(m *testing.M) {
	if spec := os.Getenv(helperEnv); spec != "" {
		os.Exit(runHelper(spec))
	}
	os.Exit(m.Run())
}

// runHelper understands "tcp <addr> <count> <hold-ms>": make count
// connections to addr one after another, read each to its end, then stay
// alive for hold-ms.
func runHelper(spec string) int {
	fields := strings.Fields(spec)
	if len(fields) != 4 || fields[0] != "tcp" {
		return 2
	}
	count, _ := strconv.Atoi(fields[2])
	hold, _ := strconv.Atoi(fields[3])

	for i := 0; i < count; i++ {
		conn, err := net.Dial("tcp", fields[1])
		if err != nil {
			return 1
		}
		io.Copy(io.Discard, conn)
		conn.Close()
	}
	time.Sleep(time.Duration(hold) * time.Millisecond)
	return 0
}

func helper(spec string) *osexec.Cmd {
	cmd := osexec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+spec)
	return cmd
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// describe is how the entrypoints describe a process the kernel named.
func describe(ctx context.Context, known core.Process) (core.Process, bool) {
	handle, err := gopsprocess.NewProcessWithContext(ctx, known.PID)
	if err != nil {
		return core.Process{}, false
	}
	return processcollector.FromGopsutil(ctx, handle), true
}

type capture struct {
	mu     sync.Mutex
	events []core.Event
	source Source
}

func (c *capture) add(event core.Event) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func (c *capture) snapshot() []core.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]core.Event(nil), c.events...)
}

// matching returns the captured events that keep returns true for.
func (c *capture) matching(keep func(core.Event) bool) []core.Event {
	var found []core.Event
	for _, event := range c.snapshot() {
		if keep(event) {
			found = append(found, event)
		}
	}
	return found
}

func startEBPF(t *testing.T) *capture {
	t.Helper()

	source, _, err := Open(BackendEBPF, Options{Describe: describe})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	recorded := &capture{source: source}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := source.Run(ctx, recorded.add); err != nil {
			t.Errorf("source stopped: %v", err)
		}
	}()

	t.Cleanup(func() {
		cancel()
		<-done
		source.Close()
	})
	return recorded
}

func waitFor(timeout time.Duration, done func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

// answering starts a TCP server that sends reply to every connection and
// closes it at once.
func answering(t *testing.T, network, address string, reply []byte) net.Listener {
	t.Helper()

	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				conn.Write(reply)
				conn.Close()
			}()
		}
	}()
	return listener
}

func portOf(address net.Addr) uint32 {
	_, port, _ := net.SplitHostPort(address.String())
	n, _ := strconv.Atoi(port)
	return uint32(n)
}

// Connections that live for a few milliseconds, from processes that live
// little longer: 200 processes, ten connections each. Every one must be
// reported, against the process that made it, and on the server's side
// against the process that accepted it.
func TestShortLivedConnectionsAreCapturedAndAttributed(t *testing.T) {
	requireRoot(t)

	const processes, perProcess = 200, 10
	const total = processes * perProcess

	recorded := startEBPF(t)

	// The same collector and detector the poll monitor runs, at its
	// interval, for comparison.
	pollCtx, stopPoll := context.WithCancel(context.Background())
	defer stopPoll()
	var pollMu sync.Mutex
	var polled []core.Event
	go func() {
		collector, detector := networkcollector.NewCollector(), networkdetector.NewLifecycleDetector()
		for pollCtx.Err() == nil {
			if connections, err := collector.Collect(pollCtx); err == nil {
				events := detector.Detect(connections)
				pollMu.Lock()
				polled = append(polled, events...)
				pollMu.Unlock()
			}
			select {
			case <-pollCtx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}()
	time.Sleep(2500 * time.Millisecond) // the poller's baseline

	server := answering(t, "tcp", "127.0.0.1:0", []byte("ok"))
	port := portOf(server.Addr())

	pids := make(map[int32]bool, processes)
	var mu sync.Mutex
	began := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := 0; i < processes; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			cmd := helper(fmt.Sprintf("tcp %s %d 0", server.Addr(), perProcess))
			if err := cmd.Start(); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			pids[int32(cmd.Process.Pid)] = true
			mu.Unlock()
			if err := cmd.Wait(); err != nil {
				t.Errorf("helper: %v", err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(began)

	outbound := func(e core.Event) bool {
		return e.Type == core.EventNetworkConnect && e.Network.Protocol == "tcp" && e.Network.RemotePort == port && e.Network.Direction == core.DirectionOutbound
	}
	inbound := func(e core.Event) bool {
		return e.Type == core.EventNetworkConnect && e.Network.LocalPort == port && e.Network.Direction == core.DirectionInbound && e.Network.State == stateEstablished
	}
	closes := func(e core.Event) bool {
		return e.Type == core.EventNetworkClose && e.Network.RemotePort == port && e.Network.Direction == core.DirectionOutbound
	}

	waitFor(5*time.Second, func() bool {
		return len(recorded.matching(outbound)) >= total && len(recorded.matching(inbound)) >= total && len(recorded.matching(closes)) >= total
	})

	// Outbound: each connection against the process that made it.
	perPID := map[int32]int{}
	wrong, longest := 0, time.Duration(0)
	for _, event := range recorded.matching(outbound) {
		if !pids[event.Process.PID] {
			wrong++
			continue
		}
		perPID[event.Process.PID]++
		if event.Network.Result != core.ResultOK || event.Network.State != stateEstablished || event.Network.RemoteAddress != "127.0.0.1" {
			t.Errorf("outbound event: %+v", *event.Network)
		}
	}
	attributed := 0
	for pid := range pids {
		if perPID[pid] > perProcess {
			t.Errorf("pid %d was given %d connections, made %d", pid, perPID[pid], perProcess)
		}
		attributed += perPID[pid]
	}
	for _, event := range recorded.matching(closes) {
		if d := time.Duration(event.Network.Transfer.DurationMs) * time.Millisecond; d > longest {
			longest = d
		}
	}

	// Inbound: every accept against this process, which is the server.
	accepted, misattributed := 0, 0
	for _, event := range recorded.matching(inbound) {
		accepted++
		if event.Process.PID != int32(os.Getpid()) {
			misattributed++
		}
	}

	// What the poller saw of the same connections.
	time.Sleep(2500 * time.Millisecond)
	stopPoll()
	pollMu.Lock()
	seenByPoll := 0
	for _, event := range polled {
		if event.Type == core.EventNetworkConnect && event.Network != nil && event.Network.RemotePort == port {
			seenByPoll++
		}
	}
	pollMu.Unlock()

	stats := recorded.source.Stats()
	t.Logf("%d connections from %d processes in %v (%.0f/s); longest lived %v", total, processes, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), longest)
	t.Logf("ebpf: %d outbound attributed to the right process (%.2f%%), %d to another; %d accepts (%.2f%%), %d misattributed; %d closes; kernel drops %d, unowned %d",
		attributed, 100*float64(attributed)/total, wrong, accepted, 100*float64(accepted)/total, misattributed, len(recorded.matching(closes)), stats.KernelDrops, stats.Unowned)
	t.Logf("poll: %d of %d connections seen (%.2f%%)", seenByPoll, total, 100*float64(seenByPoll)/total)

	if float64(attributed) < 0.999*total {
		t.Errorf("%d of %d outbound connections attributed, want at least 99.9%%", attributed, total)
	}
	if wrong != 0 || misattributed != 0 {
		t.Errorf("%d outbound and %d inbound connections were attributed to the wrong process", wrong, misattributed)
	}
	if float64(accepted) < 0.999*total {
		t.Errorf("%d of %d accepts reported", accepted, total)
	}
	if longest > 50*time.Millisecond {
		t.Logf("note: the longest connection lasted %v, more than the 50 ms the test aims for", longest)
	}
}

// The start time on a network event is the very value the process collector
// puts on that process's own events. Compared with ==, for a hundred
// processes that exit at once and a hundred that stay.
func TestIdentityEqualsTheProcessCollectors(t *testing.T) {
	requireRoot(t)

	// The process collector, running beside the network one.
	snapshot := func(ctx context.Context) ([]core.Process, error) {
		s, err := processcollector.NewCollector().Collect(ctx)
		if err != nil {
			return nil, err
		}
		return s.Processes, nil
	}
	processes, _, err := procevents.Open(procevents.BackendEBPF, procevents.Options{Snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	started := map[int32]core.ProcessIdentity{}
	ctx, cancel := context.WithCancel(context.Background())
	procDone := make(chan struct{})
	go func() {
		defer close(procDone)
		processes.Run(ctx, seed, func(event core.Event) {
			if event.Type == core.EventProcessStart {
				mu.Lock()
				started[event.Process.PID] = event.Process.Identity()
				mu.Unlock()
			}
		})
	}()
	defer func() {
		cancel()
		<-procDone
		processes.Close()
	}()

	recorded := startEBPF(t)
	time.Sleep(300 * time.Millisecond)

	server := answering(t, "tcp", "127.0.0.1:0", []byte("ok"))
	port := portOf(server.Addr())

	const each = 110
	pids := map[int32]string{}
	var commands []*osexec.Cmd
	for i := 0; i < 2*each; i++ {
		kind, hold := "short-lived", 0
		if i%2 == 1 {
			kind, hold = "long-lived", 4000
		}
		cmd := helper(fmt.Sprintf("tcp %s 1 %d", server.Addr(), hold))
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pids[int32(cmd.Process.Pid)] = kind
		commands = append(commands, cmd)
	}

	ours := func(e core.Event) bool {
		return e.Type == core.EventNetworkConnect && e.Network.RemotePort == port && e.Network.Direction == core.DirectionOutbound && pids[e.Process.PID] != ""
	}
	if !waitFor(10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		known := 0
		for pid := range pids {
			if _, ok := started[pid]; ok {
				known++
			}
		}
		return known == len(pids) && len(recorded.matching(ours)) >= len(pids)
	}) {
		t.Fatalf("not every process and connection was reported: %d connections", len(recorded.matching(ours)))
	}

	compared := map[string]int{}
	mismatches := 0
	mu.Lock()
	for _, event := range recorded.matching(ours) {
		kind := pids[event.Process.PID]
		compared[kind]++

		// ProcessIdentity is a map key: == is the comparison that
		// decides whether two events are about the same process.
		if event.Process.Identity() != started[event.Process.PID] {
			mismatches++
			t.Errorf("%s pid %d: network event says %v (%d ms), process event says %v (%d ms)", kind, event.Process.PID,
				event.Process.StartTime, event.Process.StartTime.UnixMilli(),
				started[event.Process.PID].StartTime, started[event.Process.PID].StartTime.UnixMilli())
		}
	}
	mu.Unlock()

	for _, cmd := range commands {
		cmd.Wait()
	}

	t.Logf("compared %d short-lived and %d long-lived processes: %d mismatches", compared["short-lived"], compared["long-lived"], mismatches)
	if compared["short-lived"] < 100 || compared["long-lived"] < 100 {
		t.Errorf("compared %v, want at least 100 of each", compared)
	}
}

// A connection to a port nothing listens on is reported, as refused.
func TestFailedConnectIsReportedAsRefused(t *testing.T) {
	requireRoot(t)
	recorded := startEBPF(t)

	// A port that was just free.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(probe.Addr())
	closed := probe.Addr().String()
	probe.Close()

	before := time.Now()
	if conn, err := net.DialTimeout("tcp", closed, time.Second); err == nil {
		conn.Close()
		t.Skip("something took the port")
	}

	refused := func(e core.Event) bool {
		return e.Network.RemotePort == port && e.Network.Direction == core.DirectionOutbound
	}
	if !waitFor(3*time.Second, func() bool { return len(recorded.matching(refused)) > 0 }) {
		t.Fatal("the failed connection was not reported")
	}

	events := recorded.matching(refused)
	if len(events) != 1 {
		t.Fatalf("%d events for one failed connection: %+v", len(events), events)
	}
	event := events[0]
	if event.Type != core.EventNetworkConnect || event.Network.Result != core.ResultRefused || event.Network.State != stateClose ||
		event.Network.Transfer != nil || event.Process.PID != int32(os.Getpid()) || event.Metadata[MetaErrno] != uint32(111) {
		t.Errorf("event = %s %+v, metadata %v, pid %d", event.Type, *event.Network, event.Metadata, event.Process.PID)
	}
	if event.Timestamp.Before(before.Add(-time.Millisecond)) || event.Timestamp.After(time.Now()) {
		t.Errorf("stamped %v, attempted between %v and now", event.Timestamp, before)
	}
	if recorded.source.Stats().Failed == 0 {
		t.Error("the failure was not counted")
	}
}

// Each UDP socket is reported once, at its first send, with where it sent to
// and from which port; and that port can then be looked up.
func TestUDPFirstSendAndPortOwner(t *testing.T) {
	requireRoot(t)
	recorded := startEBPF(t)

	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	port := portOf(sink.LocalAddr())

	// A connected socket, as a DNS resolver uses, sending three times.
	connected, err := net.Dial("udp", sink.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	for i := 0; i < 3; i++ {
		connected.Write([]byte("x"))
	}

	// An unconnected socket naming its destination on each send.
	loose, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loose.Close()
	for i := 0; i < 3; i++ {
		loose.WriteTo([]byte("x"), sink.LocalAddr())
	}

	toSink := func(e core.Event) bool { return e.Network.Protocol == "udp" && e.Network.RemotePort == port }
	if !waitFor(3*time.Second, func() bool { return len(recorded.matching(toSink)) >= 2 }) {
		t.Fatalf("%d UDP events, want one per socket", len(recorded.matching(toSink)))
	}
	time.Sleep(200 * time.Millisecond)

	events := recorded.matching(toSink)
	if len(events) != 2 {
		t.Fatalf("%d UDP events for two sockets sending three times each", len(events))
	}

	localPorts := map[uint32]bool{portOf(connected.LocalAddr()): true, portOf(loose.LocalAddr()): true}
	for _, event := range events {
		n := event.Network
		if event.Type != core.EventNetworkConnect || n.State != stateNone || n.Direction != core.DirectionOutbound || n.RemoteAddress != "127.0.0.1" ||
			!localPorts[n.LocalPort] || event.Process.PID != int32(os.Getpid()) {
			t.Errorf("UDP event = %+v (pid %d)", *n, event.Process.PID)
		}
		delete(localPorts, n.LocalPort)

		owner, ok := recorded.source.PortOwner("udp", uint16(n.LocalPort))
		if !ok || owner.PID != int32(os.Getpid()) || owner.Identity() != event.Process.Identity() {
			t.Errorf("owner of UDP port %d = %+v, %v", n.LocalPort, owner, ok)
		}
	}

	if _, ok := recorded.source.PortOwner("udp", 1); ok {
		t.Error("a port nothing used has an owner")
	}

	// A new socket is a new first send, even if the kernel gives it the
	// memory of one that was closed.
	for i := 0; i < 20; i++ {
		again, err := net.Dial("udp", sink.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		again.Write([]byte("x"))
		again.Close()
	}
	if !waitFor(3*time.Second, func() bool { return len(recorded.matching(toSink)) >= 22 }) {
		t.Errorf("%d UDP events after 20 more sockets, want 22", len(recorded.matching(toSink)))
	}
}

// What a close reports is what the connection carried and how long it was
// open.
func TestCloseReportsBytesAndDuration(t *testing.T) {
	requireRoot(t)
	recorded := startEBPF(t)

	const sent, received = 100_000, 250_000
	const held = 300 * time.Millisecond

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := portOf(listener.Addr())

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.CopyN(io.Discard, conn, sent)
		conn.Write(make([]byte, received))
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(make([]byte, sent))
	io.Copy(io.Discard, conn)
	time.Sleep(held)
	conn.Close()

	client := func(e core.Event) bool {
		return e.Type == core.EventNetworkClose && e.Network.RemotePort == port && e.Network.Direction == core.DirectionOutbound
	}
	serverSide := func(e core.Event) bool {
		return e.Type == core.EventNetworkClose && e.Network.LocalPort == port && e.Network.Direction == core.DirectionInbound && e.Network.Transfer != nil
	}
	if !waitFor(3*time.Second, func() bool { return len(recorded.matching(client)) == 1 && len(recorded.matching(serverSide)) == 1 }) {
		t.Fatalf("closes reported: %d client, %d server", len(recorded.matching(client)), len(recorded.matching(serverSide)))
	}

	near := func(got uint64, want int) bool { return got >= uint64(want) && got <= uint64(want)+64 }

	c := recorded.matching(client)[0].Network.Transfer
	t.Logf("client close: sent %d, received %d, open %d ms (transferred %d and %d, held %v)", c.BytesSent, c.BytesReceived, c.DurationMs, sent, received, held)
	if !near(c.BytesSent, sent) || !near(c.BytesReceived, received) {
		t.Errorf("client close reports %d sent and %d received, transferred %d and %d", c.BytesSent, c.BytesReceived, sent, received)
	}
	if d := time.Duration(c.DurationMs) * time.Millisecond; d < held || d > held+2*time.Second {
		t.Errorf("client close reports %v open, held for %v", d, held)
	}

	s := recorded.matching(serverSide)[0].Network.Transfer
	t.Logf("server close: sent %d, received %d, open %d ms", s.BytesSent, s.BytesReceived, s.DurationMs)
	if !near(s.BytesSent, received) || !near(s.BytesReceived, sent) {
		t.Errorf("server close reports %d sent and %d received", s.BytesSent, s.BytesReceived)
	}
}

// An IPv4 client of an IPv6 listener is reported with IPv4 addresses, as the
// poll collector reports it; and a listening socket is reported, as the
// poll collector reports one.
func TestMappedAddressesAndListeners(t *testing.T) {
	requireRoot(t)
	recorded := startEBPF(t)

	// "tcp" on [::] is dual-stack on Linux.
	server := answering(t, "tcp", "[::]:0", []byte("ok"))
	port := portOf(server.Addr())

	conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("no dual-stack listener here: %v", err)
	}
	io.Copy(io.Discard, conn)
	conn.Close()

	accepted := func(e core.Event) bool {
		return e.Type == core.EventNetworkConnect && e.Network.LocalPort == port && e.Network.Direction == core.DirectionInbound && e.Network.State == stateEstablished
	}
	listening := func(e core.Event) bool {
		return e.Type == core.EventNetworkConnect && e.Network.LocalPort == port && e.Network.State == stateListen
	}
	if !waitFor(3*time.Second, func() bool { return len(recorded.matching(accepted)) == 1 && len(recorded.matching(listening)) == 1 }) {
		t.Fatalf("accepted %d, listening %d", len(recorded.matching(accepted)), len(recorded.matching(listening)))
	}

	if n := recorded.matching(accepted)[0].Network; n.RemoteAddress != "127.0.0.1" || n.LocalAddress != "127.0.0.1" {
		t.Errorf("IPv4 client of an IPv6 listener: local %q, remote %q; want plain IPv4", n.LocalAddress, n.RemoteAddress)
	}

	l := recorded.matching(listening)[0]
	if l.Network.Direction != core.DirectionInbound || l.Network.RemoteAddress != "" || l.Network.RemotePort != 0 || l.Process.PID != int32(os.Getpid()) {
		t.Errorf("listening event = %+v", *l.Network)
	}
	if l.Metadata[MetaNetNS] == nil || l.Metadata[MetaNetNS] == uint32(0) {
		t.Errorf("no network namespace recorded: %v", l.Metadata)
	}

	// The listener's own close is a NETWORK_CLOSE in state LISTEN.
	server.Close()
	unlisten := func(e core.Event) bool {
		return e.Type == core.EventNetworkClose && e.Network.LocalPort == port && e.Network.State == stateListen
	}
	if !waitFor(3*time.Second, func() bool { return len(recorded.matching(unlisten)) == 1 }) {
		t.Error("closing the listener was not reported")
	}
}
