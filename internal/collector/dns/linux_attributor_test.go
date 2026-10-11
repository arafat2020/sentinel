//go:build linux

package dns

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeLinuxSocketLookup struct {
	owner *SocketOwner
	err   error

	lastIP   string
	lastPort uint32
}

func (f *fakeLinuxSocketLookup) FindOwner(
	ctx context.Context,
	sourceIP string,
	sourcePort uint32,
) (*SocketOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f.lastIP = sourceIP
	f.lastPort = sourcePort

	if f.err != nil {
		return nil, f.err
	}

	return f.owner, nil
}

type fakeLinuxProcessResolver struct {
	process *core.Process
	err     error

	lastPID int32
}

func (f *fakeLinuxProcessResolver) Resolve(
	ctx context.Context,
	pid int32,
) (*core.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f.lastPID = pid

	if f.err != nil {
		return nil, f.err
	}

	return f.process, nil
}

func TestLinuxAttributorAttribute(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		owner: &SocketOwner{PID: 1234},
	}

	processResolver := &fakeLinuxProcessResolver{
		process: &core.Process{
			PID:        1234,
			PPID:       100,
			Name:       "systemd-resolved",
			Executable: "/usr/lib/systemd/systemd-resolved",
		},
	}

	attributor := NewLinuxAttributor(lookup, processResolver)

	query := &core.DNSQuery{
		Domain: "example.com",
		Type:   "A",
	}

	err := attributor.Attribute(
		context.Background(),
		query,
		"192.168.1.10",
		54321,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if query.PID != 1234 {
		t.Fatalf("expected PID 1234, got %d", query.PID)
	}

	if query.Process == nil {
		t.Fatal("expected process, got nil")
	}

	if query.Process.Name != "systemd-resolved" {
		t.Fatalf("expected process name systemd-resolved, got %s", query.Process.Name)
	}

	if lookup.lastIP != "192.168.1.10" {
		t.Fatalf("expected source IP 192.168.1.10, got %s", lookup.lastIP)
	}

	if lookup.lastPort != 54321 {
		t.Fatalf("expected source port 54321, got %d", lookup.lastPort)
	}

	if processResolver.lastPID != 1234 {
		t.Fatalf("expected resolver PID 1234, got %d", processResolver.lastPID)
	}
}

func TestLinuxAttributorWithoutSocketLookup(t *testing.T) {
	attributor := NewLinuxAttributor(nil, &fakeLinuxProcessResolver{})

	query := &core.DNSQuery{}

	err := attributor.Attribute(
		context.Background(),
		query,
		"192.168.1.10",
		54321,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if query.PID != 0 {
		t.Fatalf("expected PID 0, got %d", query.PID)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestLinuxAttributorWithoutSource(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		owner: &SocketOwner{PID: 1234},
	}

	attributor := NewLinuxAttributor(lookup, &fakeLinuxProcessResolver{
		process: &core.Process{PID: 1234},
	})

	query := &core.DNSQuery{}

	err := attributor.Attribute(
		context.Background(),
		query,
		"",
		54321,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if query.PID != 0 {
		t.Fatalf("expected PID 0, got %d", query.PID)
	}

	if lookup.lastIP != "" {
		t.Fatalf("expected lookup not to be called, got IP %s", lookup.lastIP)
	}
}

func TestLinuxAttributorSocketLookupError(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		err: errors.New("socket lookup failed"),
	}

	processResolver := &fakeLinuxProcessResolver{
		process: &core.Process{PID: 1234},
	}

	attributor := NewLinuxAttributor(lookup, processResolver)

	query := &core.DNSQuery{}

	err := attributor.Attribute(
		context.Background(),
		query,
		"192.168.1.10",
		54321,
	)

	if err == nil {
		t.Fatal("expected socket lookup error, got nil")
	}

	if query.PID != 0 {
		t.Fatalf("expected PID 0, got %d", query.PID)
	}

	if processResolver.lastPID != 0 {
		t.Fatalf("expected resolver not to be called, got PID %d", processResolver.lastPID)
	}
}

func TestLinuxAttributorProcessResolverError(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		owner: &SocketOwner{PID: 1234},
	}

	processResolver := &fakeLinuxProcessResolver{
		err: errors.New("process resolution failed"),
	}

	attributor := NewLinuxAttributor(lookup, processResolver)

	query := &core.DNSQuery{}

	err := attributor.Attribute(
		context.Background(),
		query,
		"192.168.1.10",
		54321,
	)

	if err == nil {
		t.Fatal("expected process resolver error, got nil")
	}

	// PID is still useful even though the full process could not be resolved.
	if query.PID != 1234 {
		t.Fatalf("expected PID 1234 to be retained, got %d", query.PID)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestLinuxAttributorWithoutProcessResolver(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		owner: &SocketOwner{PID: 1234},
	}

	attributor := NewLinuxAttributor(lookup, nil)

	query := &core.DNSQuery{}

	err := attributor.Attribute(
		context.Background(),
		query,
		"192.168.1.10",
		54321,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if query.PID != 1234 {
		t.Fatalf("expected PID 1234, got %d", query.PID)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestLinuxAttributorContextCancelled(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		owner: &SocketOwner{PID: 1234},
	}

	attributor := NewLinuxAttributor(lookup, &fakeLinuxProcessResolver{
		process: &core.Process{PID: 1234},
	})

	query := &core.DNSQuery{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := attributor.Attribute(
		ctx,
		query,
		"192.168.1.10",
		54321,
	)

	if err == nil {
		t.Fatal("expected context cancellation error")
	}

	if query.PID != 0 {
		t.Fatalf("expected PID 0, got %d", query.PID)
	}
}

func TestLinuxAttributorNilQuery(t *testing.T) {
	lookup := &fakeLinuxSocketLookup{
		owner: &SocketOwner{PID: 1234},
	}

	processResolver := &fakeLinuxProcessResolver{
		process: &core.Process{PID: 1234},
	}

	attributor := NewLinuxAttributor(lookup, processResolver)

	err := attributor.Attribute(
		context.Background(),
		nil,
		"192.168.1.10",
		54321,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if processResolver.lastPID != 0 {
		t.Fatalf("expected resolver not to be called, got PID %d", processResolver.lastPID)
	}
}

// What the kernel recorded when the packet was sent is asked first; the
// socket table only when it knows nothing.
func TestLinuxAttributorAsksThePortOwnerFirst(t *testing.T) {
	recorded := core.Process{PID: 4242, Name: "getent", StartTime: time.Unix(1700000000, 0)}
	asked := []string{}

	owner := func(protocol string, port uint16) (core.Process, bool) {
		asked = append(asked, fmt.Sprintf("%s/%d", protocol, port))
		if protocol == "udp" && port == 40000 {
			return recorded, true
		}
		if protocol == "tcp" && port == 40001 {
			return core.Process{PID: 77, Name: "dig"}, true
		}
		return core.Process{}, false
	}

	table := &countingLookup{owners: map[uint32]uint32{40002: 99}}
	attributor := NewLinuxAttributorWithPortOwner(table, nil, owner)

	// Known to the kernel map: the socket table is not consulted, and the
	// whole process comes back, not just a PID.
	query := &core.DNSQuery{Domain: "a.example"}
	if err := attributor.Attribute(context.Background(), query, "127.0.0.1", 40000); err != nil {
		t.Fatal(err)
	}
	if query.PID != 4242 || query.Process == nil || query.Process.Identity() != recorded.Identity() || table.calls != 0 {
		t.Errorf("query = %+v (process %+v), socket table asked %d times", query, query.Process, table.calls)
	}

	// A query over TCP is found under tcp.
	query = &core.DNSQuery{Domain: "b.example"}
	attributor.Attribute(context.Background(), query, "127.0.0.1", 40001)
	if query.PID != 77 {
		t.Errorf("TCP query attributed to %d", query.PID)
	}

	// Unknown to the map: the socket table answers.
	query = &core.DNSQuery{Domain: "c.example"}
	attributor.Attribute(context.Background(), query, "127.0.0.1", 40002)
	if query.PID != 99 || table.calls != 1 {
		t.Errorf("fallback: pid %d, socket table asked %d times", query.PID, table.calls)
	}

	// Unknown to both.
	query = &core.DNSQuery{Domain: "d.example"}
	attributor.Attribute(context.Background(), query, "127.0.0.1", 40003)
	if query.PID != 0 || query.Process != nil {
		t.Errorf("unknown port attributed to %d", query.PID)
	}

	if got := attributor.Stats(); got != (AttributionStats{ByPortOwner: 2, BySocketTable: 1, Unattributed: 1}) {
		t.Errorf("stats = %+v", got)
	}
	if asked[0] != "udp/40000" || asked[1] != "udp/40001" || asked[2] != "tcp/40001" {
		t.Errorf("asked %v", asked)
	}

	// With no port owner it is the attributor it always was.
	plain := NewLinuxAttributorWithPortOwner(&countingLookup{owners: map[uint32]uint32{40002: 99}}, nil, nil)
	query = &core.DNSQuery{}
	plain.Attribute(context.Background(), query, "127.0.0.1", 40002)
	if query.PID != 99 {
		t.Errorf("without a port owner: pid %d", query.PID)
	}
}

type countingLookup struct {
	owners map[uint32]uint32
	calls  int
}

func (l *countingLookup) FindOwner(_ context.Context, _ string, port uint32) (*SocketOwner, error) {
	l.calls++
	if pid, ok := l.owners[port]; ok {
		return &SocketOwner{PID: pid}, nil
	}
	return nil, nil
}
