//go:build linux

package dns

import (
	"context"
	"errors"
	"testing"

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
