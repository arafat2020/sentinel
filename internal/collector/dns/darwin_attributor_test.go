//go:build darwin

package dns

import (
	"context"
	"errors"
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeProcessResolver struct {
	process *core.Process
	err     error

	lastPID int32
}

func (f *fakeProcessResolver) Resolve(
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

func TestDarwinAttributorAttribute(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	processResolver := &fakeProcessResolver{
		process: &core.Process{
			PID:        1234,
			PPID:       100,
			Name:       "node",
			Executable: "/usr/local/bin/node",
		},
	}

	attributor := NewDarwinAttributor(
		lookup,
		processResolver,
	)

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
		t.Fatalf(
			"expected PID 1234, got %d",
			query.PID,
		)
	}

	if query.Process == nil {
		t.Fatal("expected process, got nil")
	}

	if query.Process.PID != 1234 {
		t.Fatalf(
			"expected process PID 1234, got %d",
			query.Process.PID,
		)
	}

	if query.Process.Name != "node" {
		t.Fatalf(
			"expected process name node, got %s",
			query.Process.Name,
		)
	}

	if lookup.lastIP != "192.168.1.10" {
		t.Fatalf(
			"expected source IP 192.168.1.10, got %s",
			lookup.lastIP,
		)
	}

	if lookup.lastPort != 54321 {
		t.Fatalf(
			"expected source port 54321, got %d",
			lookup.lastPort,
		)
	}

	if processResolver.lastPID != 1234 {
		t.Fatalf(
			"expected resolver PID 1234, got %d",
			processResolver.lastPID,
		)
	}
}

func TestDarwinAttributorWithoutSocketLookup(t *testing.T) {
	attributor := NewDarwinAttributor(
		nil,
		&fakeProcessResolver{},
	)

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
		t.Fatalf(
			"expected PID 0, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestDarwinAttributorWithoutSource(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	processResolver := &fakeProcessResolver{
		process: &core.Process{
			PID:  1234,
			Name: "node",
		},
	}

	attributor := NewDarwinAttributor(
		lookup,
		processResolver,
	)

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
		t.Fatalf(
			"expected PID 0, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}

	if lookup.lastIP != "" {
		t.Fatalf(
			"expected lookup not to be called, got IP %s",
			lookup.lastIP,
		)
	}
}

func TestDarwinAttributorSocketLookupError(t *testing.T) {
	lookup := &fakeSocketLookup{
		err: errors.New("socket lookup failed"),
	}

	processResolver := &fakeProcessResolver{
		process: &core.Process{
			PID: 1234,
		},
	}

	attributor := NewDarwinAttributor(
		lookup,
		processResolver,
	)

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
		t.Fatalf(
			"expected PID 0, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}

	if processResolver.lastPID != 0 {
		t.Fatalf(
			"expected resolver not to be called, got PID %d",
			processResolver.lastPID,
		)
	}
}

func TestDarwinAttributorProcessResolverError(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	processResolver := &fakeProcessResolver{
		err: errors.New("process resolution failed"),
	}

	attributor := NewDarwinAttributor(
		lookup,
		processResolver,
	)

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

	// PID is still useful even though the full process
	// could not be resolved.
	if query.PID != 1234 {
		t.Fatalf(
			"expected PID 1234 to be retained, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestDarwinAttributorWithoutProcessResolver(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	attributor := NewDarwinAttributor(
		lookup,
		nil,
	)

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
		t.Fatalf(
			"expected PID 1234, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestDarwinAttributorContextCancelled(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	processResolver := &fakeProcessResolver{
		process: &core.Process{
			PID: 1234,
		},
	}

	attributor := NewDarwinAttributor(
		lookup,
		processResolver,
	)

	query := &core.DNSQuery{}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
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
		t.Fatalf(
			"expected PID 0, got %d",
			query.PID,
		)
	}

	if query.Process != nil {
		t.Fatal("expected Process to be nil")
	}
}

func TestDarwinAttributorNilQuery(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	processResolver := &fakeProcessResolver{
		process: &core.Process{
			PID: 1234,
		},
	}

	attributor := NewDarwinAttributor(
		lookup,
		processResolver,
	)

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
		t.Fatalf(
			"expected resolver not to be called, got PID %d",
			processResolver.lastPID,
		)
	}
}
