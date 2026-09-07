//go:build darwin

package dns

import (
	"context"
	"testing"
)

type fakeSocketLookup struct {
	owner *SocketOwner
	err   error
}

func (f *fakeSocketLookup) FindOwner(
	ctx context.Context,
	sourceIP string,
	sourcePort uint32,
) (*SocketOwner, error) {
	return f.owner, f.err
}

func TestSocketLookupFindOwner(t *testing.T) {
	lookup := &fakeSocketLookup{
		owner: &SocketOwner{
			PID: 1234,
		},
	}

	owner, err := lookup.FindOwner(
		context.Background(),
		"192.168.1.10",
		54321,
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if owner == nil {
		t.Fatal("expected socket owner, got nil")
	}

	if owner.PID != 1234 {
		t.Fatalf(
			"expected PID 1234, got %d",
			owner.PID,
		)
	}
}
