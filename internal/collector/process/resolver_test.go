package process

import (
	"context"
	"os"
	"testing"
)

func TestResolverResolveCurrentProcess(t *testing.T) {
	ctx := context.Background()

	resolver := NewResolver()

	pid := int32(os.Getpid())

	process, err := resolver.Resolve(ctx, pid)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if process == nil {
		t.Fatal("expected process, got nil")
	}

	if process.PID != pid {
		t.Fatalf("expected PID %d, got %d", pid, process.PID)
	}

	if process.Name == "" {
		t.Fatal("expected process name")
	}

	if process.StartTime.IsZero() {
		t.Fatal("expected process start time")
	}
}

func TestResolverResolveInvalidPID(t *testing.T) {
	ctx := context.Background()

	resolver := NewResolver()

	process, err := resolver.Resolve(ctx, -1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if process != nil {
		t.Fatalf("expected nil process, got %+v", process)
	}
}
