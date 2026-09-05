package process

import (
	"context"
	"os"
	"testing"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"
)

func TestBuildProcessCurrentProcess(t *testing.T) {
	ctx := context.Background()

	p, err := gopsprocess.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatalf("failed to create process: %v", err)
	}

	process := buildProcess(p, ctx)

	if process.PID != p.Pid {
		t.Fatalf("expected PID %d, got %d", p.Pid, process.PID)
	}

	if process.Name == "" {
		t.Fatal("expected process name")
	}

	if process.StartTime.IsZero() {
		t.Fatal("expected process start time")
	}

	if process.StartTime.After(time.Now()) {
		t.Fatal("process start time cannot be in the future")
	}
}
