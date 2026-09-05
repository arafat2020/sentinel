package process

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestProcessConversionPreservesMetadata(t *testing.T) {
	startTime := time.Unix(1000, 0)

	process := core.Process{
		PID:         123,
		PPID:        100,
		StartTime:   startTime,
		Name:        "python",
		Executable:  "/usr/bin/python3",
		CommandLine: "python3 -c test",
		User:        "test-user",
	}

	if process.PID != 123 {
		t.Fatalf("expected PID 123, got %d", process.PID)
	}

	if process.PPID != 100 {
		t.Fatalf("expected PPID 100, got %d", process.PPID)
	}

	if process.Name != "python" {
		t.Fatalf("expected name python, got %q", process.Name)
	}

	if process.Executable != "/usr/bin/python3" {
		t.Fatalf(
			"expected executable /usr/bin/python3, got %q",
			process.Executable,
		)
	}

	if process.CommandLine != "python3 -c test" {
		t.Fatalf(
			"expected command line %q, got %q",
			"python3 -c test",
			process.CommandLine,
		)
	}

	if process.User != "test-user" {
		t.Fatalf(
			"expected user test-user, got %q",
			process.User,
		)
	}
}
