package dns

import (
	"context"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeAttributor struct {
	process *core.Process
	err     error
}

func (f *fakeAttributor) Attribute(
	ctx context.Context,
	query *core.DNSQuery,
	sourceIP string,
	sourcePort uint32,
) error {
	if f.err != nil {
		return f.err
	}

	if f.process == nil {
		return nil
	}

	query.PID = f.process.PID
	query.PPID = f.process.PPID
	query.Process = f.process

	return nil
}

func TestAttributorAttribute(t *testing.T) {
	process := &core.Process{
		PID:         1234,
		PPID:        100,
		StartTime:   time.Now(),
		Name:        "node",
		Executable:  "/usr/local/bin/node",
		CommandLine: "node server.js",
		User:        "arafat",
	}

	query := &core.DNSQuery{
		Timestamp: time.Now(),
		Domain:    "example.com",
		Type:      "A",
		Resolver:  "8.8.8.8",
	}

	attributor := &fakeAttributor{
		process: process,
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

	if query.PPID != 100 {
		t.Fatalf(
			"expected PPID 100, got %d",
			query.PPID,
		)
	}

	if query.Process == nil {
		t.Fatal("expected Process to be populated")
	}

	if query.Process.Name != "node" {
		t.Fatalf(
			"expected process name node, got %s",
			query.Process.Name,
		)
	}
}
