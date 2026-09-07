package core

import (
	"testing"
	"time"
)

func TestDNSQueryIdentity(t *testing.T) {
	startTime := time.Date(
		2026,
		9,
		5,
		10,
		0,
		0,
		0,
		time.UTC,
	)

	query := DNSQuery{
		Timestamp: time.Now(),
		PID:       123,
		PPID:      100,
		Domain:    "example.com",
		Type:      "A",
		Resolver:  "8.8.8.8",
		Process: &Process{
			PID:       123,
			PPID:      100,
			StartTime: startTime,
			Name:      "curl",
		},
	}

	identity := query.Identity()

	if identity.PID != 123 {
		t.Fatalf("expected PID 123, got %d", identity.PID)
	}

	if identity.Domain != "example.com" {
		t.Fatalf(
			"expected domain example.com, got %s",
			identity.Domain,
		)
	}

	if identity.Type != "A" {
		t.Fatalf(
			"expected type A, got %s",
			identity.Type,
		)
	}
}
