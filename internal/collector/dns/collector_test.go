package dns

import (
	"context"
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeCollector struct {
	queries []core.DNSQuery
	err     error
}

func (f *fakeCollector) Run(
	ctx context.Context,
	handler func(core.DNSQuery),
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	for _, query := range f.queries {
		handler(query)
	}

	return f.err
}

func (f *fakeCollector) Close() {}

func TestCollectorRun(t *testing.T) {
	query := core.DNSQuery{
		PID:      123,
		PPID:     100,
		Domain:   "example.com",
		Type:     "A",
		Resolver: "8.8.8.8",
	}

	collector := &fakeCollector{
		queries: []core.DNSQuery{query},
	}

	var received []core.DNSQuery

	err := collector.Run(
		context.Background(),
		func(query core.DNSQuery) {
			received = append(received, query)
		},
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(received) != 1 {
		t.Fatalf(
			"expected 1 query, got %d",
			len(received),
		)
	}

	if received[0].Domain != "example.com" {
		t.Fatalf(
			"expected domain example.com, got %s",
			received[0].Domain,
		)
	}

	if received[0].PID != 123 {
		t.Fatalf(
			"expected PID 123, got %d",
			received[0].PID,
		)
	}
}
