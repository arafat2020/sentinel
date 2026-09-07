package dns

import (
	"context"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type fakeCollector struct {
	queries []core.DNSQuery
	err     error
}

func (f *fakeCollector) Collect(
	ctx context.Context,
) ([]core.DNSQuery, error) {
	return f.queries, f.err
}

func TestCollectorCollect(t *testing.T) {
	now := time.Now()

	query := core.DNSQuery{
		Timestamp: now,
		PID:       123,
		PPID:      100,
		Domain:    "example.com",
		Type:      "A",
		Resolver:  "8.8.8.8",
	}

	collector := &fakeCollector{
		queries: []core.DNSQuery{query},
	}

	queries, err := collector.Collect(context.Background())

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(queries) != 1 {
		t.Fatalf(
			"expected 1 query, got %d",
			len(queries),
		)
	}

	if queries[0].Domain != "example.com" {
		t.Fatalf(
			"expected domain example.com, got %s",
			queries[0].Domain,
		)
	}

	if queries[0].PID != 123 {
		t.Fatalf(
			"expected PID 123, got %d",
			queries[0].PID,
		)
	}
}
