package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type fakeDNSCollector struct {
	queries []core.DNSQuery
	err     error
}

func (f *fakeDNSCollector) Run(
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

func (f *fakeDNSCollector) Close() {}

func TestDNSMonitorPublishesEvents(t *testing.T) {
	query := core.DNSQuery{
		Timestamp: time.Now(),
		PID:       123,
		PPID:      100,
		Domain:    "example.com",
		Type:      "A",
		Resolver:  "8.8.8.8",
		Process: &core.Process{
			PID:  123,
			Name: "node",
		},
	}

	collector := &fakeDNSCollector{
		queries: []core.DNSQuery{query},
	}

	bus := eventbus.New(10)

	received := make(chan core.Event, 1)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Start(ctx)

	monitor := NewDNSMonitor(
		collector,
		bus,
	)

	err := monitor.Run(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	select {
	case event := <-received:
		if event.Type != core.EventDNSQuery {
			t.Fatalf(
				"expected event type %s, got %s",
				core.EventDNSQuery,
				event.Type,
			)
		}

		if event.DNS == nil {
			t.Fatal("expected DNS payload, got nil")
		}

		if event.DNS.Domain != "example.com" {
			t.Fatalf(
				"expected domain example.com, got %s",
				event.DNS.Domain,
			)
		}

		if event.Process == nil {
			t.Fatal("expected process, got nil")
		}

		if event.Process.PID != 123 {
			t.Fatalf(
				"expected process PID 123, got %d",
				event.Process.PID,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DNS event")
	}
}
