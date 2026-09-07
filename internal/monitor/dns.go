package monitor

import (
	"context"

	"github.com/arafat2020/sentinel/internal/collector/dns"
	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type DNSMonitor struct {
	collector dns.Collector
	bus       *eventbus.Bus
}

func NewDNSMonitor(
	collector dns.Collector,
	bus *eventbus.Bus,
) *DNSMonitor {
	return &DNSMonitor{
		collector: collector,
		bus:       bus,
	}
}

func (m *DNSMonitor) Run(ctx context.Context) error {
	return m.collector.Run(
		ctx,
		func(query core.DNSQuery) {
			event := core.Event{
				ID:        "",
				Timestamp: query.Timestamp,
				Type:      core.EventDNSQuery,
				Process:   query.Process,
				DNS:       &query,
			}

			m.bus.Publish(event)
		},
	)
}

func (m *DNSMonitor) Close() {
	m.collector.Close()
}
