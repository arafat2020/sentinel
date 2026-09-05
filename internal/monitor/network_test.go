package monitor

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	networkcollector "github.com/arafat2020/sentinel/internal/collector/network"
	"github.com/arafat2020/sentinel/internal/core"
	networkdetector "github.com/arafat2020/sentinel/internal/detection/network"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type fakeNetworkCollector struct {
	connections []core.NetworkConnection
	err         error
	calls       atomic.Int32
}

func (c *fakeNetworkCollector) Collect(
	ctx context.Context,
) ([]core.NetworkConnection, error) {
	c.calls.Add(1)

	return c.connections, c.err
}

type fakeNetworkDetector struct {
	events []core.Event
	calls  int
}

func (d *fakeNetworkDetector) Detect(
	connections []core.NetworkConnection,
) []core.Event {
	d.calls++

	return d.events
}

func TestNetworkMonitorPublishesEvents(t *testing.T) {
	bus := eventbus.New(10)

	received := make(chan core.Event, 1)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	bus.Start(context.Background())

	collector := &fakeNetworkCollector{
		connections: []core.NetworkConnection{
			{
				PID:           123,
				Protocol:      "tcp",
				RemoteAddress: "8.8.8.8",
				RemotePort:    443,
			},
		},
	}

	detector := &fakeNetworkDetector{
		events: []core.Event{
			{
				Type: core.EventNetworkConnect,
			},
		},
	}

	monitor := NewNetworkMonitor(
		collector,
		detector,
		time.Hour,
		bus,
	)

	ctx := context.Background()

	monitor.collectAndDetect(ctx)

	select {
	case event := <-received:
		if event.Type != core.EventNetworkConnect {
			t.Fatalf(
				"expected NETWORK_CONNECT, got %s",
				event.Type,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("timed out waiting for network event")
	}

	if collector.calls.Load() != 1 {
		t.Fatalf(
			"expected collector to be called once, got %d",
			collector.calls.Load(),
		)
	}

	if detector.calls != 1 {
		t.Fatalf(
			"expected detector to be called once, got %d",
			detector.calls,
		)
	}
}

func TestNetworkMonitorCollectsImmediately(t *testing.T) {
	bus := eventbus.New(10)

	collector := &fakeNetworkCollector{}

	detector := &fakeNetworkDetector{}

	monitor := NewNetworkMonitor(
		collector,
		detector,
		time.Hour,
		bus,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})

	go func() {
		monitor.Run(ctx)
		close(done)
	}()

	deadline := time.After(time.Second)

	for collector.calls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("monitor did not collect immediately")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
}

func TestNetworkMonitorWithRealCollectorAndDetector(t *testing.T) {
	bus := eventbus.New(100)

	received := make(chan core.Event, 10)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Start(ctx)

	collector := networkcollector.NewCollector()
	detector := networkdetector.NewLifecycleDetector()

	monitor := NewNetworkMonitor(
		collector,
		detector,
		time.Hour,
		bus,
	)

	// First collection establishes the baseline.
	monitor.collectAndDetect(ctx)

	// Second collection verifies that the real collector and detector
	// can operate together.
	monitor.collectAndDetect(ctx)
}

func TestNetworkMonitorDetectsConnectionChange(t *testing.T) {
	bus := eventbus.New(10)

	received := make(chan core.Event, 1)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	ctx := context.Background()
	bus.Start(ctx)

	connection := core.NetworkConnection{
		PID:           123,
		Protocol:      "tcp",
		LocalAddress:  "127.0.0.1",
		LocalPort:     50000,
		RemoteAddress: "8.8.8.8",
		RemotePort:    443,
		State:         "ESTABLISHED",
	}

	collector := &fakeNetworkCollector{}

	detector := networkdetector.NewLifecycleDetector()

	monitor := NewNetworkMonitor(
		collector,
		detector,
		time.Hour,
		bus,
	)

	// Snapshot 1: baseline.
	collector.connections = []core.NetworkConnection{
		connection,
	}

	monitor.collectAndDetect(ctx)

	// Snapshot 2: connection disappeared.
	collector.connections = nil

	monitor.collectAndDetect(ctx)

	select {
	case event := <-received:
		if event.Type != core.EventNetworkClose {
			t.Fatalf(
				"expected NETWORK_CLOSE, got %s",
				event.Type,
			)
		}

		if event.Network == nil {
			t.Fatal("expected network payload")
		}

		if event.Network.RemoteAddress != "8.8.8.8" {
			t.Fatalf(
				"unexpected remote address: %s",
				event.Network.RemoteAddress,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("timed out waiting for network close event")
	}
}
