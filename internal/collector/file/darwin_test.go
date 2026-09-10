//go:build darwin

package file

import (
	"context"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestMacOSCollectorStopsWithContext(t *testing.T) {
	collector, err := NewMacOSCollector()
	if err != nil {
		t.Fatalf("NewMacOSCollector() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- collector.Run(ctx, func(_ core.FileEvent) {})
	}()

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf(
				"Run() error = %v, want %v",
				err,
				context.Canceled,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("collector.Run() did not stop")
	}

	collector.Close()
}

func TestMacOSCollectorCanBeCreatedWithoutEndpointSecurity(t *testing.T) {
	collector, err := NewMacOSCollector()
	if err != nil {
		t.Fatalf("NewMacOSCollector() error = %v", err)
	}

	if collector == nil {
		t.Fatal("NewMacOSCollector() returned nil")
	}

	if collector.events == nil {
		t.Fatal("collector.events is nil")
	}

	if collector.client != nil {
		t.Fatal("collector.client should not be initialized yet")
	}
}

type fakeESClient struct {
	subscribed bool
	closed     bool
}

func (f *fakeESClient) subscribe() error {
	f.subscribed = true
	return nil
}

func (f *fakeESClient) close() {
	f.closed = true
}

func TestMacOSCollectorRunSubscribesToEndpointSecurity(
	t *testing.T,
) {
	client := &fakeESClient{}

	collector := newMacOSCollectorWithClient(client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)

	go func() {
		done <- collector.Run(ctx, func(_ core.FileEvent) {})
	}()

	deadline := time.After(time.Second)

	for !client.subscribed {
		select {
		case <-deadline:
			t.Fatal("collector did not subscribe to Endpoint Security")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf(
				"Run() error = %v, want %v",
				err,
				context.Canceled,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("collector.Run() did not stop")
	}
}

func TestMacOSCollectorRunHandlesEvents(t *testing.T) {
	client := &fakeESClient{}
	collector := newMacOSCollectorWithClient(client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	received := make(chan core.FileEvent, 1)

	done := make(chan error, 1)

	go func() {
		done <- collector.Run(ctx, func(event core.FileEvent) {
			received <- event
		})
	}()

	// Wait until Run() has subscribed.
	deadline := time.After(time.Second)

	for !client.subscribed {
		select {
		case <-deadline:
			t.Fatal("collector did not subscribe to Endpoint Security")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	collector.enqueueEvent(esEvent{
		eventType: esEventTypeCreate,
		pid:       1234,
		ppid:      100,
		path:      "/tmp/test.txt",
	})

	select {
	case event := <-received:
		if event.Operation != core.FileCreate {
			t.Fatalf(
				"Operation = %q, want %q",
				event.Operation,
				core.FileCreate,
			)
		}

		if event.PID != 1234 {
			t.Fatalf(
				"PID = %d, want %d",
				event.PID,
				1234,
			)
		}

		if event.Path != "/tmp/test.txt" {
			t.Fatalf(
				"Path = %q, want %q",
				event.Path,
				"/tmp/test.txt",
			)
		}

	case <-time.After(time.Second):
		t.Fatal("collector did not deliver file event")
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf(
				"Run() error = %v, want %v",
				err,
				context.Canceled,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("collector.Run() did not stop")
	}
}
