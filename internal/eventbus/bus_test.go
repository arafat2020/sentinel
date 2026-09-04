package eventbus

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestBusPublish(t *testing.T) {
	bus := New(100)

	received := make(chan core.Event, 1)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Start(ctx)

	event := core.Event{
		Type: core.EventProcessStart,
	}

	bus.Publish(event)

	select {
	case receivedEvent := <-received:
		if receivedEvent.Type != core.EventProcessStart {
			t.Fatalf(
				"expected %s, got %s",
				core.EventProcessStart,
				receivedEvent.Type,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBusPublishesToMultipleHandlers(t *testing.T) {
	bus := New(100)

	received := make(chan struct{}, 2)

	bus.Subscribe(func(event core.Event) {
		received <- struct{}{}
	})

	bus.Subscribe(func(event core.Event) {
		received <- struct{}{}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Start(ctx)

	bus.Publish(core.Event{
		Type: core.EventProcessStart,
	})

	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for handlers")
		}
	}
}

func TestBusAppliesBackpressure(t *testing.T) {
	bus := New(1)

	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})

	var once sync.Once
	bus.Subscribe(func(event core.Event) {
		once.Do(func() {
			close(handlerStarted)
		})

		<-releaseHandler
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus.Start(ctx)

	event1 := core.Event{
		Type: core.EventProcessStart,
	}

	event2 := core.Event{
		Type: core.EventProcessExit,
	}

	event3 := core.Event{
		Type: core.EventProcessStart,
	}

	// event1 is picked up by the worker.
	bus.Publish(event1)

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler")
	}

	// event2 fills the queue.
	bus.Publish(event2)

	// event3 should now block because:
	//
	// worker -> processing event1
	// queue  -> event2
	// event3 -> nowhere to go
	published := make(chan struct{})

	go func() {
		bus.Publish(event3)
		close(published)
	}()

	select {
	case <-published:
		t.Fatal("expected Publish to block")
	case <-time.After(100 * time.Millisecond):
		// Expected: Publish is blocked.
	}

	// Release event1.
	close(releaseHandler)

	// The worker processes event2, allowing event3 to enter.
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blocked Publish to complete")
	}
}

func TestBusDrainsQueuedEventsBeforeShutdown(t *testing.T) {
	bus := New(10)

	received := make(chan core.Event, 2)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	ctx, cancel := context.WithCancel(context.Background())

	bus.Start(ctx)

	event1 := core.Event{
		Type: core.EventProcessStart,
	}

	event2 := core.Event{
		Type: core.EventProcessExit,
	}

	bus.Publish(event1)
	bus.Publish(event2)

	// Request shutdown.
	cancel()

	// Both events should still be processed.
	for i := 0; i < 2; i++ {
		select {
		case <-received:
			// Expected.
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for queued event")
		}
	}
}

func TestBusRejectsPublishAfterShutdown(t *testing.T) {
	bus := New(10)

	ctx, cancel := context.WithCancel(context.Background())
	bus.Start(ctx)

	cancel()

	// Give the worker a moment to observe cancellation.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})

	go func() {
		bus.Publish(core.Event{
			Type: core.EventProcessStart,
		})

		close(done)
	}()

	select {
	case <-done:
		// Publish returned.
	case <-time.After(time.Second):
		t.Fatal("Publish blocked after shutdown")
	}
}
