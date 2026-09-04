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

	bus.Start(context.Background())

	bus.Shutdown()

	if accepted := bus.Publish(core.Event{
		Type: core.EventProcessStart,
	}); accepted {
		t.Fatal("expected Publish to reject event after shutdown")
	}
}

func TestBusBlockedPublishUnblocksAfterShutdown(t *testing.T) {
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

	ctx := context.Background()
	bus.Start(ctx)

	// Worker takes event1 and gets stuck in the handler.
	if !bus.Publish(core.Event{
		Type: core.EventProcessStart,
	}) {
		t.Fatal("event1 should be accepted")
	}

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	// Fill the queue.
	if !bus.Publish(core.Event{
		Type: core.EventProcessExit,
	}) {
		t.Fatal("event2 should be accepted")
	}

	// This Publish must block because the queue is full.
	publishDone := make(chan bool)

	go func() {
		publishDone <- bus.Publish(core.Event{
			Type: core.EventProcessStart,
		})
	}()

	select {
	case <-publishDone:
		t.Fatal("event3 should be blocked")
	case <-time.After(100 * time.Millisecond):
		// Expected.
	}

	// Shutdown the bus.
	bus.Shutdown()

	// Release the worker.
	close(releaseHandler)

	// The blocked publisher must eventually finish.
	select {
	case accepted := <-publishDone:
		if accepted {
			t.Fatal("event3 should be rejected after shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Publish never returned after shutdown")
	}
}

func TestBusShutdownIsIdempotent(t *testing.T) {
	bus := New(10)

	bus.Shutdown()
	bus.Shutdown()
	bus.Shutdown()

	if accepted := bus.Publish(core.Event{
		Type: core.EventProcessStart,
	}); accepted {
		t.Fatal("expected Publish to reject events after shutdown")
	}
}

func TestBusShutdownPreventsNewPublishers(t *testing.T) {
	bus := New(1)

	bus.Start(context.Background())

	// Shut the bus down first.
	bus.Shutdown()

	const publishers = 100

	results := make(chan bool, publishers)

	for i := 0; i < publishers; i++ {
		go func() {
			results <- bus.Publish(core.Event{
				Type: core.EventProcessStart,
			})
		}()
	}

	for i := 0; i < publishers; i++ {
		select {
		case accepted := <-results:
			if accepted {
				t.Fatal("Publish accepted an event after shutdown")
			}

		case <-time.After(time.Second):
			t.Fatal("timed out waiting for Publish")
		}
	}
}

func TestBusConcurrentPublishAndShutdown(t *testing.T) {
	bus := New(1)

	ctx := context.Background()
	bus.Start(ctx)

	// Put one event in the queue.
	if !bus.Publish(core.Event{
		Type: core.EventProcessStart,
	}) {
		t.Fatal("expected first event to be accepted")
	}

	// Start many publishers.
	const publishers = 100

	results := make(chan bool, publishers)

	for i := 0; i < publishers; i++ {
		go func() {
			results <- bus.Publish(core.Event{
				Type: core.EventProcessStart,
			})
		}()
	}

	// Shutdown concurrently with the publishers.
	bus.Shutdown()

	// Every publisher must eventually finish.
	for i := 0; i < publishers; i++ {
		select {
		case <-results:
			// Either result is acceptable for a publisher that
			// raced with shutdown.
		case <-time.After(time.Second):
			t.Fatal("Publish remained blocked after shutdown")
		}
	}
}

func TestBusShutdownDrainsAndStopsWorker(t *testing.T) {
	bus := New(10)

	received := make(chan core.Event, 2)

	bus.Subscribe(func(event core.Event) {
		received <- event
	})

	ctx := context.Background()
	bus.Start(ctx)

	event1 := core.Event{
		Type: core.EventProcessStart,
	}

	event2 := core.Event{
		Type: core.EventProcessExit,
	}

	if !bus.Publish(event1) {
		t.Fatal("expected event1 to be published")
	}

	if !bus.Publish(event2) {
		t.Fatal("expected event2 to be published")
	}

	bus.Shutdown()

	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for queued event")
		}
	}
}

func TestBusShutdownStopsWorker(t *testing.T) {
	bus := New(10)

	ctx := context.Background()
	bus.Start(ctx)

	bus.Shutdown()

	done := make(chan struct{})

	go func() {
		bus.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Worker exited successfully.
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event bus worker to stop")
	}
}

func TestBusShutdownCompletesWithBlockedPublisher(t *testing.T) {
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

	ctx := context.Background()
	bus.Start(ctx)

	event := core.Event{
		Type: core.EventProcessStart,
	}

	if !bus.Publish(event) {
		t.Fatal("expected first event to be published")
	}

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	if !bus.Publish(event) {
		t.Fatal("expected second event to be queued")
	}

	publishDone := make(chan bool)

	go func() {
		publishDone <- bus.Publish(event)
	}()

	select {
	case <-publishDone:
		t.Fatal("expected third publish to block")
	case <-time.After(100 * time.Millisecond):
	}

	bus.Shutdown()

	close(releaseHandler)

	select {
	case result := <-publishDone:
		if result {
			t.Fatal("expected blocked publisher to be rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked publisher did not return")
	}

	done := make(chan struct{})

	go func() {
		bus.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Worker exited successfully.
	case <-time.After(time.Second):
		t.Fatal("event bus worker did not stop")
	}
}
