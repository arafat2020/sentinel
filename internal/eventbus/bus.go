package eventbus

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/arafat2020/sentinel/internal/core"
)

type Handler func(core.Event)

type Bus struct {
	events   chan core.Event
	handlers []Handler
	mu       sync.RWMutex
	closed   bool
	done     chan struct{}
	wg       sync.WaitGroup

	published atomic.Uint64
	waited    atomic.Uint64
	dropped   atomic.Uint64
}

// Stats describes how the bus is coping.
type Stats struct {
	// Published counts events accepted.
	Published uint64 `json:"published"`
	// Waited counts events whose publisher had to wait because the buffer
	// was full. The bus does not discard events to make room: a full
	// buffer holds the publisher back, which pushes the pressure towards
	// the collector, where a kernel buffer absorbs or counts it.
	Waited uint64 `json:"waited"`
	// Dropped counts events refused because the bus was shutting down.
	Dropped uint64 `json:"dropped"`
	// Depth and Capacity are the events waiting now and the buffer size.
	Depth    int `json:"depth"`
	Capacity int `json:"capacity"`
}

// Stats returns the bus's counters.
func (b *Bus) Stats() Stats {
	return Stats{
		Published: b.published.Load(),
		Waited:    b.waited.Load(),
		Dropped:   b.dropped.Load(),
		Depth:     len(b.events),
		Capacity:  cap(b.events),
	}
}

func New(bufferSize int) *Bus {
	return &Bus{
		events: make(chan core.Event, bufferSize),
		done:   make(chan struct{}),
	}

}

func (b *Bus) Subscribe(handler Handler) {
	b.handlers = append(b.handlers, handler)
}

func (b *Bus) Publish(event core.Event) bool {
	b.mu.RLock()

	if b.closed {
		b.mu.RUnlock()
		b.dropped.Add(1)
		return false
	}

	b.mu.RUnlock()

	select {
	case b.events <- event:
		b.published.Add(1)
		return true
	default:
	}

	// The buffer is full: wait for room rather than lose the event.
	b.waited.Add(1)

	select {
	case b.events <- event:
		b.published.Add(1)
		return true

	case <-b.done:
		b.dropped.Add(1)
		return false
	}
}

func (b *Bus) Start(ctx context.Context) {
	b.wg.Add(1)

	go func() {
		defer b.wg.Done()
		b.processEvents(ctx)
	}()
}
func (b *Bus) Wait() {
	b.wg.Wait()
}
func (b *Bus) Shutdown() {
	b.mu.Lock()

	if b.closed {
		b.mu.Unlock()
		return
	}

	b.closed = true
	close(b.done)

	b.mu.Unlock()
}

func (b *Bus) drain() {
	for {
		select {
		case event := <-b.events:
			for _, handler := range b.handlers {
				handler(event)
			}
		default:
			return
		}
	}
}

func (b *Bus) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			b.drain()
			return

		case <-b.done:
			b.drain()
			return

		case event := <-b.events:
			for _, handler := range b.handlers {
				handler(event)
			}
		}
	}
}
