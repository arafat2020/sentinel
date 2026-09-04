package eventbus

import (
	"context"
	"sync"

	"github.com/arafat2020/sentinel/internal/core"
)

type Handler func(core.Event)

type Bus struct {
	events   chan core.Event
	handlers []Handler
	mu       sync.RWMutex
	closed   bool
	done     chan struct{}
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
		return false
	}

	b.mu.RUnlock()

	select {
	case b.events <- event:
		return true

	case <-b.done:
		return false
	}
}

func (b *Bus) Start(ctx context.Context) {
	go b.processEvents(ctx)
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

		case event := <-b.events:
			for _, handler := range b.handlers {
				handler(event)
			}
		}
	}
}
