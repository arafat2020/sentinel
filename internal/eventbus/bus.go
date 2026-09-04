package eventbus

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

type Handler func(core.Event)

type Bus struct {
	events   chan core.Event
	handlers []Handler
}

func New(bufferSize int) *Bus {
	return &Bus{
		events: make(chan core.Event, bufferSize),
	}
}

func (b *Bus) Subscribe(handler Handler) {
	b.handlers = append(b.handlers, handler)
}

func (b *Bus) Publish(event core.Event) {
	b.events <- event

}

func (b *Bus) Start(ctx context.Context) {
	go b.processEvents(ctx)
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
