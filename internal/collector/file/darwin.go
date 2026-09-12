//go:build darwin

package file

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

type esClientAPI interface {
	subscribe() error
	close()
}

type macOSCollector struct {
	mu     sync.Mutex
	closed bool

	events chan esEvent
	client esClientAPI
}

func newMacOSCollectorWithClient(client esClientAPI) *macOSCollector {
	return &macOSCollector{
		events: make(chan esEvent, 256),
		client: client,
	}
}

func (c *macOSCollector) Run(
	ctx context.Context,
	handler func(core.FileEvent),
) error {
	if handler == nil {
		return errors.New("file collector handler is nil")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()

	if c.closed {
		c.mu.Unlock()
		return errors.New("file collector is closed")
	}

	client := c.client

	c.mu.Unlock()

	if client == nil {
		return errors.New("Endpoint Security client is nil")
	}

	if err := client.subscribe(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event := <-c.events:
			fileEvent, err := convertESEvent(
				event,
				time.Now(),
			)
			if err != nil {
				continue
			}

			handler(fileEvent)
		}
	}
}

func (c *macOSCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.closed = true

	if c.client != nil {
		c.client.close()
	}
}

func (c *macOSCollector) enqueueEvent(event esEvent) {
	select {
	case c.events <- event:
	default:
	}
}
