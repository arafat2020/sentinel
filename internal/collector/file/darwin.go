//go:build darwin

package file

import (
	"context"
	"errors"
	"sync"

	"github.com/arafat2020/sentinel/internal/core"
)

type macOSCollector struct {
	mu     sync.Mutex
	closed bool
}

func NewMacOSCollector() (*macOSCollector, error) {
	return &macOSCollector{}, nil
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
	c.mu.Unlock()

	<-ctx.Done()

	return ctx.Err()
}

func (c *macOSCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.closed = true
}
