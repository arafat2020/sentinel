//go:build linux

package file

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// processResolver resolves a PID to its full process metadata.
type processResolver interface {
	Resolve(ctx context.Context, pid int32) (*core.Process, error)
}

// linuxCollector watches file system events on Linux via fanotify
// (requires kernel 5.9+ and CAP_SYS_ADMIN). It mirrors the macOS
// Endpoint Security collector in structure and interface.
type linuxCollector struct {
	mu       sync.Mutex
	closed   bool
	events   chan linuxFileEvent
	backend  fanotifyBackend
	resolver processResolver
}

// NewLinuxCollector creates a collector that watches the filesystem
// containing watchPath. Pass resolver as nil to skip process attribution.
// The caller must have CAP_SYS_ADMIN (or run as root) for fanotify to
// succeed; kernel 5.9+ is required for full CREATE/DELETE/RENAME support.
func NewLinuxCollector(
	watchPath string,
	resolver processResolver,
) (*linuxCollector, error) {
	return &linuxCollector{
		events:   make(chan linuxFileEvent, 256),
		backend:  newRealFanotifyBackend(watchPath),
		resolver: resolver,
	}, nil
}

// newLinuxCollectorWithBackend injects a custom backend, intended for tests.
func newLinuxCollectorWithBackend(
	backend fanotifyBackend,
	resolver processResolver,
) *linuxCollector {
	return &linuxCollector{
		events:   make(chan linuxFileEvent, 256),
		backend:  backend,
		resolver: resolver,
	}
}

func (c *linuxCollector) Run(
	ctx context.Context,
	handler func(core.FileEvent),
) error {
	if handler == nil {
		return errors.New("file event handler cannot be nil")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()

	if c.closed {
		c.mu.Unlock()
		return errors.New("collector is closed")
	}

	backend := c.backend

	c.mu.Unlock()

	if backend == nil {
		return errors.New("fanotify backend is nil")
	}

	enqueue := func(event linuxFileEvent) {
		select {
		case c.events <- event:
		default:
		}
	}

	if err := backend.start(enqueue); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event := <-c.events:
			fe, ok := convertLinuxEvent(event, time.Now())
			if !ok {
				continue
			}

			if c.resolver != nil && event.PID > 0 {
				if process, err := c.resolver.Resolve(ctx, event.PID); err == nil && process != nil {
					fe.PPID = process.PPID
					fe.Process = process
				}
			}

			handler(fe)
		}
	}
}

func (c *linuxCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.closed = true

	if c.backend != nil {
		c.backend.close()
	}
}
