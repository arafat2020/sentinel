//go:build windows

package file

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/arafat2020/sentinel/internal/core"
)

// windowsCollector watches file system events on Windows via
// ReadDirectoryChangesW. It implements the Collector interface and mirrors
// the structure of linuxCollector and macOSCollector.
//
// Prerequisites: the caller must have GENERIC_READ access to the watch root
// (typically run as Administrator for system-wide coverage).
type windowsCollector struct {
	mu      sync.Mutex
	closed  bool
	events  chan windowsFileEvent
	watcher *windowsWatcher
}

// NewWindowsCollector creates a collector that watches watchRoot and all
// subdirectories recursively. The path must be an absolute Windows path
// (e.g. `C:\`). Pass resolver as nil to skip process attribution (Windows
// file events do not carry a PID — attribution requires ETW, which is not
// yet implemented).
func NewWindowsCollector(watchRoot string) (*windowsCollector, error) {
	watcher, err := newWindowsWatcher(watchRoot)
	if err != nil {
		return nil, err
	}

	return &windowsCollector{
		events:  make(chan windowsFileEvent, 256),
		watcher: watcher,
	}, nil
}

func (c *windowsCollector) Run(
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
	watcher := c.watcher
	c.mu.Unlock()

	enqueue := func(ev windowsFileEvent) {
		select {
		case c.events <- ev:
		default:
		}
	}

	if err := watcher.start(enqueue); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case ev := <-c.events:
			fe, ok := convertWindowsEvent(ev)
			if !ok {
				continue
			}
			handler(fe)
		}
	}
}

func (c *windowsCollector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	if c.watcher != nil {
		c.watcher.close()
	}
}

// convertWindowsEvent maps a windowsFileEvent to a core.FileEvent.
// Returns false for action types that have no corresponding FileOperation
// (e.g. FILE_ACTION_RENAMED_OLD_NAME before the new-name event arrives).
//
// NOTE: Windows emits paired RENAMED_OLD_NAME / RENAMED_NEW_NAME events.
// Both are surfaced as FileRename; callers needing the old path must
// correlate consecutive rename events.
func convertWindowsEvent(ev windowsFileEvent) (core.FileEvent, bool) {
	var op core.FileOperation

	switch ev.Action {
	case fileActionAdded:
		op = core.FileCreate
	case fileActionModified:
		op = core.FileModify
	case fileActionRemoved:
		op = core.FileDelete
	case fileActionRenamedOldName, fileActionRenamedNewName:
		op = core.FileRename
	default:
		return core.FileEvent{}, false
	}

	return core.FileEvent{
		Timestamp: ev.Time,
		Path:      ev.Path,
		Operation: op,
	}, true
}

// defaultWatchRoot returns the system drive root (e.g. "C:\") which covers
// the majority of user and system activity on a typical Windows installation.
// It reads the SYSTEMDRIVE environment variable set by Windows at boot.
func DefaultWatchRoot() string {
	if d := os.Getenv("SYSTEMDRIVE"); d != "" {
		return d + `\`
	}
	return `C:\`
}
