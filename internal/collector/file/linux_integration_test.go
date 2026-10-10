//go:build linux && integration

package file

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// The real fanotify backend must report where things happened. Needs root:
//
//	sudo go test -tags integration ./internal/collector/file/
func TestFanotifyReportsPaths(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}

	collector, err := NewLinuxCollector("/", nil)
	if err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("/tmp", "sentinel-fanotify-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "created")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		time.Sleep(500 * time.Millisecond)
		os.WriteFile(target, []byte("x"), 0o644)
		os.Remove(target)
	}()

	var mu sync.Mutex
	paths := map[core.FileOperation]string{}

	if err := collector.Run(ctx, func(event core.FileEvent) {
		if event.PID != int32(os.Getpid()) {
			return
		}
		mu.Lock()
		if event.Path == target {
			paths[event.Operation] = event.Path
		}
		mu.Unlock()
	}); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, operation := range []core.FileOperation{core.FileCreate, core.FileModify, core.FileDelete} {
		if paths[operation] != target {
			t.Errorf("no %s event for %s (events with that path: %v)", operation, target, paths)
		}
	}
}
