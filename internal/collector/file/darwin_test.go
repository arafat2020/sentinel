//go:build darwin

package file

import (
	"context"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestMacOSCollectorStopsWithContext(t *testing.T) {
	collector, err := NewMacOSCollector()
	if err != nil {
		t.Fatalf("NewMacOSCollector() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- collector.Run(ctx, func(_ core.FileEvent) {})
	}()

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf(
				"Run() error = %v, want %v",
				err,
				context.Canceled,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("collector.Run() did not stop")
	}

	collector.Close()
}
