package monitor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	"github.com/arafat2020/sentinel/internal/eventbus"
)

type fakeFileCollector struct {
	event core.FileEvent
}

func (f *fakeFileCollector) Run(
	ctx context.Context,
	handler func(core.FileEvent),
) error {
	handler(f.event)
	return nil
}

func (f *fakeFileCollector) Close() {}

func TestFileMonitorPublishesFileEvents(t *testing.T) {
	tests := []struct {
		name         string
		operation    core.FileOperation
		expectedType core.EventType
	}{
		{
			name:         "create",
			operation:    core.FileCreate,
			expectedType: core.EventFileCreate,
		},
		{
			name:         "modify",
			operation:    core.FileModify,
			expectedType: core.EventFileModify,
		},
		{
			name:         "delete",
			operation:    core.FileDelete,
			expectedType: core.EventFileDelete,
		},
		{
			name:         "rename",
			operation:    core.FileRename,
			expectedType: core.EventFileRename,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := eventbus.New(10)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			bus.Start(ctx)
			defer bus.Shutdown()

			expected := core.FileEvent{
				Timestamp: time.Now(),
				PID:       1234,
				PPID:      1000,
				Path:      "/tmp/test.txt",
				OldPath:   "/tmp/old.txt",
				Operation: tt.operation,
			}

			collector := &fakeFileCollector{
				event: expected,
			}

			monitor := NewFileMonitor(collector, bus)

			var (
				wg    sync.WaitGroup
				event core.Event
			)

			wg.Add(1)

			bus.Subscribe(func(e core.Event) {
				if e.Type != tt.expectedType {
					return
				}

				event = e
				wg.Done()
			})

			if err := monitor.Run(ctx); err != nil {
				t.Fatalf("monitor.Run() error = %v", err)
			}

			wg.Wait()

			if event.Type != tt.expectedType {
				t.Fatalf(
					"event.Type = %s, want %s",
					event.Type,
					tt.expectedType,
				)
			}

			if event.File == nil {
				t.Fatal("event.File is nil")
			}

			if event.File.Operation != tt.operation {
				t.Fatalf(
					"event.File.Operation = %s, want %s",
					event.File.Operation,
					tt.operation,
				)
			}

			if event.File.Path != expected.Path {
				t.Fatalf(
					"event.File.Path = %s, want %s",
					event.File.Path,
					expected.Path,
				)
			}

			if event.File.OldPath != expected.OldPath {
				t.Fatalf(
					"event.File.OldPath = %s, want %s",
					event.File.OldPath,
					expected.OldPath,
				)
			}

			if event.File.PID != expected.PID {
				t.Fatalf(
					"event.File.PID = %d, want %d",
					event.File.PID,
					expected.PID,
				)
			}
		})
	}
}
