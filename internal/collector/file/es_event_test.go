//go:build darwin

package file

import (
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

func TestConvertESEvent(t *testing.T) {
	timestamp := time.Date(
		2026, 9, 10,
		10, 0, 0, 0,
		time.UTC,
	)

	tests := []struct {
		name      string
		eventType uint32
		wantOp    core.FileOperation
	}{
		{
			name:      "create",
			eventType: esEventTypeCreate,
			wantOp:    core.FileCreate,
		},
		{
			name:      "write",
			eventType: esEventTypeWrite,
			wantOp:    core.FileModify,
		},
		{
			name:      "unlink",
			eventType: esEventTypeUnlink,
			wantOp:    core.FileDelete,
		},
		{
			name:      "rename",
			eventType: esEventTypeRename,
			wantOp:    core.FileRename,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := esEvent{
				eventType: tt.eventType,
				pid:       1234,
				ppid:      100,
				path:      "/tmp/test.txt",
				oldPath:   "/tmp/old.txt",
			}

			got, err := convertESEvent(event, timestamp)
			if err != nil {
				t.Fatalf("convertESEvent() error = %v", err)
			}

			if got.Timestamp != timestamp {
				t.Fatalf(
					"Timestamp = %v, want %v",
					got.Timestamp,
					timestamp,
				)
			}

			if got.PID != 1234 {
				t.Fatalf("PID = %d, want 1234", got.PID)
			}

			if got.PPID != 100 {
				t.Fatalf("PPID = %d, want 100", got.PPID)
			}

			if got.Path != "/tmp/test.txt" {
				t.Fatalf(
					"Path = %q, want %q",
					got.Path,
					"/tmp/test.txt",
				)
			}

			if got.OldPath != "/tmp/old.txt" {
				t.Fatalf(
					"OldPath = %q, want %q",
					got.OldPath,
					"/tmp/old.txt",
				)
			}

			if got.Operation != tt.wantOp {
				t.Fatalf(
					"Operation = %q, want %q",
					got.Operation,
					tt.wantOp,
				)
			}
		})
	}
}

func TestConvertESEventRejectsUnknownType(t *testing.T) {
	event := esEvent{
		eventType: 9999,
		pid:       1234,
		ppid:      100,
		path:      "/tmp/test.txt",
	}

	_, err := convertESEvent(event, time.Now())
	if err == nil {
		t.Fatal("convertESEvent() error = nil, want error")
	}
}

func TestMacOSEventCallback(t *testing.T) {
	collector, err := NewMacOSCollector()
	if err != nil {
		t.Fatalf("NewMacOSCollector() error = %v", err)
	}

	event := esEvent{
		eventType: esEventTypeCreate,
		pid:       1234,
		ppid:      100,
		path:      "/tmp/test.txt",
	}

	collector.enqueueEvent(event)

	select {
	case got := <-collector.events:
		if got.eventType != event.eventType {
			t.Fatalf(
				"eventType = %d, want %d",
				got.eventType,
				event.eventType,
			)
		}

		if got.pid != event.pid {
			t.Fatalf(
				"PID = %d, want %d",
				got.pid,
				event.pid,
			)
		}

		if got.path != event.path {
			t.Fatalf(
				"path = %q, want %q",
				got.path,
				event.path,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("event was not received")
	}
}
