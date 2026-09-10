//go:build darwin

package file

import (
	"fmt"
	"testing"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

const (
	esEventTypeCreate uint32 = 1
	esEventTypeWrite  uint32 = 2
	esEventTypeUnlink uint32 = 3
	esEventTypeRename uint32 = 4
)

type esEvent struct {
	eventType uint32
	pid       int32
	ppid      int32
	path      string
	oldPath   string
}

func convertESEvent(
	event esEvent,
	timestamp time.Time,
) (core.FileEvent, error) {
	var operation core.FileOperation

	switch event.eventType {
	case esEventTypeCreate:
		operation = core.FileCreate

	case esEventTypeWrite:
		operation = core.FileModify

	case esEventTypeUnlink:
		operation = core.FileDelete

	case esEventTypeRename:
		operation = core.FileRename

	default:
		return core.FileEvent{}, fmt.Errorf(
			"unsupported Endpoint Security event type: %d",
			event.eventType,
		)
	}

	return core.FileEvent{
		Timestamp: timestamp,

		PID:  event.pid,
		PPID: event.ppid,

		Path:    event.path,
		OldPath: event.oldPath,

		Operation: operation,
	}, nil
}

func TestMacOSEventChannel(t *testing.T) {
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

	collector.events <- event

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
