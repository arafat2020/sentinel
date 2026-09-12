//go:build linux

package file

import (
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// Fanotify event mask constants (mirrors linux/fanotify.h).
const (
	maskCloseWrite uint64 = 0x00000008 // FAN_CLOSE_WRITE
	maskCreate     uint64 = 0x00000100 // FAN_CREATE
	maskDelete     uint64 = 0x00000200 // FAN_DELETE
	maskMovedFrom  uint64 = 0x00000040 // FAN_MOVED_FROM
	maskMovedTo    uint64 = 0x00000080 // FAN_MOVED_TO
)

// linuxFileEvent holds a single fanotify event after the backend has
// resolved the path and extracted the PID from the event metadata.
type linuxFileEvent struct {
	Mask uint64
	PID  int32
	Path string
}

// convertLinuxEvent maps a linuxFileEvent to a core.FileEvent.
// Returns false when the mask carries no recognised operation.
//
// NOTE: FAN_MOVED_FROM and FAN_MOVED_TO are separate fanotify events
// with no built-in correlation token (unlike inotify cookies). Both are
// emitted as FileRename; callers that need to pair them must do so by
// observing sequential rename events on the same PID.
func convertLinuxEvent(
	event linuxFileEvent,
	ts time.Time,
) (core.FileEvent, bool) {
	var op core.FileOperation

	switch {
	case event.Mask&maskCloseWrite != 0:
		op = core.FileModify
	case event.Mask&maskCreate != 0:
		op = core.FileCreate
	case event.Mask&maskDelete != 0:
		op = core.FileDelete
	case event.Mask&(maskMovedFrom|maskMovedTo) != 0:
		op = core.FileRename
	default:
		return core.FileEvent{}, false
	}

	return core.FileEvent{
		Timestamp: ts,
		PID:       event.PID,
		Path:      event.Path,
		Operation: op,
	}, true
}
