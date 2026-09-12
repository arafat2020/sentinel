//go:build darwin && cgo

package file

/*
#include <stdint.h>
*/
import "C"

import "sync/atomic"

// activeCollector is set when NewMacOSCollector creates a real ES client.
// sentinelGoESEvent (called from C) routes events into it.
var activeCollector atomic.Pointer[macOSCollector]

//export sentinelGoESEvent
func sentinelGoESEvent(
	eventType C.uint32_t,
	pid C.int32_t,
	ppid C.int32_t,
	path *C.char,
	oldPath *C.char,
) {
	c := activeCollector.Load()
	if c == nil {
		return
	}

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}

	var pathStr, oldPathStr string
	if path != nil {
		pathStr = C.GoString(path)
	}
	if oldPath != nil {
		oldPathStr = C.GoString(oldPath)
	}

	c.enqueueEvent(esEvent{
		eventType: uint32(eventType),
		pid:       int32(pid),
		ppid:      int32(ppid),
		path:      pathStr,
		oldPath:   oldPathStr,
	})
}
