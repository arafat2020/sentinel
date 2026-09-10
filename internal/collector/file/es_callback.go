//go:build darwin && cgo

package file

/*
#include <stdint.h>
*/
import "C"

import "unsafe"

//export sentinelGoESEvent
func sentinelGoESEvent(
	eventType C.uint32_t,
	pid C.int32_t,
	ppid C.int32_t,
	path *C.char,
	oldPath *C.char,
) {
	_ = unsafe.Pointer(path)
	_ = unsafe.Pointer(oldPath)
}
