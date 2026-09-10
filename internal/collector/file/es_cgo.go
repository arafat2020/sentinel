//go:build darwin && cgo

package file

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -lEndpointSecurity -lbsm

#include "es_bridge.h"
*/
import "C"
