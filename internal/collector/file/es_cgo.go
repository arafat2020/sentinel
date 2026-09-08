//go:build darwin && cgo

package file

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -framework EndpointSecurity

#include "es_bridge.h"
*/
import "C"
