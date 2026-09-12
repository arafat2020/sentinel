//go:build darwin && cgo && !es

package file

/*
#cgo CFLAGS: -I${SRCDIR}
*/
import "C"
