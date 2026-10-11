//go:build !linux

package netevents

import (
	"fmt"
	"runtime"
)

func openEBPF(Options) (Source, error) {
	return nil, fmt.Errorf("not available on %s", runtime.GOOS)
}
