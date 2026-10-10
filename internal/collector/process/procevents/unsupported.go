//go:build !linux

package procevents

import (
	"fmt"
	"runtime"
)

func openEBPF(Options) (Source, error) {
	return nil, fmt.Errorf("not available on %s", runtime.GOOS)
}

func openProcConnector(Options) (Source, error) {
	return nil, fmt.Errorf("not available on %s", runtime.GOOS)
}
