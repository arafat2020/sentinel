//go:build darwin && !cgo

package file

import "fmt"

// NewMacOSCollector is a stub for CGo-disabled builds. Endpoint Security
// requires CGo; enable it with CGO_ENABLED=1 (the default on macOS).
func NewMacOSCollector() (*macOSCollector, error) {
	return nil, fmt.Errorf("macOS file collector requires CGo (CGO_ENABLED=1)")
}
