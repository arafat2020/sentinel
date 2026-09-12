//go:build darwin && cgo && !es

package file

import "fmt"

// NewMacOSCollector returns an error when the binary was built without the
// "es" build tag. Endpoint Security requires both the tag and a real Apple
// Developer ID certificate with the com.apple.developer.endpoint-security.client
// entitlement approved by Apple.
//
// To enable: go build -tags es ./cmd/sentinel
// (and sign with a real Developer ID, not ad-hoc)
func NewMacOSCollector() (*macOSCollector, error) {
	return nil, fmt.Errorf(
		"Endpoint Security disabled in this build " +
			"(rebuild with -tags es and a valid Apple Developer ID)",
	)
}
