//go:build darwin && cgo && es

package file

// NewMacOSCollector creates a macOS file collector backed by a real
// Endpoint Security client. Requires the com.apple.developer.endpoint-security.client
// entitlement and root (or FDA) — es_new_client returns an error otherwise.
func NewMacOSCollector() (*macOSCollector, error) {
	client, err := newESClient()
	if err != nil {
		return nil, err
	}

	c := newMacOSCollectorWithClient(client)
	activeCollector.Store(c)

	return c, nil
}
