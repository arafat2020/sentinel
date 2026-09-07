//go:build darwin

package dns

import "context"

type SocketOwner struct {
	PID uint32
}

type SocketLookup interface {
	FindOwner(
		ctx context.Context,
		sourceIP string,
		sourcePort uint32,
	) (*SocketOwner, error)
}
