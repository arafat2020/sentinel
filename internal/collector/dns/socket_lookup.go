//go:build darwin

package dns

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

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

type ProcessResolver interface {
	Resolve(
		ctx context.Context,
		pid int32,
	) (*core.Process, error)
}
