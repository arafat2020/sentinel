//go:build windows

package dns

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

// windowsAttributor resolves the process that issued a DNS query using
// Windows socket-table lookup (GetExtendedTcpTable/GetExtendedUdpTable).
type windowsAttributor struct {
	socketLookup    SocketLookup
	processResolver ProcessResolver
}

func NewWindowsAttributor(
	socketLookup SocketLookup,
	processResolver ProcessResolver,
) Attributor {
	return &windowsAttributor{
		socketLookup:    socketLookup,
		processResolver: processResolver,
	}
}

func (a *windowsAttributor) Attribute(
	ctx context.Context,
	query *core.DNSQuery,
	sourceIP string,
	sourcePort uint32,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if a == nil || a.socketLookup == nil || query == nil {
		return nil
	}

	if sourceIP == "" || sourcePort == 0 {
		return nil
	}

	owner, err := a.socketLookup.FindOwner(ctx, sourceIP, sourcePort)
	if err != nil {
		return err
	}

	if owner == nil {
		return nil
	}

	query.PID = int32(owner.PID)

	if a.processResolver == nil {
		return nil
	}

	process, err := a.processResolver.Resolve(ctx, int32(owner.PID))
	if err != nil {
		return err
	}

	query.Process = process
	return nil
}
