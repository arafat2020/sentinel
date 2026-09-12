//go:build linux

package dns

import (
	"context"

	"github.com/arafat2020/sentinel/internal/core"
)

// linuxAttributor resolves the process that issued a DNS query using
// /proc-based socket lookup. Its logic is identical to darwinAttributor;
// only the underlying SocketLookup implementation differs.
type linuxAttributor struct {
	socketLookup    SocketLookup
	processResolver ProcessResolver
}

func NewLinuxAttributor(
	socketLookup SocketLookup,
	processResolver ProcessResolver,
) Attributor {
	return &linuxAttributor{
		socketLookup:    socketLookup,
		processResolver: processResolver,
	}
}

func (a *linuxAttributor) Attribute(
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

	owner, err := a.socketLookup.FindOwner(
		ctx,
		sourceIP,
		sourcePort,
	)
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

	process, err := a.processResolver.Resolve(
		ctx,
		int32(owner.PID),
	)
	if err != nil {
		return err
	}

	query.Process = process

	return nil
}
