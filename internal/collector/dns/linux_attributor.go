//go:build linux

package dns

import (
	"context"
	"sync/atomic"

	"github.com/arafat2020/sentinel/internal/core"
)

// linuxAttributor resolves the process that issued a DNS query using
// /proc-based socket lookup. Its logic is identical to darwinAttributor;
// only the underlying SocketLookup implementation differs.
type linuxAttributor struct {
	socketLookup    SocketLookup
	processResolver ProcessResolver
	// portOwner, when set, is asked first. See PortOwner.
	portOwner PortOwner

	byPort, byTable, unattributed atomic.Uint64
}

// PortOwner returns the process that last sent from a local port, as an
// event-driven network collector records it in the kernel at the moment of
// sending. protocol is "udp" or "tcp".
//
// The socket-table lookup has to find the socket while it still exists. A
// resolver that asks one question and exits has usually closed its socket by
// the time the packet has been captured and decoded, so the lookup finds
// nothing. What the kernel recorded when the packet was sent does not have
// that problem.
type PortOwner func(protocol string, port uint16) (core.Process, bool)

// AttributionStats counts how queries were attributed.
type AttributionStats struct {
	// ByPortOwner were attributed from what the kernel recorded;
	// BySocketTable by finding the socket in /proc; Unattributed not at
	// all.
	ByPortOwner   uint64
	BySocketTable uint64
	Unattributed  uint64
}

// LinuxAttributor is the Linux attributor with its counters.
type LinuxAttributor interface {
	Attributor
	Stats() AttributionStats
}

// NewLinuxAttributorWithPortOwner returns an attributor that asks owner
// first and falls back to the socket table. owner may be nil.
func NewLinuxAttributorWithPortOwner(socketLookup SocketLookup, processResolver ProcessResolver, owner PortOwner) LinuxAttributor {
	return &linuxAttributor{socketLookup: socketLookup, processResolver: processResolver, portOwner: owner}
}

func (a *linuxAttributor) Stats() AttributionStats {
	return AttributionStats{ByPortOwner: a.byPort.Load(), BySocketTable: a.byTable.Load(), Unattributed: a.unattributed.Load()}
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

	if a.portOwner != nil && sourcePort <= 0xffff {
		// Nearly all DNS is UDP; a query over TCP is looked for second.
		for _, protocol := range []string{"udp", "tcp"} {
			if process, ok := a.portOwner(protocol, uint16(sourcePort)); ok {
				query.PID = process.PID
				query.Process = &process
				a.byPort.Add(1)
				return nil
			}
		}
	}

	owner, err := a.socketLookup.FindOwner(
		ctx,
		sourceIP,
		sourcePort,
	)
	if err != nil {
		a.unattributed.Add(1)
		return err
	}

	if owner == nil {
		a.unattributed.Add(1)
		return nil
	}

	a.byTable.Add(1)
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
