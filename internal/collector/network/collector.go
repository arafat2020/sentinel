package network

import (
	"context"
	"time"

	processcollector "github.com/arafat2020/sentinel/internal/collector/process"
	"github.com/arafat2020/sentinel/internal/core"
	gopsnet "github.com/shirou/gopsutil/v4/net"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
)

type Collector struct{}

func NewCollector() *Collector {
	return &Collector{}
}

func protocolName(socketType uint32) string {
	switch socketType {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return "unknown"
	}
}

func buildConnection(
	connection gopsnet.ConnectionStat,
	process core.Process,
) core.NetworkConnection {
	// A snapshot of the socket table says little about how a socket came to
	// be: only that a listening socket is waiting for inbound connections,
	// and that an established one was opened successfully. Which side
	// opened it, and what it carried, are left unset.
	direction, result := "", ""
	switch connection.Status {
	case "LISTEN":
		direction = core.DirectionInbound
	case "ESTABLISHED":
		result = core.ResultOK
	}

	return core.NetworkConnection{
		Direction:     direction,
		Result:        result,
		Timestamp:     time.Now(),
		PID:           connection.Pid,
		PPID:          process.PPID,
		Protocol:      protocolName(connection.Type),
		LocalAddress:  connection.Laddr.IP,
		LocalPort:     connection.Laddr.Port,
		RemoteAddress: connection.Raddr.IP,
		RemotePort:    connection.Raddr.Port,
		State:         connection.Status,
		Process:       &process,
	}
}

func (c *Collector) Collect(
	ctx context.Context,
) ([]core.NetworkConnection, error) {
	processes, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	connections := make([]core.NetworkConnection, 0)

	for _, p := range processes {
		processConnections, err := p.ConnectionsWithContext(ctx)
		if err != nil {
			// Some processes may be inaccessible due to OS permissions.
			continue
		}

		// Built by the process collector's own logic, so the connection's
		// process has the same identity the process collector reports.
		process := processcollector.FromGopsutil(ctx, p)

		for _, connection := range processConnections {
			connections = append(
				connections,
				buildConnection(connection, process),
			)
		}
	}

	return connections, nil
}
