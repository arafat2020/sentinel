package network

import (
	"context"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
	gopsnet "github.com/shirou/gopsutil/v4/net"
	gopsprocess "github.com/shirou/gopsutil/v4/process"
)

type Collector struct{}

func NewCollector() *Collector {
	return &Collector{}
}

func buildProcess(
	p *gopsprocess.Process,
	ctx context.Context,
) core.Process {
	name, _ := p.NameWithContext(ctx)
	exe, _ := p.ExeWithContext(ctx)
	cmdline, _ := p.CmdlineWithContext(ctx)
	ppid, _ := p.PpidWithContext(ctx)
	startTime, _ := p.CreateTimeWithContext(ctx)
	username, _ := p.UsernameWithContext(ctx)

	return core.Process{
		PID:         p.Pid,
		PPID:        ppid,
		StartTime:   time.UnixMilli(startTime),
		Name:        name,
		Executable:  exe,
		CommandLine: cmdline,
		User:        username,
	}
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
	return core.NetworkConnection{
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

		process := buildProcess(p, ctx)

		for _, connection := range processConnections {
			connections = append(
				connections,
				buildConnection(connection, process),
			)
		}
	}

	return connections, nil
}
