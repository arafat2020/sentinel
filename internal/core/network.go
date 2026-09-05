package core

import "time"

type NetworkConnection struct {
	Timestamp time.Time

	PID  int32
	PPID int32

	Protocol string

	LocalAddress string
	LocalPort    uint32

	RemoteAddress string
	RemotePort    uint32

	State string

	Process *Process
}

type NetworkConnectionIdentity struct {
	PID           int32
	Protocol      string
	LocalAddress  string
	LocalPort     uint32
	RemoteAddress string
	RemotePort    uint32
}

func (c NetworkConnection) Identity() NetworkConnectionIdentity {
	return NetworkConnectionIdentity{
		PID:           c.PID,
		Protocol:      c.Protocol,
		LocalAddress:  c.LocalAddress,
		LocalPort:     c.LocalPort,
		RemoteAddress: c.RemoteAddress,
		RemotePort:    c.RemotePort,
	}
}
