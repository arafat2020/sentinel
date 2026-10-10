package core

import "time"

type NetworkConnection struct {
	Timestamp time.Time `json:"timestamp,omitzero"`

	PID  int32 `json:"pid"`
	PPID int32 `json:"ppid"`

	Protocol string `json:"protocol,omitempty"`

	LocalAddress string `json:"local_address,omitempty"`
	LocalPort    uint32 `json:"local_port,omitempty"`

	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint32 `json:"remote_port,omitempty"`

	State string `json:"state,omitempty"`

	Process *Process `json:"process,omitempty"`
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
