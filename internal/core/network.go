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

	// Direction is "outbound" for a connection this host's process opened
	// and "inbound" for one it accepted or is listening for. Empty when
	// the collector cannot tell.
	Direction string `json:"direction,omitempty"`
	// Result is how an attempt to connect ended: "ok", "refused",
	// "timeout", "unreachable" or "other". Empty when the collector cannot
	// tell.
	Result string `json:"result,omitempty"`
	// Transfer is what a closed connection carried and how long it lasted.
	// It is set on NETWORK_CLOSE events from a collector that measures it,
	// and nil otherwise.
	Transfer *NetworkTransfer `json:"transfer,omitempty"`
}

// The values of NetworkConnection.Direction.
const (
	DirectionOutbound = "outbound"
	DirectionInbound  = "inbound"
)

// The values of NetworkConnection.Result.
const (
	ResultOK          = "ok"
	ResultRefused     = "refused"
	ResultTimeout     = "timeout"
	ResultUnreachable = "unreachable"
	ResultOther       = "other"
)

// NetworkTransfer is the accounting of one closed connection.
type NetworkTransfer struct {
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	// DurationMs is how long the connection was open, in milliseconds.
	DurationMs int64 `json:"duration_ms"`
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
