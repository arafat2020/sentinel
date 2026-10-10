package core

import "time"

type DNSQuery struct {
	Timestamp time.Time `json:"timestamp,omitzero"`

	PID  int32 `json:"pid"`
	PPID int32 `json:"ppid"`

	Domain string `json:"domain,omitempty"`
	Type   string `json:"type,omitempty"`

	Resolver string `json:"resolver,omitempty"`

	Process *Process `json:"process,omitempty"`
}

type DNSQueryIdentity struct {
	PID    int32
	Domain string
	Type   string
}

func (q DNSQuery) Identity() DNSQueryIdentity {
	return DNSQueryIdentity{
		PID:    q.PID,
		Domain: q.Domain,
		Type:   q.Type,
	}
}
