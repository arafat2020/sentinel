package core

import "time"

type DNSQuery struct {
	Timestamp time.Time

	PID  int32
	PPID int32

	Domain string
	Type   string

	Resolver string

	Process *Process
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
