package netevents

import (
	"encoding/binary"
	"errors"
	"net"
)

// The layout of struct event in bpf/net.bpf.c.
const (
	recordSize = 120

	kindConnect  = 1
	kindClose    = 2
	kindListen   = 3
	kindUnlisten = 4
	kindUDP      = 5

	directionOut = 1
	directionIn  = 2

	familyInet  = 2
	familyInet6 = 10

	protoTCP = 6
	protoUDP = 17
)

// record is a decoded kernel record, with kernel times as the kernel gave
// them.
type record struct {
	bootNanos   uint64 // when it happened
	openedNanos uint64 // when the connection was opened, or 0
	startNanos  uint64 // the owner's start_boottime

	bytesSent, bytesReceived uint64

	kind  uint32
	pid   int32
	ppid  int32
	uid   uint32
	netns uint32
	errno uint32

	family       uint16
	lport, rport uint16
	direction    uint8
	protocol     uint8

	local, remote string
	comm          string
}

var errBadRecord = errors.New("malformed network record")

func decodeRecord(sample []byte) (record, error) {
	if len(sample) < recordSize {
		return record{}, errBadRecord
	}

	le := binary.LittleEndian
	r := record{
		bootNanos:     le.Uint64(sample[0:]),
		openedNanos:   le.Uint64(sample[8:]),
		startNanos:    le.Uint64(sample[16:]),
		bytesSent:     le.Uint64(sample[24:]),
		bytesReceived: le.Uint64(sample[32:]),
		kind:          le.Uint32(sample[40:]),
		pid:           int32(le.Uint32(sample[44:])),
		ppid:          int32(le.Uint32(sample[48:])),
		uid:           le.Uint32(sample[52:]),
		netns:         le.Uint32(sample[56:]),
		errno:         le.Uint32(sample[60:]),
		family:        le.Uint16(sample[64:]),
		lport:         le.Uint16(sample[66:]),
		rport:         le.Uint16(sample[68:]),
		direction:     sample[70],
		protocol:      sample[71],
		comm:          cString(sample[104:120]),
	}

	if r.kind < kindConnect || r.kind > kindUDP {
		return record{}, errBadRecord
	}
	if r.family != familyInet && r.family != familyInet6 {
		return record{}, errBadRecord
	}

	r.local = address(r.family, sample[72:88])
	r.remote = address(r.family, sample[88:104])

	return r, nil
}

// address renders a socket address as the poll collector does. An IPv4
// address carried in an IPv6 socket (::ffff:a.b.c.d, which is what a
// dual-stack server sees for an IPv4 client) is written as the IPv4 address:
// net.IP.String does that, and it is what the poller's library uses. The
// unspecified address is written as it is ("0.0.0.0", "::").
func address(family uint16, raw []byte) string {
	if family == familyInet {
		return net.IP(raw[:4]).String()
	}
	return net.IP(raw[:16]).String()
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
