package netevents

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/arafat2020/sentinel/internal/core"
)

// encode builds a kernel record as bpf/net.bpf.c lays it out.
func encode(r record, local, remote net.IP) []byte {
	b := make([]byte, recordSize)
	le := binary.LittleEndian

	le.PutUint64(b[0:], r.bootNanos)
	le.PutUint64(b[8:], r.openedNanos)
	le.PutUint64(b[16:], r.startNanos)
	le.PutUint64(b[24:], r.bytesSent)
	le.PutUint64(b[32:], r.bytesReceived)
	le.PutUint32(b[40:], r.kind)
	le.PutUint32(b[44:], uint32(r.pid))
	le.PutUint32(b[48:], uint32(r.ppid))
	le.PutUint32(b[52:], r.uid)
	le.PutUint32(b[56:], r.netns)
	le.PutUint32(b[60:], r.errno)
	le.PutUint16(b[64:], r.family)
	le.PutUint16(b[66:], r.lport)
	le.PutUint16(b[68:], r.rport)
	b[70], b[71] = r.direction, r.protocol
	copy(b[72:88], local)
	copy(b[88:104], remote)
	copy(b[104:120], r.comm)
	return b
}

func TestDecodeRecord(t *testing.T) {
	want := record{
		bootNanos: 5_000_000_000, openedNanos: 4_000_000_000, startNanos: 123_456_789,
		bytesSent: 1500, bytesReceived: 98765,
		kind: kindClose, pid: 4242, ppid: 77, uid: 1000, netns: 4026531840, errno: 0,
		family: familyInet, lport: 51000, rport: 443, direction: directionOut, protocol: protoTCP,
		local: "10.0.0.5", remote: "203.0.113.9", comm: "curl",
	}

	got, err := decodeRecord(encode(want, net.IPv4(10, 0, 0, 5).To4(), net.IPv4(203, 0, 113, 9).To4()))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("decoded\n %+v\nwant\n %+v", got, want)
	}

	// A name that fills all sixteen bytes has no terminator.
	long := want
	long.comm = "0123456789abcdef"
	if got, err := decodeRecord(encode(long, net.IPv4zero.To4(), net.IPv4zero.To4())); err != nil || got.comm != long.comm {
		t.Errorf("sixteen-byte name: %q, %v", got.comm, err)
	}
}

func TestDecodeRecordRejectsDamage(t *testing.T) {
	good := encode(record{kind: kindConnect, family: familyInet}, net.IPv4zero.To4(), net.IPv4zero.To4())

	cases := map[string][]byte{
		"empty":     nil,
		"truncated": good[:recordSize-1],
	}
	badKind := append([]byte(nil), good...)
	badKind[40] = 99
	cases["unknown kind"] = badKind
	zeroKind := append([]byte(nil), good...)
	zeroKind[40] = 0
	cases["kind zero"] = zeroKind
	badFamily := append([]byte(nil), good...)
	badFamily[64] = 1 // AF_UNIX
	cases["not an internet socket"] = badFamily

	for name, sample := range cases {
		if _, err := decodeRecord(sample); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
}

// Addresses are written as the poll collector writes them. In particular an
// IPv4 peer of an IPv6 socket is an IPv4 address, not ::ffff:a.b.c.d, so
// that a pattern's remote_addr and cidr tests mean the same under either
// collector.
func TestAddressNormalisation(t *testing.T) {
	cases := []struct {
		family uint16
		ip     net.IP
		want   string
	}{
		{familyInet, net.IPv4(192, 0, 2, 7).To4(), "192.0.2.7"},
		{familyInet, net.IPv4zero.To4(), "0.0.0.0"},
		{familyInet6, net.ParseIP("2001:db8::5"), "2001:db8::5"},
		{familyInet6, net.ParseIP("::1"), "::1"},
		{familyInet6, net.IPv6unspecified, "::"},
		// IPv4-mapped: the sixteen-byte form of an IPv4 address.
		{familyInet6, net.ParseIP("::ffff:192.0.2.7"), "192.0.2.7"},
		{familyInet6, net.ParseIP("::ffff:127.0.0.1"), "127.0.0.1"},
	}

	for _, c := range cases {
		raw := make([]byte, 16)
		if c.family == familyInet {
			copy(raw, c.ip.To4())
		} else {
			copy(raw, c.ip.To16())
		}
		if got := address(c.family, raw); got != c.want {
			t.Errorf("family %d, %v: %q, want %q", c.family, c.ip, got, c.want)
		}
	}
}

func TestResultMapping(t *testing.T) {
	cases := map[uint32]string{
		0:          core.ResultOK,
		111:        core.ResultRefused,     // ECONNREFUSED
		110:        core.ResultTimeout,     // ETIMEDOUT
		113:        core.ResultUnreachable, // EHOSTUNREACH
		101:        core.ResultUnreachable, // ENETUNREACH
		92:         core.ResultUnreachable, // ENOPROTOOPT
		104:        core.ResultOther,       // ECONNRESET
		99:         core.ResultOther,       // EADDRNOTAVAIL
		^uint32(0): core.ResultOther,       // failed with no error recorded
	}
	for errno, want := range cases {
		if got := resultOf(errno); got != want {
			t.Errorf("errno %d: %q, want %q", errno, got, want)
		}
	}
}

func TestDurationMs(t *testing.T) {
	if got := durationMs(1_000_000_000, 3_500_000_000); got != 2500 {
		t.Errorf("2.5 s = %d ms", got)
	}
	if got := durationMs(0, 5_000_000_000); got != 0 {
		t.Errorf("unknown opening time = %d ms", got)
	}
	if got := durationMs(5_000_000_000, 4_000_000_000); got != 0 {
		t.Errorf("closed before opened = %d ms", got)
	}
}

func TestParseBackend(t *testing.T) {
	for value, want := range map[string]Backend{"": BackendAuto, "auto": BackendAuto, " EBPF ": BackendEBPF, "poll": BackendPoll} {
		if got, err := ParseBackend(value); err != nil || got != want {
			t.Errorf("ParseBackend(%q) = %q, %v", value, got, err)
		}
	}
	if _, err := ParseBackend("proc-connector"); err == nil {
		t.Error("an unknown backend was accepted")
	}
}

// auto falls back and says why; a backend asked for by name does not.
func TestOpenSelection(t *testing.T) {
	real := openEBPFSource
	defer func() { openEBPFSource = real }()

	openEBPFSource = func(Options) (Source, error) { return nil, errBadRecord }

	source, skipped, err := Open(BackendAuto, Options{})
	if err != nil || source != nil || len(skipped) != 1 || skipped[0].Backend != BackendEBPF || skipped[0].String() != "ebpf: malformed network record" {
		t.Errorf("auto: source %v, skipped %v, err %v", source, skipped, err)
	}
	if _, _, err := Open(BackendEBPF, Options{}); err == nil {
		t.Error("ebpf by name did not report its failure")
	}
	if source, skipped, err := Open(BackendPoll, Options{}); source != nil || skipped != nil || err != nil {
		t.Errorf("poll: %v %v %v", source, skipped, err)
	}

	var got Options
	openEBPFSource = func(o Options) (Source, error) { got = o; return nil, errBadRecord }
	Open(BackendAuto, Options{})
	if got.RingBufferBytes != DefaultRingBufferBytes {
		t.Errorf("default ring buffer = %d", got.RingBufferBytes)
	}
}
