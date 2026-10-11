package netevents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// Backend names a way of collecting network events.
type Backend string

const (
	// BackendAuto uses eBPF where it works and polls otherwise.
	BackendAuto Backend = "auto"
	// BackendEBPF follows sockets through the kernel with eBPF.
	BackendEBPF Backend = "ebpf"
	// BackendPoll compares snapshots of the socket table.
	BackendPoll Backend = "poll"
)

// ParseBackend reads the value of the --network-collector flag.
func ParseBackend(value string) (Backend, error) {
	switch backend := Backend(strings.ToLower(strings.TrimSpace(value))); backend {
	case BackendAuto, BackendEBPF, BackendPoll:
		return backend, nil
	case "":
		return BackendAuto, nil
	default:
		return "", fmt.Errorf("unknown network collector %q (valid: auto, ebpf, poll)", value)
	}
}

const (
	// DefaultRingBufferBytes is the size of the eBPF ring buffer. A record
	// is 120 bytes, so this holds about 130,000 of them while userspace is
	// busy.
	DefaultRingBufferBytes = 16 << 20

	// The sizes of the kernel tables, fixed in bpf/net.bpf.c. Each is an
	// LRU: when it is full the entry least recently used makes room.
	SockTableSize = 65536
	UDPTableSize  = 16384
	PortTableSize = 16384
)

// Options configure the eBPF source.
type Options struct {
	// RingBufferBytes sizes the ring buffer; zero means the default.
	RingBufferBytes int
	// Describe returns everything known about the process with this
	// identity: its executable, command line and so on. The kernel record
	// names the process (PID, start time, parent, user, short name);
	// Describe fills in the rest when the process can still be found. It
	// may be nil.
	Describe func(ctx context.Context, known core.Process) (core.Process, bool)
}

// Owner is the process that holds a local port.
type Owner struct {
	Process core.Process
}

// Source is a running event-driven network collector.
type Source interface {
	Backend() Backend
	// Run delivers events to emit, in order, from one goroutine, until ctx
	// is cancelled or the backend fails.
	Run(ctx context.Context, emit func(core.Event)) error
	// PortOwner returns the process that last used a local port in this
	// host's network namespace, for attributing packets seen on the wire.
	// protocol is "udp" or "tcp". It is safe to call from any goroutine.
	PortOwner(protocol string, port uint16) (core.Process, bool)
	// Stats reports the source's counters. It is safe to call at any time.
	Stats() Stats
	Close() error
}

// Skip records why a backend was not used.
type Skip struct {
	Backend Backend
	Reason  string
}

func (s Skip) String() string { return fmt.Sprintf("%s: %s", s.Backend, s.Reason) }

// openEBPFSource starts the eBPF backend. Tests replace it.
var openEBPFSource = openEBPF

// Open starts the requested backend. For auto it tries eBPF and reports why
// it was skipped if it does not work; a nil Source with no error means the
// caller should poll. Asking for ebpf by name when it cannot be started is an
// error.
func Open(backend Backend, options Options) (Source, []Skip, error) {
	if options.RingBufferBytes <= 0 {
		options.RingBufferBytes = DefaultRingBufferBytes
	}

	switch backend {
	case BackendPoll:
		return nil, nil, nil

	case BackendEBPF:
		source, err := openEBPFSource(options)
		if err != nil {
			return nil, nil, fmt.Errorf("network collector ebpf: %w", err)
		}
		return source, nil, nil

	case BackendAuto:
		source, err := openEBPFSource(options)
		if err != nil {
			return nil, []Skip{{Backend: BackendEBPF, Reason: err.Error()}}, nil
		}
		return source, nil, nil

	default:
		return nil, nil, fmt.Errorf("unknown network collector %q", backend)
	}
}

// Stats are a source's counters. All only ever grow.
type Stats struct {
	Backend Backend `json:"backend"`

	// Events delivered, by what happened.
	Connects uint64 `json:"connects"` // outbound TCP connections established
	Failed   uint64 `json:"failed"`   // outbound TCP attempts that failed
	Accepts  uint64 `json:"accepts"`  // inbound TCP connections accepted
	Closes   uint64 `json:"closes"`   // established TCP connections closed
	Listens  uint64 `json:"listens"`  // TCP sockets that started listening
	UDP      uint64 `json:"udp"`      // UDP sockets on their first use

	// KernelDrops counts records the kernel could not hand over because the
	// ring buffer was full.
	KernelDrops uint64 `json:"kernel_drops"`
	// Unowned counts closes of TCP connections whose owner was not known:
	// connections older than the collector, or whose entry in the socket
	// table was pushed out because the table was full.
	Unowned uint64 `json:"unowned"`
	// SockInserts and UDPInserts count entries made in the socket and UDP
	// tables. Compared with their sizes they say how hard the tables are
	// being used; they are not a count of what the tables hold now.
	SockInserts uint64 `json:"sock_inserts"`
	UDPInserts  uint64 `json:"udp_inserts"`
	// DecodeErrors counts records that could not be understood.
	DecodeErrors uint64 `json:"decode_errors"`
	// Undescribed counts events whose process could be named but not
	// described further, because it was gone.
	Undescribed uint64 `json:"undescribed"`

	// ClockErrorNanos bounds the error of the conversion from kernel time
	// to wall-clock time.
	ClockErrorNanos int64 `json:"clock_error_nanos"`
}

// Metadata keys set on the events this package emits.
const (
	// MetaNetNS is the inode number of the network namespace the socket
	// belongs to.
	MetaNetNS = "netns"
	// MetaErrno is the kernel's error number for a failed connection.
	MetaErrno = "errno"
)

// The states reported, in the poll collector's vocabulary.
const (
	stateEstablished = "ESTABLISHED"
	stateListen      = "LISTEN"
	stateClose       = "CLOSE"
	stateNone        = "NONE" // UDP has no states
)

// Error numbers a failed connection ends with (asm-generic/errno.h; the same
// on every architecture Sentinel's eBPF backend supports).
const (
	errNetUnreach   = 101
	errTimedOut     = 110
	errConnRefused  = 111
	errHostUnreach  = 113
	errNoRouteProto = 92 // ENOPROTOOPT: ICMP protocol unreachable
)

// resultOf maps the socket error a connection attempt ended with to a result.
func resultOf(errno uint32) string {
	switch errno {
	case 0:
		return core.ResultOK
	case errConnRefused:
		return core.ResultRefused
	case errTimedOut:
		return core.ResultTimeout
	case errNetUnreach, errHostUnreach, errNoRouteProto:
		return core.ResultUnreachable
	default:
		return core.ResultOther
	}
}

// durationMs is how long a connection was open, never negative.
func durationMs(opened, closed uint64) int64 {
	if opened == 0 || closed < opened {
		return 0
	}
	return int64((closed - opened) / uint64(time.Millisecond))
}
