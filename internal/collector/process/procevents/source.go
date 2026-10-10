package procevents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arafat2020/sentinel/internal/core"
)

// Backend names a way of collecting process events.
type Backend string

const (
	// BackendAuto picks the best backend that works on this host.
	BackendAuto Backend = "auto"
	// BackendEBPF uses scheduler tracepoints through eBPF.
	BackendEBPF Backend = "ebpf"
	// BackendProcConnector uses the netlink process-event connector.
	BackendProcConnector Backend = "proc-connector"
	// BackendPoll compares snapshots of the process table.
	BackendPoll Backend = "poll"
)

// ParseBackend reads the value of the --process-collector flag.
func ParseBackend(value string) (Backend, error) {
	switch backend := Backend(strings.ToLower(strings.TrimSpace(value))); backend {
	case BackendAuto, BackendEBPF, BackendProcConnector, BackendPoll:
		return backend, nil
	case "":
		return BackendAuto, nil
	default:
		return "", fmt.Errorf("unknown process collector %q (valid: auto, ebpf, proc-connector, poll)", value)
	}
}

const (
	// DefaultGrace is how long after a fork an exec is still treated as
	// part of starting the process. A shell forks and then execs the
	// command within a fraction of a millisecond; anything that has not
	// exec'd after this long is running its parent's program on purpose.
	DefaultGrace = 50 * time.Millisecond

	// DefaultRingBufferBytes is the size of the eBPF ring buffer. An exec
	// record is about 600 bytes plus its arguments, so this holds roughly
	// ten thousand of them while userspace is busy.
	DefaultRingBufferBytes = 8 << 20

	// DefaultReceiveBufferBytes is the netlink socket receive buffer for
	// the proc connector, whose messages are about 100 bytes each.
	DefaultReceiveBufferBytes = 4 << 20

	// DefaultMaxTracked is the most processes followed at once. Events for
	// further processes are counted and dropped.
	DefaultMaxTracked = 1 << 17

	// DefaultReconcileInterval is how often the tracked processes are
	// compared with the process table, to recover from lost events.
	DefaultReconcileInterval = 30 * time.Second
)

// Options configure an event-driven source.
type Options struct {
	// Grace is the fork-to-exec grace period; zero means DefaultGrace.
	Grace time.Duration
	// RingBufferBytes sizes the eBPF ring buffer; zero means the default.
	// It must be a power of two and a multiple of the page size.
	RingBufferBytes int
	// ReceiveBufferBytes sizes the proc connector's socket buffer; zero
	// means the default.
	ReceiveBufferBytes int
	// MaxTracked caps the tracked-process table; zero means the default.
	MaxTracked int
	// ReconcileInterval is how often to reconcile with the process table;
	// zero means the default, negative disables it.
	ReconcileInterval time.Duration
	// Snapshot lists the running processes. It seeds the tracker and is
	// what reconciliation compares against. Required.
	Snapshot func(context.Context) ([]core.Process, error)
}

func (o Options) withDefaults() Options {
	if o.Grace <= 0 {
		o.Grace = DefaultGrace
	}
	if o.RingBufferBytes <= 0 {
		o.RingBufferBytes = DefaultRingBufferBytes
	}
	if o.ReceiveBufferBytes <= 0 {
		o.ReceiveBufferBytes = DefaultReceiveBufferBytes
	}
	if o.MaxTracked <= 0 {
		o.MaxTracked = DefaultMaxTracked
	}
	if o.ReconcileInterval == 0 {
		o.ReconcileInterval = DefaultReconcileInterval
	}
	return o
}

// Source is a running event-driven process collector.
type Source interface {
	// Backend is which backend this is.
	Backend() Backend
	// Run delivers events to emit, in order, from a single goroutine, until
	// ctx is cancelled or the backend fails. seed is the set of processes
	// already running, as given to the correlation engine; events for
	// anything that started after the source was opened are delivered
	// even if they happened before Run was called.
	Run(ctx context.Context, seed []core.Process, emit func(core.Event)) error
	// Stats reports the source's counters. It is safe to call at any time.
	Stats() Stats
	// Close releases the backend. Run must have returned.
	Close() error
}

// Skip records why a backend was not used.
type Skip struct {
	Backend Backend
	Reason  string
}

func (s Skip) String() string { return fmt.Sprintf("%s: %s", s.Backend, s.Reason) }

// opener starts one backend.
type opener func(Options) (Source, error)

// openers maps each event-driven backend to its implementation on this
// platform. Tests replace entries to force a backend to fail.
var openers = map[Backend]opener{
	BackendEBPF:          openEBPF,
	BackendProcConnector: openProcConnector,
}

// Open starts the requested backend.
//
// For BackendAuto it tries ebpf, then proc-connector, and reports why each
// one that did not work was skipped; if neither works it returns a nil Source
// and no error, meaning the caller should poll. For BackendPoll it returns
// nil at once. Asking for a specific event-driven backend that cannot be
// started is an error: the user asked for it by name and should be told.
func Open(backend Backend, options Options) (Source, []Skip, error) {
	options = options.withDefaults()

	switch backend {
	case BackendPoll:
		return nil, nil, nil

	case BackendEBPF, BackendProcConnector:
		source, err := openers[backend](options)
		if err != nil {
			return nil, nil, fmt.Errorf("process collector %s: %w", backend, err)
		}
		return source, nil, nil

	case BackendAuto:
		var skipped []Skip
		for _, candidate := range []Backend{BackendEBPF, BackendProcConnector} {
			source, err := openers[candidate](options)
			if err == nil {
				return source, skipped, nil
			}
			skipped = append(skipped, Skip{Backend: candidate, Reason: err.Error()})
		}
		return nil, skipped, nil

	default:
		return nil, nil, fmt.Errorf("unknown process collector %q", backend)
	}
}

// Stats are a source's counters. All of them only ever grow, except Tracked
// and Pending, which are current sizes.
type Stats struct {
	Backend Backend `json:"backend"`

	// RawEvents counts kernel events read, by kind.
	RawForks uint64 `json:"raw_forks"`
	RawExecs uint64 `json:"raw_execs"`
	RawExits uint64 `json:"raw_exits"`

	// KernelDrops counts events the kernel could not hand over because the
	// ring buffer (ebpf) was full. For the proc connector the kernel does
	// not say how many messages it discarded, so this counts the number of
	// times the socket reported an overrun.
	KernelDrops uint64 `json:"kernel_drops"`
	// DecodeErrors counts records that could not be understood.
	DecodeErrors uint64 `json:"decode_errors"`

	// Emitted counts events delivered, by type.
	Starts uint64 `json:"starts"`
	Execs  uint64 `json:"execs"`
	Exits  uint64 `json:"exits"`

	// StartsAtExec counts processes whose PROCESS_START was their first
	// exec within the grace period; StartsAtFork counts the rest.
	StartsAtExec uint64 `json:"starts_at_exec"`
	StartsAtFork uint64 `json:"starts_at_fork"`

	// Partial counts events emitted without everything that describes the
	// process, because it was gone before it could be read.
	Partial uint64 `json:"partial"`
	// ArgsTruncated counts command lines longer than the capture limit.
	ArgsTruncated uint64 `json:"args_truncated"`

	// Tracked and Pending are the current number of processes followed, and
	// of those whose PROCESS_START is being held for the grace period.
	Tracked int `json:"tracked"`
	Pending int `json:"pending"`
	// TrackedCapHits counts forks and execs ignored because MaxTracked
	// processes were already being followed.
	TrackedCapHits uint64 `json:"tracked_cap_hits"`

	// UntrackedExecs counts execs by a process whose fork was not seen; it
	// is reported as a start. UntrackedExits counts exits of processes that
	// were never reported, which are ignored.
	UntrackedExecs uint64 `json:"untracked_execs"`
	UntrackedExits uint64 `json:"untracked_exits"`
	// PIDReuses counts forks that revealed a tracked process had exited
	// unnoticed, because its PID was given to a new process.
	PIDReuses uint64 `json:"pid_reuses"`
	// DuplicateForks counts forks of a process already known, which happens
	// once for each process created while the startup snapshot was taken.
	DuplicateForks uint64 `json:"duplicate_forks"`

	// ReconciledStarts and ReconciledExits count events produced by
	// comparing with the process table rather than by a kernel event. They
	// should be zero unless events were dropped.
	ReconciledStarts uint64 `json:"reconciled_starts"`
	ReconciledExits  uint64 `json:"reconciled_exits"`

	// UserCacheSize is the number of user names cached, out of
	// maxCachedUsers; UserCacheResets counts the times it was emptied on
	// reaching that.
	UserCacheSize   int    `json:"user_cache_size"`
	UserCacheResets uint64 `json:"user_cache_resets"`

	// ClockErrorNanos bounds the error of the last conversion from kernel
	// time to wall-clock time: half the time it took to read both clocks.
	ClockErrorNanos int64 `json:"clock_error_nanos"`
}
