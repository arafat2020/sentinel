//go:build linux

package procevents

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// The kernel's process-event connector (include/uapi/linux/cn_proc.h). A
// listener on the CN_IDX_PROC netlink group is sent a message for every
// fork, exec and exit, saying which PID and nothing more.
const (
	cnIdxProc = 1
	cnValProc = 1

	procCnMcastListen = 1

	procEventNone = 0x00000000
	procEventFork = 0x00000001
	procEventExec = 0x00000002
	procEventExit = 0x80000000

	netlinkHeaderSize = 16 // struct nlmsghdr
	cnMsgSize         = 20 // struct cn_msg, before its data
	procEventHeader   = 16 // what, cpu, timestamp_ns
)

type connectorBackend struct {
	fd int

	starts *StartTimes
	clock  *wallClock
	users  *userCache

	// buffer holds one datagram; unread is what is left of it.
	buffer []byte
	unread []byte

	overruns     atomic.Uint64
	decodeErrors atomic.Uint64
}

func openProcConnector(options Options) (Source, error) {
	starts, err := NewStartTimes()
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		if errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EAFNOSUPPORT) {
			return nil, fmt.Errorf("kernel has no process connector (built without CONFIG_CONNECTOR): %v", err)
		}
		return nil, fmt.Errorf("open netlink socket: %w", err)
	}

	b := &connectorBackend{
		fd:     fd,
		starts: starts,
		// The connector stamps events with ktime_get_ns(), which is
		// CLOCK_MONOTONIC.
		clock:  newWallClock(unix.CLOCK_MONOTONIC),
		users:  newUserCache(),
		buffer: make([]byte, 64<<10),
	}

	if err := b.listen(options.ReceiveBufferBytes); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return &source{name: BackendProcConnector, options: options, backend: b, users: b.users}, nil
}

func (b *connectorBackend) listen(receiveBytes int) error {
	// A larger buffer than the system-wide limit needs the forcing
	// option, which root may use; failing that, take what is allowed.
	if unix.SetsockoptInt(b.fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, receiveBytes) != nil {
		_ = unix.SetsockoptInt(b.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, receiveBytes)
	}

	timeout := unix.NsecToTimeval(idleWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(b.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return fmt.Errorf("set receive timeout: %w", err)
	}

	address := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}
	if err := unix.Bind(b.fd, address); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return fmt.Errorf("missing capability: the process connector needs root or CAP_NET_ADMIN (%v)", err)
		}
		return fmt.Errorf("bind netlink socket: %w", err)
	}

	// nlmsghdr, cn_msg, and the one-word operation.
	message := make([]byte, netlinkHeaderSize+cnMsgSize+4)
	binary.NativeEndian.PutUint32(message[0:], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(message[12:], uint32(os.Getpid()))
	binary.NativeEndian.PutUint32(message[16:], cnIdxProc)
	binary.NativeEndian.PutUint32(message[20:], cnValProc)
	binary.NativeEndian.PutUint16(message[32:], 4)
	binary.NativeEndian.PutUint32(message[36:], procCnMcastListen)

	if err := unix.Sendto(b.fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return fmt.Errorf("missing capability: the process connector needs root or CAP_NET_ADMIN (%v)", err)
		}
		if errors.Is(err, unix.ECONNREFUSED) || errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("kernel has no process connector (built without CONFIG_PROC_EVENTS): %v", err)
		}
		return fmt.Errorf("subscribe to process events: %w", err)
	}

	return b.awaitAck()
}

// awaitAck waits for the kernel's answer to the subscription. The request
// itself is accepted from anyone; whether it was honoured comes back as a
// PROC_EVENT_NONE message carrying an error number.
func (b *connectorBackend) awaitAck() error {
	deadline := time.Now().Add(500 * time.Millisecond)

	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(b.fd, b.buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
				continue
			}
			return fmt.Errorf("subscribe to process events: %w", err)
		}

		message := b.buffer[:n]
		for len(message) >= netlinkHeaderSize {
			length := int(binary.NativeEndian.Uint32(message[0:]))
			if length < netlinkHeaderSize || length > len(message) {
				break
			}

			body := message[netlinkHeaderSize:length]
			if len(body) >= cnMsgSize+procEventHeader+4 && binary.NativeEndian.Uint32(body[cnMsgSize:]) == procEventNone {
				code := unix.Errno(binary.NativeEndian.Uint32(body[cnMsgSize+procEventHeader:]))
				switch code {
				case 0:
					return nil
				case unix.EPERM, unix.EACCES:
					return fmt.Errorf("missing capability: the process connector needs root or CAP_NET_ADMIN (%v)", code)
				default:
					return fmt.Errorf("subscribe to process events: %v", code)
				}
			}

			// Events can arrive before the acknowledgement on a busy
			// host. They are from before Sentinel started collecting.
			aligned := (length + 3) &^ 3
			if aligned >= len(message) {
				break
			}
			message = message[aligned:]
		}
	}

	return errors.New("the kernel did not acknowledge the process-event subscription")
}

func (b *connectorBackend) next(event *raw) error {
	for {
		for len(b.unread) > 0 {
			if b.parse(event) {
				return nil
			}
		}

		n, _, err := unix.Recvfrom(b.fd, b.buffer, 0)
		switch {
		case err == nil:
			b.unread = b.buffer[:n]
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			return errIdle
		case errors.Is(err, unix.ENOBUFS):
			// The socket buffer overflowed and the kernel threw
			// messages away. It does not say how many.
			b.overruns.Add(1)
		default:
			return err
		}
	}
}

// parse consumes one netlink message from unread and reports whether it was
// a process event worth passing on.
func (b *connectorBackend) parse(event *raw) bool {
	if len(b.unread) < netlinkHeaderSize {
		b.unread = nil
		return false
	}

	length := int(binary.NativeEndian.Uint32(b.unread[0:]))
	if length < netlinkHeaderSize || length > len(b.unread) {
		b.decodeErrors.Add(1)
		b.unread = nil
		return false
	}

	message := b.unread[netlinkHeaderSize:length]
	// Messages are padded to four bytes.
	if aligned := (length + 3) &^ 3; aligned < len(b.unread) {
		b.unread = b.unread[aligned:]
	} else {
		b.unread = nil
	}

	if len(message) < cnMsgSize+procEventHeader {
		return false
	}
	if binary.NativeEndian.Uint32(message[0:]) != cnIdxProc || binary.NativeEndian.Uint32(message[4:]) != cnValProc {
		return false
	}

	body := message[cnMsgSize:]
	what := binary.NativeEndian.Uint32(body[0:])
	at := b.clock.at(binary.NativeEndian.Uint64(body[8:]))
	data := body[procEventHeader:]

	word := func(i int) int32 { return int32(binary.NativeEndian.Uint32(data[4*i:])) }

	switch what {
	case procEventFork:
		// parent_pid, parent_tgid, child_pid, child_tgid
		if len(data) < 16 {
			b.decodeErrors.Add(1)
			return false
		}
		if word(2) != word(3) {
			return false // a new thread
		}
		b.forked(event, word(3), word(1), at)
		return true

	case procEventExec:
		// process_pid, process_tgid
		if len(data) < 8 {
			b.decodeErrors.Add(1)
			return false
		}
		b.execed(event, word(1), at)
		return true

	case procEventExit:
		// process_pid, process_tgid, exit_code, exit_signal
		if len(data) < 8 {
			b.decodeErrors.Add(1)
			return false
		}
		// The connector reports each thread. The exit of the thread
		// group leader is taken as the exit of the process.
		if word(0) != word(1) {
			return false
		}
		*event = raw{kind: rawExit, pid: word(1), at: at}
		return true
	}

	return false
}

// forked describes a new process. All the connector says is its PID; its
// start time and parent come from /proc, if it is still there.
func (b *connectorBackend) forked(event *raw, pid, forker int32, at time.Time) {
	*event = raw{kind: rawFork, pid: pid, ppid: forker, at: at}

	comm, ppid, ticks, err := readStat(int(pid))
	if err != nil {
		event.partial = true
		return
	}

	event.comm = comm
	event.ppid = ppid
	event.start = b.starts.FromTicks(ticks)
}

// execed describes the program a process has just started, read from /proc
// immediately. A process that has already exited leaves nothing to read; the
// event is then passed on with what is known and marked partial.
func (b *connectorBackend) execed(event *raw, pid int32, at time.Time) {
	*event = raw{kind: rawExec, pid: pid, at: at}

	comm, ppid, ticks, err := readStat(int(pid))
	if err != nil {
		event.partial = true
		return
	}
	event.comm = comm
	event.ppid = ppid
	event.start = b.starts.FromTicks(ticks)

	exe, haveExe := readExe(pid)
	cmdline, argv0, haveArgs := readCmdline(pid)
	if !haveExe || !haveArgs {
		// It exited between the reads. A name alone would replace a
		// complete image with a fragment, so report none of it.
		event.comm = ""
		event.partial = true
		return
	}
	event.exe, event.cmdline, event.argv0 = exe, cmdline, argv0

	if uid, ok := readUID(pid); ok {
		event.user = b.users.name(uid)
	}
}

func (b *connectorBackend) stats(stats *Stats) {
	stats.KernelDrops = b.overruns.Load()
	stats.DecodeErrors = b.decodeErrors.Load()
	stats.ClockErrorNanos = b.clock.bound.Load()
}

func (b *connectorBackend) syncClock() { b.clock.sync() }

func (b *connectorBackend) close() error { return unix.Close(b.fd) }
