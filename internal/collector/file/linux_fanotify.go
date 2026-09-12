//go:build linux

package file

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifyBackend abstracts the kernel fanotify subsystem. The real
// implementation calls FanotifyInit/FanotifyMark; the test implementation
// injects events via a channel.
type fanotifyBackend interface {
	start(enqueue func(linuxFileEvent)) error
	close()
}

const (
	// fanInitFlags configures fanotify for DFID_NAME reporting (kernel 5.9+),
	// which provides the parent directory handle and filename for every event.
	fanInitFlags = unix.FAN_CLASS_NOTIF |
		unix.FAN_REPORT_FID |
		unix.FAN_REPORT_DIR_FID |
		unix.FAN_REPORT_NAME |
		unix.FAN_NONBLOCK |
		unix.FAN_CLOEXEC

	fanMarkFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM

	fanEventMask uint64 = unix.FAN_CLOSE_WRITE |
		unix.FAN_CREATE |
		unix.FAN_DELETE |
		unix.FAN_MOVED_FROM |
		unix.FAN_MOVED_TO |
		unix.FAN_ONDIR

	// FAN_EVENT_INFO_TYPE_* constants (linux/fanotify.h, kernel 5.1+).
	infoTypeFID      = uint8(1)
	infoTypeDFIDName = uint8(2)
	infoTypeDFID     = uint8(3)

	fanReadBufSize = 65536
)

// realFanotifyBackend watches a filesystem via the kernel fanotify subsystem.
// It requires CAP_SYS_ADMIN and kernel 5.9+ for DFID_NAME reporting.
type realFanotifyBackend struct {
	watchPath string
	fd        int
	done      chan struct{}
}

func newRealFanotifyBackend(watchPath string) *realFanotifyBackend {
	return &realFanotifyBackend{
		watchPath: watchPath,
		fd:        -1,
		done:      make(chan struct{}),
	}
}

func (b *realFanotifyBackend) start(enqueue func(linuxFileEvent)) error {
	fd, err := unix.FanotifyInit(fanInitFlags, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}

	if err := unix.FanotifyMark(
		fd,
		fanMarkFlags,
		fanEventMask,
		unix.AT_FDCWD,
		b.watchPath,
	); err != nil {
		unix.Close(fd)
		return fmt.Errorf("fanotify_mark %s: %w", b.watchPath, err)
	}

	b.fd = fd

	// mountFd anchors open_by_handle_at calls to the watched filesystem,
	// allowing FID records to be resolved into directory paths.
	mountFd, err := unix.Open(b.watchPath, unix.O_PATH|unix.O_RDONLY, 0)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("open watch path for mount anchor: %w", err)
	}

	go b.readLoop(fd, mountFd, enqueue)

	return nil
}

func (b *realFanotifyBackend) readLoop(
	fd, mountFd int,
	enqueue func(linuxFileEvent),
) {
	defer unix.Close(fd)
	defer unix.Close(mountFd)

	buf := make([]byte, fanReadBufSize)
	pollFds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

	for {
		select {
		case <-b.done:
			return
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil {
			switch err {
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				// On Linux EAGAIN == EWOULDBLOCK; a single case covers both.
				unix.Poll(pollFds, 100) //nolint:errcheck
				continue
			}
			return
		}

		offset := 0
		for offset+metaSize <= n {
			// FanotifyEventMetadata is a fixed-size kernel struct; casting via
			// unsafe.Pointer is the standard approach for kernel ring-buffer parsing.
			meta := (*unix.FanotifyEventMetadata)(
				unsafe.Pointer(&buf[offset]),
			)

			if meta.Event_len == 0 {
				break
			}

			end := offset + int(meta.Event_len)
			if end > n {
				break
			}

			b.handleEvent(meta, buf[offset:end], mountFd, enqueue)

			offset = end
		}
	}
}

func (b *realFanotifyBackend) handleEvent(
	meta *unix.FanotifyEventMetadata,
	eventBuf []byte,
	mountFd int,
	enqueue func(linuxFileEvent),
) {
	var path string

	if meta.Fd >= 0 {
		// FAN_CLOSE_WRITE: the kernel hands us an open fd to the written file.
		path = readFdPath(int(meta.Fd))
		unix.Close(int(meta.Fd))
	} else {
		// FAN_CREATE / FAN_DELETE / FAN_MOVED_*: resolve path from FID info records.
		infoStart := int(meta.Metadata_len)
		if infoStart < len(eventBuf) {
			path = resolvePathFromFID(eventBuf[infoStart:], mountFd)
		}
	}

	enqueue(linuxFileEvent{
		Mask: meta.Mask,
		PID:  meta.Pid,
		Path: path,
	})
}

func readFdPath(fd int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}

	return target
}

// resolvePathFromFID scans the variable-length info records appended to a
// fanotify event (produced when FAN_REPORT_DFID_NAME is set) and returns
// the first resolvable absolute path.
func resolvePathFromFID(infoBuf []byte, mountFd int) string {
	const hdrSize = 4 // InfoType(1) + Pad(1) + Len(2)

	for offset := 0; offset+hdrSize <= len(infoBuf); {
		infoType := infoBuf[offset]
		infoLen := int(binary.LittleEndian.Uint16(infoBuf[offset+2:]))

		if infoLen == 0 || offset+infoLen > len(infoBuf) {
			break
		}

		switch infoType {
		case infoTypeDFIDName:
			if path := parseFIDRecord(infoBuf[offset:offset+infoLen], mountFd, true); path != "" {
				return path
			}
		case infoTypeDFID:
			if path := parseFIDRecord(infoBuf[offset:offset+infoLen], mountFd, false); path != "" {
				return path
			}
		}

		offset += infoLen
	}

	return ""
}

// parseFIDRecord decodes one DFID or DFID_NAME info record and returns an
// absolute path. Binary layout:
//
//	[InfoType:1][Pad:1][Len:2][fsid:8][handle_bytes:4][handle_type:4][handle_data:N][name\0]
//
// It opens the referenced directory via open_by_handle_at (requires
// CAP_DAC_READ_SEARCH), reads its path from /proc/self/fd, and when
// withName is true appends the trailing null-terminated filename.
func parseFIDRecord(rec []byte, mountFd int, withName bool) string {
	const (
		hdrSize  = 4 // InfoType + Pad + Len
		fsidSize = 8 // fsid_t (two int32)
		fhHdr    = 8 // struct file_handle header: handle_bytes(4) + handle_type(4)
	)

	base := hdrSize + fsidSize
	if len(rec) < base+fhHdr {
		return ""
	}

	handleBytes := int(binary.LittleEndian.Uint32(rec[base:]))
	handleType := int32(binary.LittleEndian.Uint32(rec[base+4:]))
	handleEnd := base + fhHdr + handleBytes

	if handleEnd > len(rec) {
		return ""
	}

	handle := unix.NewFileHandle(handleType, rec[base+fhHdr:handleEnd])

	dirFd, err := unix.OpenByHandleAt(
		mountFd,
		handle,
		unix.O_PATH|unix.O_RDONLY|unix.O_CLOEXEC,
	)
	if err != nil {
		return ""
	}
	defer unix.Close(dirFd)

	dirPath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", dirFd))
	if err != nil {
		return ""
	}

	if !withName || handleEnd >= len(rec) {
		return dirPath
	}

	name := cString(rec[handleEnd:])
	if name == "" || name == "." {
		return dirPath
	}

	return dirPath + "/" + name
}

// cString reads a null-terminated C string from buf.
func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

func (b *realFanotifyBackend) close() {
	close(b.done)
}
