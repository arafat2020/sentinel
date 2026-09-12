//go:build windows

package file

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsFileEvent is a raw change notification from ReadDirectoryChangesW
// before it is resolved into a core.FileEvent.
type windowsFileEvent struct {
	Action uint32
	Path   string
	Time   time.Time
}

// windowsWatcher wraps a single ReadDirectoryChangesW loop for one root
// directory. Multiple subtrees are watched by opening handles for each.
type windowsWatcher struct {
	root   string
	handle windows.Handle
	done   chan struct{}
	once   sync.Once
}

const (
	// FILE_NOTIFY_CHANGE flags: names, directory names, last-write time, and size.
	notifyFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_SIZE

	// ReadDirectoryChangesW buffer size (64 KiB — kernel rounds up internally).
	rdcBufSize = 65536
)

// FILE_NOTIFY_INFORMATION action constants.
const (
	fileActionAdded          = 0x1
	fileActionRemoved        = 0x2
	fileActionModified       = 0x3
	fileActionRenamedOldName = 0x4
	fileActionRenamedNewName = 0x5
)

func newWindowsWatcher(root string) (*windowsWatcher, error) {
	// Convert root path to UTF-16.
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, fmt.Errorf("utf16 root: %w", err)
	}

	// Open the directory with FILE_FLAG_BACKUP_SEMANTICS (required for
	// directories) and OVERLAPPED so ReadDirectoryChangesW can use completion
	// routines.
	handle, err := windows.CreateFile(
		rootPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open watch dir %s: %w", root, err)
	}

	return &windowsWatcher{
		root:   root,
		handle: handle,
		done:   make(chan struct{}),
	}, nil
}

func (w *windowsWatcher) start(enqueue func(windowsFileEvent)) error {
	go w.readLoop(enqueue)
	return nil
}

// readLoop calls ReadDirectoryChangesW in a tight loop using an overlapped
// structure and GetOverlappedResult to wait for each batch of changes.
func (w *windowsWatcher) readLoop(enqueue func(windowsFileEvent)) {
	buf := make([]byte, rdcBufSize)
	ov := &windows.Overlapped{}

	// Manual-reset event used to signal overlapped completion.
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(event)
	ov.HEvent = event

	for {
		select {
		case <-w.done:
			return
		default:
		}

		var returned uint32
		err := windows.ReadDirectoryChanges(
			w.handle,
			&buf[0],
			uint32(len(buf)),
			true, // watchSubtree
			notifyFilter,
			&returned,
			ov,
			0,
		)
		if err != nil && err != error(windows.ERROR_IO_PENDING) {
			return
		}

		// Wait for the overlapped operation to complete or for shutdown.
		waitResult, _ := windows.WaitForSingleObject(event, 200 /* ms */)

		select {
		case <-w.done:
			return
		default:
		}

		if waitResult == uint32(windows.WAIT_TIMEOUT) {
			continue
		}

		if err := windows.GetOverlappedResult(w.handle, ov, &returned, false); err != nil {
			if err == error(windows.ERROR_OPERATION_ABORTED) {
				return
			}
			continue
		}

		if returned == 0 {
			continue
		}

		// Reset the event for the next iteration.
		windows.ResetEvent(event) //nolint:errcheck

		parseNotifications(buf[:returned], w.root, enqueue)
	}
}

// parseNotifications walks a buffer of variable-length FILE_NOTIFY_INFORMATION
// records and calls enqueue for each one.
//
// Layout (per record):
//
//	NextEntryOffset (4) | Action (4) | FileNameLength (4) | FileName (FileNameLength bytes, UTF-16LE)
func parseNotifications(buf []byte, root string, enqueue func(windowsFileEvent)) {
	now := time.Now()
	offset := 0

	for {
		if offset+12 > len(buf) {
			break
		}

		nextOffset := *(*uint32)(unsafe.Pointer(&buf[offset]))
		action := *(*uint32)(unsafe.Pointer(&buf[offset+4]))
		nameLen := *(*uint32)(unsafe.Pointer(&buf[offset+8]))

		if offset+12+int(nameLen) > len(buf) {
			break
		}

		// FileName is UTF-16LE; convert to a Go string.
		u16 := make([]uint16, nameLen/2)
		for i := range u16 {
			u16[i] = *(*uint16)(unsafe.Pointer(&buf[offset+12+i*2]))
		}
		name := string(utf16.Decode(u16))
		fullPath := filepath.Join(root, name)

		enqueue(windowsFileEvent{
			Action: action,
			Path:   fullPath,
			Time:   now,
		})

		if nextOffset == 0 {
			break
		}
		offset += int(nextOffset)
	}
}

func (w *windowsWatcher) close() {
	w.once.Do(func() {
		close(w.done)
		windows.CancelIoEx(w.handle, nil) //nolint:errcheck
		windows.CloseHandle(w.handle)     //nolint:errcheck
	})
}
