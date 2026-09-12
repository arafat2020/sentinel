//go:build darwin && cgo

package dns

/*
#cgo CFLAGS: -I${SRCDIR}
#include "socket_lookup_bridge_darwin.h"
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"unsafe"
)

type darwinSocketLookup struct{}

func NewDarwinSocketLookup() SocketLookup {
	return &darwinSocketLookup{}
}

func (l *darwinSocketLookup) FindOwner(
	ctx context.Context,
	sourceIP string,
	sourcePort uint32,
) (*SocketOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(sourceIP)
	if targetIP == nil {
		return nil, fmt.Errorf(
			"invalid source IP: %s",
			sourceIP,
		)
	}

	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}

	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		owner, found, err := findSocketInProcess(
			pid,
			targetIP,
			sourcePort,
		)
		if err != nil {
			continue
		}

		if found {
			return owner, nil
		}
	}

	return nil, nil
}

func listPIDs() ([]int, error) {
	size := C.proc_listallpids(
		nil,
		0,
	)

	if size <= 0 {
		return nil, fmt.Errorf(
			"proc_listallpids failed",
		)
	}

	pids := make([]C.pid_t, int(size))

	size = C.proc_listallpids(
		unsafe.Pointer(&pids[0]),
		C.int(len(pids)*C.sizeof_pid_t),
	)

	if size <= 0 {
		return nil, fmt.Errorf(
			"proc_listallpids failed",
		)
	}

	result := make([]int, 0, int(size))

	for _, pid := range pids[:int(size)] {
		if pid > 0 {
			result = append(
				result,
				int(pid),
			)
		}
	}

	return result, nil
}

func findSocketInProcess(
	pid int,
	targetIP net.IP,
	targetPort uint32,
) (*SocketOwner, bool, error) {
	// First call tells us how many BYTES are needed for the FD information.
	size := C.proc_pidinfo(
		C.int(pid),
		C.PROC_PIDLISTFDS,
		0,
		nil,
		0,
	)

	if size <= 0 {
		return nil, false, nil
	}

	fdSize := int(C.sizeof_struct_proc_fdinfo)
	// proc_pidinfo returns bytes, so convert bytes → number of FDs.
	fdCount := int(size) / fdSize

	fds := make(
		[]C.struct_proc_fdinfo,
		fdCount,
	)

	// Now actually retrieve the FD information.
	size = C.proc_pidinfo(
		C.int(pid),
		C.PROC_PIDLISTFDS,
		0,
		unsafe.Pointer(&fds[0]),
		C.int(len(fds)*fdSize),
	)

	if size <= 0 {
		return nil, false, fmt.Errorf(
			"proc_pidinfo failed for pid %d",
			pid,
		)
	}

	// The second call also returns BYTES copied.
	fdCount = int(size) / fdSize

	for i := 0; i < fdCount; i++ {
		fd := fds[i]

		if uint32(fd.proc_fdtype) != uint32(C.PROX_FDTYPE_SOCKET) {
			continue
		}

		var ipBuffer [46]C.char
		var port C.uint32_t

		ret := C.get_socket_local_endpoint(
			C.int(pid),
			C.int(fd.proc_fd),
			(*C.char)(unsafe.Pointer(
				&ipBuffer[0],
			)),
			C.int(len(ipBuffer)),
			&port,
		)

		if ret == 0 {
			continue
		}

		localIP := C.GoString(
			(*C.char)(unsafe.Pointer(
				&ipBuffer[0],
			)),
		)

		if uint32(port) != targetPort {
			continue
		}

		if !targetIP.Equal(
			net.ParseIP(localIP),
		) {
			continue
		}

		return &SocketOwner{
			PID: uint32(pid),
		}, true, nil
	}

	return nil, false, nil
}
