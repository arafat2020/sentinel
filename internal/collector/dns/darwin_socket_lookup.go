//go:build darwin

package dns

/*
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <string.h>

static int get_socket_local_endpoint(
    int pid,
    int fd,
    char *ip,
    int ip_len,
    uint32_t *port
) {
    struct socket_fdinfo info;

    memset(&info, 0, sizeof(info));

    int ret = proc_pidfdinfo(
        pid,
        fd,
        PROC_PIDFDSOCKETINFO,
        &info,
        sizeof(info)
    );

    if (ret != sizeof(info)) {
        return 0;
    }

    if (info.psi.soi_family == AF_INET) {
        struct in_sockinfo *in = &info.psi.soi_proto.pri_in;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));

        addr.sin_addr.s_addr =
            in->insi_laddr.ina_46.i46a_addr4.s_addr;

        if (inet_ntop(
            AF_INET,
            &addr.sin_addr,
            ip,
            ip_len
        ) == NULL) {
            return 0;
        }

        *port = (uint32_t)ntohs((uint16_t)in->insi_lport);

        return 1;
    }

    if (info.psi.soi_family == AF_INET6) {
        struct in_sockinfo *in = &info.psi.soi_proto.pri_in;

        if (inet_ntop(
            AF_INET6,
            &in->insi_laddr.ina_6,
            ip,
            ip_len
        ) == NULL) {
            return 0;
        }

        *port = (uint32_t)ntohs((uint16_t)in->insi_lport);

        return 1;
    }

    return 0;
}
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
