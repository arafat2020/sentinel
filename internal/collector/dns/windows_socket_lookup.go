//go:build windows

package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/arafat2020/sentinel/internal/core"
	"golang.org/x/sys/windows"
)

// SocketOwner identifies the process that owns a network socket.
type SocketOwner struct {
	PID uint32
}

// SocketLookup resolves the process attached to a local IP:port pair.
type SocketLookup interface {
	FindOwner(
		ctx context.Context,
		sourceIP string,
		sourcePort uint32,
	) (*SocketOwner, error)
}

// ProcessResolver resolves full process metadata for a PID.
type ProcessResolver interface {
	Resolve(
		ctx context.Context,
		pid int32,
	) (*core.Process, error)
}

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtUdpTable  = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afINET              = 2
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID
)

type windowsSocketLookup struct{}

// NewWindowsSocketLookup creates a SocketLookup backed by GetExtendedTcpTable
// and GetExtendedUdpTable from iphlpapi.dll.
func NewWindowsSocketLookup() SocketLookup {
	return &windowsSocketLookup{}
}

func (l *windowsSocketLookup) FindOwner(
	ctx context.Context,
	sourceIP string,
	sourcePort uint32,
) (*SocketOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(sourceIP)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid source IP: %s", sourceIP)
	}

	if pid, ok := searchTCPTable(targetIP, sourcePort); ok {
		return &SocketOwner{PID: pid}, nil
	}
	if pid, ok := searchUDPTable(targetIP, sourcePort); ok {
		return &SocketOwner{PID: pid}, nil
	}
	return nil, nil
}

// searchTCPTable queries GetExtendedTcpTable for AF_INET with
// TCP_TABLE_OWNER_PID_ALL and scans for a matching local endpoint.
//
// Row layout (MIB_TCPROW_OWNER_PID):
//
//	DwState(4) + DwLocalAddr(4) + DwLocalPort(4) +
//	DwRemoteAddr(4) + DwRemotePort(4) + DwOwningPid(4) = 24 bytes
func searchTCPTable(targetIP net.IP, targetPort uint32) (uint32, bool) {
	buf, ok := callExtTable(procGetExtTcpTable, tcpTableOwnerPidAll)
	if !ok {
		return 0, false
	}
	if len(buf) < 4 {
		return 0, false
	}

	count := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = 24
	for i := uint32(0); i < count; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		localAddr := row[4:8]
		localPort := binary.BigEndian.Uint16(row[8:10]) // high two bytes hold BE port
		owningPid := binary.LittleEndian.Uint32(row[20:24])

		if uint32(localPort) == targetPort &&
			net.IP(localAddr).Equal(targetIP.To4()) {
			return owningPid, true
		}
	}
	return 0, false
}

// searchUDPTable queries GetExtendedUdpTable for AF_INET with
// UDP_TABLE_OWNER_PID and scans for a matching local endpoint.
//
// Row layout (MIB_UDPROW_OWNER_PID):
//
//	DwLocalAddr(4) + DwLocalPort(4) + DwOwningPid(4) = 12 bytes
func searchUDPTable(targetIP net.IP, targetPort uint32) (uint32, bool) {
	buf, ok := callExtTable(procGetExtUdpTable, udpTableOwnerPid)
	if !ok {
		return 0, false
	}
	if len(buf) < 4 {
		return 0, false
	}

	count := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = 12
	for i := uint32(0); i < count; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		localAddr := row[0:4]
		localPort := binary.BigEndian.Uint16(row[4:6])
		owningPid := binary.LittleEndian.Uint32(row[8:12])

		if uint32(localPort) == targetPort &&
			net.IP(localAddr).Equal(targetIP.To4()) {
			return owningPid, true
		}
	}
	return 0, false
}

// callExtTable calls GetExtendedTcpTable or GetExtendedUdpTable with
// automatic buffer growth (the API returns ERROR_INSUFFICIENT_BUFFER
// with the required size when the buffer is too small).
func callExtTable(proc *windows.LazyProc, tableClass uint32) ([]byte, bool) {
	var size uint32 = 4096
	for range [8]struct{}{} { // at most 8 doublings
		buf := make([]byte, size)
		r, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,          // bOrder = false (unsorted)
			uintptr(afINET),
			uintptr(tableClass),
			0,
		)
		if r == 0 {
			return buf[:size], true
		}
		if windows.Errno(r) == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		return nil, false
	}
	return nil, false
}
