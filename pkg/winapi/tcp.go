package winapi

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetTcpTable2        = iphlpapi.NewProc("GetTcpTable2")
)

const (
	TCP_TABLE_BASIC_LISTENER        = 0
	TCP_TABLE_BASIC_CONNECTIONS     = 1
	TCP_TABLE_BASIC_ALL             = 2
	TCP_TABLE_OWNER_PID_LISTENER    = 3
	TCP_TABLE_OWNER_PID_CONNECTIONS = 4
	TCP_TABLE_OWNER_PID_ALL         = 5
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

const (
	TCPStateClosed      = 1
	TCPStateListening   = 2
	TCPStateSynSent     = 3
	TCPStateSynRcvd     = 4
	TCPStateEstablished = 5
	TCPStateFinWait1    = 6
	TCPStateFinWait2    = 7
	TCPStateCloseWait   = 8
	TCPStateClosing     = 9
	TCPStateLastAck     = 10
	TCPStateTimeWait    = 11
	TCPStateDeleteTcb   = 12
)

type TCPConn struct {
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      uint32
	PID        uint32
}

func ListTCP() ([]TCPConn, error) {
	var needed uint32
	r, _, e1 := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&needed)), 0, TCP_TABLE_OWNER_PID_ALL, 0, 0)
	if r != 0 && r != uintptr(syscall.Errno(0x7a)) {
		if e1 != nil && e1 != syscall.Errno(0) {
			return nil, e1
		}
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", r)
	}
	if needed == 0 {
		return nil, nil
	}
	buf := make([]byte, needed)
	r, _, e1 = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&needed)),
		0, TCP_TABLE_OWNER_PID_ALL, 0, 0,
	)
	if r != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return nil, e1
		}
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", r)
	}
	count := binary.LittleEndian.Uint32(buf[0:4])
	rows := unsafe.Pointer(&buf[4])
	out := make([]TCPConn, 0, count)
	for i := uint32(0); i < count; i++ {
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(uintptr(rows) + uintptr(i)*unsafe.Sizeof(mibTcpRowOwnerPid{})))
		out = append(out, TCPConn{
			LocalAddr:  uint32ToIPv4(row.LocalAddr),
			LocalPort:  uint16(row.LocalPort),
			RemoteAddr: uint32ToIPv4(row.RemoteAddr),
			RemotePort: uint16(row.RemotePort),
			State:      row.State,
			PID:        row.OwningPid,
		})
	}
	return out, nil
}

func uint32ToIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
}
