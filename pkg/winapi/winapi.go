package winapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procGetProcessId               = kernel32.NewProc("GetProcessId")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procTerminateProcess           = kernel32.NewProc("TerminateProcess")
	procDuplicateHandle            = kernel32.NewProc("DuplicateHandle")
	procGetCurrentProcess          = kernel32.NewProc("GetCurrentProcess")
	procQueryDosDeviceW            = kernel32.NewProc("QueryDosDeviceW")
	procGetLogicalDriveStringsW    = kernel32.NewProc("GetLogicalDriveStringsW")

	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   = advapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

const (
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_READ                   = 0x0010
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	SYNCHRONIZE                       = 0x00100000
)

const TokenElevation = 20

const SE_DEBUG_NAME = "SeDebugPrivilege"

const currentProcess = ^uintptr(0)

type luidAndAttributes struct {
	LowPart    uint32
	HighPart   int32
	Attributes uint32
}

type tokenPrivileges struct {
	Count uint32
	Priv  luidAndAttributes
}

const sePrivilegeEnabled = 0x00000002

func EnableDebugPrivilege() error {
	const (
		tokenAdjustPrivileges = 0x0020
		tokenQuery            = 0x0008
	)
	var token syscall.Handle
	if r, _, e1 := procOpenProcessToken.Call(currentProcess, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 {
		return fmt.Errorf("OpenProcessToken: %w", errnoOr(e1))
	}
	defer procCloseHandle.Call(uintptr(token))

	var luid luidAndAttributes
	namePtr, err := syscall.UTF16PtrFromString(SE_DEBUG_NAME)
	if err != nil {
		return err
	}
	if r, _, e1 := procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&luid))); r == 0 {
		return fmt.Errorf("LookupPrivilegeValue: %w", errnoOr(e1))
	}
	tp := tokenPrivileges{Count: 1, Priv: luidAndAttributes{
		LowPart: luid.LowPart, HighPart: luid.HighPart, Attributes: sePrivilegeEnabled,
	}}
	r, _, e1 := procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %w", errnoOr(e1))
	}

	if e, ok := e1.(syscall.Errno); ok && e == 1300 {
		return fmt.Errorf("SeDebugPrivilege not assigned (not elevated)")
	}
	return nil
}

func IsElevated() bool {
	var token syscall.Handle
	if r, _, _ := procOpenProcessToken.Call(currentProcess, 0x0008, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false
	}
	defer procCloseHandle.Call(uintptr(token))
	var elevated, retLen uint32
	if r, _, _ := procGetTokenInformation.Call(uintptr(token), TokenElevation,
		uintptr(unsafe.Pointer(&elevated)), 4, uintptr(unsafe.Pointer(&retLen))); r == 0 {
		return false
	}
	return elevated != 0
}

func QueryFullProcessImageName(hProcess syscall.Handle, buf []uint16) (uint32, error) {
	size := uint32(len(buf))
	r, _, e1 := procQueryFullProcessImageNameW.Call(
		uintptr(hProcess), 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return 0, fmt.Errorf("QueryFullProcessImageNameW: %w", errnoOr(e1))
	}
	return size, nil
}

func GetProcessId(hProcess syscall.Handle) uint32 {
	r, _, _ := procGetProcessId.Call(uintptr(hProcess))
	return uint32(r)
}

func OpenProcess(access uint32, pid uint32) (syscall.Handle, error) {
	h, _, e1 := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, errnoOr(e1))
	}
	return syscall.Handle(h), nil
}

func TerminateProcess(pid uint32) error {
	h, err := OpenProcess(PROCESS_TERMINATE, pid)
	if err != nil {
		return err
	}
	defer CloseHandle(h)

	if r, _, e1 := procTerminateProcess.Call(uintptr(h), 0xDEAD); r == 0 {
		return fmt.Errorf("TerminateProcess(%d): %w", pid, errnoOr(e1))
	}
	return nil
}

func DuplicateTo(sourceProc syscall.Handle, source syscall.Handle) (syscall.Handle, error) {
	const duplicateSameAccess = 0x00000002
	me, _, _ := procGetCurrentProcess.Call()
	var dup syscall.Handle
	r, _, e1 := procDuplicateHandle.Call(
		uintptr(sourceProc), uintptr(source),
		me, uintptr(unsafe.Pointer(&dup)),
		0, 0, duplicateSameAccess,
	)
	if r == 0 {
		return 0, fmt.Errorf("DuplicateHandle: %w", errnoOr(e1))
	}
	return dup, nil
}

func CloseHandle(h syscall.Handle) {
	if h != 0 && h != syscall.InvalidHandle {
		procCloseHandle.Call(uintptr(h))
	}
}

func UTF16ToString(buf []uint16) string {
	for i, v := range buf {
		if v == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return syscall.UTF16ToString(buf)
}

func errnoOr(e error) error {
	if en, ok := e.(syscall.Errno); ok && en != 0 {
		return en
	}
	return fmt.Errorf("unknown error")
}
