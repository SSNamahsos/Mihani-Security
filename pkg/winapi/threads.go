package winapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	procOpenThread               = kernel32.NewProc("OpenThread")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = kernel32.NewProc("Thread32First")
	procThread32Next             = kernel32.NewProc("Thread32Next")

	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")
)

const (
	THREAD_QUERY_INFORMATION = 0x0040
	THREAD_ALL_ACCESS        = 0x1F03FF

	threadQuerySetWin32StartAddress = 9

	TH32CS_SNAPTHREAD = 0x00000004

	MEM_COMMIT  = 0x1000
	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x1000000
)

type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}

type MemoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type ThreadInfo struct {
	ThreadID     uint32
	StartAddress uintptr
}

func ListThreads(pid uint32) ([]uint32, error) {
	snap, _, e1 := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPTHREAD, uintptr(pid))
	h := syscall.Handle(snap)
	if h == syscall.InvalidHandle {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(%d): %w", pid, errnoOr(e1))
	}
	defer CloseHandle(h)

	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	r, _, _ := procThread32First.Call(uintptr(h), uintptr(unsafe.Pointer(&te)))
	if r == 0 {
		return nil, nil
	}
	var out []uint32
	for {
		if te.OwnerProcessID == pid {
			out = append(out, te.ThreadID)
		}
		te.Size = uint32(unsafe.Sizeof(te))
		r, _, _ = procThread32Next.Call(uintptr(h), uintptr(unsafe.Pointer(&te)))
		if r == 0 {
			break
		}
	}
	return out, nil
}

func ThreadStartAddress(threadID uint32) (uintptr, error) {
	h, _, e1 := procOpenThread.Call(THREAD_QUERY_INFORMATION, 0, uintptr(threadID))
	if h == 0 {
		return 0, fmt.Errorf("OpenThread(%d): %w", threadID, errnoOr(e1))
	}
	defer CloseHandle(syscall.Handle(h))

	var start uintptr
	r, _, _ := procNtQueryInformationThread.Call(
		h,
		threadQuerySetWin32StartAddress,
		uintptr(unsafe.Pointer(&start)),
		unsafe.Sizeof(start),
		0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationThread(%d): status=0x%x", threadID, uint32(r))
	}
	return start, nil
}

func QueryMemory(pid uint32, addr uintptr) (*MemoryBasicInfo, error) {
	h, err := OpenProcess(PROCESS_QUERY_INFORMATION, pid)
	if err != nil {
		return nil, err
	}
	defer CloseHandle(h)

	var mbi MemoryBasicInfo
	r, _, _ := procVirtualQueryEx.Call(
		uintptr(h), addr,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)
	if r == 0 {
		return nil, fmt.Errorf("VirtualQueryEx(%d, 0x%x)", pid, addr)
	}
	return &mbi, nil
}

func ThreadStartAddresses(pid uint32) []ThreadInfo {
	tids, err := ListThreads(pid)
	if err != nil {
		return nil
	}
	var out []ThreadInfo
	for _, tid := range tids {
		addr, err := ThreadStartAddress(tid)
		if err != nil {
			continue
		}
		out = append(out, ThreadInfo{ThreadID: tid, StartAddress: addr})
	}
	return out
}

func UnbackedThreadAddress(pid uint32, addr uintptr) bool {
	if addr == 0 {
		return false
	}
	mbi, err := QueryMemory(pid, addr)
	if err != nil {
		return false
	}
	if mbi.State&MEM_COMMIT == 0 {
		return false
	}
	if mbi.Type == MEM_IMAGE {
		return false
	}
	prot := mbi.Protect & 0xFF
	if prot != 0x10 && prot != 0x20 && prot != 0x40 && prot != 0x80 {
		return false
	}
	return true
}
