package winapi

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

var (
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
	procNtQueryInformationFile   = ntdll.NewProc("NtQueryInformationFile")
)

const (
	SystemProcessInformation        = 5
	SystemExtendedHandleInformation = 64
)

type systemProcessInformation struct {
	NextEntryOffset    uint32
	NumberOfThreads    uint32
	WorkingSetSize     uint64
	HardFaultCount     uint32
	cycleTime          uint64
	CreateTime         uint64
	UserTime           uint64
	KernelTime         uint64
	ImageName          unicodeString
	BasePriority       int32
	UniqueProcessId    uintptr
	InheritedFromId    uintptr
	HandleCount        uint32
	SessionId          uint32
	UniqueProcessKey   uintptr
	PeakVirtualSize    uint64
	VirtualSize        uint64
	PageFaultCount     uint32
	PeakWorkingSetSize uint32
	WorkingSetSize2    uint32
	QuotaPagedPool     uintptr
	QuotaNonPagedPool  uintptr
	PagefileUsage      uintptr
	PeakPagefileUsage  uintptr
	PrivatePageCount   uintptr
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

func (u unicodeString) String(buf []byte) string {
	if u.Buffer == 0 || u.Length == 0 || len(buf) == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	if u.Buffer < base {
		return ""
	}
	off := uintptr(u.Buffer - base)
	if off+uintptr(u.Length) > uintptr(len(buf)) {
		return ""
	}
	n := int(u.Length) / 2
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = *(*uint16)(unsafe.Pointer(&buf[off+uintptr(i*2)]))
	}
	return syscall.UTF16ToString(out)
}

type ProcInfo struct {
	PID  uint32
	PPID uint32
	Name string
	Path string
}

func ListProcesses() ([]ProcInfo, error) {

	var needed uint32
	procNtQuerySystemInformation.Call(0, SystemProcessInformation, 0, 0, uintptr(unsafe.Pointer(&needed)))
	size := needed + needed/4
	if size < 1<<20 {
		size = 1 << 20
	}
	var buf []byte
	for attempt := 0; ; attempt++ {
		buf = make([]byte, size)
		r, _, _ := procNtQuerySystemInformation.Call(
			0,
			SystemProcessInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&needed)),
		)
		if r == 0 {
			break
		}
		if attempt >= 4 || uint32(r) != statusInfoLengthMismatch {
			return nil, fmt.Errorf("NtQuerySystemInformation(processes): status=0x%x", uint32(r))
		}
		size *= 2
	}

	var out []ProcInfo
	for off := uint32(0); ; {
		sp := (*systemProcessInformation)(unsafe.Pointer(&buf[off]))
		out = append(out, ProcInfo{
			PID:  uint32(sp.UniqueProcessId),
			PPID: uint32(sp.InheritedFromId),
			Name: sp.ImageName.String(buf),
		})
		if sp.NextEntryOffset == 0 {
			break
		}
		off += sp.NextEntryOffset
		if uintptr(off)+unsafe.Sizeof(systemProcessInformation{}) > uintptr(len(buf)) {
			break
		}
	}

	sem := make(chan struct{}, 8)
	for i := range out {
		i := i
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			h, err := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, out[i].PID)
			if err != nil {
				return
			}
			defer CloseHandle(h)
			buf16 := make([]uint16, 1024)
			n, err := QueryFullProcessImageName(h, buf16)
			if err != nil || n == 0 {
				return
			}
			out[i].Path = UTF16ToString(buf16[:n])
			if out[i].Name == "" {
				if idx := strings.LastIndex(out[i].Path, `\`); idx >= 0 {
					out[i].Name = out[i].Path[idx+1:]
				} else {
					out[i].Name = out[i].Path
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		sem <- struct{}{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

type systemHandleTableEntryInfoEx struct {
	Object                uintptr
	UniqueProcessId       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

type HandleEntry struct {
	PID           uint32
	Handle        uintptr
	ObjectTypeIdx uint16
	GrantedAccess uint32
}

const statusInfoLengthMismatch = 0xC0000004

func ListHandles() ([]HandleEntry, error) {
	size := uint32(1 << 22)
	var buf []byte
	for attempt := 0; attempt < 6; attempt++ {
		buf = make([]byte, size)
		var needed uint32
		r, _, _ := procNtQuerySystemInformation.Call(
			0,
			SystemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&needed)),
		)
		if r == 0 {
			break
		}
		if uint32(r) != statusInfoLengthMismatch {
			return nil, fmt.Errorf("NtQuerySystemInformation(handles): status=0x%x", uint32(r))
		}
		if needed > size {
			size = needed + (needed / 8)
		} else {
			size *= 2
		}
		if attempt == 5 {
			return nil, fmt.Errorf("NtQuerySystemInformation(handles): buffer never sufficed")
		}
	}

	count := *(*uint64)(unsafe.Pointer(&buf[0]))
	const headerSize = 16
	entrySize := unsafe.Sizeof(systemHandleTableEntryInfoEx{})
	if max := uint64((uintptr(len(buf)) - headerSize) / entrySize); count > max {
		count = max
	}
	entries := unsafe.Pointer(&buf[headerSize])

	out := make([]HandleEntry, 0, count)
	for i := uint64(0); i < count; i++ {
		e := (*systemHandleTableEntryInfoEx)(unsafe.Pointer(uintptr(entries) + uintptr(i)*entrySize))
		out = append(out, HandleEntry{
			PID:           uint32(e.UniqueProcessId),
			Handle:        e.HandleValue,
			ObjectTypeIdx: e.ObjectTypeIndex,
			GrantedAccess: e.GrantedAccess,
		})
	}
	return out, nil
}
