package winapi

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	procNtQueryObject             = ntdll.NewProc("NtQueryObject")
	procGetFinalPathNameByHandleW = kernel32.NewProc("GetFinalPathNameByHandleW")
	procReadProcessMemory         = kernel32.NewProc("ReadProcessMemory")
)

const (
	ObjectNameInformation = 1
	ObjectTypeInformation = 2
)

type objectNameInformation struct {
	Name unicodeString
}

func HandleObjectName(h syscall.Handle) (string, error) {
	buf := make([]byte, 2048)
	var needed uint32
	r, _, _ := procNtQueryObject.Call(uintptr(h), ObjectNameInformation,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	if uint32(r) == statusInfoLengthMismatch && needed > uint32(len(buf)) {
		buf = make([]byte, needed)
		r, _, _ = procNtQueryObject.Call(uintptr(h), ObjectNameInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	}
	if r != 0 {
		return "", fmt.Errorf("NtQueryObject: status=0x%x", uint32(r))
	}
	oni := (*objectNameInformation)(unsafe.Pointer(&buf[0]))
	return oni.Name.String(buf), nil
}

func ObjectTypeName(h syscall.Handle) (string, error) {
	buf := make([]byte, 1024)
	var needed uint32
	r, _, _ := procNtQueryObject.Call(uintptr(h), ObjectTypeInformation,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	if r != 0 {
		return "", fmt.Errorf("NtQueryObject(type): status=0x%x", uint32(r))
	}

	oni := (*objectNameInformation)(unsafe.Pointer(&buf[0]))
	return oni.Name.String(buf), nil
}

func FinalPathByHandle(h syscall.Handle) (string, error) {
	buf := make([]uint16, 1024)
	r, _, e1 := procGetFinalPathNameByHandleW.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if r == 0 {
		return "", fmt.Errorf("GetFinalPathNameByHandleW: %w", errnoOr(e1))
	}
	return UTF16ToString(buf[:r]), nil
}

const nameQueryTimeout = 120 * time.Millisecond

type nameResult struct {
	name string
	err  error
}

func DupHandleName(sourceProc syscall.Handle, source uintptr) (string, error) {
	dup, err := DuplicateTo(sourceProc, syscall.Handle(source))
	if err != nil {
		return "", err
	}
	ch := make(chan nameResult, 1)
	go func() {
		name, err := HandleObjectName(dup)
		ch <- nameResult{name, err}
		CloseHandle(dup)
	}()
	select {
	case res := <-ch:
		return res.name, res.err
	case <-time.After(nameQueryTimeout):

		return "", fmt.Errorf("handle name query timed out")
	}
}

var (
	fileTypeOnce sync.Once
	fileTypeIdx  uint16
	fileTypeOK   bool
)

func FileTypeIndex() (uint16, bool) {
	fileTypeOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		f, err := os.Open(exe)
		if err != nil {
			return
		}
		defer f.Close()
		self := uint32(os.Getpid())
		want := f.Fd()

		handles, err := ListHandles()
		if err != nil {
			return
		}
		for _, h := range handles {
			if h.PID == self && h.Handle == want {
				fileTypeIdx, fileTypeOK = h.ObjectTypeIdx, true
				return
			}
		}
	})
	return fileTypeIdx, fileTypeOK
}

func IsFileTypeIndex(idx uint16) bool {
	if want, ok := FileTypeIndex(); ok {
		return idx == want
	}
	return true
}

var (
	dosOnce sync.Once
	dosMap  [][2]string
)

func loadDosMap() {
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		namePtr, err := syscall.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		buf := make([]uint16, 1024)
		r, _, _ := procQueryDosDeviceW.Call(
			uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if r == 0 {
			continue
		}
		dev := UTF16ToString(buf)
		if dev != "" {
			dosMap = append(dosMap, [2]string{dev, drive})
		}
	}
}

func DeviceToDOS(ntPath string) string {
	if ntPath == "" || !strings.HasPrefix(ntPath, `\Device\`) {
		return ntPath
	}
	dosOnce.Do(loadDosMap)
	for _, m := range dosMap {
		if len(ntPath) > len(m[0]) && strings.EqualFold(ntPath[:len(m[0])], m[0]) && ntPath[len(m[0])] == '\\' {
			return m[1] + ntPath[len(m[0]):]
		}
	}
	return ntPath
}

func ReadProcessMemory(hProcess syscall.Handle, baseAddress uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)
	var read uintptr
	r, _, e1 := procReadProcessMemory.Call(
		uintptr(hProcess),
		baseAddress,
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		uintptr(unsafe.Pointer(&read)),
	)
	if r == 0 {
		return nil, fmt.Errorf("ReadProcessMemory: %w", errnoOr(e1))
	}
	return buf[:read], nil
}
