package winapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	psapi                    = syscall.NewLazyDLL("psapi.dll")
	procEnumProcessModulesEx = psapi.NewProc("EnumProcessModulesEx")
	procGetModuleFileNameExW = psapi.NewProc("GetModuleFileNameExW")
)

const listModulesAll = 0x03

func ListModules(pid uint32) ([]string, error) {
	h, err := OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, pid)
	if err != nil {
		return nil, err
	}
	defer CloseHandle(h)

	mods := make([]uintptr, 1024)
	var needed uint32
	for {
		r, _, e1 := procEnumProcessModulesEx.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&mods[0])),
			uintptr(len(mods)*int(unsafe.Sizeof(uintptr(0)))),
			uintptr(unsafe.Pointer(&needed)),
			listModulesAll,
		)
		if r == 0 {
			return nil, fmt.Errorf("EnumProcessModulesEx(%d): %w", pid, errnoOr(e1))
		}
		count := int(needed) / int(unsafe.Sizeof(uintptr(0)))
		if count <= len(mods) {
			mods = mods[:count]
			break
		}
		mods = make([]uintptr, count)
	}

	out := make([]string, 0, len(mods))
	buf := make([]uint16, 1024)
	for _, m := range mods {
		r, _, _ := procGetModuleFileNameExW.Call(
			uintptr(h), m,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if r == 0 {
			continue
		}
		out = append(out, UTF16ToString(buf[:r]))
	}
	return out, nil
}
