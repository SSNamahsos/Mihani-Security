package winapi

import (
	"fmt"
	"unsafe"
)

var procVirtualQueryEx = kernel32.NewProc("VirtualQueryEx")

const (
	memCommit  = 0x1000
	memPrivate = 0x20000
	memImage   = 0x1000000

	pageNoAccess = 0x01
	pageGuard    = 0x100
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	alignment1        uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	alignment2        uint32
}

func readableProtect(p uint32) bool {
	if p&pageGuard != 0 || p&pageNoAccess != 0 || p == 0 {
		return false
	}
	switch p & 0xFF {
	case 0x02, 0x04, 0x08, 0x20, 0x40, 0x80:
		return true
	}
	return false
}

type MemoryScanOptions struct {
	MaxBytes int64

	MaxRegionBytes int64

	PrivateOnly bool
}

func DefaultMemoryScan() MemoryScanOptions {
	return MemoryScanOptions{
		MaxBytes:       192 << 20,
		MaxRegionBytes: 32 << 20,
		PrivateOnly:    true,
	}
}

func ScanProcessMemory(pid uint32, opts MemoryScanOptions, fn func(addr uintptr, chunk []byte) bool) error {
	if opts.MaxBytes <= 0 {
		opts = DefaultMemoryScan()
	}
	h, err := OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, pid)
	if err != nil {

		h, err = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ, pid)
		if err != nil {
			return err
		}
	}
	defer CloseHandle(h)

	const chunkSize = 4 << 20
	var (
		addr    uintptr
		scanned int64
		mbi     memoryBasicInformation
	)
	for scanned < opts.MaxBytes {
		r, _, _ := procVirtualQueryEx.Call(
			uintptr(h), addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if r == 0 {
			break
		}
		region := mbi
		next := region.BaseAddress + region.RegionSize
		if next <= addr {
			break
		}
		addr = next

		if region.State != memCommit || !readableProtect(region.Protect) {
			continue
		}
		if opts.PrivateOnly && region.Type != memPrivate {
			continue
		}
		if opts.MaxRegionBytes > 0 && int64(region.RegionSize) > opts.MaxRegionBytes {
			continue
		}

		for off := uintptr(0); off < region.RegionSize; off += chunkSize {
			size := chunkSize
			if remain := region.RegionSize - off; remain < uintptr(size) {
				size = int(remain)
			}
			if scanned+int64(size) > opts.MaxBytes {
				return nil
			}
			buf, err := ReadProcessMemory(h, region.BaseAddress+off, uintptr(size))
			if err != nil || len(buf) == 0 {
				break
			}
			scanned += int64(len(buf))
			if !fn(region.BaseAddress+off, buf) {
				return nil
			}
		}
	}
	return nil
}

func ProcessImagePath(pid uint32) (string, error) {
	h, err := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid)
	if err != nil {
		return "", err
	}
	defer CloseHandle(h)
	buf := make([]uint16, 1024)
	n, err := QueryFullProcessImageName(h, buf)
	if err != nil || n == 0 {
		return "", fmt.Errorf("image path for pid %d unavailable", pid)
	}
	return UTF16ToString(buf[:n]), nil
}
