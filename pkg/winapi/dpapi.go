package winapi

import (
	"errors"
	"syscall"
	"unsafe"
)

var (
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

const (
	cryptProtectUIForbidden = 0x1
)

type dataBlob struct {
	Size uint32
	Data *byte
}

func ProtectData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("winapi: empty data to protect")
	}
	in := dataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out dataBlob
	r, _, e := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, e
	}
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
	return res, nil
}

func UnprotectData(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("winapi: empty blob to unprotect")
	}
	in := dataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out dataBlob
	r, _, e := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, e
	}
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
	return res, nil
}

var (
	procLocalFree = kernel32.NewProc("LocalFree")
	crypt32       = syscall.NewLazyDLL("crypt32.dll")
)
