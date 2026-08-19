package winapi

import (
	"syscall"
	"unsafe"
)

var (
	advapi32DLL                 = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW           = advapi32DLL.NewProc("RegOpenKeyExW")
	procRegNotifyChangeKeyValue = advapi32DLL.NewProc("RegNotifyChangeKeyValue")
	procRegCloseKey             = advapi32DLL.NewProc("RegCloseKey")
	procRegEnumKeyExW           = advapi32DLL.NewProc("RegEnumKeyExW")
)

const (
	HKEY_CLASSES_ROOT   = 0x80000000
	HKEY_CURRENT_USER   = 0x80000001
	HKEY_LOCAL_MACHINE  = 0x80000002
	HKEY_USERS          = 0x80000003
	HKEY_CURRENT_CONFIG = 0x80000005
)

const (
	REG_NOTIFY_CHANGE_NAME       = 0x00000001
	REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
	REG_NOTIFY_CHANGE_LAST_SET   = 0x00000004
	REG_NOTIFY_CHANGE_SECURITY   = 0x00000008
)

func RegRoot(name string) (syscall.Handle, error) {
	switch name {
	case "HKCR", "HKEY_CLASSES_ROOT":
		return HKEY_CLASSES_ROOT, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return HKEY_CURRENT_USER, nil
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return HKEY_LOCAL_MACHINE, nil
	case "HKU", "HKEY_USERS":
		return HKEY_USERS, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return HKEY_CURRENT_CONFIG, nil
	}
	return 0, syscall.ERROR_FILE_NOT_FOUND
}

func RegOpenSubkey(root syscall.Handle, subkey string) (syscall.Handle, error) {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	r, _, e1 := procRegOpenKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		0x20019|0x00010,
		uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, syscall.Errno(r)
	}
	return h, nil
}

func RegClose(h syscall.Handle) { procRegCloseKey.Call(uintptr(h)) }

func RegNotifyChangeKeyValue(h syscall.Handle, watchSubtree bool, filter uint32) error {
	subtree := 0
	if watchSubtree {
		subtree = 1
	}
	r, _, e1 := procRegNotifyChangeKeyValue.Call(uintptr(h), uintptr(subtree), uintptr(filter), 0, 0, 0)
	if r != 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.Errno(r)
	}
	return nil
}
