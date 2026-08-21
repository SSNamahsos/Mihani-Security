package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

var procGetNamedPipeClientProcessId = syscall.NewLazyDLL("kernel32.dll").NewProc("GetNamedPipeClientProcessId")

func clientPID(c net.Conn) (uint32, error) {
	var fd uintptr
	var rcErr error
	if sc, ok := c.(syscall.Conn); ok {
		rc, err := sc.SyscallConn()
		if err == nil {
			var gerr error
			var pidTmp uint32
			if err := rc.Control(func(fd2 uintptr) {
				r, _, e := procGetNamedPipeClientProcessId.Call(fd2, uintptr(unsafe.Pointer(&pidTmp)))
				if r == 0 {
					gerr = e
				}
				fd = fd2
			}); err == nil && gerr == nil && pidTmp != 0 {
				return pidTmp, nil
			}
			if err != nil {
				rcErr = err
			} else if gerr != nil {
				rcErr = gerr
			}
		} else {
			rcErr = err
		}
	}
	if fder, ok := c.(interface{ Fd() uintptr }); ok {
		fd = fder.Fd()
	} else {
		if rcErr != nil {
			return 0, rcErr
		}
		return 0, errors.New("connection type does not expose syscall interface")
	}
	var pid uint32
	r, _, e := procGetNamedPipeClientProcessId.Call(fd, uintptr(unsafe.Pointer(&pid)))
	if r == 0 {
		if e != nil && e != syscall.Errno(0) {
			return 0, e
		}
		return 0, errors.New("GetNamedPipeClientProcessId failed")
	}
	if pid == 0 {
		return 0, errors.New("pipe client pid is zero")
	}
	return pid, nil
}

func clientImagePath(c net.Conn) (string, error) {
	pid, err := clientPID(c)
	if err != nil {
		return "", err
	}
	return winapi.ProcessImagePath(pid)
}

func defaultAllowedPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(filepath.Dir(exe), "MihaniSecurity.exe")}
}

func isAllowedPath(path string, allowed []string) bool {
	if path == "" {
		return false
	}
	clean := strings.ToLower(filepath.Clean(path))
	for _, a := range allowed {
		if clean == strings.ToLower(filepath.Clean(a)) {
			return true
		}
	}
	if strings.ToLower(filepath.Base(clean)) == "mihanisecurity.exe" {
		return true
	}
	return false
}
