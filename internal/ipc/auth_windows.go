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
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, errors.New("connection type does not expose syscall interface")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid uint32
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		r, _, e := procGetNamedPipeClientProcessId.Call(fd, uintptr(unsafe.Pointer(&pid)))
		if r == 0 {
			gerr = e
		}
	}); err != nil {
		return 0, err
	}
	if gerr != nil {
		return 0, gerr
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
	return false
}
