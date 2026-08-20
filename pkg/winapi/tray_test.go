package winapi

import (
	"fmt"
	"testing"
	"time"
)

func TestDebugTray(t *testing.T) {
	opened := make(chan struct{}, 1)
	quit := make(chan struct{}, 1)
	tray, err := NewTray("MihaniSecurity", "Open", "Exit", "en",
		func() { opened <- struct{}{} },
		func() { quit <- struct{}{} },
	)
	if err != nil {
		t.Fatalf("NewTray: %v", err)
	}
	defer tray.Remove()
	fmt.Println("tray ok", tray.hwnd)

	postMessage(uintptr(tray.hwnd), trayMsgBase, 0, wmLButtonDblClick)
	select {
	case <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("double-click callback not fired")
	}

	postMessage(uintptr(tray.hwnd), wmCommand, menuQuit, 0)
	select {
	case <-quit:
	case <-time.After(3 * time.Second):
		t.Fatal("quit callback not fired")
	}
}