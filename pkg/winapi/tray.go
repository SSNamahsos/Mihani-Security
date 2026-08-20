package winapi

import (
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const (
	appIconResourceID = 3

	errorClassAlreadyExists = 0x582

	trayMsgBase       = 0x8001
	wmCommand         = 0x0111
	wmDestroy         = 0x0002
	wmQuit            = 0x0012
	wmRButtonUp       = 0x0205
	wmLButtonDblClick = 0x0203

	nifMessage = 0x0001
	nifIcon    = 0x0002
	nifTip     = 0x0004
	nimAdd     = 0x00000000
	nimModify  = 0x00000001
	nimDelete  = 0x00000002

	imageIcon = 0x0001

	mfString       = 0x0000
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmNonNotify   = 0x0080

	menuOpen = 1
	menuQuit = 2

	hwndMessage = ^uintptr(2)
)

type Tray struct {
	mu      sync.Mutex
	hwnd    uintptr
	tid     uint32
	hicon   uintptr
	openLab *uint16
	quitLab *uint16
	tooltip [128]uint16
	onOpen  func()
	onQuit  func()
	active  bool
	lang    string
	done    chan struct{}
}

var (
	trayOnce        sync.Mutex
	currentTray     *Tray
	classRegistered bool
	trayWindows     = map[uintptr]*Tray{}
	trayWndProc     = syscall.NewCallback(trayWndProcImpl)
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type point struct {
	X int32
	Y int32
}

type msgT struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

var (
	procRegisterClassExW  = user32.NewProc("RegisterClassExW")
	procCreateWindowExW   = user32.NewProc("CreateWindowExW")
	procDefWindowProcW    = user32.NewProc("DefWindowProcW")
	procDestroyWindow     = user32.NewProc("DestroyWindow")
	procGetMessageW       = user32.NewProc("GetMessageW")
	procTranslateMessage  = user32.NewProc("TranslateMessage")
	procDispatchMessageW  = user32.NewProc("DispatchMessageW")
	procPostThreadMessage = user32.NewProc("PostThreadMessageW")
	procPostMessageW      = user32.NewProc("PostMessageW")
	procGetModuleHandleW  = kernel32.NewProc("GetModuleHandleW")
	procGetCurrentThreadId = kernel32.NewProc("GetCurrentThreadId")
	procLoadIconW         = user32.NewProc("LoadIconW")
	procLoadImageW        = user32.NewProc("LoadImageW")
	procShellNotifyIconW  = shell32.NewProc("Shell_NotifyIconW")
	procCreatePopupMenu   = user32.NewProc("CreatePopupMenu")
	procAppendMenuW       = user32.NewProc("AppendMenuW")
	procTrackPopupMenu    = user32.NewProc("TrackPopupMenu")
	procDestroyMenu       = user32.NewProc("DestroyMenu")
	procGetCursorPos      = user32.NewProc("GetCursorPos")
	procSetForegroundWin  = user32.NewProc("SetForegroundWindow")
	procGetLastError      = kernel32.NewProc("GetLastError")
	user32                = syscall.NewLazyDLL("user32.dll")
	shell32               = syscall.NewLazyDLL("shell32.dll")
)

var trayWindowClass = []uint16{'M', 'i', 'h', 'a', 'n', 'i', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'T', 'r', 'a', 'y', 0}

func postMessage(hwnd uintptr, msg, wParam, lParam uintptr) {
	procPostMessageW.Call(hwnd, msg, wParam, lParam)
}

func NewTray(tooltip, openLabel, quitLabel, lang string, onOpen, onQuit func()) (*Tray, error) {
	trayOnce.Lock()
	old := currentTray
	currentTray = nil
	trayOnce.Unlock()
	if old != nil {
		old.Remove()
	}

	t := &Tray{
		onOpen: onOpen,
		onQuit: onQuit,
		lang:   lang,
		done:   make(chan struct{}),
	}
	copy(t.tooltip[:], utf16Slice(tooltip, 127))
	t.openLab = utf16Ptr(openLabel)
	t.quitLab = utf16Ptr(quitLabel)

	hInst, _, _ := procGetModuleHandleW.Call(0)
	trayOnce.Lock()
	if !classRegistered {
		wc := wndClassExW{
			cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			lpfnWndProc:   trayWndProc,
			hInstance:     hInst,
			lpszClassName: &trayWindowClass[0],
		}
		atom, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 {
			e, _, _ := procGetLastError.Call()
			trayOnce.Unlock()
			if e != errorClassAlreadyExists {
				return nil, lastError("register tray window class")
			}
		}
		classRegistered = true
	}
	trayOnce.Unlock()

	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid, _, _ := procGetCurrentThreadId.Call()
		t.tid = uint32(tid)

		hwnd, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(&trayWindowClass[0])),
			uintptr(unsafe.Pointer(&trayWindowClass[0])),
			0, 0, 0, 0, 0,
			hwndMessage,
			0,
			hInst,
			0,
		)
		if hwnd == 0 {
			errCh <- lastError("create tray window")
			return
		}
		t.hwnd = hwnd

		hIcon, _, _ := procLoadIconW.Call(hInst, appIconResourceID)
		if hIcon == 0 {
			hIcon, _, _ = procLoadImageW.Call(0, appIconResourceID, imageIcon, 32, 32, 0)
		}
		t.hicon = hIcon

		nid := notifyIconDataW{
			cbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
			hWnd:             hwnd,
			uID:              1,
			uFlags:           nifIcon | nifMessage | nifTip,
			uCallbackMessage: trayMsgBase,
			hIcon:            hIcon,
			szTip:            t.tooltip,
		}
		r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
		if r == 0 {
			procDestroyWindow.Call(hwnd)
			errCh <- lastError("add tray icon")
			return
		}
		trayOnce.Lock()
		trayWindows[hwnd] = t
		currentTray = t
		trayOnce.Unlock()
		t.active = true
		errCh <- nil

		var m msgT
		for {
			ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(ret) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}

		trayOnce.Lock()
		delete(trayWindows, hwnd)
		trayOnce.Unlock()
		nidDel := notifyIconDataW{cbSize: uint32(unsafe.Sizeof(notifyIconDataW{})), hWnd: hwnd, uID: 1}
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nidDel)))
		procDestroyWindow.Call(hwnd)
		t.active = false
		if currentTray == t {
			currentTray = nil
		}
		close(t.done)
	}()

	if err := <-errCh; err != nil {
		<-t.done
		return nil, err
	}
	return t, nil
}

func (t *Tray) Lang() string { return t.lang }

func (t *Tray) Remove() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.active {
		return
	}
	procPostThreadMessage.Call(uintptr(t.tid), wmQuit, 0, 0)
	<-t.done
}

func trayWndProcImpl(hwnd, msg, wParam, lParam uintptr) uintptr {
	trayOnce.Lock()
	t := trayWindows[hwnd]
	trayOnce.Unlock()
	if t == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return r
	}
	switch msg {
	case trayMsgBase:
		switch lParam {
		case wmRButtonUp:
			t.showMenu()
		case wmLButtonDblClick:
			if t.onOpen != nil {
				t.onOpen()
			}
		}
		return 0
	case wmCommand:
		switch wParam & 0xFFFF {
		case menuOpen:
			if t.onOpen != nil {
				t.onOpen()
			}
		case menuQuit:
			if t.onQuit != nil {
				t.onQuit()
			}
		}
		return 0
	case wmDestroy:
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func (t *Tray) showMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	procAppendMenuW.Call(menu, mfString, menuOpen, uintptr(unsafe.Pointer(t.openLab)))
	procAppendMenuW.Call(menu, mfString, menuQuit, uintptr(unsafe.Pointer(t.quitLab)))
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWin.Call(t.hwnd)
	sel, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd|tpmNonNotify, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	procDestroyMenu.Call(menu)
	switch sel {
	case menuOpen:
		if t.onOpen != nil {
			t.onOpen()
		}
	case menuQuit:
		if t.onQuit != nil {
			t.onQuit()
		}
	}
}

func utf16Slice(s string, max int) []uint16 {
	u := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		if r > 0xFFFF {
			u = append(u, 0xFFFD)
		} else {
			u = append(u, uint16(r))
		}
	}
	if len(u) > max {
		u = u[:max]
	}
	u = append(u, 0)
	return u
}

func utf16Ptr(s string) *uint16 {
	u := utf16Slice(s, 127)
	return &u[0]
}

func lastError(what string) error {
	e, _, _ := procGetLastError.Call()
	if e == 0 {
		return errors.New(what)
	}
	return syscall.Errno(e)
}