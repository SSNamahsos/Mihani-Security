package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"git.sr.ht/~jackmordaunt/go-toast/v2"
	"github.com/google/uuid"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/mihanistudio/mihanisecurity/internal/config"
	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/internal/ipc"
)

type App struct {
	ctx context.Context
	mu  sync.Mutex
	cli *ipc.Client

	settings config.Config

	onVerdict      func(events.Verdict)
	onScanProgress func(events.ScanProgress)
	onScanResult   func(*ipc.ScanResult)
	onStatus       func(events.Status)
}

func New() *App { return &App{} }

func (a *App) Init(ctx context.Context, onVerdict func(events.Verdict), onScanProgress func(events.ScanProgress), onScanResult func(*ipc.ScanResult), onStatus func(events.Status)) {
	a.ctx = ctx
	a.onVerdict = onVerdict
	a.onScanProgress = onScanProgress
	a.onScanResult = onScanResult
	a.onStatus = onStatus
}

func (a *App) Connect() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cli != nil {
		return nil
	}
	pipeName := ipc.PipeName
	a.cli = ipc.NewClient(pipeName, a.onBroadcast)
	a.cli.OnDisconnect = func() {
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "ipc_disconnected", true)
		}
	}
	return a.cli.ConnectRetry(10 * time.Second)
}

func (a *App) ConnectService() error { return a.Connect() }

func (a *App) Disconnect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cli != nil {
		a.cli.Close()
		a.cli = nil
	}
}

func (a *App) onBroadcast(m ipc.Msg) {
	switch m.Type {
	case ipc.MsgVerdict:
		if a.onVerdict != nil {
			var v events.Verdict
			if err := json.Unmarshal(m.Payload, &v); err == nil {
				a.onVerdict(v)
				a.notifyThreat(v)
			}
		}
	case ipc.MsgScanProgress:
		if a.onScanProgress != nil {
			var p events.ScanProgress
			if err := json.Unmarshal(m.Payload, &p); err == nil {
				a.onScanProgress(p)
			}
		}
	case ipc.MsgScanResult:
		if a.onScanResult != nil {
			var r ipc.ScanResult
			if err := json.Unmarshal(m.Payload, &r); err == nil {
				a.onScanResult(&r)
			}
		}
	case ipc.MsgStatus:
		if a.onStatus != nil {
			var s events.Status
			if err := json.Unmarshal(m.Payload, &s); err == nil {
				a.onStatus(s)
			}
		}
	}
}

func (a *App) notifyThreat(v events.Verdict) {
	a.mu.Lock()
	enabled := a.settings.Notifications.ShowTrayOnThreat
	verbosity := a.settings.RealTime.AlertVerbosity
	installPath := a.settings.General.InstallPath
	a.mu.Unlock()
	if !enabled || verbosity == config.AlertSilent {
		return
	}
	n := toast.Notification{
		AppID: "MihaniSecurity",
		Title: "MihaniSecurity: " + v.Name,
		Body:  v.Description,
	}

	if icon := findIconPath(installPath); icon != "" {
		n.Icon = icon
	}
	go func() {
		if err := n.Push(); err != nil {
			log.Printf("toast push failed: %v", err)
		}
	}()
}

func findIconPath(installPath string) string {
	candidates := []string{filepath.Join(installPath, "icon.png")}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for i := 0; i < 3; i++ {
			candidates = append(candidates, filepath.Join(dir, "icon.png"))
			dir = filepath.Dir(dir)
		}
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

func (a *App) GetSettings() (config.Config, error) {
	var c config.Config
	if a.cli == nil {
		return c, fmt.Errorf("not connected")
	}
	rep, err := a.cli.Call(ipc.Msg{Type: ipc.MsgSettingsGet, ID: uuid.NewString()}, 3*time.Second)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(rep.Payload, &c)
	if err == nil {
		a.mu.Lock()
		a.settings = c
		a.mu.Unlock()
	}
	return c, err
}

func (a *App) SaveSettings(c config.Config) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(c)
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgSettingsSet, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	if err == nil {
		a.mu.Lock()
		a.settings = c
		a.mu.Unlock()
	}
	return err
}

func (a *App) Status() (events.Status, error) {
	var s events.Status
	if a.cli == nil {
		return s, fmt.Errorf("not connected")
	}
	rep, err := a.cli.Call(ipc.Msg{Type: ipc.MsgStatusGet, ID: uuid.NewString()}, 3*time.Second)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(rep.Payload, &s)
	return s, err
}

func (a *App) ScanCancel(scanID string) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(map[string]string{"scan_id": scanID})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgScanCancel, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) LogTail(lines int) ([]string, error) {
	if a.cli == nil {
		return nil, fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(map[string]int{"lines": lines})
	rep, err := a.cli.Call(ipc.Msg{Type: ipc.MsgLogTail, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	if err != nil {
		return nil, err
	}
	var out []string
	err = json.Unmarshal(rep.Payload, &out)
	return out, err
}

func (a *App) ToggleRealTime(enabled bool) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(struct{ Enabled bool }{Enabled: enabled})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgToggleRealTime, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) WscRegister(enabled bool) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(struct{ Enabled bool }{Enabled: enabled})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgWscRegister, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) ScanNow(paths []string) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(events.ScanRequest{Type: "folder", Paths: paths})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgScanNow, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) ScanSmart() error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(events.ScanRequest{Type: "smart"})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgScanNow, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) VerdictAction(verdictID, path, action string) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(map[string]string{"id": verdictID, "path": path, "action": action})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgVerdictAction, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) QuarantineList() ([]map[string]any, error) {
	if a.cli == nil {
		return nil, fmt.Errorf("not connected")
	}
	rep, err := a.cli.Call(ipc.Msg{Type: ipc.MsgQuarantineList, ID: uuid.NewString()}, 3*time.Second)
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(rep.Payload, &raw); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

func (a *App) QuarantineDelete(id string) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(map[string]string{"id": id})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgQuarantineDelete, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) QuarantineRestore(id string) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(map[string]string{"id": id})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgQuarantineRestore, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) ReloadSignatures() error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgSignaturesReload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) ImportSignatures(path string) error {
	if a.cli == nil {
		return fmt.Errorf("not connected")
	}
	payload, _ := json.Marshal(map[string]string{"path": path})
	_, err := a.cli.Call(ipc.Msg{Type: ipc.MsgSignaturesImport, Payload: payload, ID: uuid.NewString()}, 3*time.Second)
	return err
}

func (a *App) WinMinimize() { runtime.WindowMinimise(a.ctx) }

func (a *App) PickFolder() string {
	p, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{Title: "Choose a folder"})
	if err != nil || p == "" {
		return ""
	}
	return p
}

func (a *App) PickFile() string {
	p, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Choose a file",
		Filters: []runtime.FileFilter{{DisplayName: "Signature database", Pattern: "*.db"}},
	})
	if err != nil || p == "" {
		return ""
	}
	return p
}

func (a *App) WinMaximize() {
	if runtime.WindowIsMaximised(a.ctx) {
		runtime.WindowUnmaximise(a.ctx)
		return
	}
	runtime.WindowMaximise(a.ctx)
}

func (a *App) WinClose() {
	a.mu.Lock()
	hide := a.settings.HideInTray
	a.mu.Unlock()
	if hide {
		runtime.Hide(a.ctx)
		return
	}
	runtime.Quit(a.ctx)
}

var getEnv = func(k string) string {
	v, _ := lookupEnv(k)
	return v
}

var lookupEnv = func(k string) (string, bool) {
	v, ok := readEnv(k)
	return v, ok
}
