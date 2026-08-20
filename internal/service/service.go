package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/kardianos/service"

	"github.com/mihanistudio/mihanisecurity/internal/config"
	"github.com/mihanistudio/mihanisecurity/internal/detector"
	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/internal/ipc"
	"github.com/mihanistudio/mihanisecurity/internal/logger"
	"github.com/mihanistudio/mihanisecurity/internal/monitor"
	"github.com/mihanistudio/mihanisecurity/internal/quarantine"
	sigpkg "github.com/mihanistudio/mihanisecurity/pkg/signatures"
	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

type program struct {
	cfg     *config.Store
	log     *logger.Logger
	sigs    *sigpkg.DB
	quar    *quarantine.Store
	engine  *detector.Engine
	pipe    *ipc.Server
	monCtx  context.Context
	monStop context.CancelFunc
	mu      sync.Mutex
	started bool

	scanMu sync.Mutex
	scans  map[string]context.CancelFunc
}

func Run(mode string) error {
	cfgStore, err := config.OpenStore("")
	if err != nil {
		return err
	}
	cfg := cfgStore.Get()
	log, err := logger.Open(cfg.General.DataPath, cfg.General.LogLevel)
	if err != nil {
		return err
	}

	log.Info().Str("mode", mode).Str("data", cfg.General.DataPath).Msg("starting")

	dbPath := filepath.Join(cfg.General.DataPath, "signatures.db")

	if err := seedSignaturesFromBundle(dbPath); err != nil {
		log.Warn().Err(err).Msg("bundled signature sync failed")
	}
	sigs, err := sigpkg.Open(dbPath)
	if err != nil {
		log.Error().Err(err).Msg("open signature db")
		return err
	}
	quar, err := quarantine.Open(cfg.Quarantine.Path, int64(cfg.Quarantine.MaxSizeMB)*1024*1024, time.Duration(cfg.Quarantine.MaxAgeDays)*24*time.Hour, cfg.Quarantine.Encrypt)
	if err != nil {
		log.Error().Err(err).Msg("open quarantine")
		return err
	}

	adapter := &detector.SignatureDBAdapter{DB: sigs}
	engine := detector.New(cfgStore, log, quar, adapter)

	svcConfig := &service.Config{
		Name:        "MihaniSecurity",
		DisplayName: "MihaniSecurity Protection Service",
		Description: "Real-time malware and credential-theft protection engine.",
	}

	prg := &program{
		cfg:    cfgStore,
		log:    log,
		sigs:   sigs,
		quar:   quar,
		engine: engine,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		return err
	}

	switch mode {
	case "install":
		return s.Install()
	case "uninstall":
		return s.Uninstall()
	case "run", "":
		if mode == "" {

			if isInteractive() {
				return s.Run()
			}
		}
		return s.Run()
	}
	return fmt.Errorf("unknown mode: %s", mode)
}

func isInteractive() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func (p *program) Start(s service.Service) error {
	if s != nil {

		go p.run()
	} else {

		go p.run()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		p.Stop(s)
	}
	return nil
}

func (p *program) Stop(s service.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return nil
	}
	p.started = false
	if p.monStop != nil {
		p.monStop()
	}
	if p.pipe != nil {
		p.pipe.Close()
	}
	p.log.Info().Msg("stopped")
	return nil
}

func (p *program) run() {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	cfg0 := p.cfg.Get()
	go func() {
		if err := winapi.HardenDataDir(cfg0.General.DataPath); err != nil {
			p.log.Warn().Err(err).Msg("data dir ACL hardening failed")
		} else {
			p.log.Info().Msg("data dir ACL hardened")
		}
		if err := winapi.HardenServiceACL("MihaniSecurity"); err != nil {
			p.log.Warn().Err(err).Msg("service ACL hardening failed")
		} else {
			p.log.Info().Msg("service ACL hardened")
		}
	}()

	pipeName := ipc.PipeName
	p.pipe = ipc.NewServer(pipeName, p.handleClient)
	p.scanMu.Lock()
	p.scans = map[string]context.CancelFunc{}
	p.scanMu.Unlock()
	if err := p.pipe.Listen(); err != nil {
		p.log.Error().Err(err).Msg("pipe listen")
		return
	}
	p.log.Info().Str("pipe", pipeName).Msg("ipc listening")

	p.engine.AddSink(ipcSink{p.pipe})

	cfg := p.cfg.Get()
	if cfg.RealTime.Enabled {
		p.startMonitors()
	}
}

func (p *program) startMonitors() {
	cfg := p.cfg.Get()
	p.monCtx, p.monStop = context.WithCancel(context.Background())

	sens := sensitivePaths()
	if cfg.RealTime.MonitorNewFiles {
		go func() {
			m := monitor.NewFsMonitor(sens)
			m.Log = func(format string, args ...any) {
				p.log.Info().Msgf("monitor: "+format, args...)
			}
			m.Start(p.monCtx, p.engine)
		}()
	}
	if cfg.RealTime.MonitorProcesses {
		go func() {
			m := &monitor.ProcMonitor{}
			m.Start(p.monCtx, p.engine)
		}()
	}
	if cfg.RealTime.MonitorHandles {
		go func() {
			m := &monitor.HandleMonitor{}
			m.Start(p.monCtx, p.engine)
		}()

		go func() {
			m := &monitor.MemMonitor{}
			m.Start(p.monCtx, p.engine)
		}()
	}
	if cfg.RealTime.MonitorRegistry {
		go func() {
			m := &monitor.RegistryMonitor{}
			m.Start(p.monCtx, p.engine)
		}()
	}
	if cfg.RealTime.MonitorNetwork {
		go func() {
			m := &monitor.NetMonitor{}
			m.Start(p.monCtx, p.engine)
		}()
	}

	if cfg.Behavior.DetectDLLInjection {
		go func() {
			m := &monitor.ModuleMonitor{}
			m.Start(p.monCtx, p.engine)
		}()
	}
	if cfg.Behavior.DetectProcessInject {
		go func() {
			m := &monitor.InjectMonitor{}
			m.Start(p.monCtx, p.engine)
		}()
	}
	go p.engine.StartLogJanitor(p.monCtx)
}

func (p *program) handleClient(c net.Conn, m ipc.Msg) {
	switch m.Type {
	case ipc.MsgSettingsGet:
		cfg := p.cfg.Get()
		_ = p.pipe.Send(c, ipc.Reply(m, ipc.MsgSettingsGet, cfg))
	case ipc.MsgStatusGet:
		_ = p.pipe.Send(c, ipc.Reply(m, ipc.MsgStatus, p.status()))
	case ipc.MsgLogTail:
		var q struct {
			Lines int `json:"lines"`
		}
		_ = json.Unmarshal(m.Payload, &q)
		if q.Lines <= 0 || q.Lines > 500 {
			q.Lines = 200
		}
		logPath := filepath.Join(p.cfg.Get().General.DataPath, "logs", "mihanisecurity.log")
		_ = p.pipe.Send(c, ipc.Reply(m, ipc.MsgLogTail, tailLog(logPath, q.Lines)))
	case ipc.MsgScanCancel:
		var q struct {
			ScanID string `json:"scan_id"`
		}
		_ = json.Unmarshal(m.Payload, &q)
		if q.ScanID != "" {
			p.cancelScan(q.ScanID)
		}
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgSettingsSet:
		var c2 config.Config
		if err := json.Unmarshal(m.Payload, &c2); err == nil {
			if err := p.cfg.Set(&c2); err == nil {

				p.reconcileMonitors()
			}
		}
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgScanNow:
		var req events.ScanRequest
		_ = json.Unmarshal(m.Payload, &req)
		go p.runScan(c, req)
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgQuarantineList:
		_ = p.pipe.Send(c, ipc.Reply(m, ipc.MsgQuarantineList, p.quar.List()))
	case ipc.MsgQuarantineDelete:
		var q struct{ ID string }
		_ = json.Unmarshal(m.Payload, &q)
		if err := p.quar.Delete(q.ID); err != nil {
			_ = p.pipe.Send(c, ipc.ErrorReply(m, err))
			break
		}
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgQuarantineRestore:
		var q struct{ ID string }
		_ = json.Unmarshal(m.Payload, &q)
		if err := p.quar.Restore(q.ID); err != nil {
			_ = p.pipe.Send(c, ipc.ErrorReply(m, err))
			break
		}
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgSignaturesReload:
		_ = p.sigs.Reload()
		_ = p.pipe.Broadcast(ipc.Msg{Type: ipc.MsgSignaturesReload})
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgSignaturesImport:
		var q struct{ Path string }
		_ = json.Unmarshal(m.Payload, &q)
		added, err := p.sigs.AppendFile(q.Path)
		if err == nil {
			p.log.Info().Int("added", added).Msg("signatures imported")
			_ = p.pipe.Broadcast(ipc.Msg{Type: ipc.MsgSignaturesReload})
			_ = p.pipe.Send(c, ipc.Ack(m))
		} else {
			_ = p.pipe.Send(c, ipc.ErrorReply(m, err))
		}
	case ipc.MsgToggleRealTime:
		var q struct{ Enabled bool }
		_ = json.Unmarshal(m.Payload, &q)
		_ = p.cfg.Update(func(c *config.Config) { c.RealTime.Enabled = q.Enabled })
		p.reconcileMonitors()
		_ = p.pipe.Send(c, ipc.Ack(m))
	case ipc.MsgWscRegister:
		var q struct{ Enabled bool }
		_ = json.Unmarshal(m.Payload, &q)
		if err := wscSetRegistered(q.Enabled); err != nil {
			p.log.Error().Err(err).Bool("enabled", q.Enabled).Msg("wsc register failed")
			_ = p.pipe.Send(c, ipc.ErrorReply(m, err))
			break
		}
		p.log.Info().Bool("enabled", q.Enabled).Msg("windows security center registration updated")
		_ = p.pipe.Send(c, ipc.Ack(m))
		_ = p.pipe.Broadcast(ipc.StatusMsg(p.status()))
	case ipc.MsgVerdictAction:
		var q struct {
			ID     string `json:"id"`
			Path   string `json:"path"`
			Action string `json:"action"`
		}
		_ = json.Unmarshal(m.Payload, &q)
		if err := p.verdictAction(q.Path, q.Action); err != nil {
			_ = p.pipe.Send(c, ipc.ErrorReply(m, err))
			break
		}
		_ = p.pipe.Send(c, ipc.Ack(m))
		_ = p.pipe.Broadcast(ipc.StatusMsg(p.status()))
	case ipc.MsgPing:
		_ = p.pipe.Send(c, ipc.Reply(m, ipc.MsgPong, nil))
	default:
		p.log.Warn().Str("type", m.Type).Msg("unknown ipc message")
	}
}

func (p *program) reconcileMonitors() {

	p.engine.ApplyConfig()
	cfg := p.cfg.Get()
	wasStarted := p.monCtx != nil
	if cfg.RealTime.Enabled && !wasStarted {
		p.startMonitors()
	} else if !cfg.RealTime.Enabled && wasStarted {
		p.monStop()
		p.monCtx = nil
		p.monStop = nil
	}
}

func (p *program) runScan(c net.Conn, req events.ScanRequest) {

	scanID := uuid.NewString()
	ctx, cancel := context.WithCancel(context.Background())
	p.scanMu.Lock()
	if p.scans == nil {
		p.scans = map[string]context.CancelFunc{}
	}
	p.scans[scanID] = cancel
	p.scanMu.Unlock()
	defer func() {
		cancel()
		p.scanMu.Lock()
		delete(p.scans, scanID)
		p.scanMu.Unlock()
	}()
	ctx, cancel = context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	scan := detector.NewOnDemand(&detector.SignatureDBAdapter{DB: p.sigs})
	scan.Exclusions = p.cfg.Get().Exclusions
	progress := func(pr events.ScanProgress) {
		pr.ScanID = scanID
		_ = p.pipe.Send(c, ipc.ScanProgressMsg(pr))
	}
	var res *detector.ScanResult
	var err error
	switch req.Type {
	case "smart":
		res, err = scan.ScanSmart(ctx, progress)
	case "full":
		if len(req.Paths) == 0 {
			res, err = scan.Scan(ctx, detector.FullScanRoots(), progress)
		} else {
			res, err = scan.Scan(ctx, req.Paths, progress)
		}
	default:
		res, err = scan.Scan(ctx, req.Paths, progress)
	}
	if err != nil {
		return
	}
	res.ScanID = scanID

	p.engine.ApplyScanResult(res)
	_ = p.pipe.Send(c, ipc.ScanResultMsg(res))
}

func (p *program) verdictAction(path, action string) error {
	if path == "" {
		return fmt.Errorf("no file path")
	}
	switch action {
	case "quarantine":
		if detector.IsProtectedPath(path) {
			return fmt.Errorf("path is inside a protected location")
		}
		if detector.IsProtectedAssetPath(path) {
			return fmt.Errorf("asset is protected")
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("file not found")
		}
		entry, err := p.quar.Add(path, filepath.Base(path), "high", "manual quarantine from user action", "")
		if err != nil {
			return err
		}
		p.log.Info().Str("path", path).Str("qid", entry.ID).Msg("user quarantined file")
		return nil
	case "allow":
		name := strings.ToLower(filepath.Base(path))
		if name == "" {
			return fmt.Errorf("invalid path")
		}
		if err := p.cfg.Update(func(c *config.Config) {
			for _, w := range c.Whitelist {
				if strings.EqualFold(w, name) {
					return
				}
			}
			c.Whitelist = append(c.Whitelist, name)
		}); err != nil {
			return err
		}
		p.engine.ApplyConfig()
		p.log.Info().Str("name", name).Msg("user allowed file")
		return nil
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func (p *program) cancelScan(id string) {
	p.scanMu.Lock()
	cancel, ok := p.scans[id]
	p.scanMu.Unlock()
	if ok {
		cancel()
	}
}

func (p *program) status() events.Status {
	cfg := p.cfg.Get()
	var monitors []string
	if p.monCtx != nil {
		if cfg.RealTime.MonitorNewFiles {
			monitors = append(monitors, "filesystem")
		}
		if cfg.RealTime.MonitorProcesses {
			monitors = append(monitors, "processes")
		}
		if cfg.RealTime.MonitorHandles {
			monitors = append(monitors, "handles", "memory")
		}
		if cfg.RealTime.MonitorRegistry {
			monitors = append(monitors, "registry")
		}
		if cfg.RealTime.MonitorNetwork {
			monitors = append(monitors, "network")
		}
		if cfg.Behavior.DetectDLLInjection {
			monitors = append(monitors, "modules")
		}
		if cfg.Behavior.DetectProcessInject {
			monitors = append(monitors, "injections")
		}
	}
	st := p.engine.Status(p.sigs.Count(), p.sigs.Version(), monitors, p.sigs.Path(), len(cfg.Whitelist))
	st.Drives = detector.FullScanRoots()
	st.WscRegistered = wscRegistered()
	return st
}

func tailLog(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	const maxTail = 4 << 20
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	start := fi.Size() - maxTail
	if start < 0 {
		start = 0
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil
	}
	text := string(buf)

	if idx := strings.Index(text, "\n"); idx >= 0 {
		text = text[idx+1:]
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func seedSignaturesFromBundle(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	for _, c := range []string{
		filepath.Join(dir, "signatures", "signatures.db"),
		filepath.Join(dir, "signatures.db"),
	} {
		if _, err := os.Stat(c); err != nil {
			continue
		}
		data, err := os.ReadFile(c)
		if err != nil {
			return err
		}
		cur, err := os.ReadFile(dst)
		if err == nil && bytes.Equal(cur, data) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	}
	return nil
}

type ipcSink struct{ p *ipc.Server }

func (s ipcSink) OnVerdict(v events.Verdict) { s.p.Broadcast(ipc.VerdictMsg(v)) }

func sensitivePaths() []string {

	return detector.SensitivePaths()
}
