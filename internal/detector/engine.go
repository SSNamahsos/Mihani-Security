package detector

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/config"
	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/internal/logger"
	"github.com/mihanistudio/mihanisecurity/internal/quarantine"
)

type Sink interface {
	OnVerdict(v events.Verdict)
}

type EventSink interface {
	OnEvent(e events.Event)
}

const dedupeWindow = 90 * time.Second

type Engine struct {
	cfg        *config.Store
	log        *logger.Logger
	quarantine *quarantine.Store
	scanner    *OnDemandScanner

	mu         sync.RWMutex
	detectors  []Detector
	sinks      []Sink
	eventSinks []EventSink
	tokensDet  *Tokens
	wlPaths    []string
	wlNames    map[string]bool
	exclPaths  []string

	realTime     atomic.Bool
	startedAt    time.Time
	threatsToday atomic.Int64
	blocked      atomic.Int64
	dayStamp     atomic.Int64
	lastScan     atomic.Int64

	recent sync.Map
}

func New(cfg *config.Store, log *logger.Logger, q *quarantine.Store, sigs *SignatureDBAdapter) *Engine {
	c := cfg.Get()
	e := &Engine{
		cfg:        cfg,
		log:        log,
		quarantine: q,
		scanner:    NewOnDemand(sigs),
		startedAt:  time.Now(),
		tokensDet:  NewTokens(),
	}
	beaconWindow := time.Duration(c.Behavior.BeaconIntervalMax) * time.Second
	if beaconWindow <= 0 {
		beaconWindow = 5 * time.Minute
	}
	e.detectors = []Detector{
		e.tokensDet,
		NewStaticFiles(),
		NewSignatures(sigs),
		NewBehavior(),
		NewBeaconing(6, beaconWindow),
	}
	e.realTime.Store(c.RealTime.Enabled)
	e.dayStamp.Store(dayKey(time.Now()))
	e.ApplyConfig()
	return e
}

func (e *Engine) Scanner() *OnDemandScanner { return e.scanner }

func (e *Engine) ApplyConfig() {
	c := e.cfg.Get()
	names := make(map[string]bool, len(c.Whitelist))
	var paths []string
	for _, w := range c.Whitelist {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}

		if strings.ContainsAny(w, `\/`) {
			paths = append(paths, strings.ToLower(filepath.Clean(w)))
			continue
		}
		names[strings.ToLower(w)] = true
	}
	e.mu.Lock()
	e.wlNames, e.wlPaths = names, paths
	e.exclPaths = normalizedPaths(c.Exclusions)
	e.mu.Unlock()
	e.tokensDet.SetUserWhitelist(c.Whitelist)
	e.realTime.Store(c.RealTime.Enabled)
}

func (e *Engine) SetRealTime(on bool) {
	e.realTime.Store(on)
	_ = e.cfg.Update(func(c *config.Config) { c.RealTime.Enabled = on })
}

func (e *Engine) RealTimeEnabled() bool { return e.realTime.Load() }

func (e *Engine) AddSink(s Sink) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sinks = append(e.sinks, s)
	if es, ok := s.(EventSink); ok {
		e.eventSinks = append(e.eventSinks, es)
	}
}

func (e *Engine) MarkScan(t time.Time) { e.lastScan.Store(t.Unix()) }

func (e *Engine) Status(sigCount int, sigVersion string, monitors []string, dbPath string, whitelistCount int) events.Status {
	e.rollDay()
	var last time.Time
	if u := e.lastScan.Load(); u > 0 {
		last = time.Unix(u, 0)
	}
	return events.Status{
		RealTimeActive:   e.realTime.Load(),
		SignatureCount:   sigCount,
		SignatureVersion: sigVersion,
		Monitors:         monitors,
		ThreatsToday:     int(e.threatsToday.Load()),
		ThreatsBlocked:   int(e.blocked.Load()),
		LastScan:         last,
		StartedAt:        e.startedAt,
		DBPath:           dbPath,
		QuarantineCount:  e.quarantine.Count(),
		Whitelisted:      whitelistCount,
	}
}

func (e *Engine) Handle(ev events.Event) {
	if ev.ID == "" {
		ev.ID = newID()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	e.mu.RLock()
	esinks := append([]EventSink(nil), e.eventSinks...)
	e.mu.RUnlock()
	for _, s := range esinks {
		s.OnEvent(ev)
	}
	if !e.realTime.Load() {
		return
	}
	e.Process(ev)
}

func (e *Engine) Process(ev events.Event) {
	e.mu.RLock()
	dets := append([]Detector(nil), e.detectors...)
	e.mu.RUnlock()

	var (
		mu   sync.Mutex
		outs []events.Verdict
		wg   sync.WaitGroup
	)
	for _, d := range dets {
		if !e.detectorEnabled(d) {
			continue
		}
		d := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			vs := d.Evaluate(ev)
			if len(vs) == 0 {
				return
			}
			for i := range vs {
				if vs[i].Source == "" {
					vs[i].Source = d.Name()
				}
			}
			mu.Lock()
			outs = append(outs, vs...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, v := range outs {
		e.Report(v)
	}
}

func (e *Engine) Report(v events.Verdict) {
	if isProtectedAsset(v) || e.whitelisted(v) || e.suppressed(v) || e.excluded(v) {
		return
	}
	e.enforce(&v)
	scrubVerdict(&v)
	e.log.Verdict(v)

	e.mu.RLock()
	sinks := append([]Sink(nil), e.sinks...)
	e.mu.RUnlock()
	for _, s := range sinks {
		s.OnVerdict(v)
	}
}

func scrubVerdict(v *events.Verdict) {
	v.Name = logger.Redact(v.Name)
	v.Description = logger.Redact(v.Description)
	v.ActionDetail = logger.Redact(v.ActionDetail)
	for i := range v.Evidence {
		v.Evidence[i] = logger.Redact(v.Evidence[i])
	}
}

func (e *Engine) detectorEnabled(d Detector) bool {
	c := e.cfg.Get()
	switch d.Name() {
	case "tokens":
		return c.TokenGuard.Enabled
	case "behavior":
		return c.Behavior.Enabled
	case "beaconing":
		return c.Behavior.Enabled && c.Behavior.DetectBeaconing
	}
	return true
}

func (e *Engine) whitelisted(v events.Verdict) bool {
	e.mu.RLock()
	names, paths := e.wlNames, e.wlPaths
	e.mu.RUnlock()

	var cands []string
	if v.Process != nil {
		cands = append(cands, v.Process.Name, v.Process.Path)
	}
	cands = append(cands, v.Path)
	for _, c := range cands {
		if c == "" {
			continue
		}
		lc := strings.ToLower(filepath.Clean(c))
		if names[strings.ToLower(filepath.Base(c))] {
			return true
		}
		for _, p := range paths {
			if lc == p || strings.HasPrefix(lc, strings.TrimSuffix(p, `\`)+`\`) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) excluded(v events.Verdict) bool {
	e.mu.RLock()
	excl := e.exclPaths
	e.mu.RUnlock()
	if len(excl) == 0 {
		return false
	}
	for _, p := range []string{v.Path, v.TargetPath} {
		if p == "" {
			continue
		}
		lc := strings.ToLower(filepath.Clean(p))
		for _, x := range excl {
			if lc == x || strings.HasPrefix(lc, x+`\`) {
				return true
			}
		}
	}
	return false
}

func normalizedPaths(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.ToLower(filepath.Clean(p))
		p = strings.TrimSuffix(p, `\`)
		if p != "" && p != "." {
			out = append(out, p)
		}
	}
	return out
}

func (e *Engine) suppressed(v events.Verdict) bool {
	pid := ""
	if v.Process != nil {
		pid = intToString(int(v.Process.PID))
	}
	key := string(v.Threat) + "|" + v.Name + "|" + strings.ToLower(v.Path) + "|" +
		strings.ToLower(v.TargetPath) + "|" + pid
	now := time.Now()
	if prev, ok := e.recent.Load(key); ok {
		if t, ok := prev.(time.Time); ok && now.Sub(t) < dedupeWindow {
			return true
		}
	}
	e.recent.Store(key, now)

	e.recent.Range(func(k, val any) bool {
		if t, ok := val.(time.Time); ok && now.Sub(t) > 4*dedupeWindow {
			e.recent.Delete(k)
		}
		return true
	})
	return false
}

func (e *Engine) rollDay() {
	today := dayKey(time.Now())
	if e.dayStamp.Swap(today) != today {
		e.threatsToday.Store(0)
	}
}

func dayKey(t time.Time) int64 {
	y, m, d := t.Date()
	return int64(y)*10000 + int64(m)*100 + int64(d)
}

func (e *Engine) enforce(v *events.Verdict) {
	c := e.cfg.Get()
	e.rollDay()
	e.threatsToday.Add(1)

	var policy config.ThreatAction
	switch v.Threat {
	case events.ThreatTokenTheft:
		policy = c.RealTime.OnTokenTheft
		if c.TokenGuard.NotifyOnly {
			policy = config.ActionLogOnly
		}
	case events.ThreatMalware:
		policy = c.RealTime.OnMalware
	case events.ThreatBeaconing:
		policy = c.RealTime.OnBeaconing
	case events.ThreatPersistence, events.ThreatDLLInjection, events.ThreatProcessInject:
		policy = c.Behavior.OnDetect
	default:
		policy = c.RealTime.OnSuspicious
	}
	v.Action = decideAction(*v, policy)

	var detail []string

	if e.shouldTerminate(*v, c) {
		if err := terminateProcess(v.Process.PID); err == nil {
			detail = append(detail, "process terminated (pid "+intToString(int(v.Process.PID))+")")
			e.blocked.Add(1)
		} else {
			detail = append(detail, "terminate failed: "+err.Error())
		}
	}

	switch v.Action {
	case events.ActionQuarantine, events.ActionDelete:
		target := v.Path
		if target == "" || protectedPath(target) {
			if target != "" {
				detail = append(detail, "left in place (protected location)")
			}
			break
		}
		if v.Action == events.ActionDelete {
			if err := removeFile(target); err == nil {
				v.ActionTaken = true
				e.blocked.Add(1)
				detail = append(detail, "file deleted")
			} else {
				detail = append(detail, "delete failed: "+err.Error())
			}
			break
		}
		entry, err := e.quarantine.Add(target, v.Name, string(v.Severity), stringsJoin(v.Evidence, " | "), v.ID)
		if err == nil {
			v.QuarantineID = entry.ID
			v.ActionTaken = true
			e.blocked.Add(1)
			detail = append(detail, "image quarantined")
		} else {
			detail = append(detail, "quarantine failed: "+err.Error())
		}
	case events.ActionBlock:
		v.ActionTaken = len(detail) > 0
		detail = append(detail, "access reported; no kernel-mode deny available")
	}

	v.ActionDetail = stringsJoin(detail, "; ")
}

func (e *Engine) shouldTerminate(v events.Verdict, c config.Config) bool {
	if v.Process == nil || v.Process.PID <= 4 {
		return false
	}
	if v.Severity != events.SeverityCritical && v.Severity != events.SeverityHigh {
		return false
	}
	switch v.Action {
	case events.ActionBlock, events.ActionQuarantine, events.ActionDelete:
	default:
		return false
	}
	if v.Threat == events.ThreatTokenTheft && (c.TokenGuard.NotifyOnly || !c.TokenGuard.BlockReads) {
		return false
	}
	name := v.Process.Name
	if name == "" {
		name = filepath.Base(v.Process.Path)
	}
	if isSystemProcessName(name) || protectedPath(v.Process.Path) {
		return false
	}
	return true
}

func decideAction(v events.Verdict, policy config.ThreatAction) events.Action {
	switch policy {
	case config.ActionAutoDelete:
		return events.ActionDelete
	case config.ActionAutoQuarantine:
		return events.ActionQuarantine
	case config.ActionLogOnly:
		return events.ActionLog
	case config.ActionPrompt:

		if v.Severity == events.SeverityCritical {
			return events.ActionQuarantine
		}
		return events.ActionAlert
	}
	if v.Severity == events.SeverityCritical {
		return events.ActionQuarantine
	}
	return events.ActionAlert
}

func (e *Engine) ApplyScanResult(res *ScanResult) {
	if res == nil {
		return
	}
	for i := range res.Verdicts {
		v := res.Verdicts[i]
		if isProtectedAsset(v) || e.whitelisted(v) || e.excluded(v) {
			continue
		}
		e.enforce(&v)
		e.log.Verdict(v)
		res.Verdicts[i] = v
		e.mu.RLock()
		sinks := append([]Sink(nil), e.sinks...)
		e.mu.RUnlock()
		for _, s := range sinks {
			s.OnVerdict(v)
		}
	}
	e.MarkScan(time.Now())
}

func protectedPath(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.Clean(path))
	for _, frag := range []string{
		`c:\windows\`, `\program files\`, `\program files (x86)\`,
		`\mihanisecurity\`,
	} {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

func IsProtectedPath(path string) bool { return protectedPath(path) }

func IsProtectedAssetPath(path string) bool {
	return path != "" && protectedAssets[strings.ToLower(filepath.Base(path))]
}

var protectedAssets = map[string]bool{
	"onlinefix64.dll": true,
	"onlinefix.dll":   true,
}

func isProtectedAsset(v events.Verdict) bool {
	for _, p := range []string{v.Path, v.TargetPath} {
		if p != "" && protectedAssets[strings.ToLower(filepath.Base(p))] {
			return true
		}
	}
	if v.Process != nil && v.Process.Path != "" &&
		protectedAssets[strings.ToLower(filepath.Base(v.Process.Path))] {
		return true
	}
	return false
}

func (e *Engine) StartLogJanitor(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if e.cfg.Get().Quarantine.AutoPurge {
				e.quarantine.PurgeOld()
			}
		}
	}
}

func stringsJoin(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	out := s[0]
	for i := 1; i < len(s); i++ {
		out += sep + s[i]
	}
	return out
}

func removeFile(path string) error { return removeFileOS(path) }
