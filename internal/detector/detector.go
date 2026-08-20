package detector

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
)

type Detector interface {
	Name() string

	Evaluate(e events.Event) []events.Verdict
}

type Signatures struct {
	DB SignaturesDB
}

type SignaturesDB interface {
	MatchFile(path string) ([]SigMatch, error)
}

type SigMatch struct {
	Name     string
	Severity string
	Family   string
	Evidence string
}

func NewSignatures(db SignaturesDB) *Signatures { return &Signatures{DB: db} }

func (d *Signatures) Evaluate(e events.Event) []events.Verdict {
	if d.DB == nil {
		return nil
	}
	var path string
	switch e.Kind {
	case events.EventFileCreate, events.EventFileModify, events.EventFileRename, events.EventFileRead:
		path = e.Path
	default:
		return nil
	}
	if path == "" {
		return nil
	}
	matches, err := d.DB.MatchFile(path)
	if err != nil || len(matches) == 0 {
		return nil
	}
	out := make([]events.Verdict, 0, len(matches))
	for _, m := range matches {
		v := events.Verdict{
			ID:          newID(),
			Time:        time.Now(),
			Severity:    mapSeverity(m.Severity),
			Threat:      events.ThreatMalware,
			Name:        m.Name,
			Description: "Signature match: " + m.Family,
			Path:        path,
			Evidence:    []string{m.Evidence},
			Action:      events.ActionQuarantine,
		}
		if e.Process != nil {
			v.Process = e.Process
		}
		out = append(out, v)
	}
	return out
}

func (d *Signatures) Name() string { return "signatures" }

type Tokens struct {
	mu            sync.RWMutex
	userWhitelist map[string]bool
}

func NewTokens() *Tokens { return &Tokens{userWhitelist: map[string]bool{}} }

func (d *Tokens) SetUserWhitelist(names []string) {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[strings.ToLower(filepath.Base(strings.TrimSpace(n)))] = true
	}
	d.mu.Lock()
	d.userWhitelist = m
	d.mu.Unlock()
}

func (d *Tokens) trusted(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.userWhitelist[strings.ToLower(filepath.Base(name))]
}

func (d *Tokens) Evaluate(e events.Event) []events.Verdict {
	if e.Process == nil {
		return nil
	}
	switch e.Kind {
	case events.EventHandleOpen, events.EventFileRead, events.EventFileModify, events.EventFileCreate:
	default:
		return nil
	}
	sf := tokens.MatchSensitive(e.Path)
	if sf == nil {
		return nil
	}
	name := strings.ToLower(filepath.Base(e.Process.Name))
	if name == "" && e.Process.Path != "" {
		name = strings.ToLower(filepath.Base(e.Process.Path))
	}
	legitOwner := tokens.IsLegitimateOwner(sf.App, sf.Pattern, name)
	if legitOwner {
		ok, why := tokens.TrustedOwnerProcess(name, e.Process.Path)
		if ok {
			return nil
		}
		sev := events.SeverityCritical
		evidence := []string{
			"protected_store=" + sf.Path,
			"application=" + sf.App,
			"accessing_process=" + name,
			"process_image=" + e.Process.Path,
			"access=" + e.Access,
			"owner_verification=" + why,
		}
		if isUntrustedLocation(e.Process.Path) {
			evidence = append(evidence, "origin=untrusted_location")
		}
		if owners := tokens.LegitimateOwnersFor(sf.App); len(owners) > 0 {
			evidence = append(evidence, "expected_owner="+strings.Join(owners, ","))
		}
		return []events.Verdict{{
			ID:          newID(),
			Time:        time.Now(),
			Severity:    sev,
			Threat:      events.ThreatTokenTheft,
			Name:        "Spoofed " + sf.App + " process accessing credential store",
			Description: e.Process.Name + " claims to be " + sf.App + " but failed signature verification (" + why + ").",
			Path:        firstNonEmpty(e.Process.Path, e.Path),
			TargetPath:  e.Path,
			Process:     e.Process,
			Evidence:    evidence,
			Action:      events.ActionBlock,
		}}
	}
	if d.trusted(name) {
		return nil
	}

	sev := events.SeverityHigh
	if sf.Severity == "critical" {
		sev = events.SeverityCritical
	}
	evidence := []string{
		"protected_store=" + sf.Path,
		"application=" + sf.App,
		"accessing_process=" + name,
		"process_image=" + e.Process.Path,
		"access=" + e.Access,
	}
	if isUntrustedLocation(e.Process.Path) {
		sev = events.SeverityCritical
		evidence = append(evidence, "origin=untrusted_location")
	}
	if owners := tokens.LegitimateOwnersFor(sf.App); len(owners) > 0 {
		evidence = append(evidence, "expected_owner="+strings.Join(owners, ","))
	}
	return []events.Verdict{{
		ID:          newID(),
		Time:        time.Now(),
		Severity:    sev,
		Threat:      events.ThreatTokenTheft,
		Name:        "Unauthorized access to " + sf.App + " credential store",
		Description: e.Process.Name + " touched " + sf.Description + ", which only " + sf.App + " itself should read.",
		Path:        firstNonEmpty(e.Process.Path, e.Path),
		TargetPath:  e.Path,
		Process:     e.Process,
		Evidence:    evidence,
		Action:      events.ActionBlock,
	}}
}

func isUntrustedLocation(path string) bool {
	return tokens.UntrustedLocation(path)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (d *Tokens) Name() string { return "tokens" }

type BehaviorDetector struct {
	mu       sync.Mutex
	policies map[string][]BehaviorRule
}

type BehaviorRule struct {
	Name        string
	Description string
	Severity    events.Severity
	Threat      events.ThreatType
	Match       func(e events.Event) bool
	Evidence    func(e events.Event) []string
}

func NewBehavior() *BehaviorDetector {
	d := &BehaviorDetector{policies: map[string][]BehaviorRule{}}
	d.registerDefaults()
	return d
}

func (d *BehaviorDetector) registerDefaults() {
	d.policies["persistence_run"] = []BehaviorRule{{
		Name:        "Suspicious Run key write",
		Description: "A process wrote to a Run/RunOnce registry key",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatPersistence,
		Match: func(e events.Event) bool {
			if e.Registry == nil {
				return false
			}
			k := strings.ToLower(e.Registry.Key)
			return strings.Contains(k, "\\run") || strings.Contains(k, "\\runonce")
		},
		Evidence: func(e events.Event) []string {
			return []string{"key=" + e.Registry.Key, "value=" + e.Registry.Value}
		},
	}}
	d.policies["winlogon_shell"] = []BehaviorRule{{
		Name:        "Winlogon shell tampering",
		Description: "Modification to Winlogon Shell/Userinit",
		Severity:    events.SeverityCritical,
		Threat:      events.ThreatPersistence,
		Match: func(e events.Event) bool {
			if e.Registry == nil {
				return false
			}
			k := strings.ToLower(e.Registry.Key)
			vn := strings.ToLower(e.Registry.Value)
			if !strings.Contains(k, "winlogon") {
				return false
			}
			return strings.Contains(vn, "shell") || strings.Contains(vn, "userinit") || strings.Contains(k, "userinit")
		},
	}}
	d.policies["ifeo_debugger"] = []BehaviorRule{{
		Name:        "Image File Execution Options tampering",
		Description: "A process installed an IFEO Debugger or SilentProcessExit handler",
		Severity:    events.SeverityCritical,
		Threat:      events.ThreatPersistence,
		Match: func(e events.Event) bool {
			if e.Registry == nil {
				return false
			}
			k := strings.ToLower(e.Registry.Key)
			vn := strings.ToLower(e.Registry.Value)
			if !strings.Contains(k, "image file execution options") {
				return false
			}
			return strings.Contains(vn, "debugger") || strings.Contains(k, "silentprocessexit")
		},
		Evidence: func(e events.Event) []string {
			return []string{"key=" + e.Registry.Key, "value=" + e.Registry.Value}
		},
	}}
	d.policies["appinit_dlls"] = []BehaviorRule{{
		Name:        "AppInit_DLLs modification",
		Description: "A process modified AppInit_DLLs, a system-wide DLL preload hook",
		Severity:    events.SeverityCritical,
		Threat:      events.ThreatPersistence,
		Match: func(e events.Event) bool {
			if e.Registry == nil {
				return false
			}
			vn := strings.ToLower(e.Registry.Value)
			return strings.Contains(vn, "appinit_dlls") || strings.Contains(vn, "requireSignedAppInitDlls")
		},
		Evidence: func(e events.Event) []string {
			return []string{"key=" + e.Registry.Key, "value=" + e.Registry.Value}
		},
	}}
	d.policies["startup_folder"] = []BehaviorRule{{
		Name:        "Startup folder planting",
		Description: "A file was created in a Startup directory",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatPersistence,
		Match: func(e events.Event) bool {
			if e.Kind != events.EventFileCreate && e.Kind != events.EventFileModify {
				return false
			}
			p := strings.ToLower(e.Path)
			return strings.Contains(p, "\\startup\\")
		},
		Evidence: func(e events.Event) []string {
			return []string{"path=" + e.Path}
		},
	}}
	d.policies["suspicious_spawn"] = []BehaviorRule{{
		Name:        "Suspicious command-line",
		Description: "Process started with -enc / hidden PowerShell / mimikatz",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatSuspicious,
		Match: func(e events.Event) bool {
			if e.Process == nil {
				return false
			}
			cl := strings.ToLower(strings.ReplaceAll(e.Process.CommandLine, ".exe", ""))
			if cl == "" {
				return false
			}
			matches := []string{"powershell -enc", "powershell -nop -w hidden",
				"vssadmin delete shadows", "bcdedit /set", "mimikatz", "lazagne"}
			for _, m := range matches {
				if strings.Contains(cl, m) {
					return true
				}
			}
			return false
		},
		Evidence: func(e events.Event) []string { return []string{"cmd=" + e.Process.CommandLine} },
	}}
	d.policies["enc_powershell"] = []BehaviorRule{{
		Name:        "Encoded PowerShell payload",
		Description: "Process ran PowerShell with an encoded or hidden payload",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatSuspicious,
		Match: func(e events.Event) bool {
			if e.Process == nil {
				return false
			}
			cl := strings.ToLower(e.Process.CommandLine)
			if cl == "" {
				return false
			}
			matches := []string{"-encodedcommand", "frombase64string",
				"-executionpolicy bypass -file"}
			for _, m := range matches {
				if strings.Contains(cl, m) {
					return true
				}
			}
			return false
		},
		Evidence: func(e events.Event) []string { return []string{"cmd=" + e.Process.CommandLine} },
	}}
	d.policies["scheduled_task"] = []BehaviorRule{{
		Name:        "Scheduled task creation",
		Description: "Process created a scheduled task",
		Severity:    events.SeverityMedium,
		Threat:      events.ThreatPersistence,
		Match: func(e events.Event) bool {
			if e.Process == nil {
				return false
			}
			cl := strings.ToLower(e.Process.CommandLine)
			if !strings.Contains(cl, "schtasks") {
				return false
			}
			return strings.Contains(cl, "/create") || strings.Contains(cl, " -create")
		},
		Evidence: func(e events.Event) []string { return []string{"cmd=" + e.Process.CommandLine} },
	}}
	d.policies["download_exec"] = []BehaviorRule{{
		Name:        "Download-and-execute pattern",
		Description: "Process used a download-and-execute technique",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatSuspicious,
		Match: func(e events.Event) bool {
			if e.Process == nil {
				return false
			}
			cl := strings.ToLower(strings.ReplaceAll(e.Process.CommandLine, ".exe", ""))
			if cl == "" {
				return false
			}
			matches := []string{"certutil -urlcache", "bitsadmin /transfer",
				"regsvr32 /s /u /i:", "rundll32 javascript", "mshta"}
			for _, m := range matches {
				if strings.Contains(cl, m) {
					return true
				}
			}
			return false
		},
		Evidence: func(e events.Event) []string { return []string{"cmd=" + e.Process.CommandLine} },
	}}
	d.policies["process_inject"] = []BehaviorRule{{
		Name:        "Thread in unbacked memory",
		Description: "A thread is executing from memory not backed by any module",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatProcessInject,
		Match: func(e events.Event) bool {
			return e.Kind == events.EventThreadInject && e.Process != nil && e.Process.Path != ""
		},
		Evidence: func(e events.Event) []string {
			return []string{"start_address=" + e.Access}
		},
	}}
	d.policies["dll_injection"] = []BehaviorRule{{
		Name:        "DLL injection pattern",
		Description: "Process is being written to from an unrelated parent",
		Severity:    events.SeverityHigh,
		Threat:      events.ThreatDLLInjection,
		Match: func(e events.Event) bool {

			if e.Process == nil {
				return false
			}
			n := strings.ToLower(e.Process.Name)
			if n != "cmd.exe" && n != "powershell.exe" && n != "rundll32.exe" {
				return false
			}
			return strings.TrimSpace(e.Process.CommandLine) == ""
		},
	}}
}

func (d *BehaviorDetector) Evaluate(e events.Event) []events.Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []events.Verdict
	for _, rules := range d.policies {
		for _, r := range rules {
			if r.Match(e) {
				v := events.Verdict{
					ID:          newID(),
					Time:        time.Now(),
					Severity:    r.Severity,
					Threat:      r.Threat,
					Name:        r.Name,
					Description: r.Description,
					Process:     e.Process,
					Path:        e.Path,
					Action:      events.ActionAlert,
				}
				if r.Evidence != nil {
					v.Evidence = r.Evidence(e)
				}
				out = append(out, v)
			}
		}
	}
	return out
}

func (d *BehaviorDetector) Name() string { return "behavior" }

type BeaconingDetector struct {
	mu        sync.Mutex
	history   map[string][]time.Time
	threshold int
	window    time.Duration
}

func NewBeaconing(threshold int, window time.Duration) *BeaconingDetector {
	return &BeaconingDetector{
		history:   map[string][]time.Time{},
		threshold: threshold,
		window:    window,
	}
}

func (d *BeaconingDetector) Evaluate(e events.Event) []events.Verdict {
	if e.Network == nil || e.Process == nil {
		return nil
	}
	key := uint32ToString(e.Process.PID) + ":" + e.Network.RemoteAddr + ":" + uint16ToString(e.Network.RemotePort)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-d.window)
	hits := d.history[key]

	i := 0
	for ; i < len(hits); i++ {
		if hits[i].After(cutoff) {
			break
		}
	}
	hits = hits[i:]
	hits = append(hits, now)
	d.history[key] = hits
	if d.threshold > 0 && len(hits) >= d.threshold {

		if len(hits) == d.threshold {
			return []events.Verdict{{
				ID:          newID(),
				Time:        now,
				Severity:    events.SeverityHigh,
				Threat:      events.ThreatBeaconing,
				Name:        "Possible beaconing",
				Description: "Process connected repeatedly to the same remote endpoint",
				Process:     e.Process,
				Evidence: []string{
					"endpoint=" + e.Network.RemoteAddr + ":" + uint16ToString(e.Network.RemotePort),
					"hits=" + intToString(len(hits)),
				},
				Action: events.ActionAlert,
			}}
		}
	}

	if len(d.history) > 4096 {
		for k := range d.history {
			if len(d.history[k]) == 0 || d.history[k][len(d.history[k])-1].Before(cutoff) {
				delete(d.history, k)
			}
		}
	}
	return nil
}

func (d *BeaconingDetector) Name() string { return "beaconing" }

func newID() string {
	now := time.Now().UnixNano()
	return intToHex(now)
}

func mapSeverity(s string) events.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return events.SeverityCritical
	case "high":
		return events.SeverityHigh
	case "medium":
		return events.SeverityMedium
	case "low":
		return events.SeverityLow
	}
	return events.SeverityMedium
}

var TokenRegex = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(tokens.TokenRegexes))
	for _, p := range tokens.TokenRegexes {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		out = append(out, re)
	}
	return out
}()

func uint32ToString(v uint32) string { return intToString(int(v)) }
func uint16ToString(v uint16) string { return intToString(int(v)) }
func intToString(v int) string       { return formatInt(v) }
func intToHex(v int64) string        { return formatHex(v) }
