package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/config"
	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/internal/logger"
	"github.com/mihanistudio/mihanisecurity/internal/quarantine"
)

func TestIsProtectedAsset(t *testing.T) {
	base := events.Verdict{Path: `C:\Games\Game\onlinefix64.dll`}
	if !isProtectedAsset(base) {
		t.Error("onlinefix64.dll in Path must be protected")
	}
	if !isProtectedAsset(events.Verdict{Path: `D:\Games\X\ONLINEFIX.DLL`}) {
		t.Error("case-insensitive match required")
	}
	if !isProtectedAsset(events.Verdict{TargetPath: `C:\Games\Y\onlinefix64.dll`}) {
		t.Error("TargetPath match required")
	}
	if !isProtectedAsset(events.Verdict{
		Process: &events.Process{Name: "game.exe", Path: `C:\Games\Z\onlinefix.dll`},
	}) {
		t.Error("Process.Path match required")
	}
	for _, p := range []string{
		`C:\Games\Game\onlinefix.exe`,
		`C:\Games\Game\onlinefix64.exe`,
		`C:\Games\Game\steam_api64.dll`,
		`C:\Games\Game\onlinefix64.dll.bak`,
		"",
	} {
		if isProtectedAsset(events.Verdict{Path: p}) {
			t.Errorf("path %q must NOT be protected", p)
		}
	}
}

func TestReportNeverTouchesProtectedAssets(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.OpenStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := logger.Open(filepath.Join(os.TempDir(), "mihanisec-test-log"), "info")
	if err != nil {
		t.Fatal(err)
	}
	q, err := quarantine.Open(filepath.Join(dir, "quarantine"), 1<<20, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	e := New(cfg, log, q, nil)

	got := 0
	e.AddSink(sinkFunc(func(v events.Verdict) { got++ }))

	cfg.Update(func(c *config.Config) {
		c.RealTime.OnMalware = config.ActionAutoDelete
	})

	e.Report(events.Verdict{
		Name:     "EvoGen:Test",
		Path:     `C:\Games\Game\onlinefix64.dll`,
		Threat:   events.ThreatMalware,
		Severity: events.SeverityCritical,
	})

	if got != 0 {
		t.Errorf("protected asset must not reach sinks, got %d verdicts", got)
	}
	if n := q.Count(); n != 0 {
		t.Errorf("protected asset must not be quarantined, count=%d", n)
	}
	if e.threatsToday.Load() != 0 {
		t.Errorf("protected asset must not count as a threat, got %d", e.threatsToday.Load())
	}
}

func TestApplyScanSkipsProtectedAssets(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "games")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	prot := filepath.Join(root, "onlinefix.dll")
	real := filepath.Join(root, "real_malware.exe")
	for _, p := range []string{prot, real} {
		if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := config.OpenStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := logger.Open(filepath.Join(os.TempDir(), "mihanisec-test-log"), "info")
	if err != nil {
		t.Fatal(err)
	}
	q, err := quarantine.Open(filepath.Join(dir, "quarantine"), 1<<20, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	e := New(cfg, log, q, nil)

	got := 0
	e.AddSink(sinkFunc(func(v events.Verdict) { got++ }))

	cfg.Update(func(c *config.Config) {
		c.RealTime.OnMalware = config.ActionAutoQuarantine
	})

	e.ApplyScanResult(&ScanResult{
		Verdicts: []events.Verdict{
			{Name: "t1", Path: prot, Threat: events.ThreatMalware, Severity: events.SeverityHigh},
			{Name: "t2", Path: real, Threat: events.ThreatMalware, Severity: events.SeverityHigh},
		},
	})

	if got != 1 {
		t.Errorf("only the real malware should be reported, got %d verdicts", got)
	}
	if n := q.Count(); n != 1 {
		t.Errorf("expected exactly 1 quarantined entry, got %d", n)
	}
	if _, err := os.Stat(prot); err != nil {
		t.Errorf("onlinefix.dll must remain in place, err=%v", err)
	}
	if _, err := os.Stat(real); err == nil {
		t.Errorf("real malware should have been moved to quarantine")
	}
	entries := q.List()
	if len(entries) == 1 && strings.Contains(strings.ToLower(entries[0].OriginalPath), "onlinefix") {
		t.Errorf("onlinefix.dll must never be quarantined: %+v", entries[0])
	}
}

type sinkFunc func(v events.Verdict)

func (f sinkFunc) OnVerdict(v events.Verdict) { f(v) }
