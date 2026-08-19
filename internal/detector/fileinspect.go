package detector

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
)

const maxInspectBytes = 32 << 20

var credentialStoreIndicators = []struct{ Needle, Label string }{
	{`loginusers.vdf`, "Steam login store"},
	{`config.vdf`, "Steam config/auth ticket store"},
	{`ssfn`, "Steam sentry file"},
	{`local storage\leveldb`, "Discord token LevelDB"},
	{`local storage/leveldb`, "Discord token LevelDB"},
	{`leveldb`, "LevelDB token store"},
	{`discord\local storage`, "Discord local storage"},
	{`\discord\`, "Discord app data"},
	{`\discordcanary\`, "Discord Canary app data"},
	{`\steam\config`, "Steam config directory"},
	{`login cookies`, "browser session cookies"},
	{`cookies.sqlite`, "Firefox cookie store"},
	{`network\cookies`, "Chromium cookie store"},
	{`local state`, "Chromium master key store"},
	{`os_crypt`, "Chromium DPAPI master key"},
	{`tdata`, "Telegram session store"},
}

var exfilIndicators = []struct{ Needle, Label string }{
	{`discord.com/api/webhooks`, "Discord webhook"},
	{`discordapp.com/api/webhooks`, "Discord webhook"},
	{`canary.discord.com/api/webhooks`, "Discord webhook"},
	{`api.telegram.org/bot`, "Telegram bot API"},
	{`pastebin.com/api`, "Pastebin upload"},
	{`gofile.io/uploadfile`, "GoFile upload"},
	{`anonfiles.com/api`, "AnonFiles upload"},
	{`file.io`, "file.io upload"},
	{`transfer.sh`, "transfer.sh upload"},
	{`ngrok.io`, "ngrok tunnel"},
	{`webhook.site`, "webhook.site collector"},
	{`/api/v9/users/@me`, "Discord account API"},
	{`steamcommunity.com/tradeoffer`, "Steam trade offer endpoint"},
	{`steamcommunity.com/gid`, "Steam group messaging"},
	{`api.steampowered.com/isteamuser`, "Steam user API"},
}

var evasionIndicators = []struct{ Needle, Label string }{
	{`amsi.dll`, "AMSI bypass surface"},
	{`amsiscanbuffer`, "AMSI patching"},
	{`virtualallocex`, "remote memory allocation"},
	{`createremotethread`, "remote thread creation"},
	{`writeprocessmemory`, "remote memory write"},
	{`setwindowshookex`, "global hook installation"},
	{`schtasks /create`, "scheduled-task persistence"},
	{`reg add hkcu\software\microsoft\windows\currentversion\run`, "Run key persistence"},
	{`attrib +h +s`, "file hiding"},
	{`taskkill /f /im`, "defensive process kill"},
	{`vssadmin delete shadows`, "shadow copy deletion"},
	{`add-mppreference -exclusionpath`, "Defender exclusion"},
}

type FileFinding struct {
	Category string
	Label    string
	Needle   string
}

func InspectFile(path string) []FileFinding {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() == 0 || fi.Size() > maxInspectBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return inspectBytes(data)
}

func inspectBytes(data []byte) []FileFinding {

	hay := strings.ToLower(string(data)) + "\x00" + strings.ToLower(squashUTF16(data))

	var out []FileFinding
	seen := map[string]bool{}
	scan := func(cat string, table []struct{ Needle, Label string }) {
		for _, ind := range table {
			if seen[cat+ind.Label] {
				continue
			}
			if strings.Contains(hay, ind.Needle) {
				seen[cat+ind.Label] = true
				out = append(out, FileFinding{Category: cat, Label: ind.Label, Needle: ind.Needle})
			}
		}
	}
	scan("credential_store", credentialStoreIndicators)
	scan("exfil", exfilIndicators)
	scan("evasion", evasionIndicators)

	for _, re := range TokenRegex {
		if loc := re.FindString(hay); loc != "" {
			out = append(out, FileFinding{Category: "credential_store", Label: "embedded credential token", Needle: truncateStr(loc, 24)})
			break
		}
	}
	return out
}

func squashUTF16(data []byte) string {
	var b strings.Builder
	b.Grow(len(data) / 2)
	for i := 0; i+1 < len(data); i += 2 {
		if data[i+1] == 0 && data[i] != 0 {
			b.WriteByte(data[i])
		}
	}
	return b.String()
}

func ScoreFindings(path string, proc *events.Process, findings []FileFinding) *events.Verdict {
	var creds, exfil, evade []FileFinding
	for _, f := range findings {
		switch f.Category {
		case "credential_store":
			creds = append(creds, f)
		case "exfil":
			exfil = append(exfil, f)
		case "evasion":
			evade = append(evade, f)
		}
	}
	if len(creds) == 0 && len(exfil) == 0 {
		return nil
	}

	evidence := make([]string, 0, len(findings))
	for _, f := range findings {
		evidence = append(evidence, f.Category+": "+f.Label)
	}

	switch {
	case len(creds) > 0 && len(exfil) > 0:
		return &events.Verdict{
			ID:          newID(),
			Time:        time.Now(),
			Severity:    events.SeverityCritical,
			Threat:      events.ThreatTokenTheft,
			Name:        "Credential/session stealer",
			Description: "File reads " + creds[0].Label + " and can transmit it via " + exfil[0].Label + ". This is the pattern used by fake gift-card and giveaway tools to hijack Steam and Discord sessions.",
			Path:        path,
			Process:     proc,
			Evidence:    evidence,
			Action:      events.ActionQuarantine,
			Source:      "static",
		}
	case len(creds) >= 3:
		return &events.Verdict{
			ID:          newID(),
			Time:        time.Now(),
			Severity:    events.SeverityHigh,
			Threat:      events.ThreatTokenTheft,
			Name:        "Credential store enumeration",
			Description: "File references several protected credential stores without being the application that owns them.",
			Path:        path,
			Process:     proc,
			Evidence:    evidence,
			Action:      events.ActionQuarantine,
			Source:      "static",
		}
	case len(exfil) > 0 && len(evade) > 0:
		return &events.Verdict{
			ID:          newID(),
			Time:        time.Now(),
			Severity:    events.SeverityHigh,
			Threat:      events.ThreatSuspicious,
			Name:        "Suspicious uploader with evasion",
			Description: "File combines a hard-coded upload endpoint (" + exfil[0].Label + ") with " + evade[0].Label + ".",
			Path:        path,
			Process:     proc,
			Evidence:    evidence,
			Action:      events.ActionAlert,
			Source:      "static",
		}
	case len(creds) > 0 && len(evade) > 0:
		return &events.Verdict{
			ID:          newID(),
			Time:        time.Now(),
			Severity:    events.SeverityMedium,
			Threat:      events.ThreatSuspicious,
			Name:        "Credential store access with evasion",
			Description: "File references " + creds[0].Label + " alongside " + evade[0].Label + ".",
			Path:        path,
			Process:     proc,
			Evidence:    evidence,
			Action:      events.ActionAlert,
			Source:      "static",
		}
	}
	return nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type StaticFiles struct{}

func NewStaticFiles() *StaticFiles { return &StaticFiles{} }

func (d *StaticFiles) Name() string { return "static" }

func (d *StaticFiles) Evaluate(e events.Event) []events.Verdict {
	switch e.Kind {
	case events.EventFileCreate, events.EventFileModify, events.EventFileRename:
	default:
		return nil
	}
	if e.Path == "" || !scannableExt(filepath.Base(e.Path)) {
		return nil
	}

	v := ScoreFindings(e.Path, e.Process, InspectFile(e.Path))
	if v == nil {
		return nil
	}
	return []events.Verdict{*v}
}
