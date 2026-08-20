package tokens

import (
	"strings"

	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

var ownerPublishers = map[string][]string{
	"discord":  {"discord inc", "discord, inc", "discord inc."},
	"steam":    {"valve corp", "valve corporation", "valve"},
	"chrome":   {"google llc", "google inc", "google llc (google inc)"},
	"edge":     {"microsoft corporation", "microsoft corp"},
	"firefox":  {"mozilla corporation"},
	"brave":    {"brave software, inc", "brave software inc"},
	"opera":    {"opera software as", "opera norway as", "opera software"},
	"vivaldi":  {"vivaldi technologies as", "vivaldi technologies"},
	"telegram": {"telegram fz-llc", "telegram messenger llp", "telegram llp"},
}

func ownerForName(name string) string {
	base := strings.ToLower(strings.TrimSpace(name))
	switch base {
	case "steam.exe", "steamwebhelper.exe", "steamservice.exe", "gameoverlayhelper.exe":
		return "steam"
	case "discord.exe", "discordcanary.exe", "discordptb.exe", "discorddevelopment.exe":
		return "discord"
	case "msedge.exe":
		return "edge"
	case "chrome.exe", "chromium.exe":
		return "chrome"
	case "firefox.exe":
		return "firefox"
	case "brave.exe":
		return "brave"
	case "opera.exe", "operagx.exe":
		return "opera"
	case "vivaldi.exe":
		return "vivaldi"
	case "telegram.exe":
		return "telegram"
	}
	return ""
}

func publisherMatches(pub string, allowed []string) bool {
	p := strings.ToLower(strings.TrimSpace(pub))
	p = strings.TrimSuffix(p, ".")
	if p == "" {
		return false
	}
	for _, a := range allowed {
		if p == a {
			return true
		}
	}
	return false
}

func TrustedOwnerProcess(name, exePath string) (bool, string) {
	owner := ownerForName(name)
	if owner == "" {
		return false, "unknown owner"
	}
	allowed := ownerPublishers[owner]
	if len(allowed) == 0 {
		return false, "no publisher allowlist for owner " + owner
	}
	if exePath == "" {
		return false, "missing process image path"
	}
	if err := winapi.VerifySignedFile(exePath); err != nil {
		return false, "signature verification failed"
	}
	pub, err := winapi.SignedPublisher(exePath)
	if err != nil {
		return false, "publisher unavailable: " + err.Error()
	}
	if !publisherMatches(pub, allowed) {
		return false, "publisher mismatch: " + pub
	}
	return true, "verified publisher " + pub
}
