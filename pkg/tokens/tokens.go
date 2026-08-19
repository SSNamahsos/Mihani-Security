package tokens

import (
	"os"
	"path/filepath"
	"strings"
)

type SensitiveFile struct {
	App         string
	Path        string
	Pattern     string
	Description string
	Severity    string
	IsDirectory bool
}

var sensitivePaths = func() []SensitiveFile {
	mk := func(app, path, pattern, desc, sev string, isDir bool) SensitiveFile {
		return SensitiveFile{App: app, Path: filepath.Clean(path), Pattern: strings.ToLower(pattern), Description: desc, Severity: sev, IsDirectory: isDir}
	}

	var out []SensitiveFile

	for _, home := range Profiles() {
		if home == "" {
			continue
		}
		appData := filepath.Join(home, "AppData", "Roaming")
		localAppData := filepath.Join(home, "AppData", "Local")

		discordRoots := []string{
			filepath.Join(appData, "discord"),
			filepath.Join(appData, "discordcanary"),
			filepath.Join(appData, "discordptb"),
			filepath.Join(appData, "discorddevelopment"),
		}
		for _, d := range discordRoots {
			out = append(out,
				mk("discord", filepath.Join(d, "Local Storage", "leveldb"), "discord", "Discord LevelDB token store", "critical", true),
				mk("discord", filepath.Join(d, "Local Storage"), "discord", "Discord local storage", "critical", true),
				mk("discord", filepath.Join(d, "Token"), "discord", "Discord encrypted token blob", "critical", true),
				mk("discord", d, "discord", "Discord app data", "high", true),
			)
		}

		browserRoots := []struct {
			App, Root string
		}{
			{"chrome", filepath.Join(localAppData, "Google", "Chrome", "User Data")},
			{"edge", filepath.Join(localAppData, "Microsoft", "Edge", "User Data")},
			{"brave", filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data")},
			{"opera", filepath.Join(appData, "Opera Software", "Opera Stable")},
			{"operagx", filepath.Join(appData, "Opera Software", "Opera GX Stable")},
			{"vivaldi", filepath.Join(localAppData, "Vivaldi", "User Data")},
			{"chromium", filepath.Join(localAppData, "Chromium", "User Data")},
			{"firefox", filepath.Join(appData, "Mozilla", "Firefox", "Profiles")},
		}
		for _, b := range browserRoots {
			if b.Root == "" {
				continue
			}
			out = append(out,
				mk("browser", b.Root, b.App, b.App+" profile data", "high", true),
			)
		}

		out = append(out,
			mk("telegram", filepath.Join(appData, "Telegram Desktop", "tdata"), "telegram", "Telegram session data", "high", true),
		)
	}

	for _, d := range steamInstallDirs() {
		if d == "" {
			continue
		}
		out = append(out,
			mk("steam", filepath.Join(d, "config", "loginusers.vdf"), "steam", "Steam login users", "critical", false),
			mk("steam", filepath.Join(d, "config", "config.vdf"), "steam", "Steam config + auth ticket", "critical", false),
			mk("steam", filepath.Join(d, "config"), "steam", "Steam config dir", "critical", true),
			mk("steam", filepath.Join(d, "userdata"), "steam", "Steam userdata dir", "high", true),
		)
	}

	return out
}()

func All() []SensitiveFile { return sensitivePaths }

func MatchSensitive(path string) *SensitiveFile {
	if path == "" {
		return nil
	}
	clean := filepath.Clean(path)
	lower := strings.ToLower(clean)
	for i := range sensitivePaths {
		s := &sensitivePaths[i]
		if s.IsDirectory {
			if strings.HasPrefix(lower, strings.ToLower(s.Path)+string(filepath.Separator)) || lower == strings.ToLower(s.Path) {
				return s
			}
		} else {
			if lower == strings.ToLower(s.Path) {
				return s
			}
		}
	}
	return nil
}

var TokenRegexes = []TokenPattern{
	{
		Name:        "Discord token (classic)",
		Regex:       `[\w-]{24,26}\.[\w-]{6,7}\.[\w-]{27,}`,
		Description: "Classic Discord user token (3 base64 segments)",
		Severity:    "critical",
	},
	{
		Name:        "Discord token (mfa.)",
		Regex:       `mfa\.[\w-]{84,}`,
		Description: "Discord MFA token",
		Severity:    "critical",
	},
	{
		Name:        "Steam auth ticket",
		Regex:       `steamAuthTicket[\s"':=]+([A-Za-z0-9+/=]{40,})`,
		Description: "Steam session auth ticket string",
		Severity:    "critical",
	},
	{
		Name:        "Steam login token",
		Regex:       `eyA[\w+/=]{40,}`,
		Description: "Steam login token blob",
		Severity:    "critical",
	},
}

type TokenPattern struct {
	Name        string `json:"name"`
	Regex       string `json:"regex"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func IsWhitelistedProcess(name string) bool {
	if name == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(name))
	allowed := map[string]bool{
		"steam.exe": true, "steamwebhelper.exe": true, "steamservice.exe": true, "gameoverlayhelper.exe": true,
		"discord.exe": true, "discordcanary.exe": true, "discordptb.exe": true, "discorddevelopment.exe": true,
		"msedge.exe": true, "chrome.exe": true, "brave.exe": true, "firefox.exe": true,
		"opera.exe": true, "operagx.exe": true, "vivaldi.exe": true, "chromium.exe": true,
		"telegram.exe": true,
	}
	return allowed[base]
}

func envDir(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", nil
	}
	return v, nil
}
