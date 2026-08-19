package tokens

import (
	"path/filepath"
	"strings"
)

var ownersByApp = map[string][]string{
	"steam": {
		"steam.exe", "steamwebhelper.exe", "steamservice.exe",
		"steamerrorreporter.exe", "steamerrorreporter64.exe",
		"gameoverlayui.exe", "gameoverlayhelper.exe", "streaming_client.exe",
	},
	"discord": {
		"discord.exe", "discordcanary.exe", "discordptb.exe",
		"discorddevelopment.exe", "update.exe", "squirrel.exe",
	},
	"telegram": {"telegram.exe", "telegramdesktop.exe", "updater.exe"},
	"browser": {
		"chrome.exe", "msedge.exe", "msedgewebview2.exe", "brave.exe",
		"firefox.exe", "opera.exe", "opera_crashreporter.exe", "operagx.exe",
		"launcher.exe", "vivaldi.exe", "chromium.exe", "thorium.exe",
	},
}

var systemOwners = map[string]bool{
	"explorer.exe": true, "searchindexer.exe": true, "searchprotocolhost.exe": true,
	"searchfilterhost.exe": true, "svchost.exe": true, "services.exe": true,
	"wmiprvse.exe": true, "trustedinstaller.exe": true, "tiworker.exe": true,
	"msmpeng.exe": true, "mpcmdrun.exe": true, "nissrv.exe": true,
	"securityhealthservice.exe": true, "defenderui.exe": true,
	"backgroundtaskhost.exe": true, "runtimebroker.exe": true,
	"csrss.exe": true, "lsass.exe": true, "smss.exe": true, "wininit.exe": true,
	"dllhost.exe": true, "sihost.exe": true, "taskhostw.exe": true,
	"onedrive.exe": true, "filecoauth.exe": true, "filesyncconfig.exe": true,
	"mihanisecurity.exe": true, "mihanisecurity-service.exe": true,
}

func IsSystemOwner(name string) bool {
	return systemOwners[strings.ToLower(filepath.Base(name))]
}

func IsLegitimateOwner(app, pattern, procName string) bool {
	base := strings.ToLower(filepath.Base(procName))
	if base == "" {
		return false
	}
	if IsSystemOwner(base) {
		return true
	}

	if pattern != "" && strings.Contains(base, strings.ToLower(pattern)) {
		return true
	}
	for _, owner := range ownersByApp[strings.ToLower(app)] {
		if base == owner {
			return true
		}
	}
	return false
}

func LegitimateOwnersFor(app string) []string {
	out := append([]string(nil), ownersByApp[strings.ToLower(app)]...)
	return out
}

func AppOf(path string) string {
	if sf := MatchSensitive(path); sf != nil {
		return sf.App
	}
	return ""
}

func IsKnownOwnerName(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if base == "" {
		return false
	}
	for _, owners := range ownersByApp {
		for _, o := range owners {
			if base == o {
				return true
			}
		}
	}
	return false
}

var untrustedFragments = []string{
	`\downloads\`, `\temp\`, `\tmp\`, `\$recycle.bin\`,
	`\appdata\local\temp\`, `\desktop\`, `\onedrive\downloads\`,
	`\public\downloads\`,
}

func UntrustedLocation(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.Clean(path))
	for _, frag := range untrustedFragments {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

func IsTrustedApp(name, path string) bool {
	if IsSystemOwner(name) {
		return true
	}
	return IsKnownOwnerName(name) && !UntrustedLocation(path)
}
