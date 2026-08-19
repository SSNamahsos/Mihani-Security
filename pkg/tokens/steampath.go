package tokens

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func steamInstallDirs() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		key := strings.ToLower(p)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}

	for _, src := range []struct {
		root registry.Key
		path string
		name string
	}{
		{registry.CURRENT_USER, `Software\Valve\Steam`, "SteamPath"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Valve\Steam`, "InstallPath"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Valve\Steam`, "InstallPath"},
	} {
		k, err := registry.OpenKey(src.root, src.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue(src.name)
		k.Close()
		if err == nil {
			add(filepath.FromSlash(v))
		}
	}

	for _, envKey := range []string{"ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"} {
		if base, _ := envDir(envKey); base != "" {
			add(filepath.Join(base, "Steam"))
		}
	}
	if la, _ := envDir("LOCALAPPDATA"); la != "" {
		add(filepath.Join(la, "Steam"))
	}
	if pd, _ := envDir("ProgramData"); pd != "" {
		add(filepath.Join(pd, "Steam"))
	}
	if home, _ := userHomeDir(); home != "" {
		add(filepath.Join(home, ".steam"))
		add(filepath.Join(home, ".local", "share", "Steam"))
	}

	for _, drive := range []string{"D:", "E:", "F:"} {
		add(filepath.Join(drive+`\`, "Steam"))
		add(filepath.Join(drive+`\`, "Program Files (x86)", "Steam"))
		add(filepath.Join(drive+`\`, "SteamLibrary"))
	}
	return out
}
