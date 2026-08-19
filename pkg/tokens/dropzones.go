package tokens

import (
	"os"
	"path/filepath"
	"strings"
)

func DropZones() []string {
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

	for _, home := range Profiles() {
		if home == "" {
			continue
		}
		add(filepath.Join(home, "Downloads"))
		add(filepath.Join(home, "Desktop"))
		add(filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
		add(filepath.Join(home, "AppData", "Local", "Temp"))
	}
	if tmp := os.TempDir(); tmp != "" {
		add(tmp)
	}
	return out
}
