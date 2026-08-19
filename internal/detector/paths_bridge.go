package detector

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
)

func SensitivePaths() []string {
	out := make([]string, 0, 64)
	seen := map[string]bool{}
	add := func(p string) {
		if strings.TrimSpace(p) == "" {
			return
		}
		key := strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, filepath.Clean(p))
	}

	for _, s := range tokens.All() {
		if s.IsDirectory {
			add(s.Path)
			continue
		}
		add(filepath.Dir(s.Path))
	}
	for _, p := range DropZones() {
		add(p)
	}
	return out
}

func DropZones() []string { return tokens.DropZones() }

func ExistingPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}
