package tokens

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func profileHomes() ([]string, error) {
	const keyPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string
	for _, sid := range sids {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath+`\`+sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dir, _, err := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if err != nil || strings.TrimSpace(dir) == "" {
			continue
		}
		dir = filepath.Clean(dir)
		if isSystemProfile(dir) {
			continue
		}
		key := strings.ToLower(dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dir)
	}
	return out, nil
}

func isSystemProfile(dir string) bool {
	lower := strings.ToLower(dir)
	if strings.Contains(lower, "systemprofile") ||
		strings.Contains(lower, "localservice") ||
		strings.Contains(lower, "networkservice") {
		return true
	}

	return strings.HasPrefix(lower, `c:\windows\`)
}
