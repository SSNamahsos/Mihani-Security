package tokens

import (
	"os"
	"path/filepath"
	"runtime"
)

func userHomeDir() (string, error) {
	if runtime.GOOS == "windows" {
		if h := os.Getenv("USERPROFILE"); h != "" {
			return h, nil
		}
		if h := os.Getenv("HOME"); h != "" {
			return h, nil
		}
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		if drive != "" && path != "" {
			return filepath.Join(drive, path), nil
		}
		return "", nil
	}
	return os.UserHomeDir()
}

func Profiles() []string {
	homes, err := profileHomes()
	if err == nil && len(homes) > 0 {
		return homes
	}
	if h, err := userHomeDir(); err == nil && h != "" {
		return []string{h}
	}
	return nil
}
