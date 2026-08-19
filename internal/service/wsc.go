package service

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const wscAvGUID = "{4F2E3B7A-9C1D-4E5F-8A6B-2D3E4F5A6B7C}"

const (
	wscProviderPath = `SOFTWARE\Microsoft\Security Center\Provider\Av`
	wscActivePath   = `SOFTWARE\Microsoft\Security Center\ActiveSvc\Av`
)

func wscRegistered() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, wscProviderPath+`\`+wscAvGUID, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("DisplayName")
	return err == nil
}

func wscSetRegistered(enabled bool) error {
	if !enabled {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, wscActivePath+`\`+wscAvGUID)
		return registry.DeleteKey(registry.LOCAL_MACHINE, wscProviderPath+`\`+wscAvGUID)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	values := map[string]any{
		"DisplayName":              "MihaniSecurity",
		"ProductState":             uint32(0x10010),
		"PathToSignedProductExe":   filepath.Join(dir, "mihanisecurity-service.exe"),
		"PathToSignedReportingExe": filepath.Join(dir, "MihaniSecurity.exe"),
	}
	for _, root := range []string{wscProviderPath, wscActivePath} {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, root+`\`+wscAvGUID, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("create %s: %w", root, err)
		}
		for name, v := range values {
			switch t := v.(type) {
			case string:
				if err := k.SetStringValue(name, t); err != nil {
					k.Close()
					return fmt.Errorf("set %s/%s: %w", root, name, err)
				}
			case uint32:
				if err := k.SetDWordValue(name, t); err != nil {
					k.Close()
					return fmt.Errorf("set %s/%s: %w", root, name, err)
				}
			}
		}
		k.Close()
	}
	return nil
}
