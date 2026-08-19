package detector

import (
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

func terminateProcess(pid uint32) error {
	return winapi.TerminateProcess(pid)
}

func isSystemProcessName(name string) bool {
	return tokens.IsSystemOwner(name)
}
