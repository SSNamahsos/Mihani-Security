package monitor

import (
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

const (
	scanBudget = 6 * time.Second

	maxHandlesPerProc = 3072

	reportInterval = 5 * time.Minute
)

var (
	reportedMu sync.Mutex
	reported   = map[string]time.Time{}
)

func alreadyReported(key string) bool {
	now := time.Now()
	reportedMu.Lock()
	defer reportedMu.Unlock()
	if t, ok := reported[key]; ok && now.Sub(t) < reportInterval {
		return true
	}
	reported[key] = now
	if len(reported) > 8192 {
		for k, t := range reported {
			if now.Sub(t) > reportInterval {
				delete(reported, k)
			}
		}
	}
	return false
}

func scanHandles(sink Sink) {
	deadline := time.Now().Add(scanBudget)

	procs, err := listProcesses()
	if err != nil {
		return
	}
	self := uint32(syscall.Getpid())
	byPID := make(map[uint32]events.Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}

	handles, err := winapi.ListHandles()
	if err != nil {
		return
	}

	grouped := make(map[uint32][]winapi.HandleEntry, 256)
	for _, h := range handles {
		if h.PID == self || h.PID <= 4 {
			continue
		}
		if !winapi.IsFileTypeIndex(h.ObjectTypeIdx) {
			continue
		}
		if isPipeLikeAccess(h.GrantedAccess) {
			continue
		}
		p, ok := byPID[h.PID]
		if !ok || tokens.IsTrustedApp(p.Name, p.Path) {
			continue
		}
		if len(grouped[h.PID]) >= maxHandlesPerProc {
			continue
		}
		grouped[h.PID] = append(grouped[h.PID], h)
	}

	for pid, entries := range grouped {
		if time.Now().After(deadline) {
			return
		}
		inspectProcessHandles(sink, byPID[pid], entries, deadline)
	}
}

func inspectProcessHandles(sink Sink, proc events.Process, entries []winapi.HandleEntry, deadline time.Time) {
	ph, err := winapi.OpenProcess(winapi.PROCESS_DUP_HANDLE|winapi.PROCESS_QUERY_LIMITED_INFORMATION, proc.PID)
	if err != nil {

		return
	}
	defer winapi.CloseHandle(ph)

	seen := make(map[uintptr]bool, len(entries))
	for _, h := range entries {
		if time.Now().After(deadline) {
			return
		}
		if seen[h.Handle] {
			continue
		}
		seen[h.Handle] = true

		name, err := winapi.DupHandleName(ph, h.Handle)
		if err != nil || name == "" {
			continue
		}
		dos := winapi.DeviceToDOS(name)
		if !strings.Contains(dos, `:\`) {
			continue
		}
		sf := tokens.MatchSensitive(dos)
		if sf == nil {
			continue
		}
		if alreadyReported(intKey(proc.PID) + "|" + strings.ToLower(dos)) {
			continue
		}
		p := proc
		if p.Name == "" {
			p.Name = filepath.Base(p.Path)
		}
		sink.Handle(events.Event{
			ID:      newID(),
			Time:    time.Now(),
			Kind:    events.EventHandleOpen,
			Path:    dos,
			Access:  accessString(h.GrantedAccess),
			Process: &p,
			Source:  "handles",
		})

		flagSuspect(proc.PID)
	}
}

func isPipeLikeAccess(access uint32) bool {
	switch access {
	case 0x0012019F, 0x001A019F, 0x00120189, 0x00100000:
		return true
	}
	return false
}

func accessString(access uint32) string {
	const (
		fileReadData      = 0x0001
		fileWriteData     = 0x0002
		fileAppendData    = 0x0004
		fileReadEA        = 0x0008
		fileWriteEA       = 0x0010
		fileExecute       = 0x0020
		fileDeleteChild   = 0x0040
		fileReadAttrs     = 0x0080
		fileWriteAttrs    = 0x0100
		deleteAccess      = 0x00010000
		genericReadAccess = 0x80000000
	)
	var parts []string
	add := func(bit uint32, label string) {
		if access&bit != 0 {
			parts = append(parts, label)
		}
	}
	add(fileReadData|genericReadAccess, "read data")
	add(fileWriteData, "write data")
	add(fileAppendData, "append")
	add(fileExecute, "execute")
	add(deleteAccess|fileDeleteChild, "delete")
	add(fileReadEA|fileReadAttrs, "read attributes")
	add(fileWriteEA|fileWriteAttrs, "write attributes")
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func intKey(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
