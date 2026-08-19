package monitor

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

var tokenRes = func() []struct {
	Name string
	RE   *regexp.Regexp
} {
	var out []struct {
		Name string
		RE   *regexp.Regexp
	}
	for _, p := range tokens.TokenRegexes {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		out = append(out, struct {
			Name string
			RE   *regexp.Regexp
		}{p.Name, re})
	}
	return out
}()

var (
	memScanMu sync.Mutex
	memScaned = map[uint32]time.Time{}
)

const memRescan = 10 * time.Minute

const suspectRescan = 30 * time.Second

var (
	suspectMu sync.Mutex
	suspects  = map[uint32]time.Time{}
)

func flagSuspect(pid uint32) {
	if pid <= 4 {
		return
	}
	suspectMu.Lock()
	defer suspectMu.Unlock()
	suspects[pid] = time.Now()
}

func drainSuspects() []uint32 {
	now := time.Now()
	suspectMu.Lock()
	defer suspectMu.Unlock()
	if len(suspects) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(suspects))
	for pid, t := range suspects {
		if now.Sub(t) <= memRescan {
			out = append(out, pid)
		}
		delete(suspects, pid)
	}
	return out
}

func scanMemoryForTokens(sink Sink, extra []uint32) {
	procs, err := listProcesses()
	if err != nil {
		return
	}
	want := map[uint32]bool{}
	for _, pid := range extra {
		want[pid] = true
	}

	now := time.Now()
	for _, p := range procs {
		if p.PID <= 4 || tokens.IsSystemOwner(p.Name) {
			continue
		}
		if !want[p.PID] && !tokens.UntrustedLocation(p.Path) {
			continue
		}
		memScanMu.Lock()
		last, ok := memScaned[p.PID]

		window := memRescan
		if want[p.PID] {
			window = suspectRescan
		}
		if ok && now.Sub(last) < window {
			memScanMu.Unlock()
			continue
		}
		memScaned[p.PID] = now
		if len(memScaned) > 4096 {
			for pid, t := range memScaned {
				if now.Sub(t) > memRescan {
					delete(memScaned, pid)
				}
			}
		}
		memScanMu.Unlock()

		scanOneProcess(sink, p)
	}
}

func scanOneProcess(sink Sink, p events.Process) {
	var (
		matchName string
		sample    string
	)
	_ = winapi.ScanProcessMemory(p.PID, winapi.DefaultMemoryScan(), func(_ uintptr, chunk []byte) bool {

		hay := string(chunk)
		for _, t := range tokenRes {
			if m := t.RE.FindString(hay); m != "" {
				matchName, sample = t.Name, m
				return false
			}
		}
		return true
	})
	if matchName == "" {
		return
	}
	proc := p
	sink.Handle(events.Event{
		ID:      newID(),
		Time:    time.Now(),
		Kind:    events.EventTokenString,
		Path:    p.Path,
		Match:   matchName,
		Access:  "memory: " + redactToken(sample),
		Process: &proc,
		Source:  "memory",
	})
}

func redactToken(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "…" + s[len(s)-4:] + " (" + intKey(uint32(len(s))) + " chars)"
}

var (
	moduleMu   sync.Mutex
	moduleSeen = map[string]time.Time{}
)

func scanModules(sink Sink) {
	procs, err := listProcesses()
	if err != nil {
		return
	}
	now := time.Now()
	for _, p := range procs {
		if p.PID <= 4 || tokens.IsSystemOwner(p.Name) {
			continue
		}
		mods, err := winapi.ListModules(p.PID)
		if err != nil {
			continue
		}
		for _, m := range mods {
			if !suspiciousModule(m, p.Path) {
				continue
			}
			key := intKey(p.PID) + "|" + strings.ToLower(m)
			moduleMu.Lock()
			last, ok := moduleSeen[key]
			if ok && now.Sub(last) < reportInterval {
				moduleMu.Unlock()
				continue
			}
			moduleSeen[key] = now
			if len(moduleSeen) > 8192 {
				for k, t := range moduleSeen {
					if now.Sub(t) > reportInterval {
						delete(moduleSeen, k)
					}
				}
			}
			moduleMu.Unlock()

			proc := p
			sink.Handle(events.Event{
				ID:      newID(),
				Time:    time.Now(),
				Kind:    events.EventModuleLoad,
				Path:    p.Path,
				Module:  m,
				Process: &proc,
				Source:  "modules",
			})
		}
	}
}

func suspiciousModule(module, imagePath string) bool {
	if module == "" || !tokens.UntrustedLocation(module) {
		return false
	}
	if imagePath != "" {
		dir := strings.ToLower(imagePath)
		if idx := strings.LastIndex(dir, `\`); idx > 0 {
			dir = dir[:idx+1]
			if strings.HasPrefix(strings.ToLower(module), dir) {
				return false
			}
		}
	}
	return true
}
