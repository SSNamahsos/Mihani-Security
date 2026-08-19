package monitor

import (
	"sync"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

var (
	injectMu   sync.Mutex
	injectSeen = map[string]time.Time{}
)

func scanThreadInjection(sink Sink) {
	procs, err := listProcesses()
	if err != nil {
		return
	}
	now := time.Now()
	for _, p := range procs {
		if p.PID <= 4 || tokens.IsSystemOwner(p.Name) {
			continue
		}
		threads := winapi.ThreadStartAddresses(p.PID)
		if len(threads) == 0 {
			continue
		}
		for _, t := range threads {
			if !winapi.UnbackedThreadAddress(p.PID, t.StartAddress) {
				continue
			}
			key := intKey(p.PID) + "|" + intKey(t.ThreadID) + "|" + hexAddr(t.StartAddress)
			injectMu.Lock()
			last, ok := injectSeen[key]
			if ok && now.Sub(last) < reportInterval {
				injectMu.Unlock()
				continue
			}
			injectSeen[key] = now
			if len(injectSeen) > 4096 {
				for k, t2 := range injectSeen {
					if now.Sub(t2) > reportInterval {
						delete(injectSeen, k)
					}
				}
			}
			injectMu.Unlock()

			proc := p
			sink.Handle(events.Event{
				ID:      newID(),
				Time:    time.Now(),
				Kind:    events.EventThreadInject,
				Path:    p.Path,
				Access:  "start=0x" + hexAddr(t.StartAddress),
				Process: &proc,
				Source:  "threads",
			})
		}
	}
}

func hexAddr(a uintptr) string {
	const digits = "0123456789abcdef"
	var b [16]byte
	i := len(b)
	for a > 0 {
		i--
		b[i] = digits[a&0xF]
		a >>= 4
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}
