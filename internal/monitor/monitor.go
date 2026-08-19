package monitor

import (
	"context"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
)

type Sink interface {
	Handle(e events.Event)
}

type FsMonitor struct {
	paths []string
	debug bool

	Log func(format string, args ...any)
}

func NewFsMonitor(paths []string) *FsMonitor { return &FsMonitor{paths: paths} }

func (m *FsMonitor) Start(ctx context.Context, sink Sink) error {
	w, err := newWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	for _, p := range m.paths {
		if err := w.Add(p); err != nil {

			if m.Log != nil {
				m.Log("fs watch %q failed: %v", p, err)
			}
			continue
		}
		if m.Log != nil {
			m.Log("fs watch %q added", p)
		}
	}

	for _, fallback := range defaultWatchPaths() {
		if err := w.Add(fallback); err != nil {
			if m.Log != nil {
				m.Log("fs watch %q failed: %v", fallback, err)
			}
			continue
		}
		if m.Log != nil {
			m.Log("fs watch %q added", fallback)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if m.debug && m.Log != nil {
				m.Log("fs event %s %s", ev.Op, ev.Name)
			}
			sink.Handle(events.Event{
				ID:     newID(),
				Time:   time.Now(),
				Kind:   classify(ev.Op),
				Path:   ev.Name,
				Source: "fs",
			})
		case _, ok := <-w.Errors:
			if !ok {
				return nil
			}
		}
	}
}

type ProcMonitor struct {
	Interval time.Duration
}

func (m *ProcMonitor) Start(ctx context.Context, sink Sink) error {
	if m.Interval <= 0 {
		m.Interval = 1500 * time.Millisecond
	}
	known := map[uint32]struct{}{}
	first := true
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			procs, err := listProcesses()
			if err != nil {
				continue
			}
			now := map[uint32]struct{}{}
			for _, p := range procs {
				now[p.PID] = struct{}{}
				if first {
					known[p.PID] = struct{}{}
					continue
				}
				if _, ok := known[p.PID]; !ok {
					sink.Handle(events.Event{
						ID:   newID(),
						Time: time.Now(),
						Kind: events.EventProcessStart,
						Process: &events.Process{
							PID:       p.PID,
							PPID:      p.PPID,
							Name:      p.Name,
							Path:      p.Path,
							StartedAt: time.Now(),
						},
						Source: "proc",
					})
				}
			}
			if !first {
				for pid := range known {
					if _, ok := now[pid]; !ok {
						sink.Handle(events.Event{
							ID:      newID(),
							Time:    time.Now(),
							Kind:    events.EventProcessStop,
							Process: &events.Process{PID: pid},
							Source:  "proc",
						})
					}
				}
			}
			known = now
			first = false
		}
	}
}

type HandleMonitor struct {
	Interval time.Duration
}

func (m *HandleMonitor) Start(ctx context.Context, sink Sink) error {
	if m.Interval <= 0 {
		m.Interval = 8 * time.Second
	}
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scanHandles(sink)
		}
	}
}

type RegistryMonitor struct {
	Keys []RegistryKey
}

type RegistryKey struct {
	Root string
	Path string
}

func (m *RegistryMonitor) Start(ctx context.Context, sink Sink) error {
	if len(m.Keys) == 0 {
		m.Keys = defaultRegistryKeys()
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, k := range m.Keys {
		go watchKey(cctx, k, sink)
	}
	<-ctx.Done()
	return nil
}

type NetMonitor struct {
	Interval time.Duration
}

func (m *NetMonitor) Start(ctx context.Context, sink Sink) error {
	if m.Interval <= 0 {
		m.Interval = 2 * time.Second
	}
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scanConnections(sink)
		}
	}
}

type MemMonitor struct {
	Interval time.Duration

	SuspectInterval time.Duration
}

func (m *MemMonitor) Start(ctx context.Context, sink Sink) error {
	if m.Interval <= 0 {
		m.Interval = 3 * time.Minute
	}
	if m.SuspectInterval <= 0 {
		m.SuspectInterval = 2 * time.Second
	}
	sweep := time.NewTicker(m.Interval)
	defer sweep.Stop()
	fast := time.NewTicker(m.SuspectInterval)
	defer fast.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-fast.C:
			if pids := drainSuspects(); len(pids) > 0 {
				scanMemoryForTokens(sink, pids)
			}
		case <-sweep.C:
			scanMemoryForTokens(sink, drainSuspects())
		}
	}
}

type ModuleMonitor struct {
	Interval time.Duration
}

func (m *ModuleMonitor) Start(ctx context.Context, sink Sink) error {
	if m.Interval <= 0 {
		m.Interval = 45 * time.Second
	}
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scanModules(sink)
		}
	}
}

type InjectMonitor struct {
	Interval time.Duration
}

func (m *InjectMonitor) Start(ctx context.Context, sink Sink) error {
	if m.Interval <= 0 {
		m.Interval = 30 * time.Second
	}
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scanThreadInjection(sink)
		}
	}
}
