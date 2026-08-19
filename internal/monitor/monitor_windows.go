package monitor

import (
	"context"
	"fmt"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"

	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

func newWatcher() (*fsnotify.Watcher, error) {
	return fsnotify.NewWatcher()
}

func classify(op fsnotify.Op) events.EventKind {
	switch {
	case op&fsnotify.Create != 0:
		return events.EventFileCreate
	case op&fsnotify.Write != 0:
		return events.EventFileModify
	case op&fsnotify.Remove != 0:
		return events.EventFileDelete
	case op&fsnotify.Rename != 0:
		return events.EventFileRename
	case op&fsnotify.Chmod != 0:
		return events.EventFileModify
	}
	return events.EventFileRead
}

func newID() string { return uuid.NewString() }

func listProcesses() ([]events.Process, error) {
	infos, err := winapi.ListProcesses()
	if err != nil {
		return nil, err
	}
	out := make([]events.Process, 0, len(infos))
	for _, p := range infos {
		name := p.Name
		if name == "" && p.Path != "" {
			name = filepath.Base(p.Path)
		}
		out = append(out, events.Process{
			PID:  p.PID,
			PPID: p.PPID,
			Name: name,
			Path: p.Path,
		})
	}
	return out, nil
}

func defaultWatchPaths() []string {
	return tokens.DropZones()
}

func scanConnections(sink Sink) {
	conns, err := winapi.ListTCP()
	if err != nil {
		return
	}

	byPID := map[uint32]events.Process{}
	if procs, err := listProcesses(); err == nil {
		for _, p := range procs {
			byPID[p.PID] = p
		}
	}
	for _, c := range conns {

		if c.RemoteAddr == "" || c.RemoteAddr == "0.0.0.0" || c.RemotePort == 0 {
			continue
		}
		proc := byPID[c.PID]
		proc.PID = c.PID
		p := proc
		sink.Handle(events.Event{
			ID:   newID(),
			Time: time.Now(),
			Kind: events.EventNetworkConnect,
			Network: &events.NetConn{
				Protocol:   "tcp",
				LocalAddr:  c.LocalAddr,
				RemoteAddr: c.RemoteAddr,
				RemotePort: c.RemotePort,
			},
			Process: &p,
			Source:  "net",
		})
	}
}

func regRoot(name string) (registry.Key, error) {
	switch name {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	}
	return 0, fmt.Errorf("unknown registry root %q", name)
}

func watchKey(ctx context.Context, k RegistryKey, sink Sink) {
	root, err := regRoot(k.Root)
	if err != nil {
		return
	}
	key, err := registry.OpenKey(root, k.Path, registry.QUERY_VALUE|registry.NOTIFY)
	if err != nil {
		return
	}
	defer key.Close()

	full := k.Root + `\` + k.Path
	prev := snapshotValues(key)

	for {
		if ctx.Err() != nil {
			return
		}
		const filter = 0x01 | 0x04
		if err := winapi.RegNotifyChangeKeyValue(syscall.Handle(key), true, filter); err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		cur := snapshotValues(key)
		for name, data := range cur {
			if old, ok := prev[name]; ok && old == data {
				continue
			}
			kind := events.EventRegistrySet
			if _, existed := prev[name]; !existed {
				kind = events.EventRegistryCreate
			}
			sink.Handle(events.Event{
				ID:   newID(),
				Time: time.Now(),
				Kind: kind,
				Path: data,
				Registry: &events.RegistryOp{
					Key:   full,
					Value: name,
					Data:  data,
				},
				Source: "registry",
			})
		}
		prev = cur
	}
}

func snapshotValues(key registry.Key) map[string]string {
	out := map[string]string{}
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return out
	}
	for _, n := range names {
		if s, _, err := key.GetStringValue(n); err == nil {
			out[n] = s
			continue
		}
		if ss, _, err := key.GetStringsValue(n); err == nil {
			out[n] = fmt.Sprint(ss)
			continue
		}
		if i, _, err := key.GetIntegerValue(n); err == nil {
			out[n] = fmt.Sprint(i)
			continue
		}
		if b, _, err := key.GetBinaryValue(n); err == nil {
			out[n] = fmt.Sprintf("<%d bytes binary>", len(b))
		}
	}
	return out
}

func defaultRegistryKeys() []RegistryKey {
	return []RegistryKey{
		{Root: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\Run`},
		{Root: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{Root: "HKLM", Path: `Software\Microsoft\Windows\CurrentVersion\Run`},
		{Root: "HKLM", Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{Root: "HKLM", Path: `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
		{Root: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`},
		{Root: "HKLM", Path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`},
		{Root: "HKLM", Path: `Software\Microsoft\Windows NT\CurrentVersion\Windows`},
		{Root: "HKCU", Path: `Environment`},
	}
}
