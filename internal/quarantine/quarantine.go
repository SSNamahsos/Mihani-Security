package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	ID            string    `json:"id"`
	OriginalPath  string    `json:"original_path"`
	StoredPath    string    `json:"stored_path"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	Threat        string    `json:"threat"`
	Severity      string    `json:"severity"`
	Evidence      string    `json:"evidence"`
	VerdictID     string    `json:"verdict_id"`
}

type Store struct {
	mu        sync.RWMutex
	dir       string
	index     map[string]Entry
	indexPath string
	maxBytes  int64
	maxAge    time.Duration
}

func Open(dir string, maxBytes int64, maxAge time.Duration) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:       dir,
		index:     map[string]Entry{},
		indexPath: filepath.Join(dir, "index.json"),
		maxBytes:  maxBytes,
		maxAge:    maxAge,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Add(path, threat, severity, evidence, verdictID string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if recent, ok := s.recentByPath(path, 60*time.Second); ok {
		return recent, nil
	}

	id := newID()
	storedName := fmt.Sprintf("%s_%s.bin", time.Now().UTC().Format("20060102T150405"), id)
	stored := filepath.Join(s.dir, storedName)

	entry := Entry{
		ID:            id,
		OriginalPath:  path,
		StoredPath:    stored,
		Threat:        threat,
		Severity:      severity,
		Evidence:      evidence,
		QuarantinedAt: time.Now().UTC(),
		VerdictID:     verdictID,
	}

	in, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			entry.Evidence = "[source missing] " + evidence
			s.index[id] = entry
			s.persistLocked()
			return entry, nil
		}
		return Entry{}, err
	}
	defer in.Close()

	out, err := os.OpenFile(stored, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Entry{}, err
	}
	h := sha256.New()
	mw := io.MultiWriter(out, h)
	n, err := io.Copy(mw, in)
	if err != nil {
		out.Close()
		os.Remove(stored)
		return Entry{}, err
	}
	if err := out.Close(); err != nil {
		os.Remove(stored)
		return Entry{}, err
	}
	entry.SHA256 = hex.EncodeToString(h.Sum(nil))
	entry.Size = n

	if err := in.Close(); err != nil {
		os.Remove(stored)
		return Entry{}, err
	}

	_ = os.Chmod(path, 0o200)
	if err := removeWithRetry(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		if rerr := os.Rename(path, path+".quarantine.pending"); rerr != nil {
			entry.Evidence = "[delete pending] " + entry.Evidence
		}
	}

	s.index[id] = entry
	if err := s.persistLocked(); err != nil {
		return entry, err
	}
	s.enforceLimitsLocked()
	return entry, nil
}

func removeWithRetry(path string) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}

func (s *Store) recentByPath(path string, window time.Duration) (Entry, bool) {
	lc := strings.ToLower(filepath.Clean(path))
	for _, e := range s.index {
		if strings.ToLower(filepath.Clean(e.OriginalPath)) == lc && time.Since(e.QuarantinedAt) < window {
			return e, true
		}
	}
	return Entry{}, false
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.index[id]
	if !ok {
		return os.ErrNotExist
	}
	if !s.insideDir(e.StoredPath) {
		return fmt.Errorf("refusing to touch %s: outside quarantine", e.StoredPath)
	}
	if err := os.Remove(e.StoredPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.index, id)
	return s.persistLocked()
}

func (s *Store) Restore(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.index[id]
	if !ok {
		return os.ErrNotExist
	}
	if !s.insideDir(e.StoredPath) {
		return fmt.Errorf("refusing to restore %s: stored file outside quarantine", e.StoredPath)
	}
	if !s.restorableTarget(e.OriginalPath) {
		return fmt.Errorf("refusing to restore into protected location: %s", e.OriginalPath)
	}
	if _, err := os.Stat(e.OriginalPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing file at %s", e.OriginalPath)
	}
	if err := os.MkdirAll(filepath.Dir(e.OriginalPath), 0o755); err != nil {
		return err
	}
	in, err := os.Open(e.StoredPath)
	if err != nil {
		return fmt.Errorf("quarantined file is missing (%s); it was probably removed externally, e.g. by another antivirus", e.StoredPath)
	}
	defer in.Close()
	out, err := os.OpenFile(e.OriginalPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(e.OriginalPath)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	delete(s.index, id)
	return s.persistLocked()
}

func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.index))
	for _, e := range s.index {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QuarantinedAt.After(out[j].QuarantinedAt) })
	return out
}

func (s *Store) PurgeOld() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforceLimitsLocked()
}

func (s *Store) TotalSize() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int64
	for _, e := range s.index {
		total += e.Size
	}
	return total
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.index)
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, &s.index); err != nil {
		return err
	}
	for id, e := range s.index {
		if !s.insideDir(e.StoredPath) {
			delete(s.index, id)
		}
	}
	return nil
}

func (s *Store) insideDir(p string) bool {
	if p == "" {
		return false
	}
	rel, err := filepath.Rel(s.dir, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func (s *Store) restorableTarget(p string) bool {
	if p == "" || s.insideDir(p) {
		return false
	}
	lc := strings.ToLower(filepath.Clean(p))
	for _, frag := range []string{
		`c:\windows\`, `\program files\`, `\program files (x86)\`, `\mihanisecurity\`,
	} {
		if strings.Contains(lc, frag) {
			return false
		}
	}
	return true
}

func (s *Store) persistLocked() error {
	b, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.indexPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath)
}

func (s *Store) enforceLimitsLocked() {
	cutoff := time.Now().Add(-s.maxAge)
	var entries []Entry
	for _, e := range s.index {
		if e.QuarantinedAt.Before(cutoff) {
			if s.insideDir(e.StoredPath) {
				os.Remove(e.StoredPath)
			}
			delete(s.index, e.ID)
			continue
		}
		entries = append(entries, e)
	}
	if s.maxBytes <= 0 {
		_ = s.persistLocked()
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].QuarantinedAt.Before(entries[j].QuarantinedAt) })
	var total int64

	sort.Slice(entries, func(i, j int) bool { return entries[i].QuarantinedAt.After(entries[j].QuarantinedAt) })
	for i := len(entries) - 1; i >= 0; i-- {
		total += entries[i].Size
		if total > s.maxBytes {
			if s.insideDir(entries[i].StoredPath) {
				os.Remove(entries[i].StoredPath)
			}
			delete(s.index, entries[i].ID)
		}
	}
	_ = s.persistLocked()
}

func newID() string {
	now := time.Now().UnixNano()
	return strings.ToLower(fmt.Sprintf("%x", now))
}
