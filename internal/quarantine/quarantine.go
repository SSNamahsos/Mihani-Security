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
	encrypt   bool
	key       []byte

	OnBeforeRestoreWrite func(original, target string)
}

func Open(dir string, maxBytes int64, maxAge time.Duration, encrypt bool) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:       dir,
		index:     map[string]Entry{},
		indexPath: filepath.Join(dir, "index.json"),
		maxBytes:  maxBytes,
		maxAge:    maxAge,
		encrypt:   encrypt,
	}
	if err := s.loadKey(); err != nil {
		return nil, err
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

	var fi0 os.FileInfo
	if fi0, err = in.Stat(); err != nil {
		return Entry{}, err
	}

	out, err := os.OpenFile(stored, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Entry{}, err
	}
	h := sha256.New()
	var n int64
	if s.encrypt {
		n, err = s.encryptFile(in, out, h)
	} else {
		mw := io.MultiWriter(out, h)
		n, err = io.Copy(mw, in)
	}
	if err == nil {
		var fi1 os.FileInfo
		fi1, err = in.Stat()
		if err == nil && fi1.Size() != fi0.Size() {
			err = errSourceChangedDuringCapture
		}
	}
	if errors.Is(err, errSourceChangedDuringCapture) {
		out.Close()
		os.Remove(stored)
		in.Close()
		time.Sleep(300 * time.Millisecond)
		return s.Add(path, threat, severity, evidence, verdictID)
	}
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

var errAlreadyRestored = errors.New("identical file already present at original location")
var errSourceChangedDuringCapture = errors.New("source file changed while being captured")

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
	if e.Size == 0 {
		return fmt.Errorf("nothing to restore: the original file was already gone when it was detected (%s); use Delete to remove this entry", filepath.Base(e.OriginalPath))
	}
	if _, err := os.Stat(e.StoredPath); err != nil {
		return fmt.Errorf("quarantined copy of %s is missing from the vault; use Delete to remove this entry", filepath.Base(e.OriginalPath))
	}

	target, err := s.pickRestoreTarget(e)
	if err == errAlreadyRestored {
		delete(s.index, id)
		if perr := s.persistLocked(); perr != nil {
			return perr
		}
		return nil
	}
	if err != nil {
		return err
	}

	if s.OnBeforeRestoreWrite != nil {
		s.OnBeforeRestoreWrite(e.OriginalPath, target)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("cannot create destination folder: %w", err)
	}
	in, err := os.Open(e.StoredPath)
	if err != nil {
		return fmt.Errorf("cannot open quarantined copy: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", target, err)
	}
	if s.encrypt {
		hdr := make([]byte, headerSize)
		n, _ := io.ReadFull(in, hdr)
		if _, serr := in.Seek(0, io.SeekStart); serr != nil {
			out.Close()
			os.Remove(target)
			return serr
		}
		if n == headerSize && string(hdr) == string(magicHeader) {
			err = s.decryptFile(in, out)
		} else {
			_, err = io.Copy(out, in)
		}
	} else {
		_, err = io.Copy(out, in)
	}
	if err != nil {
		out.Close()
		os.Remove(target)
		return fmt.Errorf("stored copy of %s is damaged and cannot be decrypted (%v); use Delete to remove this entry", filepath.Base(e.OriginalPath), err)
	}
	if err := out.Close(); err != nil {
		os.Remove(target)
		return err
	}
	delete(s.index, id)
	return s.persistLocked()
}

func (s *Store) pickRestoreTarget(e Entry) (string, error) {
	if _, err := os.Stat(e.OriginalPath); err != nil {
		return e.OriginalPath, nil
	}
	if e.SHA256 != "" {
		if h, herr := fileSHA256(e.OriginalPath); herr == nil && strings.EqualFold(h, e.SHA256) {
			return "", errAlreadyRestored
		}
	}
	ext := filepath.Ext(e.OriginalPath)
	base := strings.TrimSuffix(e.OriginalPath, ext)
	for i := 1; i < 100; i++ {
		name := fmt.Sprintf("%s.restored%d%s", base, i, ext)
		if i == 1 {
			name = fmt.Sprintf("%s.restored%s", base, ext)
		}
		if _, err := os.Stat(name); err != nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free name to restore beside existing file at %s", e.OriginalPath)
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
