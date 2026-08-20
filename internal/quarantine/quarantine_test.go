package quarantine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAddRemovesOriginal(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "threat.bin")
	if err := os.WriteFile(src, []byte("malicious content"), 0o600); err != nil {
		t.Fatal(err)
	}

	entry, err := s.Add(src, "Test", "high", "evidence", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if entry.OriginalPath != src {
		t.Fatalf("entry.OriginalPath = %q, want %q", entry.OriginalPath, src)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("original %q still exists after quarantine (err=%v)", src, err)
	}
	stored, err := os.ReadFile(entry.StoredPath)
	if err != nil {
		t.Fatalf("stored copy unreadable: %v", err)
	}
	if string(stored) == "malicious content" {
		t.Fatal("stored copy is plaintext; expected encrypted bytes")
	}
	if len(stored) <= headerSize || string(stored[:headerSize]) != string(magicHeader) {
		t.Fatal("stored copy missing encryption header")
	}
	if entry.Size != int64(len("malicious content")) {
		t.Fatalf("entry.Size = %d, want plaintext size", entry.Size)
	}
}

func TestAddRestoreEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("secret payload with sensitive content that must not sit on disk in plaintext")
	src := filepath.Join(t.TempDir(), "stealer.exe")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	entry, err := s.Add(src, "Test", "critical", "evidence", "v1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(entry.StoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == len(payload) && string(raw) == string(payload) {
		t.Fatal("quarantined file stored in plaintext")
	}

	if err := s.Restore(entry.ID); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("restored content mismatch: got %q", string(got))
	}
}

func TestRestoreLegacyPlainFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("legacy plain quarantined bytes")
	src := filepath.Join(t.TempDir(), "old.exe")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := s.Add(src, "Test", "high", "evidence", "v1")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(entry.StoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry.StoredPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if string(encrypted) == string(payload) {
		t.Fatal("setup error: encryption did not alter bytes")
	}

	if err := s.Restore(entry.ID); err != nil {
		t.Fatalf("legacy restore failed: %v", err)
	}
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("legacy restore content mismatch: got %q", string(got))
	}
}

func TestAddMissingSource(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "ghost.bin")
	entry, err := s.Add(missing, "Test", "low", "evidence", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if entry.OriginalPath != missing {
		t.Fatalf("unexpected entry %+v", entry)
	}
}

func TestAddDedupe(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "drop.bin")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := s.Add(src, "Test", "high", "ev", "v1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Add(src, "Test", "high", "ev", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("duplicate Add produced a second entry: %s vs %s", first.ID, second.ID)
	}
	if n := len(s.List()); n != 1 {
		t.Fatalf("expected 1 entry, got %d", n)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("original still exists after deduped Adds")
	}
}

func TestRestoreMissingBin(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "victim.bin")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := s.Add(src, "Test", "high", "ev", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(entry.StoredPath); err != nil {
		t.Fatal(err)
	}
	err = s.Restore(entry.ID)
	if err == nil {
		t.Fatal("Restore succeeded with a missing stored copy")
	}
	if _, ok := s.index[entry.ID]; !ok {
		t.Fatal("failed Restore must keep the entry listed")
	}
}
func TestDeleteRefusesPathOutsideQuarantine(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "keep.bin")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "tampered"
	s.index[id] = Entry{ID: id, OriginalPath: victim, StoredPath: victim}
	if err := s.Delete(id); err == nil {
		t.Fatal("Delete must refuse StoredPath outside quarantine")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("outside file was removed: %v", err)
	}
}

func TestRestoreRefusesSystemLocation(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(stored, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "tampered2"
	s.index[id] = Entry{ID: id, OriginalPath: `C:\Windows\System32\evil.dll`, StoredPath: stored}
	if err := s.Restore(id); err == nil {
		t.Fatal("Restore must refuse system locations")
	}
	if _, ok := s.index[id]; !ok {
		t.Fatal("failed Restore must keep the entry listed")
	}
}

func TestLoadDropsEscapingEntries(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.bin")
	if err := os.WriteFile(good, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, 1024*1024, 30*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	s.index["ok"] = Entry{ID: "ok", StoredPath: good}
	s.index["bad"] = Entry{ID: "bad", StoredPath: `C:\Windows\System32\winlogon.exe`}
	if err := s.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.index["bad"]; ok {
		t.Fatal("escaping entry survived load")
	}
	if _, ok := s.index["ok"]; !ok {
		t.Fatal("legitimate entry dropped by load")
	}
}
