package signatures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAndParse(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}
	if db.Count() == 0 {
		t.Fatal("seed DB has no signatures")
	}
	if db.Version() == "unknown" || db.Version() == "" {
		t.Errorf("bad version: %q", db.Version())
	}
	if db.LoadedAt().IsZero() {
		t.Error("LoadedAt is zero")
	}
	if db.Path() == "" {
		t.Error("Path is empty")
	}
}

func TestMatchFileEICAR(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}

	clean := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(clean, []byte("nothing to see here"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits, err := db.MatchFile(clean)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("clean file matched %d signatures", len(hits))
	}

	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits, err = db.MatchFile(bad)
	if err != nil {
		t.Fatal(err)
	}
	var eicar bool
	for _, h := range hits {
		if strings.Contains(h.Sig.Name, "EICAR") {
			eicar = true
		}
	}
	if !eicar {
		t.Errorf("EICAR file produced no EICAR hit: %+v", hits)
	}
}

func TestMatchFileMissing(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.MatchFile(filepath.Join(dir, "nope.txt")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestAppendFile(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}
	before := db.Count()

	upd := filepath.Join(dir, "update.db")
	content := "# update\n[HASH] deadbeef|Fake Sig|low|Test\n[PE-STRING] sentinel-string|Sentinel|high|Test\n"
	if err := os.WriteFile(upd, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	added, err := db.AppendFile(upd)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Errorf("added %d, want 2", added)
	}
	if db.Count() != before+2 {
		t.Errorf("count %d, want %d", db.Count(), before+2)
	}

	if err := db.Reload(); err != nil {
		t.Fatal(err)
	}
	if db.Count() != before+2 {
		t.Errorf("after reload count %d, want %d", db.Count(), before+2)
	}
}

func TestAppendFileInvalid(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}
	upd := filepath.Join(dir, "bad.db")
	if err := os.WriteFile(upd, []byte("not a signature line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AppendFile(upd); err == nil {
		t.Error("expected error for file with no valid signatures")
	}
}

func TestParseLine(t *testing.T) {
	s, ok := parseLine("[HASH] abc123|Name|high|Family")
	if !ok || s.Kind != KindHash || s.Match != "abc123" || s.Name != "Name" || s.Severity != "high" || s.Family != "Family" {
		t.Errorf("parse failed: %+v ok=%v", s, ok)
	}
	if _, ok := parseLine("garbage"); ok {
		t.Error("garbage parsed as signature")
	}
	if _, ok := parseLine("[UNKNOWN] a|b|c|d"); ok {
		t.Error("unknown kind accepted")
	}
}

func TestMatchMemory(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}
	hits := db.MatchMemory([]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))
	if len(hits) == 0 {
		t.Error("memory scan missed EICAR string")
	}
	if len(db.MatchMemory([]byte("plain text"))) != 0 {
		t.Error("memory scan flagged plain text")
	}
}
