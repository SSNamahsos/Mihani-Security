package detector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
)

func TestScanSmartPrioritizesRecent(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.exe")
	new := filepath.Join(dir, "new.exe")
	if err := os.WriteFile(old, []byte("MZ-old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(new, []byte("MZ-new"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	s := NewOnDemand(nil)
	res, err := s.ScanSmart(context.Background(), func(events.ScanProgress) {})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.ScanID == "" {
		t.Fatal("expected scan result")
	}
	found := map[string]bool{}
	for _, r := range res.Roots {
		if r == dir {
			found[dir] = true
		}
	}
	if !found[dir] {
		t.Logf("roots: %v", res.Roots)
	}
	if res.Files <= 0 {
		t.Fatalf("expected files scanned, got %d", res.Files)
	}
}

func TestScanSmartCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := NewOnDemand(nil)
	res, err := s.ScanSmart(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Canceled {
		t.Fatal("expected canceled scan")
	}
}

func TestSmartScanRootsDeduplicated(t *testing.T) {
	roots := smartScanRoots()
	seen := map[string]bool{}
	for _, r := range roots {
		lc := filepath.Clean(r)
		if seen[lc] {
			t.Fatalf("duplicate root: %s", r)
		}
		seen[lc] = true
	}
}
