package detector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExcludedPath(t *testing.T) {
	excl := []string{"C:\\Games", "D:\\keep.exe", "  ", ""}
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Games`, true},
		{`C:\Games\Mods\foo.exe`, true},
		{`c:\games\sub\file.dll`, true},
		{`C:\Games2\foo.exe`, false},
		{`D:\keep.exe`, true},
		{`D:\keep.exe.bak`, false},
		{`C:\Windows\foo.exe`, false},
		{"", false},
	}
	for _, c := range cases {
		if got := excludedPath(c.path, excl); got != c.want {
			t.Errorf("excludedPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestWalkSkipsExclusions(t *testing.T) {
	root := t.TempDir()
	exclDir := filepath.Join(root, "excl")
	mustMkdir(t, filepath.Join(root, "keep"))
	mustMkdir(t, filepath.Join(exclDir, "sub"))
	for _, p := range []string{
		filepath.Join(root, "keep", "a.exe"),
		filepath.Join(root, "b.dll"),
		filepath.Join(exclDir, "c.exe"),
		filepath.Join(exclDir, "sub", "d.bat"),
	} {
		mustWrite(t, p)
	}

	var seen []string
	walkCandidates(context.Background(), root, []string{exclDir}, func(path string, _ int64) {
		seen = append(seen, path)
	})

	if len(seen) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %v", len(seen), seen)
	}
	for _, p := range seen {
		if p == filepath.Join(exclDir, "c.exe") || p == filepath.Join(exclDir, "sub", "d.bat") {
			t.Errorf("excluded file walked: %s", p)
		}
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}
