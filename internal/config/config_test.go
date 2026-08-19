package config

import (
	"path/filepath"
	"testing"
)

func TestExclusionsPersistAndMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("MIHANISEC_CONFIG", path)

	s, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	excl := []string{`C:\Games`, `D:\mods`}
	if err := s.Update(func(c *Config) { c.Exclusions = excl }); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Get().Exclusions
	if len(got) != 2 || got[0] != `C:\Games` || got[1] != `D:\mods` {
		t.Fatalf("exclusions after reload = %v", got)
	}
}

func TestDefaultHasNoExclusions(t *testing.T) {
	if len(Default().Exclusions) != 0 {
		t.Fatal("default config must start with no exclusions")
	}
}
