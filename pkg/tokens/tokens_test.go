package tokens

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestProfiles(t *testing.T) {
	homes := Profiles()
	if len(homes) == 0 {
		t.Fatal("Profiles() returned no homes")
	}
	for _, h := range homes {
		if !filepath.IsAbs(h) {
			t.Errorf("home %q is not absolute", h)
		}
	}
}

func TestAllCoversCoreApps(t *testing.T) {
	paths := All()
	if len(paths) == 0 {
		t.Fatal("All() returned no entries")
	}
	var discord, steam, browser bool
	for _, p := range paths {
		switch p.App {
		case "discord":
			discord = true
		case "steam":
			steam = true
		case "browser":
			browser = true
		}
	}
	if !discord || !steam || !browser {
		t.Errorf("expected all three app groups, got discord=%v steam=%v browser=%v", discord, steam, browser)
	}
}

func TestMatchSensitive(t *testing.T) {
	var target *SensitiveFile
	for _, p := range All() {
		if p.IsDirectory && strings.Contains(strings.ToLower(p.Path), "discord") {
			target = &p
			break
		}
	}
	if target == nil {
		t.Fatal("no discord dir entry found")
	}
	child := filepath.Join(target.Path, "Local Storage", "leveldb", "CURRENT")
	if m := MatchSensitive(child); m == nil || m.App != "discord" {
		t.Errorf("expected prefix match for %q, got %+v", child, m)
	}
	if m := MatchSensitive("C:\\Windows\\notepad.exe"); m != nil {
		t.Errorf("unexpected match for unrelated path: %+v", m)
	}
}

func TestIsWhitelistedProcess(t *testing.T) {
	cases := map[string]bool{
		"steam.exe":                   true,
		"C:\\Games\\Steam\\steam.exe": true,
		"DISCORD.EXE":                 true,
		"msedge.exe":                  true,
		"totally_stealer.exe":         false,
		"":                            false,
	}
	for name, want := range cases {
		if got := IsWhitelistedProcess(name); got != want {
			t.Errorf("IsWhitelistedProcess(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTokenRegexesCompile(t *testing.T) {
	if len(TokenRegexes) == 0 {
		t.Fatal("no token regexes defined")
	}
	for _, p := range TokenRegexes {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			t.Errorf("pattern %q (%s) does not compile: %v", p.Regex, p.Name, err)
			continue
		}
		if !re.MatchString("mfa.abc") && p.Name == "Discord token (mfa.)" {
			t.Log("mfa pattern requires longer input; compile check only")
		}
	}
}

func TestDropZones(t *testing.T) {
	zones := DropZones()
	if len(zones) == 0 {
		t.Fatal("DropZones() returned nothing")
	}
	for _, z := range zones {
		if !filepath.IsAbs(z) {
			t.Errorf("zone %q is not absolute", z)
		}
	}

	for _, h := range Profiles() {
		want := filepath.Join(h, "Downloads")
		found := false
		for _, z := range zones {
			if strings.EqualFold(z, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing Downloads drop zone for %q", h)
		}
	}
}
