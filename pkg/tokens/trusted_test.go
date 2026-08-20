package tokens

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mihanistudio/mihanisecurity/pkg/winapi"
)

func TestOwnerForName(t *testing.T) {
	cases := map[string]string{
		"discord.exe":  "discord",
		"steam.exe":    "steam",
		"msedge.exe":   "edge",
		"chrome.exe":   "chrome",
		"firefox.exe":  "firefox",
		"telegram.exe": "telegram",
		"stealer.exe":  "",
		"notepad.exe":  "",
		"":             "",
	}
	for name, want := range cases {
		if got := ownerForName(name); got != want {
			t.Errorf("ownerForName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPublisherMatches(t *testing.T) {
	allowed := []string{"discord inc", "discord, inc"}
	if !publisherMatches("Discord Inc.", allowed) {
		t.Error("exact publisher should match")
	}
	if !publisherMatches("DISCORD INC", allowed) {
		t.Error("case-insensitive publisher should match")
	}
	if publisherMatches("Evil Corp", allowed) {
		t.Error("unrelated publisher must not match")
	}
	if publisherMatches("", allowed) {
		t.Error("empty publisher must not match")
	}
	if publisherMatches("Discord Inc", nil) {
		t.Error("empty allowlist must not match")
	}
}

func TestTrustedOwnerProcessRejectsUnsigned(t *testing.T) {
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "discord.exe")
	data := []byte("not a real discord binary, unsigned")
	if err := os.WriteFile(unsigned, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, why := TrustedOwnerProcess("discord.exe", unsigned)
	if ok {
		t.Fatal("unsigned impostor passed TrustedOwnerProcess")
	}
	if !strings.Contains(why, "signature") && !strings.Contains(why, "publisher") {
		t.Fatalf("unexpected reason: %q", why)
	}
}

func TestSignedPublisherMicrosoftBinary(t *testing.T) {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	candidate := filepath.Join(sys, "System32", "kernel32.dll")
	if _, err := os.Stat(candidate); err != nil {
		t.Skip("kernel32.dll not available for signature test")
	}
	if err := winapi.VerifySignedFile(candidate); err != nil {
		t.Fatalf("kernel32.dll should verify as signed: %v", err)
	}
	pub, err := winapi.SignedPublisher(candidate)
	if err != nil {
		t.Fatalf("publisher lookup failed: %v", err)
	}
	if !strings.Contains(strings.ToLower(pub), "microsoft") {
		t.Fatalf("unexpected publisher for kernel32.dll: %q", pub)
	}
}
