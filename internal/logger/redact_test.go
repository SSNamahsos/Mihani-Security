package logger

import "testing"

func TestRedactDiscordClassic(t *testing.T) {
	tok := "ABCDEFGHIJKLMNOPQRSTUVWX.YZABCD.aBCDEFGHIJKLMNOPQRSTUVWXYZa"
	in := "process read token " + tok + " from memory"
	out := Redact(in)
	if out == in || contains(out, tok) {
		t.Fatalf("classic Discord token not redacted: %q", out)
	}
	if !contains(out, "process read token") {
		t.Fatalf("context lost: %q", out)
	}
}

func TestRedactDiscordMFA(t *testing.T) {
	tok := "mfa." + repeat("a", 90)
	out := Redact("cookie " + tok + " leaked")
	if contains(out, tok) {
		t.Fatalf("MFA token not redacted: %q", out)
	}
}

func TestRedactSteamTicket(t *testing.T) {
	tok := "steamAuthTicket=" + repeat("B", 50)
	out := Redact("found " + tok)
	if contains(out, tok) {
		t.Fatalf("steam ticket not redacted: %q", out)
	}
}

func TestRedactBearer(t *testing.T) {
	out := Redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890")
	if contains(out, "abcdefghijklmnopqrstuvwxyz1234567890") {
		t.Fatalf("bearer token not redacted: %q", out)
	}
}

func TestRedactAssignment(t *testing.T) {
	for _, s := range []string{
		"cmd=app.exe token=abcdefghijklmnopqrstuvwxyz123456 end",
		"password=sup3rs3cretvalue123! x",
		"api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
	} {
		out := Redact(s)
		if out == s {
			t.Fatalf("assignment not redacted: %q", s)
		}
	}
}

func TestRedactEncodedCommand(t *testing.T) {
	payload := repeat("Q", 80)
	for _, s := range []string{
		"powershell.exe -enc " + payload,
		"powershell.exe -encodedcommand " + payload,
	} {
		out := Redact(s)
		if contains(out, payload) {
			t.Fatalf("-enc payload leaked: %q", s)
		}
		if !contains(out, "powershell.exe") {
			t.Fatalf("command name lost: %q", out)
		}
	}
}

func TestRedactLeavesPlainData(t *testing.T) {
	for _, s := range []string{
		`C:\Users\pc\AppData\Roaming\discord\Local Storage\leveldb\000003.log`,
		`key=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`sha256 match 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`,
		`accessing_process=gift-stealer.exe`,
		`value="C:\Windows\Temp\updater.exe"`,
	} {
		if Redact(s) != s {
			t.Fatalf("plain data was scrubbed: %q -> %q", s, Redact(s))
		}
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func repeat(c string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = c[0]
	}
	return string(out)
}
