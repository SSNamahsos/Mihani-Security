package signatures

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Kind string

const (
	KindHash   Kind = "HASH"
	KindString Kind = "PE-STRING"
	KindImport Kind = "PE-IMPORT"
	KindYara   Kind = "YARA-LITE"
)

type Signature struct {
	Kind     Kind
	Match    string
	Name     string
	Severity string
	Family   string
}

type Match struct {
	Sig      Signature
	FilePath string
	Evidence string
}

type DB struct {
	mu         sync.RWMutex
	signatures []Signature
	path       string
	loadedAt   time.Time
	version    string
}

func Open(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("signatures: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeSeed(path); err != nil {
			return nil, err
		}
	}
	db := &DB{path: path}
	if err := db.reload(); err != nil {
		return nil, err
	}
	return db, nil
}

func (d *DB) Path() string { return d.path }

func (d *DB) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.signatures)
}

func (d *DB) Version() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.version
}

func (d *DB) LoadedAt() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loadedAt
}

func (d *DB) Reload() error { return d.reload() }

func (d *DB) MatchFile(path string) ([]Match, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	d.mu.RLock()
	sigs := append([]Signature(nil), d.signatures...)
	d.mu.RUnlock()

	if len(sigs) == 0 {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	str := string(data)

	var hits []Match
	for _, s := range sigs {
		switch s.Kind {
		case KindHash:
			if strings.EqualFold(hexSum, s.Match) {
				hits = append(hits, Match{Sig: s, FilePath: path, Evidence: "sha256=" + hexSum})
			}
		case KindString, KindYara:

			if isTextDoc(path) {
				continue
			}
			if strings.Contains(str, s.Match) {
				hits = append(hits, Match{Sig: s, FilePath: path, Evidence: truncate(s.Match, 80)})
			}
		case KindImport:

			if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
				continue
			}
			if containsImport(data, s.Match) {
				hits = append(hits, Match{Sig: s, FilePath: path, Evidence: "import=" + s.Match})
			}
		}
	}
	return hits, nil
}

func (d *DB) MatchMemory(data []byte) []Match {
	d.mu.RLock()
	sigs := append([]Signature(nil), d.signatures...)
	d.mu.RUnlock()
	str := string(data)
	var hits []Match
	for _, s := range sigs {
		if s.Kind != KindString && s.Kind != KindYara {
			continue
		}
		if strings.Contains(str, s.Match) {
			hits = append(hits, Match{Sig: s, Evidence: truncate(s.Match, 80)})
		}
	}
	return hits
}

func (d *DB) reload() error {
	f, err := os.Open(d.path)
	if err != nil {
		return err
	}
	defer f.Close()

	var sigs []Signature
	rd := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := rd.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			if s, ok := parseLine(line); ok {
				sigs = append(sigs, s)
			}
		}
		if err == io.EOF {
			break
		}
	}

	st, _ := os.Stat(d.path)
	d.mu.Lock()
	d.signatures = sigs
	if st != nil {
		d.version = st.ModTime().UTC().Format("2006-01-02")
	} else {
		d.version = "unknown"
	}
	d.loadedAt = time.Now()
	d.mu.Unlock()
	return nil
}

func parseLine(line string) (Signature, bool) {

	if len(line) < 3 || line[0] != '[' {
		return Signature{}, false
	}
	end := strings.Index(line, "]")
	if end < 0 {
		return Signature{}, false
	}
	kind := Kind(strings.ToUpper(line[1:end]))
	switch kind {
	case KindHash, KindString, KindImport, KindYara:
	default:

		return Signature{}, false
	}
	rest := strings.TrimSpace(line[end+1:])
	parts := strings.SplitN(rest, "|", 4)
	if len(parts) < 4 {
		return Signature{}, false
	}
	return Signature{
		Kind:     kind,
		Match:    strings.TrimSpace(parts[0]),
		Name:     strings.TrimSpace(parts[1]),
		Severity: strings.TrimSpace(parts[2]),
		Family:   strings.TrimSpace(parts[3]),
	}, true
}

func containsImport(data []byte, dll string) bool {
	if len(dll) < 3 {
		return false
	}
	needle := []byte(strings.ToLower(dll))
	for i := 0; i+len(needle) <= len(data); i++ {
		if data[i] != needle[0] {
			continue
		}
		match := true
		for j := 1; j < len(needle); j++ {
			c := data[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func writeSeed(path string) error {
	seed := `# MihaniSecurity seed signature database
# Format: [KIND] match|name|severity|family
# KINDs: HASH (sha256), PE-STRING (substring in file), PE-IMPORT (DLL name), YARA-LITE (substring)
#
# The EICAR test string lets you verify the scanner end-to-end. Save any
# file whose contents start with X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
# and MihaniSecurity will flag it as the EICAR test signature.

[HASH] 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f|EICAR Test File|medium|EICAR
[PE-STRING] X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*|EICAR Test String|medium|EICAR
[PE-IMPORT] wininet.dll|Mimicry: Internet access without UI|low|SuspiciousImports
[PE-IMPORT] crypt32.dll|Suspicious crypto usage|low|SuspiciousImports
[PE-STRING] cmd.exe /c |Command shell spawn string|high|SuspiciousCommands
[PE-STRING] powershell -nop -w hidden |PowerShell hidden window|high|SuspiciousCommands
[PE-STRING] powershell -enc |Encoded PowerShell command|high|SuspiciousCommands
[PE-STRING] vssadmin delete shadows /all|Shadow copy deletion|critical|Wiper
[PE-STRING] wbadmin delete catalog|Backup catalog deletion|critical|Wiper
[PE-STRING] bcdedit /set {default} bootstatuspolicy ignoreallfailures|Safe-boot tampering|critical|Bootkit
[PE-STRING] mimikatz|Mimikatz credential tool|high|CredentialTheft
[PE-STRING] LaZagne|LaZagne credential tool|high|CredentialTheft
[PE-STRING] Invoke-Mimikatz|PowerShell Mimikatz loader|high|CredentialTheft
[PE-STRING] token=|Token exfil attempt (Discord/Steam pattern)|critical|CredentialTheft
[PE-STRING] loginusers.vdf|Steam login users access|critical|CredentialTheft
[PE-STRING] Local Storage\\leveldb|Discord token storage access|critical|CredentialTheft
`
	return os.WriteFile(path, []byte(seed), 0o644)
}

func (d *DB) AppendFile(src string) (added int, err error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	var batch []Signature
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if s, ok := parseLine(line); ok {
			batch = append(batch, s)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, fmt.Errorf("no valid signatures in %s", src)
	}

	d.mu.Lock()
	d.signatures = append(d.signatures, batch...)
	d.mu.Unlock()

	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for _, s := range batch {
		fmt.Fprintf(f, "[%s] %s|%s|%s|%s\n", s.Kind, s.Match, s.Name, s.Severity, s.Family)
	}
	return len(batch), nil
}

var textDocExts = map[string]bool{
	".html": true, ".htm": true, ".txt": true, ".md": true, ".markdown": true,
	".css": true, ".xml": true, ".json": true, ".yml": true, ".yaml": true,
	".csv": true, ".svg": true, ".log": true, ".nfo": true, ".rst": true,
}

func isTextDoc(path string) bool {
	return textDocExts[strings.ToLower(filepath.Ext(path))]
}
