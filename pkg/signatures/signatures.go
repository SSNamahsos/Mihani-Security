package signatures

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
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

const maxStringScanBytes = 32 << 20

func (d *DB) MatchFile(path string) ([]Match, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	d.mu.RLock()
	sigs := append([]Signature(nil), d.signatures...)
	d.mu.RUnlock()

	if len(sigs) == 0 {
		return nil, nil
	}

	if st.Size() > maxStringScanBytes {
		return d.matchHashesOnly(path, sigs)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	str := string(data)

	var imports []string
	importsParsed := false
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
			if !importsParsed {
				imports = peImports(data)
				importsParsed = true
			}
			if len(imports) == 0 {
				continue
			}
			for _, imp := range imports {
				if strings.EqualFold(imp, s.Match) {
					hits = append(hits, Match{Sig: s, FilePath: path, Evidence: "import=" + s.Match})
					break
				}
			}
		}
	}
	return hits, nil
}

func (d *DB) matchHashesOnly(path string, sigs []Signature) ([]Match, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	hexSum := hex.EncodeToString(h.Sum(nil))
	var hits []Match
	for _, s := range sigs {
		if s.Kind != KindHash {
			continue
		}
		if strings.EqualFold(hexSum, s.Match) {
			hits = append(hits, Match{Sig: s, FilePath: path, Evidence: "sha256=" + hexSum})
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

type peSection struct {
	virtualAddress uint32
	virtualSize    uint32
	rawSize        uint32
	rawOffset      uint32
}

func peImports(data []byte) []string {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if eLfanew+44 > len(data) {
		return nil
	}
	if data[eLfanew] != 'P' || data[eLfanew+1] != 'E' || data[eLfanew+2] != 0 || data[eLfanew+3] != 0 {
		return nil
	}
	magic := binary.LittleEndian.Uint16(data[eLfanew+24 : eLfanew+26])
	var ddOffset int
	switch magic {
	case 0x10B:
		ddOffset = 96
	case 0x20B:
		ddOffset = 112
	default:
		return nil
	}
	secCount := int(binary.LittleEndian.Uint16(data[eLfanew+6 : eLfanew+8]))
	optSize := int(binary.LittleEndian.Uint16(data[eLfanew+20 : eLfanew+22]))
	secStart := eLfanew + 24 + optSize
	if secCount < 1 || secCount > 96 || secStart+secCount*40 > len(data) {
		return nil
	}
	sections := make([]peSection, 0, secCount)
	for i := 0; i < secCount; i++ {
		base := secStart + i*40
		sections = append(sections, peSection{
			virtualAddress: binary.LittleEndian.Uint32(data[base+12 : base+16]),
			virtualSize:    binary.LittleEndian.Uint32(data[base+8 : base+12]),
			rawSize:        binary.LittleEndian.Uint32(data[base+16 : base+20]),
			rawOffset:      binary.LittleEndian.Uint32(data[base+20 : base+24]),
		})
	}
	toOffset := func(rva uint32) (int, bool) {
		for _, s := range sections {
			span := s.virtualSize
			if s.rawSize > span {
				span = s.rawSize
			}
			if span > 0 && rva >= s.virtualAddress && rva-s.virtualAddress < span {
				return int(s.rawOffset + (rva - s.virtualAddress)), true
			}
		}
		return 0, false
	}
	ddBase := eLfanew + 24 + ddOffset
	if ddBase+16 > len(data) {
		return nil
	}
	impRVA := binary.LittleEndian.Uint32(data[ddBase+8 : ddBase+12])
	if impRVA == 0 {
		return nil
	}
	impOff, ok := toOffset(impRVA)
	if !ok {
		return nil
	}
	var out []string
	for i := 0; i < 4096; i++ {
		desc := impOff + i*20
		if desc+20 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[desc+12 : desc+16])
		if nameRVA == 0 {
			break
		}
		off, ok := toOffset(nameRVA)
		if !ok {
			continue
		}
		end := off
		for end < len(data) && end-off < 512 && data[end] != 0 {
			end++
		}
		if end == off {
			continue
		}
		out = append(out, string(data[off:end]))
	}
	return out
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
