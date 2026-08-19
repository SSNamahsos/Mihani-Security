package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/pkg/tokens"
)

type ProgressFn func(events.ScanProgress)

const (
	countBudget    = 6 * time.Second
	countFileLimit = 500_000

	scanMaxFileSize = 64 << 20

	smartFileLimit = 10_000
)

type ScanResult struct {
	ScanID    string           `json:"scan_id"`
	Type      string           `json:"type"`
	Roots     []string         `json:"roots"`
	StartedAt time.Time        `json:"started_at"`
	EndedAt   time.Time        `json:"ended_at"`
	Files     int64            `json:"files"`
	Threats   int64            `json:"threats"`
	Verdicts  []events.Verdict `json:"verdicts"`
	Canceled  bool             `json:"canceled"`
}

func (r *ScanResult) Duration() time.Duration {
	if r.EndedAt.IsZero() {
		return time.Since(r.StartedAt)
	}
	return r.EndedAt.Sub(r.StartedAt)
}

type OnDemandScanner struct {
	DB *SignatureDBAdapter

	Exclusions []string
}

func NewOnDemand(db *SignatureDBAdapter) *OnDemandScanner {
	return &OnDemandScanner{DB: db}
}

func (s *OnDemandScanner) ScanFile(path string) []events.Verdict {
	var out []events.Verdict
	if s.DB != nil {
		if matches, err := s.DB.MatchFile(path); err == nil {
			for _, m := range matches {
				out = append(out, events.Verdict{
					ID:          newID(),
					Time:        time.Now(),
					Severity:    mapSeverity(m.Severity),
					Threat:      events.ThreatMalware,
					Name:        m.Name,
					Description: "Signature match: " + m.Family,
					Path:        path,
					Evidence:    []string{m.Evidence},
					Action:      events.ActionQuarantine,
					Source:      "signatures",
				})
			}
		}
	}

	if v := ScoreFindings(path, nil, InspectFile(path)); v != nil {
		out = append(out, *v)
	}
	return out
}

func (s *OnDemandScanner) Scan(ctx context.Context, roots []string, progress ProgressFn) (*ScanResult, error) {
	if len(roots) == 0 {
		roots = defaultScanRoots()
	}
	res := &ScanResult{ScanID: newID(), Roots: roots, StartedAt: time.Now()}
	defer func() { res.EndedAt = time.Now() }()

	total := countCandidates(ctx, roots, s.Exclusions)

	var (
		done    atomic.Int64
		threats atomic.Int64
		current atomic.Value
	)
	current.Store("")

	report := func() {
		if progress == nil {
			return
		}
		d := done.Load()
		pct := 0.0
		if total > 0 {
			pct = float64(d) / float64(total) * 100
			if pct > 100 {
				pct = 100
			}
		}
		cur, _ := current.Load().(string)
		progress(events.ScanProgress{
			ScanID:     res.ScanID,
			FilesDone:  d,
			FilesTotal: total,
			Percent:    pct,
			Current:    cur,
			Threats:    threats.Load(),
		})
	}

	tickDone := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-tickDone:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				report()
			}
		}
	}()

	for _, root := range roots {
		walkCandidates(ctx, root, s.Exclusions, func(path string, size int64) {
			current.Store(path)
			done.Add(1)
			res.Files++
			for _, v := range s.ScanFile(path) {
				res.Verdicts = append(res.Verdicts, v)
				res.Threats++
				threats.Add(1)
			}
		})
		if ctx.Err() != nil {
			break
		}
	}

	close(tickDone)
	if ctx.Err() != nil {
		res.Canceled = true
	}

	if total < res.Files {
		total = res.Files
	}
	done.Store(res.Files)
	current.Store("")
	report()
	return res, nil
}

func (s *OnDemandScanner) ScanSmart(ctx context.Context, progress ProgressFn) (*ScanResult, error) {
	roots := smartScanRoots()
	res := &ScanResult{ScanID: newID(), Roots: roots, StartedAt: time.Now()}
	defer func() { res.EndedAt = time.Now() }()

	cands := collectRecent(ctx, roots, s.Exclusions)
	total := int64(len(cands))
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })

	var (
		done    atomic.Int64
		threats atomic.Int64
		current atomic.Value
	)
	current.Store("")

	report := func() {
		if progress == nil {
			return
		}
		d := done.Load()
		pct := 0.0
		if total > 0 {
			pct = float64(d) / float64(total) * 100
			if pct > 100 {
				pct = 100
			}
		}
		cur, _ := current.Load().(string)
		progress(events.ScanProgress{
			ScanID:     res.ScanID,
			FilesDone:  d,
			FilesTotal: total,
			Percent:    pct,
			Current:    cur,
			Threats:    threats.Load(),
		})
	}

	tickDone := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-tickDone:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				report()
			}
		}
	}()

	scanDeadline := time.Now().Add(90 * time.Second)
	for _, c := range cands {
		if ctx.Err() != nil || time.Now().After(scanDeadline) {
			break
		}
		current.Store(c.path)
		done.Add(1)
		res.Files++
		for _, v := range s.ScanFile(c.path) {
			res.Verdicts = append(res.Verdicts, v)
			res.Threats++
			threats.Add(1)
		}
	}

	close(tickDone)
	if ctx.Err() != nil {
		res.Canceled = true
	}
	done.Store(res.Files)
	current.Store("")
	report()
	return res, nil
}

type candFile struct {
	path string
	mod  time.Time
}

func collectRecent(ctx context.Context, roots []string, excl []string) []candFile {
	var out []candFile
	deadline := time.Now().Add(countBudget)
	for _, root := range roots {
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if time.Now().After(deadline) {
				return filepath.SkipDir
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if excludedPath(path, excl) || skipDir(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if excludedPath(path, excl) || !scannableExt(d.Name()) {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() == 0 || fi.Size() > scanMaxFileSize {
				return nil
			}
			out = append(out, candFile{path: path, mod: fi.ModTime()})
			if len(out) >= smartFileLimit {
				return filepath.SkipDir
			}
			return nil
		})
		if len(out) >= smartFileLimit {
			break
		}
	}
	return out
}

func smartScanRoots() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append(ExistingPaths(tokens.DropZones()), ExistingPaths(untrustedRoots())...) {
		lc := strings.ToLower(filepath.Clean(r))
		if seen[lc] {
			continue
		}
		seen[lc] = true
		out = append(out, r)
	}
	return out
}

func untrustedRoots() []string {
	dirs := []string{
		filepath.Join(os.Getenv("ProgramData"), "MihaniSecurity"),
		filepath.Join(os.Getenv("ProgramData"), "Temp"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp"),
	}
	var out []string
	for _, d := range dirs {
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func walkCandidates(ctx context.Context, root string, excl []string, fn func(path string, size int64)) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if excludedPath(path, excl) || skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if excludedPath(path, excl) || !scannableExt(d.Name()) {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() == 0 || fi.Size() > scanMaxFileSize {
			return nil
		}
		fn(path, fi.Size())
		return nil
	})
}

func countCandidates(ctx context.Context, roots []string, excl []string) int64 {
	deadline := time.Now().Add(countBudget)
	var n int64
	for _, root := range roots {
		over := false
		walkCandidates(ctx, root, excl, func(string, int64) {
			n++
			if n >= countFileLimit || (n%512 == 0 && time.Now().After(deadline)) {
				over = true
			}
		})
		if over || ctx.Err() != nil {
			return 0
		}
	}
	return n
}

func QuickHash(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func FullScanRoots() []string {
	var out []string
	for c := 'C'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		if fi, err := os.Stat(root); err == nil && fi.IsDir() {
			out = append(out, root)
		}
	}
	if len(out) == 0 {
		out = defaultScanRoots()
	}
	return out
}

func defaultScanRoots() []string {
	return ExistingPaths(tokens.DropZones())
}

var skipDirNames = map[string]bool{
	"system volume information": true,
	"$recycle.bin":              true,
	"$windows.~ws":              true,
	"$windows.~bt":              true,
	"node_modules":              true,
	".git":                      true,
	".svn":                      true,
	"__pycache__":               true,
	"winsxs":                    true,
	"servicing":                 true,
	"assembly":                  true,
	"driverstore":               true,
	"quarantine":                true,
}

func skipDir(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if skipDirNames[base] {
		return true
	}

	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}

func excludedPath(p string, excl []string) bool {
	if len(excl) == 0 || p == "" {
		return false
	}
	lc := strings.ToLower(filepath.Clean(p))
	for _, x := range excl {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		xc := strings.ToLower(filepath.Clean(x))
		xc = strings.TrimSuffix(xc, `\`)
		if xc == "" || xc == "." {
			continue
		}
		if lc == xc || strings.HasPrefix(lc, xc+`\`) {
			return true
		}
	}
	return false
}

func scannableExt(name string) bool {
	if name == "" {
		return false
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi", ".msix",
		".jar", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
		".wsf", ".wsh", ".hta", ".lnk", ".py", ".pyc", ".au3", ".reg", ".tmp", "":
		return true
	}
	return false
}
