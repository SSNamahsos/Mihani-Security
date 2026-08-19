package logger

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Logger struct {
	zl zerolog.Logger
	mu sync.Mutex
}

func Open(dataDir, level string) (*Logger, error) {
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	purgeOld(logDir, 14*24*3600)

	lvl, err := zerolog.ParseLevel(level)
	if err != nil || level == "" {
		lvl = zerolog.InfoLevel
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano

	logFile := filepath.Join(logDir, "mihanisecurity.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	zl := zerolog.New(io.MultiWriter(f, os.Stderr)).
		Level(lvl).
		With().
		Timestamp().
		Str("app", "mihanisecurity").
		Logger()

	return &Logger{zl: zl}, nil
}

func (l *Logger) With() zerolog.Context { return l.zl.With() }

func (l *Logger) Info() *zerolog.Event  { return l.zl.Info() }
func (l *Logger) Warn() *zerolog.Event  { return l.zl.Warn() }
func (l *Logger) Error() *zerolog.Event { return l.zl.Error() }
func (l *Logger) Debug() *zerolog.Event { return l.zl.Debug() }
func (l *Logger) Fatal() *zerolog.Event { return l.zl.Fatal() }

func (l *Logger) Verdict(v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.zl.Error().Err(err).Msg("verdict marshal")
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.zl.Info().RawJSON("verdict", []byte(Redact(string(b)))).Msg("verdict")
}

func (l *Logger) Event(kind string, fields map[string]any) {
	ev := l.zl.Info().Str("kind", kind)
	for k, v := range fields {
		ev = ev.Interface(k, v)
	}
	ev.Msg("event")
}

func (l *Logger) ScanProgress(scanID string, done, total int64, current string, threats int64) {
	l.zl.Info().
		Str("scan_id", scanID).
		Int64("done", done).
		Int64("total", total).
		Int64("threats", threats).
		Str("current", current).
		Msg("scan_progress")
}

func purgeOld(dir string, maxAge int64) {
	cutoff := time.Now().Add(-time.Duration(maxAge) * time.Second)
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(p)
		}
		return nil
	})
}
