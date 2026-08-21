package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type AlertVerbosity string

const (
	AlertSilent    AlertVerbosity = "silent"
	AlertNotify    AlertVerbosity = "notify"
	AlertFullAlert AlertVerbosity = "full"
)

type ThreatAction string

const (
	ActionAutoDelete     ThreatAction = "auto_delete"
	ActionAutoQuarantine ThreatAction = "auto_quarantine"
	ActionPrompt         ThreatAction = "prompt"
	ActionLogOnly        ThreatAction = "log_only"
)

type Config struct {
	General          General       `json:"general"`
	RealTime         RealTime      `json:"real_time"`
	TokenGuard       TokenGuard    `json:"token_guard"`
	Behavior         Behavior      `json:"behavior"`
	Quarantine       Quarantine    `json:"quarantine"`
	Notifications    Notifications `json:"notifications"`
	Whitelist        []string      `json:"whitelist"`
	WhitelistDomains []string      `json:"whitelist_domains"`
	Exclusions       []string      `json:"exclusions"`
	Theme            string        `json:"theme"`
	Language         string        `json:"language"`
	HideInTray       bool          `json:"hide_in_tray"`
	Schema           int           `json:"schema"`
}

type General struct {
	InstallPath         string `json:"install_path"`
	DataPath            string `json:"data_path"`
	LogLevel            string `json:"log_level"`
	StartOnBoot         bool   `json:"start_on_boot"`
	SendAnonymizedStats bool   `json:"send_anonymized_stats"`
}

type RealTime struct {
	Enabled          bool           `json:"enabled"`
	MonitorNewFiles  bool           `json:"monitor_new_files"`
	MonitorProcesses bool           `json:"monitor_processes"`
	MonitorHandles   bool           `json:"monitor_handles"`
	MonitorRegistry  bool           `json:"monitor_registry"`
	MonitorNetwork   bool           `json:"monitor_network"`
	AlertVerbosity   AlertVerbosity `json:"alert_verbosity"`
	OnTokenTheft     ThreatAction   `json:"on_token_theft"`
	OnMalware        ThreatAction   `json:"on_malware"`
	OnSuspicious     ThreatAction   `json:"on_suspicious"`
	OnBeaconing      ThreatAction   `json:"on_beaconing"`
	ScanDownloads    bool           `json:"scan_downloads"`
	ScanTemp         bool           `json:"scan_temp"`
}

type TokenGuard struct {
	Enabled         bool         `json:"enabled"`
	ProtectSteam    bool         `json:"protect_steam"`
	ProtectDiscord  bool         `json:"protect_discord"`
	ProtectBrowsers bool         `json:"protect_browsers"`
	BlockReads      bool         `json:"block_reads"`
	OnDetect        ThreatAction `json:"on_detect"`
	NotifyOnly      bool         `json:"notify_only"`
}

type Behavior struct {
	Enabled             bool         `json:"enabled"`
	DetectDLLInjection  bool         `json:"detect_dll_injection"`
	DetectProcessInject bool         `json:"detect_process_injection"`
	DetectPersistence   bool         `json:"detect_persistence"`
	DetectBeaconing     bool         `json:"detect_beaconing"`
	BeaconIntervalMax   int          `json:"beacon_interval_max"`
	OnDetect            ThreatAction `json:"on_detect"`
}

type Quarantine struct {
	Path       string `json:"path"`
	MaxSizeMB  int    `json:"max_size_mb"`
	MaxAgeDays int    `json:"max_age_days"`
	AutoPurge  bool   `json:"auto_purge"`
	Encrypt    bool   `json:"encrypt"`
}

type Notifications struct {
	ShowTrayOnThreat bool `json:"show_tray_on_threat"`
	ShowToast        bool `json:"show_toast"`
	PlaySound        bool `json:"play_sound"`
}

func Default() *Config {
	return &Config{
		General: General{
			LogLevel: "info",
		},
		RealTime: RealTime{
			Enabled:          true,
			MonitorNewFiles:  true,
			MonitorProcesses: true,
			MonitorHandles:   true,
			MonitorRegistry:  true,
			MonitorNetwork:   true,
			AlertVerbosity:   AlertNotify,
			OnTokenTheft:     ActionAutoQuarantine,
			OnMalware:        ActionAutoQuarantine,
			OnSuspicious:     ActionPrompt,
			OnBeaconing:      ActionPrompt,
			ScanDownloads:    true,
			ScanTemp:         true,
		},
		TokenGuard: TokenGuard{
			Enabled:         true,
			ProtectSteam:    true,
			ProtectDiscord:  true,
			ProtectBrowsers: true,
			BlockReads:      true,
			OnDetect:        ActionAutoQuarantine,
		},
		Behavior: Behavior{
			Enabled:             true,
			DetectDLLInjection:  true,
			DetectProcessInject: true,
			DetectPersistence:   true,
			DetectBeaconing:     true,
			BeaconIntervalMax:   300,
			OnDetect:            ActionPrompt,
		},
		Quarantine: Quarantine{
			MaxSizeMB:  512,
			MaxAgeDays: 30,
			AutoPurge:  true,
			Encrypt:    true,
		},
		Notifications: Notifications{
			ShowTrayOnThreat: true,
			ShowToast:        true,
			PlaySound:        false,
		},
		Theme:      "mihani",
		Language:   "en",
		HideInTray: true,
		Whitelist: []string{
			"steam.exe",
			"steamwebhelper.exe",
			"discord.exe",
			"discordcanary.exe",
			"discordptb.exe",
			"msedge.exe",
			"chrome.exe",
			"firefox.exe",
			"brave.exe",
			"opera.exe",
		},
		WhitelistDomains: []string{
			"steampowered.com",
			"steamcommunity.com",
			"discord.com",
			"discordapp.com",
			"discord.gg",
			"google.com",
			"youtube.com",
			"github.com",
		},
		Schema: 1,
	}
}

func (c *Config) Resolve() error {
	if c.General.DataPath == "" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		c.General.DataPath = filepath.Join(pd, "MihaniSecurity")
	}
	if c.Quarantine.Path == "" {
		c.Quarantine.Path = filepath.Join(c.General.DataPath, "Quarantine")
	}
	if c.General.InstallPath == "" {
		exe, err := os.Executable()
		if err == nil {
			c.General.InstallPath = filepath.Dir(exe)
		}
	}
	if err := os.MkdirAll(c.General.DataPath, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(c.Quarantine.Path, 0o755); err != nil {
		return fmt.Errorf("create quarantine dir: %w", err)
	}
	return nil
}

type Store struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		path = os.Getenv("MIHANISEC_CONFIG")
	}
	if path == "" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		path = filepath.Join(pd, "MihaniSecurity", "config.json")
	}
	s := &Store{path: path, cfg: Default()}
	if err := s.cfg.Resolve(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {

			if err := s.save(); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, err
	}
	var onDisk Config
	if err := json.Unmarshal(b, &onDisk); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	merged := mergeDefaults(Default(), &onDisk)
	if _, ok := raw["hide_in_tray"]; !ok {
		merged.HideInTray = true
	}
	if !merged.HideInTray {
		if strings.Contains(strings.ToLower(merged.General.InstallPath), "build\\bin") {
			merged.HideInTray = true
		}
	}
	if strings.Contains(strings.ToLower(merged.General.InstallPath), "build\\bin") {
		merged.General.InstallPath = ""
	}
	if err := merged.Resolve(); err != nil {
		return nil, err
	}
	s.cfg = merged
	if !onDisk.HideInTray && merged.HideInTray {
		_ = s.save()
	}
	if strings.Contains(strings.ToLower(onDisk.General.InstallPath), "build\\bin") {
		_ = s.save()
	}
	return s, nil
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.cfg
}

func (s *Store) Set(c *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := c.Resolve(); err != nil {
		return err
	}
	s.cfg = c
	return s.save()
}

func (s *Store) Update(fn func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.cfg
	fn(&cp)
	if err := cp.Resolve(); err != nil {
		return err
	}
	s.cfg = &cp
	return s.save()
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func mergeDefaults(base, onDisk *Config) *Config {
	out := *base
	if onDisk.General.LogLevel != "" {
		out.General.LogLevel = onDisk.General.LogLevel
	}
	out.General.StartOnBoot = onDisk.General.StartOnBoot
	out.General.SendAnonymizedStats = onDisk.General.SendAnonymizedStats
	if onDisk.General.InstallPath != "" {
		out.General.InstallPath = onDisk.General.InstallPath
	}
	if onDisk.General.DataPath != "" {
		out.General.DataPath = onDisk.General.DataPath
	}

	r := out.RealTime
	rt := onDisk.RealTime
	r.Enabled = rt.Enabled
	r.MonitorNewFiles = rt.MonitorNewFiles
	r.MonitorProcesses = rt.MonitorProcesses
	r.MonitorHandles = rt.MonitorHandles
	r.MonitorRegistry = rt.MonitorRegistry
	r.MonitorNetwork = rt.MonitorNetwork
	r.ScanDownloads = rt.ScanDownloads
	r.ScanTemp = rt.ScanTemp
	if rt.AlertVerbosity != "" {
		r.AlertVerbosity = rt.AlertVerbosity
	}
	if rt.OnTokenTheft != "" {
		r.OnTokenTheft = rt.OnTokenTheft
	}
	if rt.OnMalware != "" {
		r.OnMalware = rt.OnMalware
	}
	if rt.OnSuspicious != "" {
		r.OnSuspicious = rt.OnSuspicious
	}
	if rt.OnBeaconing != "" {
		r.OnBeaconing = rt.OnBeaconing
	}
	out.RealTime = r

	if onDisk.TokenGuard.OnDetect != "" {
		out.TokenGuard.OnDetect = onDisk.TokenGuard.OnDetect
	}
	out.TokenGuard.Enabled = onDisk.TokenGuard.Enabled || out.TokenGuard.Enabled
	out.TokenGuard.ProtectSteam = onDisk.TokenGuard.ProtectSteam
	out.TokenGuard.ProtectDiscord = onDisk.TokenGuard.ProtectDiscord
	out.TokenGuard.ProtectBrowsers = onDisk.TokenGuard.ProtectBrowsers
	out.TokenGuard.BlockReads = onDisk.TokenGuard.BlockReads
	out.TokenGuard.NotifyOnly = onDisk.TokenGuard.NotifyOnly

	out.Behavior.Enabled = onDisk.Behavior.Enabled
	out.Behavior.DetectDLLInjection = onDisk.Behavior.DetectDLLInjection
	out.Behavior.DetectProcessInject = onDisk.Behavior.DetectProcessInject
	out.Behavior.DetectPersistence = onDisk.Behavior.DetectPersistence
	out.Behavior.DetectBeaconing = onDisk.Behavior.DetectBeaconing
	if onDisk.Behavior.BeaconIntervalMax > 0 {
		out.Behavior.BeaconIntervalMax = onDisk.Behavior.BeaconIntervalMax
	}
	if onDisk.Behavior.OnDetect != "" {
		out.Behavior.OnDetect = onDisk.Behavior.OnDetect
	}

	if onDisk.Quarantine.Path != "" {
		out.Quarantine.Path = onDisk.Quarantine.Path
	}
	if onDisk.Quarantine.MaxSizeMB > 0 {
		out.Quarantine.MaxSizeMB = onDisk.Quarantine.MaxSizeMB
	}
	if onDisk.Quarantine.MaxAgeDays > 0 {
		out.Quarantine.MaxAgeDays = onDisk.Quarantine.MaxAgeDays
	}
	out.Quarantine.AutoPurge = onDisk.Quarantine.AutoPurge

	out.Notifications = onDisk.Notifications

	if len(onDisk.Whitelist) > 0 {
		out.Whitelist = onDisk.Whitelist
	}
	if len(onDisk.WhitelistDomains) > 0 {
		out.WhitelistDomains = onDisk.WhitelistDomains
	}
	if len(onDisk.Exclusions) > 0 {
		out.Exclusions = onDisk.Exclusions
	}
	if onDisk.Theme != "" {
		out.Theme = onDisk.Theme
	}
	if onDisk.Language != "" {
		out.Language = onDisk.Language
	}
	out.HideInTray = onDisk.HideInTray

	out.Schema = onDisk.Schema
	return &out
}
