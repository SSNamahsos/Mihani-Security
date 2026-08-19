package events

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type ThreatType string

const (
	ThreatTokenTheft    ThreatType = "token_theft"
	ThreatMalware       ThreatType = "malware"
	ThreatSuspicious    ThreatType = "suspicious_behavior"
	ThreatPersistence   ThreatType = "persistence"
	ThreatDLLInjection  ThreatType = "dll_injection"
	ThreatProcessInject ThreatType = "process_injection"
	ThreatBeaconing     ThreatType = "network_beaconing"
	ThreatUnauthorized  ThreatType = "unauthorized_access"
)

type Action string

const (
	ActionAllow      Action = "allow"
	ActionLog        Action = "log"
	ActionAlert      Action = "alert"
	ActionBlock      Action = "block"
	ActionQuarantine Action = "quarantine"
	ActionDelete     Action = "delete"
)

type EventKind string

const (
	EventProcessStart   EventKind = "process_start"
	EventProcessStop    EventKind = "process_stop"
	EventFileCreate     EventKind = "file_create"
	EventFileModify     EventKind = "file_modify"
	EventFileRead       EventKind = "file_read"
	EventFileRename     EventKind = "file_rename"
	EventFileDelete     EventKind = "file_delete"
	EventHandleOpen     EventKind = "handle_open"
	EventRegistrySet    EventKind = "registry_set"
	EventRegistryCreate EventKind = "registry_create"
	EventNetworkConnect EventKind = "network_connect"

	EventModuleLoad EventKind = "module_load"

	EventThreadInject EventKind = "thread_inject"

	EventTokenString EventKind = "token_string"
)

type Process struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	StartedAt   time.Time `json:"started_at"`
	Signed      bool      `json:"signed"`
	Signer      string    `json:"signer"`
}

type Event struct {
	ID       string      `json:"id"`
	Kind     EventKind   `json:"kind"`
	Time     time.Time   `json:"time"`
	Process  *Process    `json:"process,omitempty"`
	Path     string      `json:"path,omitempty"`
	OldPath  string      `json:"old_path,omitempty"`
	Access   string      `json:"access,omitempty"`
	Registry *RegistryOp `json:"registry,omitempty"`
	Network  *NetConn    `json:"network,omitempty"`

	Module string `json:"module,omitempty"`

	Match  string `json:"match,omitempty"`
	Source string `json:"source"`
}

type RegistryOp struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Data  string `json:"data"`
}

type NetConn struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	RemoteHost string `json:"remote_host"`
	RemotePort uint16 `json:"remote_port"`
}

type Verdict struct {
	ID          string     `json:"id"`
	Time        time.Time  `json:"time"`
	Severity    Severity   `json:"severity"`
	Threat      ThreatType `json:"threat"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Process     *Process   `json:"process,omitempty"`

	Path string `json:"path"`

	TargetPath  string   `json:"target_path,omitempty"`
	Evidence    []string `json:"evidence"`
	Action      Action   `json:"action"`
	ActionTaken bool     `json:"action_taken"`

	ActionDetail string `json:"action_detail,omitempty"`
	QuarantineID string `json:"quarantine_id,omitempty"`

	Source string `json:"source,omitempty"`
}

type ScanRequest struct {
	Type  string   `json:"type"`
	Paths []string `json:"paths"`
}

type ScanProgress struct {
	ScanID     string  `json:"scan_id"`
	FilesDone  int64   `json:"files_done"`
	FilesTotal int64   `json:"files_total"`
	Percent    float64 `json:"percent"`
	Current    string  `json:"current"`
	Threats    int64   `json:"threats"`
}

type Status struct {
	RealTimeActive   bool      `json:"real_time_active"`
	SignatureCount   int       `json:"signature_count"`
	SignatureVersion string    `json:"signature_version"`
	Monitors         []string  `json:"monitors"`
	ThreatsToday     int       `json:"threats_today"`
	ThreatsBlocked   int       `json:"threats_blocked"`
	LastScan         time.Time `json:"last_scan"`
	StartedAt        time.Time `json:"started_at"`
	DBPath           string    `json:"db_path"`
	QuarantineCount  int       `json:"quarantine_count"`
	Whitelisted      int       `json:"whitelisted"`
	WscRegistered    bool      `json:"wsc_registered"`
	Drives           []string  `json:"drives,omitempty"`
}
