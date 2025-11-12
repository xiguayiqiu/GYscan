package audit

import (
	"time"
)

// AuditLevel 审计级别
type AuditLevel string

const (
	AuditLevelLow    AuditLevel = "low"
	AuditLevelMedium AuditLevel = "medium"
	AuditLevelHigh   AuditLevel = "high"
)

// AuditResult 审计结果
type AuditResult struct {
	ModuleName     string      `json:"module_name"`
	CheckName      string      `json:"check_name"`
	Level          AuditLevel  `json:"level"`
	Status         string      `json:"status"`      // pass, fail, warning, error
	Description    string      `json:"description"`
	Details        interface{} `json:"details"`
	RiskScore      int         `json:"risk_score"` // 0-100
	Recommendation string      `json:"recommendation"`
	Remediation    string      `json:"remediation"`
	Impact         string      `json:"impact"`
	Evidence       string      `json:"evidence"`
	Category       string      `json:"category"`
	Timestamp      time.Time   `json:"timestamp"`
	ReferenceID    string      `json:"reference_id"`
}

// AuditModule 审计模块接口
type AuditModule interface {
	Name() string
	Description() string
	Run() ([]AuditResult, error)
	RequiredPermissions() []string
}

// EventLogEntry 事件日志条目
type EventLogEntry struct {
	EventID     int       `json:"event_id"`
	Level       string    `json:"level"`
	Source      string    `json:"source"`
	TimeCreated time.Time `json:"time_created"`
	Message     string    `json:"message"`
	Data        []byte    `json:"data"`
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	PID         int32     `json:"pid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	Owner       string    `json:"owner"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemoryMB    float64   `json:"memory_mb"`
	CreateTime  time.Time `json:"create_time"`
}

// NetworkConnection 网络连接信息
type NetworkConnection struct {
	Protocol    string    `json:"protocol"`
	LocalAddr   string    `json:"local_addr"`
	LocalPort   int       `json:"local_port"`
	RemoteAddr  string    `json:"remote_addr"`
	RemotePort  int       `json:"remote_port"`
	State       string    `json:"state"`
	PID         int32     `json:"pid"`
	ProcessName string    `json:"process_name"`
}

// FileInfo 文件信息
type FileInfo struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	Permissions  string    `json:"permissions"`
	Owner        string    `json:"owner"`
	Group        string    `json:"group"`
	ModifiedTime time.Time `json:"modified_time"`
	Hash         string    `json:"hash"`
}

// RegistryEntry 注册表条目
type RegistryEntry struct {
	Path    string      `json:"path"`
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Value   interface{} `json:"value"`
	Owner   string      `json:"owner"`
	ACL     string      `json:"acl"`
}

// UserAccount 用户账户信息
type UserAccount struct {
	Name        string   `json:"name"`
	SID         string   `json:"sid"`
	FullName    string   `json:"full_name"`
	Description string   `json:"description"`
	Groups      []string `json:"groups"`
	IsAdmin     bool     `json:"is_admin"`
	IsDisabled  bool     `json:"is_disabled"`
	LastLogon   string   `json:"last_logon"`
}

// PasswordPolicy 密码策略
type PasswordPolicy struct {
	MinPasswordLength                  int  `json:"min_password_length"`
	PasswordComplexity                bool `json:"password_complexity"`
	MaxPasswordAge                    int  `json:"max_password_age"`
	MinPasswordAge                    int  `json:"min_password_age"`
	PasswordHistorySize               int  `json:"password_history_size"`
	StorePasswordUsingReversibleEncryption bool `json:"store_password_using_reversible_encryption"`
}

// AccountLockoutPolicy 账户锁定策略
type AccountLockoutPolicy struct {
	LockoutThreshold int `json:"lockout_threshold"`
	LockoutDuration   int `json:"lockout_duration"`
	ResetAfter        int `json:"reset_after"`
}

// SecurityPolicy 安全策略信息
type SecurityPolicy struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Compliance  string `json:"compliance"` // compliant, non-compliant, unknown
}

// AuditReport 审计报告
type AuditReport struct {
	SystemInfo   SystemInfo     `json:"system_info"`
	Results      []AuditResult  `json:"results"`
	Summary      AuditSummary   `json:"summary"`
	Timestamp    time.Time      `json:"timestamp"`
	Duration     time.Duration  `json:"duration"`
}

// SystemInfo 系统信息
type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Domain       string `json:"domain"`
	CurrentUser  string `json:"current_user"`
	IsAdmin      bool   `json:"is_admin"`
}

// AuditSummary 审计摘要
type AuditSummary struct {
	TotalChecks  int `json:"total_checks"`
	Passed       int `json:"passed"`
	Failed       int `json:"failed"`
	Warnings     int `json:"warnings"`
	Errors       int `json:"errors"`
	RiskScore    int `json:"risk_score"`
}

// Config 审计配置
type Config struct {
	Modules          []string `json:"modules"`
	OutputFormat     string   `json:"output_format"` // json, html, text
	OutputFile       string   `json:"output_file"`
	Verbose          bool     `json:"verbose"`
	IncludeDetails   bool     `json:"include_details"`
	EventLogDays     int      `json:"event_log_days"`
	NetworkTimeout   int      `json:"network_timeout"`
	FileHashAlgo     string   `json:"file_hash_algo"` // md5, sha1, sha256
}