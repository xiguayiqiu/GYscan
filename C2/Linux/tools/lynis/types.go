package lynis

import "time"

// AuditResult 安全审计结果
type AuditResult struct {
	Timestamp    time.Time         `json:"timestamp"`
	SystemInfo   SystemInfo        `json:"system_info"`
	Tests        []SecurityTest    `json:"tests"`
	Findings     []SecurityFinding `json:"findings"`
	Summary      AuditSummary      `json:"summary"`
	ScanDuration time.Duration     `json:"scan_duration"`
}

// SystemInfo 系统信息
type SystemInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	KernelVersion string `json:"kernel_version"`
	Architecture  string `json:"architecture"`
	Uptime        string `json:"uptime"`
	CPUCount      int    `json:"cpu_count"`
	MemoryTotal   string `json:"memory_total"`
	DiskUsage     string `json:"disk_usage"`
}

// SecurityTest 安全测试项
type SecurityTest struct {
	ID          string            `json:"id"`
	Category    string            `json:"category"`
	Group       string            `json:"group"`
	Description string            `json:"description"`
	Status      TestStatus        `json:"status"`
	Severity    SeverityLevel     `json:"severity"`
	Details     map[string]string `json:"details"`
	Timestamp   time.Time         `json:"timestamp"`
}

// SecurityFinding 安全发现
type SecurityFinding struct {
	ID          string        `json:"id"`
	TestID      string        `json:"test_id"`
	Category    string        `json:"category"`
	Severity    SeverityLevel `json:"severity"`
	Description string        `json:"description"`
	Recommendation string     `json:"recommendation"`
	Evidence    string        `json:"evidence"`
	Timestamp   time.Time     `json:"timestamp"`
}

// AuditSummary 审计摘要
type AuditSummary struct {
	TotalTests    int `json:"total_tests"`
	PassedTests   int `json:"passed_tests"`
	FailedTests   int `json:"failed_tests"`
	WarningTests  int `json:"warning_tests"`
	SkippedTests  int `json:"skipped_tests"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings       int `json:"low_findings"`
	InfoFindings      int `json:"info_findings"`
}

// TestStatus 测试状态类型
type TestStatus string

const (
	TestStatusPassed  TestStatus = "passed"
	TestStatusFailed  TestStatus = "failed"
	TestStatusWarning TestStatus = "warning"
	TestStatusSkipped TestStatus = "skipped"
	TestStatusError   TestStatus = "error"
)

// SeverityLevel 严重级别类型
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityInfo     SeverityLevel = "info"
)

// TestCategory 测试分类
const (
	CategoryAuthentication = "authentication"
	CategoryBootServices   = "boot_services"
	CategoryContainers     = "containers"
	CategoryCrypto        = "crypto"
	CategoryDatabases     = "databases"
	CategoryDNS          = "dns"
	CategoryFileIntegrity = "file_integrity"
	CategoryFilePermissions = "file_permissions"
	CategoryFilesystems  = "filesystems"
	CategoryFirewalls    = "firewalls"
	CategoryHardening    = "hardening"
	CategoryHomedirs     = "homedirs"
	CategoryInsecureServices = "insecure_services"
	CategoryKernel       = "kernel"
	CategoryLogging      = "logging"
	CategoryMail         = "mail"
	CategoryMemoryProtection = "memory_protection"
	CategoryNetworking   = "networking"
	CategoryProcesses    = "processes"
	CategorySoftware     = "software"
	CategoryStorage      = "storage"
	CategorySystemIntegrity = "system_integrity"
	CategoryTime         = "time"
	CategoryTools        = "tools"
	CategoryVirtualization = "virtualization"
	CategoryWebservers   = "webservers"
)