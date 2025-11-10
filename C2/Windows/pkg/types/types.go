package types

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Solution    string
	CVE         string
	Affected    string
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name            string
	Port            int
	Protocol        string
	Status          string
	Version         string
	Vulnerabilities []Vulnerability
}

// ProgramInfo 程序信息
type ProgramInfo struct {
	Name            string
	Version         string
	Path            string
	Vulnerabilities []Vulnerability
}

// SecurityConfig 安全配置信息
type SecurityConfig struct {
	Category    string
	Setting     string
	Value       string
	Recommended string
	Compliant   bool
}