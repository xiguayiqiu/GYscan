package types

import "time"

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

// ScanResult 扫描结果
type ScanResult struct {
	Target        string
	Timestamp     time.Time
	ScanDuration  time.Duration
	OSInfo        string
	Distribution  string
	Vulnerabilities []Vulnerability
	Services      []ServiceInfo
	Programs      []ProgramInfo
}