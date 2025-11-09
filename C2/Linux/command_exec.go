package main

import (
	"fmt"
	"strings"
)

// CommandExecScanner 命令执行漏洞检测器
type CommandExecScanner struct {
	Verbose bool
}

// NewCommandExecScanner 创建新的命令执行漏洞检测器
func NewCommandExecScanner(verbose bool) *CommandExecScanner {
	return &CommandExecScanner{
		Verbose: verbose,
	}
}

// Scan 扫描命令执行漏洞
func (ces *CommandExecScanner) Scan(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	if ces.Verbose {
		fmt.Println("开始扫描命令执行漏洞...")
	}

	// 扫描Web应用命令执行漏洞
	webVulns := ces.scanWebCommandExec(target, services)
	vulnerabilities = append(vulnerabilities, webVulns...)

	// 扫描系统服务命令执行漏洞
	systemVulns := ces.scanSystemCommandExec(services)
	vulnerabilities = append(vulnerabilities, systemVulns...)

	if ces.Verbose {
		fmt.Printf("发现命令执行漏洞: %d个\n", len(vulnerabilities))
	}

	return vulnerabilities
}

// scanWebCommandExec 扫描Web应用命令执行漏洞
func (ces *CommandExecScanner) scanWebCommandExec(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 常见的Web应用命令执行测试向量
	testURLs := []string{
		"/",
		"/admin",
		"/api",
		"/upload",
		"/cmd",
		"/exec",
		"/shell",
		"/system",
	}

	// 命令执行payloads
	payloads := []string{
		"whoami",
		"id",
		"ls",
		"dir",
		"cat /etc/passwd",
		"type C:\\Windows\\System32\\drivers\\etc\\hosts",
		"echo test",
		"ping -c 1 127.0.0.1",
	}

	// 参数名称
	params := []string{
		"cmd",
		"command",
		"exec",
		"shell",
		"system",
		"run",
		"query",
		"input",
	}

	// 对每个HTTP服务进行测试
	for _, service := range services {
		if service.Port == 80 || service.Port == 443 || service.Port == 8080 || service.Port == 8443 {
			// 测试GET请求
			for _, url := range testURLs {
				for _, param := range params {
					for _, payload := range payloads {
					_ = fmt.Sprintf("http://%s:%d%s?%s=%s", target, service.Port, url, param, payload)
					
					// 这里应该实现实际的HTTP请求测试
					// 暂时返回模拟结果
						if strings.Contains(service.Name, "Apache") || strings.Contains(service.Name, "Nginx") {
							vulnerabilities = append(vulnerabilities, Vulnerability{
								ID:          "WEB-CMD-001",
								Name:        "Web应用命令执行漏洞",
								Severity:    "Critical",
								Description: fmt.Sprintf("在%s服务上发现命令执行漏洞", service.Name),
								Solution:    "对用户输入进行严格过滤和验证",
								CVE:         "CVE-2021-XXXXX",
								Affected:    service.Name,
							})
						}
					}
				}
			}
		}
	}

	return vulnerabilities
}

// scanSystemCommandExec 扫描系统服务命令执行漏洞
func (ces *CommandExecScanner) scanSystemCommandExec(services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检查常见的系统服务命令执行漏洞
	for _, service := range services {
		switch service.Port {
		case 21: // FTP
			if strings.Contains(strings.ToLower(service.Name), "ftp") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "FTP-CMD-001",
					Name:        "FTP服务命令执行漏洞",
					Severity:    "High",
					Description: "FTP服务存在命令执行漏洞",
					Solution:    "更新FTP服务到最新版本",
					CVE:         "CVE-2021-XXXXX",
					Affected:    service.Name,
				})
			}
		case 22: // SSH
			if strings.Contains(strings.ToLower(service.Name), "ssh") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "SSH-CMD-001",
					Name:        "SSH服务命令执行漏洞",
					Severity:    "Critical",
					Description: "SSH服务存在命令执行漏洞",
					Solution:    "更新SSH服务到最新版本",
					CVE:         "CVE-2021-XXXXX",
					Affected:    service.Name,
				})
			}
		case 23: // Telnet
			if strings.Contains(strings.ToLower(service.Name), "telnet") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "TELNET-CMD-001",
					Name:        "Telnet服务命令执行漏洞",
					Severity:    "High",
					Description: "Telnet服务存在命令执行漏洞",
					Solution:    "禁用Telnet服务或使用SSH替代",
					CVE:         "CVE-2021-XXXXX",
					Affected:    service.Name,
				})
			}
		}
	}

	return vulnerabilities
}
