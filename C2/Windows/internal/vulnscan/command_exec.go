package vulnscan

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CommandExecScanner 命令执行漏洞扫描器
type CommandExecScanner struct {
	Verbose bool
}

// NewCommandExecScanner 创建新的命令执行漏洞扫描器
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

	// 检测Web应用命令执行漏洞
	for _, service := range services {
		if service.Service == "HTTP" {
			webVulns := ces.scanWebCommandExec(target, service.Port)
			vulnerabilities = append(vulnerabilities, webVulns...)
		}
	}

	// 检测系统服务命令执行漏洞
	systemVulns := ces.scanSystemCommandExec(services)
	vulnerabilities = append(vulnerabilities, systemVulns...)

	if ces.Verbose {
		fmt.Printf("发现命令执行漏洞: %d个\n", len(vulnerabilities))
	}

	return vulnerabilities
}

// scanWebCommandExec 扫描Web应用命令执行漏洞
func (ces *CommandExecScanner) scanWebCommandExec(target string, port int) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 常见命令执行漏洞检测点
	testURLs := []string{
		"/",
		"/index.php",
		"/admin/",
		"/upload/",
		"/api/",
	}

	// 常见命令执行payload
	payloads := []string{
		"whoami",
		"dir",
		"ls",
		"id",
		"echo test",
	}

	// 常见命令执行参数
	params := []string{
		"cmd",
		"command",
		"exec",
		"system",
		"shell",
		"query",
		"q",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, testURL := range testURLs {
		for _, param := range params {
			for _, payload := range payloads {
				// 构建测试URL
				baseURL := fmt.Sprintf("http://%s:%d%s", target, port, testURL)
				
				// GET请求测试
				getURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
				if ces.testCommandExec(client, getURL, payload) {
					vulnerabilities = append(vulnerabilities, Vulnerability{
						ID:          "CMD-EXEC-001",
						Name:        "Web应用命令执行漏洞",
						Severity:    "Critical",
						Description: fmt.Sprintf("在 %s 发现命令执行漏洞，参数: %s", testURL, param),
						Solution:    "对用户输入进行严格过滤和验证",
						CVE:         "CVE-2021-XXXXX",
						Affected:    "Web应用程序",
						Confidence:  85,
					})
				}

				// POST请求测试
				postData := url.Values{}
				postData.Set(param, payload)
				if ces.testPostCommandExec(client, baseURL, postData, payload) {
					vulnerabilities = append(vulnerabilities, Vulnerability{
						ID:          "CMD-EXEC-002",
						Name:        "Web应用POST命令执行漏洞",
						Severity:    "Critical",
						Description: fmt.Sprintf("在 %s 发现POST命令执行漏洞，参数: %s", testURL, param),
						Solution:    "对POST参数进行严格过滤和验证",
						CVE:         "CVE-2021-XXXXX",
						Affected:    "Web应用程序",
						Confidence:  80,
					})
				}
			}
		}
	}

	return vulnerabilities
}

// testCommandExec 测试GET请求命令执行漏洞
func (ces *CommandExecScanner) testCommandExec(client *http.Client, url, payload string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 简单的响应内容检测
	// 在实际应用中应该使用更复杂的检测逻辑
	return ces.checkResponseForCommandExec(resp, payload)
}

// testPostCommandExec 测试POST请求命令执行漏洞
func (ces *CommandExecScanner) testPostCommandExec(client *http.Client, url string, data url.Values, payload string) bool {
	resp, err := client.PostForm(url, data)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return ces.checkResponseForCommandExec(resp, payload)
}

// checkResponseForCommandExec 检查响应是否包含命令执行特征
func (ces *CommandExecScanner) checkResponseForCommandExec(resp *http.Response, payload string) bool {
	// 这里应该实现更复杂的检测逻辑
	// 目前使用简单的关键词匹配
	
	// 读取响应内容（简化版）
	// 在实际应用中应该完整读取并分析响应
	
	// 检查状态码
	if resp.StatusCode != 200 {
		return false
	}

	// 检查响应头
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || 
	   strings.Contains(contentType, "text/plain") {
		// 这里应该实现实际的内容分析
		return false
	}

	return false
}

// scanSystemCommandExec 扫描系统服务命令执行漏洞
func (ces *CommandExecScanner) scanSystemCommandExec(services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		switch service.Service {
		case "FTP":
			// 检测FTP命令执行漏洞
			if ces.checkFTPCommandExec(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "FTP-CMD-001",
					Name:        "FTP服务命令执行漏洞",
					Severity:    "High",
					Description: "FTP服务存在命令执行漏洞",
					Solution:    "升级FTP服务到最新版本",
					CVE:         "CVE-2021-XXXXX",
					Affected:    "FTP服务器",
					Confidence:  70,
				})
			}
		case "SSH":
			// 检测SSH命令执行漏洞
			if ces.checkSSHCommandExec(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "SSH-CMD-001",
					Name:        "SSH服务命令执行漏洞",
					Severity:    "Critical",
					Description: "SSH服务存在命令执行漏洞",
					Solution:    "升级SSH服务到最新版本",
					CVE:         "CVE-2021-XXXXX",
					Affected:    "SSH服务器",
					Confidence:  75,
				})
			}
		}
	}

	return vulnerabilities
}

// checkFTPCommandExec 检查FTP命令执行漏洞
func (ces *CommandExecScanner) checkFTPCommandExec(service ServiceInfo) bool {
	// 检查FTP版本是否存在已知漏洞
	if strings.Contains(service.Version, "2.3.4") {
		return true
	}
	return false
}

// checkSSHCommandExec 检查SSH命令执行漏洞
func (ces *CommandExecScanner) checkSSHCommandExec(service ServiceInfo) bool {
	// 检查SSH版本是否存在已知漏洞
	if strings.Contains(service.Version, "7.2") {
		return true
	}
	return false
}

// detectCommonCommandExecPatterns 检测常见命令执行模式
func (ces *CommandExecScanner) detectCommonCommandExecPatterns() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "CMD-PATTERN-001",
			Name:        "系统命令注入漏洞",
			Severity:    "Critical",
			Description: "应用程序存在系统命令注入漏洞",
			Solution:    "使用安全的API替代系统命令调用",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "应用程序",
			Confidence:  90,
		},
		{
			ID:          "CMD-PATTERN-002",
			Name:        "代码注入漏洞",
			Severity:    "High",
			Description: "应用程序存在代码注入漏洞",
			Solution:    "对用户输入进行严格验证和过滤",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "应用程序",
			Confidence:  85,
		},
	}
}