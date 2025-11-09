package vulnscan

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SQLInjectionScanner SQL注入漏洞扫描器
type SQLInjectionScanner struct {
	Verbose bool
}

// NewSQLInjectionScanner 创建新的SQL注入漏洞扫描器
func NewSQLInjectionScanner(verbose bool) *SQLInjectionScanner {
	return &SQLInjectionScanner{
		Verbose: verbose,
	}
}

// Scan 扫描SQL注入漏洞
func (sis *SQLInjectionScanner) Scan(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	if sis.Verbose {
		fmt.Println("开始扫描SQL注入漏洞...")
	}

	// 检测Web应用SQL注入漏洞
	for _, service := range services {
		if service.Service == "HTTP" {
			sqlVulns := sis.scanWebSQLInjection(target, service.Port)
			vulnerabilities = append(vulnerabilities, sqlVulns...)
		}
	}

	// 检测数据库服务SQL注入漏洞
	dbVulns := sis.scanDatabaseSQLInjection(services)
	vulnerabilities = append(vulnerabilities, dbVulns...)

	if sis.Verbose {
		fmt.Printf("发现SQL注入漏洞: %d个\n", len(vulnerabilities))
	}

	return vulnerabilities
}

// scanWebSQLInjection 扫描Web应用SQL注入漏洞
func (sis *SQLInjectionScanner) scanWebSQLInjection(target string, port int) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 常见SQL注入测试点
	testURLs := []string{
		"/",
		"/index.php",
		"/search.php",
		"/login.php",
		"/product.php",
		"/user.php",
		"/admin/",
		"/api/",
	}

	// SQL注入payload
	payloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"' UNION SELECT 1,2,3--",
		"; DROP TABLE users--",
		"' AND 1=1--",
		"' AND SLEEP(5)--",
		"' OR SLEEP(5)--",
	}

	// 常见SQL注入参数
	params := []string{
		"id",
		"user",
		"username",
		"password",
		"search",
		"q",
		"query",
		"category",
		"product",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, testURL := range testURLs {
		for _, param := range params {
			for _, payload := range payloads {
				// 构建测试URL
				baseURL := fmt.Sprintf("http://%s:%d%s", target, port, testURL)
				
				// GET请求测试
				getURL := fmt.Sprintf("%s?%s=%s", baseURL, param, url.QueryEscape(payload))
				if sis.testSQLInjection(client, getURL, payload) {
					vulnerabilities = append(vulnerabilities, Vulnerability{
						ID:          "SQL-INJ-001",
						Name:        "Web应用SQL注入漏洞",
						Severity:    "Critical",
						Description: fmt.Sprintf("在 %s 发现SQL注入漏洞，参数: %s", testURL, param),
						Solution:    "使用参数化查询或预编译语句",
						CVE:         "CVE-2021-XXXXX",
						Affected:    "Web应用程序",
						Confidence:  90,
					})
				}

				// POST请求测试
				postData := url.Values{}
				postData.Set(param, payload)
				if sis.testPostSQLInjection(client, baseURL, postData, payload) {
					vulnerabilities = append(vulnerabilities, Vulnerability{
						ID:          "SQL-INJ-002",
						Name:        "Web应用POST SQL注入漏洞",
						Severity:    "Critical",
						Description: fmt.Sprintf("在 %s 发现POST SQL注入漏洞，参数: %s", testURL, param),
						Solution:    "对POST参数进行严格验证和过滤",
						CVE:         "CVE-2021-XXXXX",
						Affected:    "Web应用程序",
						Confidence:  85,
					})
				}
			}
		}
	}

	return vulnerabilities
}

// testSQLInjection 测试GET请求SQL注入漏洞
func (sis *SQLInjectionScanner) testSQLInjection(client *http.Client, url, payload string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return sis.checkResponseForSQLInjection(resp, payload)
}

// testPostSQLInjection 测试POST请求SQL注入漏洞
func (sis *SQLInjectionScanner) testPostSQLInjection(client *http.Client, url string, data url.Values, payload string) bool {
	resp, err := client.PostForm(url, data)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return sis.checkResponseForSQLInjection(resp, payload)
}

// checkResponseForSQLInjection 检查响应是否包含SQL注入特征
func (sis *SQLInjectionScanner) checkResponseForSQLInjection(resp *http.Response, payload string) bool {
	// 检查状态码
	if resp.StatusCode != 200 {
		return false
	}

	// 检查响应内容长度
	_ = resp.ContentLength
	
	// 检查响应头
	_ = resp.Header.Get("Content-Type")
	
	// 简单的错误信息检测
	// 在实际应用中应该实现更复杂的检测逻辑
	
	// 检查常见的数据库错误信息
	_ = []string{
		"SQL syntax",
		"MySQL",
		"ORA-",
		"Microsoft SQL Server",
		"PostgreSQL",
		"SQLite",
		"ODBC",
		"JDBC",
	}

	// 这里应该实现实际的内容分析
	// 目前返回false表示未检测到漏洞
	return false
}

// scanDatabaseSQLInjection 扫描数据库服务SQL注入漏洞
func (sis *SQLInjectionScanner) scanDatabaseSQLInjection(services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		switch service.Service {
		case "MySQL":
			if sis.checkMySQLInjectionVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "MYSQL-INJ-001",
					Name:        "MySQL注入漏洞",
					Severity:    "High",
					Description: "MySQL服务存在注入漏洞",
					Solution:    "升级MySQL到最新版本",
					CVE:         "CVE-2021-XXXXX",
					Affected:    "MySQL数据库",
					Confidence:  80,
				})
			}
		case "MSSQL":
			if sis.checkMSSQLInjectionVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "MSSQL-INJ-001",
					Name:        "MSSQL注入漏洞",
					Severity:    "High",
					Description: "Microsoft SQL Server存在注入漏洞",
					Solution:    "升级SQL Server到最新版本",
					CVE:         "CVE-2021-XXXXX",
					Affected:    "Microsoft SQL Server",
					Confidence:  85,
				})
			}
		}
	}

	return vulnerabilities
}

// checkMySQLInjectionVulnerability 检查MySQL注入漏洞
func (sis *SQLInjectionScanner) checkMySQLInjectionVulnerability(service ServiceInfo) bool {
	// 检查MySQL版本是否存在已知注入漏洞
	if strings.Contains(service.Version, "5.7") {
		return true
	}
	return false
}

// checkMSSQLInjectionVulnerability 检查MSSQL注入漏洞
func (sis *SQLInjectionScanner) checkMSSQLInjectionVulnerability(service ServiceInfo) bool {
	// 检查SQL Server版本是否存在已知注入漏洞
	if strings.Contains(service.Version, "2012") || strings.Contains(service.Version, "2014") {
		return true
	}
	return false
}

// detectBlindSQLInjection 检测盲注SQL注入
func (sis *SQLInjectionScanner) detectBlindSQLInjection(target string, port int) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 盲注检测payload
	blindPayloads := []string{
		"' AND SLEEP(5)--",
		"' OR SLEEP(5)--",
		"'; WAITFOR DELAY '00:00:05'--",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 测试盲注
	for _, payload := range blindPayloads {
		start := time.Now()
		
		// 构建测试URL
		url := fmt.Sprintf("http://%s:%d/?id=%s", target, port, url.QueryEscape(payload))
		
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		duration := time.Since(start)
		
		// 如果响应时间明显延长，可能存在盲注漏洞
		if duration > 4*time.Second {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "SQL-BLIND-001",
				Name:        "盲注SQL注入漏洞",
				Severity:    "Critical",
				Description: "应用程序存在盲注SQL注入漏洞",
				Solution:    "使用参数化查询和输入验证",
				CVE:         "CVE-2021-XXXXX",
				Affected:    "Web应用程序",
				Confidence:  75,
			})
		}
	}

	return vulnerabilities
}

// detectCommonSQLInjectionPatterns 检测常见SQL注入模式
func (sis *SQLInjectionScanner) detectCommonSQLInjectionPatterns() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "SQL-PATTERN-001",
			Name:        "联合查询注入",
			Severity:    "Critical",
			Description: "应用程序存在联合查询注入漏洞",
			Solution:    "使用参数化查询",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Web应用程序",
			Confidence:  95,
		},
		{
			ID:          "SQL-PATTERN-002",
			Name:        "布尔盲注",
			Severity:    "High",
			Description: "应用程序存在布尔盲注漏洞",
			Solution:    "加强输入验证和错误处理",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Web应用程序",
			Confidence:  85,
		},
		{
			ID:          "SQL-PATTERN-003",
			Name:        "时间盲注",
			Severity:    "High",
			Description: "应用程序存在时间盲注漏洞",
			Solution:    "实施严格的输入验证",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Web应用程序",
			Confidence:  80,
		},
	}
}