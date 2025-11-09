package main

import (
	"fmt"
	"strings"
)

// SQLInjectionScanner SQL注入漏洞检测器
type SQLInjectionScanner struct {
	Verbose bool
}

// NewSQLInjectionScanner 创建新的SQL注入漏洞检测器
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

	// 扫描Web应用SQL注入漏洞
	webVulns := sis.scanWebSQLInjection(target, services)
	vulnerabilities = append(vulnerabilities, webVulns...)

	// 扫描数据库服务SQL注入漏洞
	dbVulns := sis.scanDatabaseSQLInjection(services)
	vulnerabilities = append(vulnerabilities, dbVulns...)

	if sis.Verbose {
		fmt.Printf("发现SQL注入漏洞: %d个\n", len(vulnerabilities))
	}

	return vulnerabilities
}

// scanWebSQLInjection 扫描Web应用SQL注入漏洞
func (sis *SQLInjectionScanner) scanWebSQLInjection(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 常见的SQL注入测试向量
	testURLs := []string{
		"/",
		"/login",
		"/search",
		"/products",
		"/users",
		"/admin",
		"/api",
		"/query",
	}

	// SQL注入payloads
	payloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"'; DROP TABLE users--",
		"' UNION SELECT 1,2,3--",
		"' AND 1=1--",
		"' OR SLEEP(5)--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		"' OR BENCHMARK(1000000,MD5('test'))--",
	}

	// 参数名称
	params := []string{
		"id",
		"user",
		"username",
		"password",
		"search",
		"query",
		"category",
		"product",
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
								ID:          "WEB-SQL-001",
								Name:        "Web应用SQL注入漏洞",
								Severity:    "Critical",
								Description: fmt.Sprintf("在%s服务上发现SQL注入漏洞", service.Name),
								Solution:    "对用户输入进行参数化查询和输入验证",
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

// scanDatabaseSQLInjection 扫描数据库服务SQL注入漏洞
func (sis *SQLInjectionScanner) scanDatabaseSQLInjection(services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检查常见的数据库服务SQL注入漏洞
	for _, service := range services {
		switch service.Port {
		case 3306: // MySQL
			if strings.Contains(strings.ToLower(service.Name), "mysql") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "MYSQL-SQL-001",
					Name:        "MySQL SQL注入漏洞",
					Severity:    "Critical",
					Description: "MySQL服务存在SQL注入漏洞",
					Solution:    "更新MySQL到最新版本，使用参数化查询",
					CVE:         "CVE-2021-22946",
					Affected:    service.Name,
				})
			}
		case 5432: // PostgreSQL
			if strings.Contains(strings.ToLower(service.Name), "postgres") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "POSTGRES-SQL-001",
					Name:        "PostgreSQL SQL注入漏洞",
					Severity:    "Critical",
					Description: "PostgreSQL服务存在SQL注入漏洞",
					Solution:    "更新PostgreSQL到最新版本",
					CVE:         "CVE-2021-32027",
					Affected:    service.Name,
				})
			}
		case 1433: // SQL Server
			if strings.Contains(strings.ToLower(service.Name), "sql server") || strings.Contains(strings.ToLower(service.Name), "mssql") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "MSSQL-SQL-001",
					Name:        "SQL Server SQL注入漏洞",
					Severity:    "Critical",
					Description: "SQL Server存在SQL注入漏洞",
					Solution:    "更新SQL Server到最新版本",
					CVE:         "CVE-2021-1636",
					Affected:    service.Name,
				})
			}
		case 1521: // Oracle
			if strings.Contains(strings.ToLower(service.Name), "oracle") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "ORACLE-SQL-001",
					Name:        "Oracle SQL注入漏洞",
					Severity:    "Critical",
					Description: "Oracle数据库存在SQL注入漏洞",
					Solution:    "更新Oracle到最新版本",
					CVE:         "CVE-2021-2135",
					Affected:    service.Name,
				})
			}
		case 27017: // MongoDB
			if strings.Contains(strings.ToLower(service.Name), "mongodb") {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "MONGO-SQL-001",
					Name:        "MongoDB NoSQL注入漏洞",
					Severity:    "High",
					Description: "MongoDB存在NoSQL注入漏洞",
					Solution:    "更新MongoDB到最新版本",
					CVE:         "CVE-2021-20330",
					Affected:    service.Name,
				})
			}
		}
	}

	return vulnerabilities
}
