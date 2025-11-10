package utils

import (
	"GYscan-Win-C2/pkg/types"
)

// DetectMiddlewareVulnerabilities 检测中间件漏洞
func DetectMiddlewareVulnerabilities() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检测Web服务器漏洞
	vulnerabilities = append(vulnerabilities, detectWebServerVulnerabilities()...)
	
	// 检测数据库漏洞
	vulnerabilities = append(vulnerabilities, detectDatabaseVulnerabilities()...)
	
	// 检测应用服务器漏洞
	vulnerabilities = append(vulnerabilities, detectApplicationServerVulnerabilities()...)

	return vulnerabilities
}

// detectWebServerVulnerabilities 检测Web服务器漏洞
func detectWebServerVulnerabilities() []types.Vulnerability {
	return []types.Vulnerability{
		{
			ID:          "WEB-001",
			Name:        "Apache Struts2远程代码执行漏洞",
			Severity:    "Critical",
			Description: "Apache Struts2存在OGNL表达式注入漏洞",
			Solution:    "升级到Struts 2.5.26或更高版本",
			CVE:         "CVE-2021-31805",
			Affected:    "Apache Struts2",
		},
		{
			ID:          "WEB-002",
			Name:        "Nginx路径遍历漏洞",
			Severity:    "High",
			Description: "Nginx存在路径遍历漏洞",
			Solution:    "升级到Nginx 1.20.1或更高版本",
			CVE:         "CVE-2021-23017",
			Affected:    "Nginx",
		},
		{
			ID:          "WEB-003",
			Name:        "IIS远程代码执行漏洞",
			Severity:    "Critical",
			Description: "IIS存在远程代码执行漏洞",
			Solution:    "安装最新的Windows更新",
			CVE:         "CVE-2021-31166",
			Affected:    "Microsoft IIS",
		},
		{
			ID:          "WEB-004",
			Name:        "Tomcat文件包含漏洞",
			Severity:    "High",
			Description: "Apache Tomcat存在文件包含漏洞",
			Solution:    "升级到Tomcat 9.0.46或更高版本",
			CVE:         "CVE-2021-24122",
			Affected:    "Apache Tomcat",
		},
	}
}

// detectDatabaseVulnerabilities 检测数据库漏洞
func detectDatabaseVulnerabilities() []types.Vulnerability {
	return []types.Vulnerability{
		{
			ID:          "DB-001",
			Name:        "MySQL权限提升漏洞",
			Severity:    "High",
			Description: "MySQL存在权限提升漏洞",
			Solution:    "升级到MySQL 8.0.23或更高版本",
			CVE:         "CVE-2021-22946",
			Affected:    "MySQL",
		},
		{
			ID:          "DB-002",
			Name:        "PostgreSQL代码执行漏洞",
			Severity:    "Critical",
			Description: "PostgreSQL存在代码执行漏洞",
			Solution:    "升级到PostgreSQL 13.3或更高版本",
			CVE:         "CVE-2021-32027",
			Affected:    "PostgreSQL",
		},
		{
			ID:          "DB-003",
			Name:        "MongoDB注入漏洞",
			Severity:    "High",
			Description: "MongoDB存在NoSQL注入漏洞",
			Solution:    "升级到MongoDB 4.4.9或更高版本",
			CVE:         "CVE-2021-20330",
			Affected:    "MongoDB",
		},
		{
			ID:          "DB-004",
			Name:        "Redis未授权访问漏洞",
			Severity:    "Critical",
			Description: "Redis存在未授权访问漏洞",
			Solution:    "配置Redis认证和网络访问控制",
			CVE:         "CVE-2021-32761",
			Affected:    "Redis",
		},
		{
			ID:          "DB-005",
			Name:        "SQL Server远程代码执行漏洞",
			Severity:    "Critical",
			Description: "Microsoft SQL Server存在远程代码执行漏洞",
			Solution:    "安装最新的SQL Server更新",
			CVE:         "CVE-2021-1636",
			Affected:    "Microsoft SQL Server",
		},
	}
}

// detectApplicationServerVulnerabilities 检测应用服务器漏洞
func detectApplicationServerVulnerabilities() []types.Vulnerability {
	return []types.Vulnerability{
		{
			ID:          "APP-001",
			Name:        "WebLogic反序列化漏洞",
			Severity:    "Critical",
			Description: "Oracle WebLogic存在反序列化远程代码执行漏洞",
			Solution:    "升级到WebLogic 14.1.1.0.0或应用补丁",
			CVE:         "CVE-2021-2135",
			Affected:    "Oracle WebLogic",
		},
		{
			ID:          "APP-002",
			Name:        "JBoss反序列化漏洞",
			Severity:    "Critical",
			Description: "JBoss存在反序列化远程代码执行漏洞",
			Solution:    "升级到JBoss EAP 7.3或更高版本",
			CVE:         "CVE-2021-44228",
			Affected:    "JBoss",
		},
		{
			ID:          "APP-003",
			Name:        "GlassFish远程代码执行漏洞",
			Severity:    "High",
			Description: "GlassFish存在远程代码执行漏洞",
			Solution:    "升级到GlassFish 6.2.2或更高版本",
			CVE:         "CVE-2021-41381",
			Affected:    "GlassFish",
		},
		{
			ID:          "APP-004",
			Name:        "Jenkins远程代码执行漏洞",
			Severity:    "Critical",
			Description: "Jenkins存在远程代码执行漏洞",
			Solution:    "升级到Jenkins 2.303.2或更高版本",
			CVE:         "CVE-2021-21671",
			Affected:    "Jenkins",
		},
	}
}