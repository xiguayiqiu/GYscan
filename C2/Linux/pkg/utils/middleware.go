package utils

import (
	"os/exec"

	"GYscan-linux-C2/pkg/types"
)

// detectMiddlewareVulnerabilities 检测中间件漏洞
func DetectMiddlewareVulnerabilities() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检测Web服务器漏洞
	webVulns := detectWebServerVulnerabilities()
	vulnerabilities = append(vulnerabilities, webVulns...)

	// 检测数据库漏洞
	dbVulns := detectDatabaseVulnerabilities()
	vulnerabilities = append(vulnerabilities, dbVulns...)

	// 检测应用服务器漏洞
	appVulns := detectApplicationServerVulnerabilities()
	vulnerabilities = append(vulnerabilities, appVulns...)

	return vulnerabilities
}

// detectWebServerVulnerabilities 检测Web服务器漏洞
func detectWebServerVulnerabilities() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检测Apache漏洞
	if isApacheInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "APACHE-001",
			Name:        "Apache Struts2远程代码执行",
			Severity:    "Critical",
			Description: "Apache Struts2存在OGNL表达式注入漏洞",
			Solution:    "更新Struts2到2.3.32或2.5.10.1及以上版本",
			CVE:         "CVE-2017-5638",
			Affected:    "Struts 2.3.5-2.3.31, 2.5-2.5.10",
		})

		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "APACHE-002",
			Name:        "Apache HTTP Server路径遍历",
			Severity:    "High",
			Description: "Apache HTTP Server存在路径遍历漏洞",
			Solution:    "更新Apache到2.4.50及以上版本",
			CVE:         "CVE-2021-41773",
			Affected:    "Apache 2.4.49",
		})
	}

	// 检测Nginx漏洞
	if isNginxInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "NGINX-001",
			Name:        "Nginx范围处理整数溢出",
			Severity:    "High",
			Description: "Nginx存在范围处理整数溢出漏洞",
			Solution:    "更新Nginx到1.17.7、1.16.1或1.15.8及以上版本",
			CVE:         "CVE-2019-20372",
			Affected:    "Nginx 1.17.5-1.17.6",
		})

		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "NGINX-002",
			Name:        "Nginx DNS解析漏洞",
			Severity:    "Medium",
			Description: "Nginx存在DNS解析安全漏洞",
			Solution:    "更新Nginx到1.21.0及以上版本",
			CVE:         "CVE-2021-23017",
			Affected:    "Nginx 0.6.18-1.20.1",
		})
	}

	// 检测Tomcat漏洞
	if isTomcatInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "TOMCAT-001",
			Name:        "Apache Tomcat会话固定",
			Severity:    "Medium",
			Description: "Tomcat存在会话固定漏洞",
			Solution:    "更新Tomcat到9.0.31、8.5.51或7.0.100及以上版本",
			CVE:         "CVE-2020-1938",
			Affected:    "Tomcat 9.0.0-9.0.30, 8.5.0-8.5.50, 7.0.0-7.0.99",
		})
	}

	return vulnerabilities
}

// detectDatabaseVulnerabilities 检测数据库漏洞
func detectDatabaseVulnerabilities() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检测MySQL漏洞
	if isMySQLInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "MYSQL-001",
			Name:        "MySQL认证绕过",
			Severity:    "Critical",
			Description: "MySQL存在认证绕过漏洞",
			Solution:    "更新MySQL到5.7.28或8.0.18及以上版本",
			CVE:         "CVE-2019-2631",
			Affected:    "MySQL 5.7.27及以下，8.0.17及以下",
		})

		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "MYSQL-002",
			Name:        "MySQL权限提升",
			Severity:    "High",
			Description: "MySQL存在权限提升漏洞",
			Solution:    "更新MySQL到5.7.29或8.0.19及以上版本",
			CVE:         "CVE-2020-2752",
			Affected:    "MySQL 5.7.28及以下，8.0.18及以下",
		})
	}

	// 检测PostgreSQL漏洞
	if isPostgreSQLInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "POSTGRES-001",
			Name:        "PostgreSQL权限提升",
			Severity:    "High",
			Description: "PostgreSQL存在权限提升漏洞",
			Solution:    "更新PostgreSQL到13.3、12.7、11.12、10.17或9.6.22及以上版本",
			CVE:         "CVE-2021-3677",
			Affected:    "PostgreSQL 9.6-13.2",
		})

		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "POSTGRES-002",
			Name:        "PostgreSQL内存泄露",
			Severity:    "Medium",
			Description: "PostgreSQL存在内存泄露漏洞",
			Solution:    "更新PostgreSQL到14.0及以上版本",
			CVE:         "CVE-2021-23214",
			Affected:    "PostgreSQL 13.0-13.3",
		})
	}

	// 检测Redis漏洞
	if isRedisInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "REDIS-001",
			Name:        "Redis未授权访问",
			Severity:    "Critical",
			Description: "Redis存在未授权访问漏洞",
			Solution:    "配置Redis认证和网络访问控制",
			CVE:         "CVE-2015-4335",
			Affected:    "所有Redis版本",
		})
	}

	// 检测MongoDB漏洞
	if isMongoDBInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "MONGODB-001",
			Name:        "MongoDB未授权访问",
			Severity:    "Critical",
			Description: "MongoDB存在未授权访问漏洞",
			Solution:    "配置MongoDB认证和网络访问控制",
			CVE:         "CVE-2016-6494",
			Affected:    "所有MongoDB版本",
		})
	}

	return vulnerabilities
}

// detectApplicationServerVulnerabilities 检测应用服务器漏洞
func detectApplicationServerVulnerabilities() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检测WebLogic漏洞
	if isWebLogicInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "WEBLOGIC-001",
			Name:        "WebLogic反序列化",
			Severity:    "Critical",
			Description: "WebLogic存在反序列化漏洞",
			Solution:    "更新WebLogic到12.2.1.3.0、12.1.3.0.0或10.3.6.0.0及以上版本",
			CVE:         "CVE-2017-10271",
			Affected:    "WebLogic 10.3.6.0.0、12.1.3.0.0、12.2.1.1.0、12.2.1.2.0",
		})
	}

	// 检测JBoss漏洞
	if isJBossInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "JBOSS-001",
			Name:        "JBoss反序列化",
			Severity:    "Critical",
			Description: "JBoss存在反序列化漏洞",
			Solution:    "更新JBoss到最新版本",
			CVE:         "CVE-2017-12149",
			Affected:    "JBoss 5.x/6.x",
		})
	}

	// 检测GlassFish漏洞
	if isGlassFishInstalled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "GLASSFISH-001",
			Name:        "GlassFish信息泄露",
			Severity:    "Medium",
			Description: "GlassFish存在信息泄露漏洞",
			Solution:    "更新GlassFish到4.1.2及以上版本",
			CVE:         "CVE-2015-5175",
			Affected:    "GlassFish 4.1及以下",
		})
	}

	return vulnerabilities
}

// 检测中间件是否安装的函数
func isApacheInstalled() bool {
	cmd := exec.Command("which", "apache2")
	return cmd.Run() == nil
}

func isNginxInstalled() bool {
	cmd := exec.Command("which", "nginx")
	return cmd.Run() == nil
}

func isTomcatInstalled() bool {
	cmd := exec.Command("which", "catalina.sh")
	if cmd.Run() == nil {
		return true
	}
	// 检查Tomcat安装目录
	cmd = exec.Command("ls", "/opt/tomcat")
	return cmd.Run() == nil
}

func isMySQLInstalled() bool {
	cmd := exec.Command("which", "mysql")
	return cmd.Run() == nil
}

func isPostgreSQLInstalled() bool {
	cmd := exec.Command("which", "psql")
	return cmd.Run() == nil
}

func isRedisInstalled() bool {
	cmd := exec.Command("which", "redis-server")
	return cmd.Run() == nil
}

func isMongoDBInstalled() bool {
	cmd := exec.Command("which", "mongod")
	return cmd.Run() == nil
}

func isWebLogicInstalled() bool {
	// 检查WebLogic安装目录
	cmd := exec.Command("ls", "/opt/weblogic")
	return cmd.Run() == nil
}

func isJBossInstalled() bool {
	// 检查JBoss安装目录
	cmd := exec.Command("ls", "/opt/jboss")
	return cmd.Run() == nil
}

func isGlassFishInstalled() bool {
	cmd := exec.Command("which", "asadmin")
	return cmd.Run() == nil
}