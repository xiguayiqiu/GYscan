package vulnscan

import (
	"fmt"
	"strings"
)
// MiddlewareScanner 中间件漏洞扫描器
type MiddlewareScanner struct {
	Verbose bool
}

// NewMiddlewareScanner 创建新的中间件漏洞扫描器
func NewMiddlewareScanner(verbose bool) *MiddlewareScanner {
	return &MiddlewareScanner{
		Verbose: verbose,
	}
}

// Scan 扫描中间件漏洞
func (ms *MiddlewareScanner) Scan(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	if ms.Verbose {
		fmt.Println("开始扫描中间件漏洞...")
	}

	// 检测Web服务器漏洞
	webVulns := ms.scanWebServerVulnerabilities(target, services)
	vulnerabilities = append(vulnerabilities, webVulns...)

	// 检测应用服务器漏洞
	appVulns := ms.scanApplicationServerVulnerabilities(target, services)
	vulnerabilities = append(vulnerabilities, appVulns...)

	// 检测缓存服务器漏洞
	cacheVulns := ms.scanCacheServerVulnerabilities(target, services)
	vulnerabilities = append(vulnerabilities, cacheVulns...)

	// 检测消息队列漏洞
	mqVulns := ms.scanMessageQueueVulnerabilities(target, services)
	vulnerabilities = append(vulnerabilities, mqVulns...)

	if ms.Verbose {
		fmt.Printf("发现中间件漏洞: %d个\n", len(vulnerabilities))
	}

	return vulnerabilities
}

// scanWebServerVulnerabilities 扫描Web服务器漏洞
func (ms *MiddlewareScanner) scanWebServerVulnerabilities(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		if service.Service == "HTTP" {
			// 识别Web服务器类型
			serverType := ms.identifyWebServer(service)
			
			// 根据服务器类型检测相应漏洞
			switch serverType {
			case "IIS":
				iisVulns := ms.scanIISVulnerabilities(target, service)
				vulnerabilities = append(vulnerabilities, iisVulns...)
			case "Apache":
				apacheVulns := ms.scanApacheVulnerabilities(target, service)
				vulnerabilities = append(vulnerabilities, apacheVulns...)
			case "Nginx":
				nginxVulns := ms.scanNginxVulnerabilities(target, service)
				vulnerabilities = append(vulnerabilities, nginxVulns...)
			case "Tomcat":
				tomcatVulns := ms.scanTomcatVulnerabilities(target, service)
				vulnerabilities = append(vulnerabilities, tomcatVulns...)
			}
		}
	}

	return vulnerabilities
}

// identifyWebServer 识别Web服务器类型
func (ms *MiddlewareScanner) identifyWebServer(service ServiceInfo) string {
	banner := strings.ToLower(service.Banner)
	
	if strings.Contains(banner, "iis") || strings.Contains(banner, "microsoft") {
		return "IIS"
	} else if strings.Contains(banner, "apache") {
		return "Apache"
	} else if strings.Contains(banner, "nginx") {
		return "Nginx"
	} else if strings.Contains(banner, "tomcat") {
		return "Tomcat"
	}
	
	return "Unknown"
}

// scanIISVulnerabilities 扫描IIS漏洞
func (ms *MiddlewareScanner) scanIISVulnerabilities(target string, service ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检测IIS版本和已知漏洞
	if ms.checkIISVersionVulnerability(service) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "IIS-001",
			Name:        "IIS远程代码执行漏洞",
			Severity:    "Critical",
			Description: "IIS存在远程代码执行漏洞",
			Solution:    "安装最新的Windows更新",
			CVE:         "CVE-2021-31166",
			Affected:    "Microsoft IIS",
			Confidence:  90,
		})
	}

	// 检测IIS配置漏洞
	if ms.checkIISConfigurationVulnerability(target, service.Port) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "IIS-002",
			Name:        "IIS配置漏洞",
			Severity:    "Medium",
			Description: "IIS配置存在安全风险",
			Solution:    "修复IIS安全配置",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Microsoft IIS",
			Confidence:  70,
		})
	}

	return vulnerabilities
}

// scanApacheVulnerabilities 扫描Apache漏洞
func (ms *MiddlewareScanner) scanApacheVulnerabilities(target string, service ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检测Apache版本漏洞
	if ms.checkApacheVersionVulnerability(service) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "APACHE-001",
			Name:        "Apache路径遍历漏洞",
			Severity:    "High",
			Description: "Apache存在路径遍历漏洞",
			Solution:    "升级到Apache 2.4.49或更高版本",
			CVE:         "CVE-2021-41773",
			Affected:    "Apache HTTP Server",
			Confidence:  85,
		})
	}

	// 检测Apache模块漏洞
	if ms.checkApacheModuleVulnerability(target, service.Port) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "APACHE-002",
			Name:        "Apache模块漏洞",
			Severity:    "Medium",
			Description: "Apache模块存在安全风险",
			Solution:    "禁用或更新有问题的模块",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Apache HTTP Server",
			Confidence:  65,
		})
	}

	return vulnerabilities
}

// scanNginxVulnerabilities 扫描Nginx漏洞
func (ms *MiddlewareScanner) scanNginxVulnerabilities(target string, service ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检测Nginx版本漏洞
	if ms.checkNginxVersionVulnerability(service) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "NGINX-001",
			Name:        "Nginx路径遍历漏洞",
			Severity:    "High",
			Description: "Nginx存在路径遍历漏洞",
			Solution:    "升级到Nginx 1.20.1或更高版本",
			CVE:         "CVE-2021-23017",
			Affected:    "Nginx",
			Confidence:  80,
		})
	}

	return vulnerabilities
}

// scanTomcatVulnerabilities 扫描Tomcat漏洞
func (ms *MiddlewareScanner) scanTomcatVulnerabilities(target string, service ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检测Tomcat版本漏洞
	if ms.checkTomcatVersionVulnerability(service) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "TOMCAT-001",
			Name:        "Tomcat文件包含漏洞",
			Severity:    "High",
			Description: "Apache Tomcat存在文件包含漏洞",
			Solution:    "升级到Tomcat 9.0.46或更高版本",
			CVE:         "CVE-2021-24122",
			Affected:    "Apache Tomcat",
			Confidence:  75,
		})
	}

	return vulnerabilities
}

// scanApplicationServerVulnerabilities 扫描应用服务器漏洞
func (ms *MiddlewareScanner) scanApplicationServerVulnerabilities(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		switch service.Service {
		case "WebLogic":
			if ms.checkWebLogicVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "WEBLOGIC-001",
					Name:        "WebLogic反序列化漏洞",
					Severity:    "Critical",
					Description: "Oracle WebLogic存在反序列化远程代码执行漏洞",
					Solution:    "升级到WebLogic 14.1.1.0.0或应用补丁",
					CVE:         "CVE-2021-2135",
					Affected:    "Oracle WebLogic",
					Confidence:  90,
				})
			}
		case "JBoss":
			if ms.checkJBossVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "JBOSS-001",
					Name:        "JBoss反序列化漏洞",
					Severity:    "Critical",
					Description: "JBoss存在反序列化远程代码执行漏洞",
					Solution:    "升级到JBoss EAP 7.3或更高版本",
					CVE:         "CVE-2021-44228",
					Affected:    "JBoss",
					Confidence:  85,
				})
			}
		case "GlassFish":
			if ms.checkGlassFishVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "GLASSFISH-001",
					Name:        "GlassFish远程代码执行漏洞",
					Severity:    "High",
					Description: "GlassFish存在远程代码执行漏洞",
					Solution:    "升级到GlassFish 6.2.2或更高版本",
					CVE:         "CVE-2021-41381",
					Affected:    "GlassFish",
					Confidence:  80,
				})
			}
		}
	}

	return vulnerabilities
}

// scanCacheServerVulnerabilities 扫描缓存服务器漏洞
func (ms *MiddlewareScanner) scanCacheServerVulnerabilities(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		switch service.Service {
		case "Redis":
			if ms.checkRedisVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "REDIS-001",
					Name:        "Redis未授权访问漏洞",
					Severity:    "Critical",
					Description: "Redis存在未授权访问漏洞",
					Solution:    "配置Redis认证和网络访问控制",
					CVE:         "CVE-2021-32761",
					Affected:    "Redis",
					Confidence:  95,
				})
			}
		case "Memcached":
			if ms.checkMemcachedVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "MEMCACHED-001",
					Name:        "Memcached未授权访问漏洞",
					Severity:    "High",
					Description: "Memcached存在未授权访问漏洞",
					Solution:    "配置Memcached访问控制",
					CVE:         "CVE-2021-XXXXX",
					Affected:    "Memcached",
					Confidence:  85,
				})
			}
		}
	}

	return vulnerabilities
}

// scanMessageQueueVulnerabilities 扫描消息队列漏洞
func (ms *MiddlewareScanner) scanMessageQueueVulnerabilities(target string, services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		switch service.Service {
		case "RabbitMQ":
			if ms.checkRabbitMQVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "RABBITMQ-001",
					Name:        "RabbitMQ远程代码执行漏洞",
					Severity:    "Critical",
					Description: "RabbitMQ存在远程代码执行漏洞",
					Solution:    "升级到RabbitMQ 3.8.16或更高版本",
					CVE:         "CVE-2021-22119",
					Affected:    "RabbitMQ",
					Confidence:  90,
				})
			}
		case "ActiveMQ":
			if ms.checkActiveMQVulnerability(service) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					ID:          "ACTIVEMQ-001",
					Name:        "ActiveMQ反序列化漏洞",
					Severity:    "Critical",
					Description: "ActiveMQ存在反序列化远程代码执行漏洞",
					Solution:    "升级到ActiveMQ 5.16.2或更高版本",
					CVE:         "CVE-2021-26117",
					Affected:    "ActiveMQ",
					Confidence:  85,
				})
			}
		}
	}

	return vulnerabilities
}

// 以下为检测方法的占位实现
func (ms *MiddlewareScanner) checkIISVersionVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "10.0")
}

func (ms *MiddlewareScanner) checkIISConfigurationVulnerability(target string, port int) bool {
	// 检查IIS配置
	return false
}

func (ms *MiddlewareScanner) checkApacheVersionVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "2.4")
}

func (ms *MiddlewareScanner) checkApacheModuleVulnerability(target string, port int) bool {
	return false
}

func (ms *MiddlewareScanner) checkNginxVersionVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "1.18")
}

func (ms *MiddlewareScanner) checkTomcatVersionVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "9.0")
}

func (ms *MiddlewareScanner) checkWebLogicVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "12.2")
}

func (ms *MiddlewareScanner) checkJBossVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "7.")
}

func (ms *MiddlewareScanner) checkGlassFishVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "5.")
}

func (ms *MiddlewareScanner) checkRedisVulnerability(service ServiceInfo) bool {
	return true // Redis默认未授权访问
}

func (ms *MiddlewareScanner) checkMemcachedVulnerability(service ServiceInfo) bool {
	return true // Memcached默认未授权访问
}

func (ms *MiddlewareScanner) checkRabbitMQVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "3.8")
}

func (ms *MiddlewareScanner) checkActiveMQVulnerability(service ServiceInfo) bool {
	return strings.Contains(service.Version, "5.16")
}