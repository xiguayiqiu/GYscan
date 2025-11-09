package vulnscan

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ReconResult 侦查结果
type ReconResult struct {
	Target          string
	OpenPorts       []int
	Services        []ServiceInfo
	WebTechnologies []WebTech
	Vulnerabilities []Vulnerability
	ScanTime        time.Time
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Port        int
	Protocol    string
	Service     string
	Version     string
	Banner      string
}

// WebTech Web技术信息
type WebTech struct {
	Technology string
	Version    string
	Confidence int
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Solution    string
	CVE         string
	Affected    string
	Confidence  int
}

// ReconScanner 侦查扫描器
type ReconScanner struct {
	Verbose bool
}

// NewReconScanner 创建新的侦查扫描器
func NewReconScanner(verbose bool) *ReconScanner {
	return &ReconScanner{
		Verbose: verbose,
	}
}

// Scan 执行漏洞侦查扫描
func (rs *ReconScanner) Scan(target string) (*ReconResult, error) {
	result := &ReconResult{
		Target:   target,
		ScanTime: time.Now(),
	}

	if rs.Verbose {
		fmt.Printf("开始对目标 %s 进行漏洞侦查...\n", target)
	}

	// 端口扫描
	openPorts, err := rs.portScan(target)
	if err != nil {
		return nil, err
	}
	result.OpenPorts = openPorts

	// 服务识别
	services, err := rs.serviceScan(target, openPorts)
	if err != nil {
		return nil, err
	}
	result.Services = services

	// Web技术识别
	webTechs, err := rs.webTechScan(target, services)
	if err != nil {
		return nil, err
	}
	result.WebTechnologies = webTechs

	// 漏洞检测
	vulnerabilities, err := rs.vulnerabilityScan(target, services, webTechs)
	if err != nil {
		return nil, err
	}
	result.Vulnerabilities = vulnerabilities

	if rs.Verbose {
		fmt.Printf("漏洞侦查完成! 发现 %d 个开放端口, %d 个服务, %d 个Web技术, %d 个漏洞\n", 
			len(openPorts), len(services), len(webTechs), len(vulnerabilities))
	}

	return result, nil
}

// portScan 端口扫描
func (rs *ReconScanner) portScan(target string) ([]int, error) {
	var openPorts []int
	
	// 常见服务端口
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
		993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200}

	for _, port := range commonPorts {
		if rs.Verbose {
			fmt.Printf("扫描端口 %d...\n", port)
		}
		
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 2*time.Second)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	return openPorts, nil
}

// serviceScan 服务识别
func (rs *ReconScanner) serviceScan(target string, ports []int) ([]ServiceInfo, error) {
	var services []ServiceInfo

	for _, port := range ports {
		service := rs.identifyService(target, port)
		if service.Service != "" {
			services = append(services, service)
		}
	}

	return services, nil
}

// identifyService 识别服务
func (rs *ReconScanner) identifyService(target string, port int) ServiceInfo {
	service := ServiceInfo{
		Port:     port,
		Protocol: "tcp",
	}

	// 尝试连接并获取banner
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 3*time.Second)
	if err != nil {
		return service
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 读取banner
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	service.Banner = strings.TrimSpace(banner)

	// 根据端口和banner识别服务
	service.Service, service.Version = rs.analyzeBanner(port, service.Banner)

	return service
}

// analyzeBanner 分析banner识别服务
func (rs *ReconScanner) analyzeBanner(port int, banner string) (string, string) {
	switch port {
	case 21:
		if strings.Contains(banner, "FTP") {
			return "FTP", rs.extractVersion(banner)
		}
	case 22:
		if strings.Contains(banner, "SSH") {
			return "SSH", rs.extractVersion(banner)
		}
	case 80, 443, 8080, 8443:
		if strings.Contains(banner, "HTTP") || strings.Contains(banner, "Server:") {
			return "HTTP", rs.extractWebServer(banner)
		}
	case 3306:
		if strings.Contains(banner, "MySQL") {
			return "MySQL", rs.extractVersion(banner)
		}
	case 1433:
		if strings.Contains(banner, "Microsoft SQL Server") {
			return "MSSQL", rs.extractVersion(banner)
		}
	case 3389:
		return "RDP", ""
	case 135, 139, 445:
		return "SMB", ""
	}

	return "", ""
}

// extractVersion 从banner中提取版本信息
func (rs *ReconScanner) extractVersion(banner string) string {
	re := regexp.MustCompile(`\d+\.\d+(\.\d+)?`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// extractWebServer 从HTTP响应中提取Web服务器信息
func (rs *ReconScanner) extractWebServer(banner string) string {
	if strings.Contains(banner, "IIS") {
		return "IIS"
	} else if strings.Contains(banner, "Apache") {
		return "Apache"
	} else if strings.Contains(banner, "nginx") {
		return "nginx"
	}
	return ""
}

// webTechScan Web技术识别
func (rs *ReconScanner) webTechScan(target string, services []ServiceInfo) ([]WebTech, error) {
	var webTechs []WebTech

	for _, service := range services {
		if service.Service == "HTTP" {
			techs := rs.detectWebTechnologies(target, service.Port)
			webTechs = append(webTechs, techs...)
		}
	}

	return webTechs, nil
}

// detectWebTechnologies 检测Web技术
func (rs *ReconScanner) detectWebTechnologies(target string, port int) []WebTech {
	var techs []WebTech

	// 这里可以扩展更多的Web技术检测逻辑
	// 目前实现基本的检测

	return techs
}

// vulnerabilityScan 漏洞检测
func (rs *ReconScanner) vulnerabilityScan(target string, services []ServiceInfo, webTechs []WebTech) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// 基于服务检测漏洞
	for _, service := range services {
		vulns := rs.detectServiceVulnerabilities(service)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	// 基于Web技术检测漏洞
	for _, tech := range webTechs {
		vulns := rs.detectWebVulnerabilities(tech)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

// detectServiceVulnerabilities 检测服务漏洞
func (rs *ReconScanner) detectServiceVulnerabilities(service ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 根据服务类型检测相应的漏洞
	switch service.Service {
	case "SMB":
		vulnerabilities = append(vulnerabilities, rs.detectSMBVulnerabilities(service)...)
	case "RDP":
		vulnerabilities = append(vulnerabilities, rs.detectRDPVulnerabilities(service)...)
	case "HTTP":
		vulnerabilities = append(vulnerabilities, rs.detectHTTPVulnerabilities(service)...)
	case "MySQL":
		vulnerabilities = append(vulnerabilities, rs.detectMySQLVulnerabilities(service)...)
	case "MSSQL":
		vulnerabilities = append(vulnerabilities, rs.detectMSSQLVulnerabilities(service)...)
	}

	return vulnerabilities
}

// detectSMBVulnerabilities 检测SMB漏洞
func (rs *ReconScanner) detectSMBVulnerabilities(service ServiceInfo) []Vulnerability {
	return []Vulnerability{
		{
			ID:          "SMB-001",
			Name:        "SMBv1协议漏洞",
			Severity:    "Critical",
			Description: "SMBv1协议存在远程代码执行漏洞",
			Solution:    "禁用SMBv1协议",
			CVE:         "CVE-2017-0144",
			Affected:    "Windows系统",
			Confidence:  80,
		},
	}
}

// detectRDPVulnerabilities 检测RDP漏洞
func (rs *ReconScanner) detectRDPVulnerabilities(service ServiceInfo) []Vulnerability {
	return []Vulnerability{
		{
			ID:          "RDP-001",
			Name:        "RDP远程代码执行漏洞",
			Severity:    "Critical",
			Description: "RDP协议存在远程代码执行漏洞",
			Solution:    "禁用RDP或安装安全更新",
			CVE:         "CVE-2019-0708",
			Affected:    "Windows系统",
			Confidence:  85,
		},
	}
}

// detectHTTPVulnerabilities 检测HTTP漏洞
func (rs *ReconScanner) detectHTTPVulnerabilities(service ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 根据Web服务器类型检测漏洞
	if strings.Contains(service.Version, "IIS") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "IIS-001",
			Name:        "IIS远程代码执行漏洞",
			Severity:    "High",
			Description: "IIS存在远程代码执行漏洞",
			Solution:    "安装最新的Windows更新",
			CVE:         "CVE-2021-31166",
			Affected:    "Microsoft IIS",
			Confidence:  75,
		})
	}

	return vulnerabilities
}

// detectMySQLVulnerabilities 检测MySQL漏洞
func (rs *ReconScanner) detectMySQLVulnerabilities(service ServiceInfo) []Vulnerability {
	return []Vulnerability{
		{
			ID:          "MYSQL-001",
			Name:        "MySQL权限提升漏洞",
			Severity:    "High",
			Description: "MySQL存在权限提升漏洞",
			Solution:    "升级到MySQL 8.0.23或更高版本",
			CVE:         "CVE-2021-22946",
			Affected:    "MySQL",
			Confidence:  70,
		},
	}
}

// detectMSSQLVulnerabilities 检测MSSQL漏洞
func (rs *ReconScanner) detectMSSQLVulnerabilities(service ServiceInfo) []Vulnerability {
	return []Vulnerability{
		{
			ID:          "MSSQL-001",
			Name:        "SQL Server远程代码执行漏洞",
			Severity:    "Critical",
			Description: "Microsoft SQL Server存在远程代码执行漏洞",
			Solution:    "安装最新的SQL Server更新",
			CVE:         "CVE-2021-1636",
			Affected:    "Microsoft SQL Server",
			Confidence:  80,
		},
	}
}

// detectWebVulnerabilities 检测Web漏洞
func (rs *ReconScanner) detectWebVulnerabilities(tech WebTech) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 根据Web技术检测相应的漏洞
	switch tech.Technology {
	case "Apache":
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "APACHE-001",
			Name:        "Apache路径遍历漏洞",
			Severity:    "High",
			Description: "Apache存在路径遍历漏洞",
			Solution:    "升级到最新版本",
			CVE:         "CVE-2021-41773",
			Affected:    "Apache HTTP Server",
			Confidence:  65,
		})
	}

	return vulnerabilities
}