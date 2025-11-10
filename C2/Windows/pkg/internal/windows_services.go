package internal

import (
	"os/exec"
	"strconv"
	"strings"
)

// scanWindowsServices 扫描Windows服务
func scanWindowsServices() ([]ServiceInfo, []Vulnerability) {
	var services []ServiceInfo
	var vulnerabilities []Vulnerability

	// 使用netstat检测网络服务
	cmd := exec.Command("netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return services, vulnerabilities
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTENING") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				addr := fields[1]
				if strings.Contains(addr, ":") {
					parts := strings.Split(addr, ":")
					if len(parts) == 2 {
						port, err := strconv.Atoi(parts[1])
						if err == nil {
							service := ServiceInfo{
								Name:     getServiceNameByPort(port),
								Port:     port,
								Protocol: "tcp",
								Status:   "LISTENING",
							}
							services = append(services, service)
						}
					}
				}
			}
		}
	}

	// 检测常见Windows服务漏洞
	vulnerabilities = append(vulnerabilities, detectWindowsServiceVulnerabilities(services)...)

	return services, vulnerabilities
}

// getServiceNameByPort 根据端口号获取服务名称
func getServiceNameByPort(port int) string {
	serviceMap := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		993:  "IMAPS",
		995:  "POP3S",
		1433: "MSSQL",
		1434: "MSSQL Browser",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	}

	if name, exists := serviceMap[port]; exists {
		return name
	}
	return "Unknown Service"
}

// detectWindowsServiceVulnerabilities 检测Windows服务漏洞
func detectWindowsServiceVulnerabilities(services []ServiceInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, service := range services {
		switch service.Port {
		case 445: // SMB服务
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "SMB-001",
				Name:        "SMBv1 EternalBlue漏洞",
				Severity:    "Critical",
				Description: "SMBv1协议存在远程代码执行漏洞",
				Solution:    "禁用SMBv1协议，安装MS17-010更新",
				CVE:         "CVE-2017-0144",
				Affected:    "SMB服务",
			})
		case 3389: // RDP服务
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "RDP-001",
				Name:        "RDP BlueKeep漏洞",
				Severity:    "Critical",
				Description: "RDP协议存在远程代码执行漏洞",
				Solution:    "禁用RDP或安装安全更新",
				CVE:         "CVE-2019-0708",
				Affected:    "RDP服务",
			})
		case 135: // RPC服务
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "RPC-001",
				Name:        "RPC DCOM漏洞",
				Severity:    "High",
				Description: "RPC DCOM接口存在远程代码执行漏洞",
				Solution:    "安装MS03-026安全更新",
				CVE:         "CVE-2003-0352",
				Affected:    "RPC服务",
			})
		case 53: // DNS服务
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "DNS-001",
				Name:        "DNS服务器漏洞",
				Severity:    "Critical",
				Description: "Windows DNS服务器存在远程代码执行漏洞",
				Solution:    "安装KB4569509安全更新",
				CVE:         "CVE-2020-1350",
				Affected:    "DNS服务",
			})
		}
	}

	return vulnerabilities
}