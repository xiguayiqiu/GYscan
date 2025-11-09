package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// scanLinuxServices 扫描Linux服务
func scanLinuxServices() ([]ServiceInfo, []Vulnerability) {
	var services []ServiceInfo
	var vulnerabilities []Vulnerability

	// 检测网络服务
	networkServices := detectNetworkServices()
	services = append(services, networkServices...)

	// 检测系统服务
	systemServices := detectSystemServices()
	services = append(services, systemServices...)

	// 检测服务漏洞
	for i := range services {
		serviceVulns := detectServiceVulnerabilities(services[i].Name, services[i].Version)
		services[i].Vulnerabilities = serviceVulns
		vulnerabilities = append(vulnerabilities, serviceVulns...)
	}

	return services, vulnerabilities
}

// detectNetworkServices 检测网络服务
func detectNetworkServices() []ServiceInfo {
	var services []ServiceInfo

	// 使用netstat检测网络服务
	cmd := exec.Command("netstat", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				addr := fields[3]
				if strings.Contains(addr, ":") {
					parts := strings.Split(addr, ":")
					if len(parts) > 0 {
						portStr := parts[len(parts)-1]
						port, err := strconv.Atoi(portStr)
						if err == nil {
							service := ServiceInfo{
								Port:     port,
								Protocol: getProtocol(fields[0]),
								Status:   "LISTEN",
								Name:     getServiceNameByPort(port),
								Version:  getServiceVersion(getServiceNameByPort(port)),
							}
							services = append(services, service)
						}
					}
				}
			}
		}
	}

	return services
}

// detectSystemServices 检测系统服务
func detectSystemServices() []ServiceInfo {
	var services []ServiceInfo

	// 检测systemd服务
	systemdServices := detectSystemdServices()
	services = append(services, systemdServices...)

	// 检测SysV init服务
	sysvServices := detectSysVServices()
	services = append(services, sysvServices...)

	return services
}

// detectSystemdServices 检测systemd服务
func detectSystemdServices() []ServiceInfo {
	var services []ServiceInfo

	// 使用systemctl检测运行的服务
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ".service") && !strings.Contains(line, "LOAD") && !strings.Contains(line, "SUB") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				serviceName := fields[0]
				service := ServiceInfo{
					Name:     strings.TrimSuffix(serviceName, ".service"),
					Status:   "running",
					Version:  getServiceVersion(strings.TrimSuffix(serviceName, ".service")),
				}
				services = append(services, service)
			}
		}
	}

	return services
}

// detectSysVServices 检测SysV init服务
func detectSysVServices() []ServiceInfo {
	var services []ServiceInfo

	// 检查/etc/init.d目录
	cmd := exec.Command("ls", "/etc/init.d/")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line != "" {
			// 检查服务是否在运行
			statusCmd := exec.Command("service", line, "status")
			if statusCmd.Run() == nil {
				service := ServiceInfo{
					Name:     line,
					Status:   "running",
					Version:  getServiceVersion(line),
				}
				services = append(services, service)
			}
		}
	}

	return services
}

// getProtocol 获取协议类型
func getProtocol(proto string) string {
	if strings.Contains(proto, "tcp") {
		return "tcp"
	} else if strings.Contains(proto, "udp") {
		return "udp"
	}
	return "unknown"
}

// getServiceNameByPort 根据端口获取服务名称
func getServiceNameByPort(port int) string {
	portServices := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		993:  "imaps",
		995:  "pop3s",
		3306: "mysql",
		5432: "postgresql",
		6379: "redis",
		27017: "mongodb",
	}

	if name, exists := portServices[port]; exists {
		return name
	}
	return "unknown"
}

// getServiceVersion 获取服务版本
func getServiceVersion(serviceName string) string {
	// 这里实现获取服务版本的逻辑
	// 实际实现需要根据具体服务进行版本检测
	return "Unknown"
}

// detectServiceVulnerabilities 检测服务漏洞
func detectServiceVulnerabilities(serviceName, version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// SSH服务漏洞
	if serviceName == "ssh" {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "SSH-001",
			Name:        "SSH弱加密算法",
			Severity:    "Medium",
			Description: "SSH服务使用弱加密算法",
			Solution:    "禁用弱加密算法，使用强加密",
			CVE:         "CVE-2008-5161",
			Affected:    "所有SSH版本",
		})
	}

	// FTP服务漏洞
	if serviceName == "ftp" {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "FTP-001",
			Name:        "FTP明文传输",
			Severity:    "High",
			Description: "FTP使用明文传输密码",
			Solution:    "使用SFTP或FTPS替代FTP",
			CVE:         "CVE-1999-0497",
			Affected:    "所有FTP服务",
		})
	}

	// HTTP服务漏洞
	if serviceName == "http" || serviceName == "https" {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "HTTP-001",
			Name:        "Web服务器信息泄露",
			Severity:    "Low",
			Description: "Web服务器版本信息泄露",
			Solution:    "隐藏服务器版本信息",
			CVE:         "CVE-2000-0649",
			Affected:    "所有Web服务器",
		})
	}

	return vulnerabilities
}