package scanners

import (
	"fmt"
	"os/exec"
	"strings"

	"GYscan-linux-C2/pkg/types"
)

// detectLinuxKernelVulnerabilities 检测Linux内核漏洞
func detectLinuxKernelVulnerabilities() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检测内核版本
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return vulnerabilities
	}

	kernelVersion := strings.TrimSpace(string(output))

	// 常见的内核漏洞检测
	if strings.Contains(kernelVersion, "4.4") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "KERNEL-001",
			Name:        "Linux内核提权漏洞",
			Severity:    "Critical",
			Description: fmt.Sprintf("Linux内核版本 %s 存在提权漏洞", kernelVersion),
			Solution:    "更新内核到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Linux内核 4.4.x",
		})
	}

	if strings.Contains(kernelVersion, "5.4") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "KERNEL-002",
			Name:        "Linux内核内存泄露",
			Severity:    "High",
			Description: fmt.Sprintf("Linux内核版本 %s 存在内存泄露漏洞", kernelVersion),
			Solution:    "更新内核到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Linux内核 5.4.x",
		})
	}

	return vulnerabilities
}

// scanLinuxServices 扫描Linux服务
func scanLinuxServices() ([]types.ServiceInfo, []types.Vulnerability) {
	var services []types.ServiceInfo
	var vulnerabilities []types.Vulnerability

	// 检测运行的服务
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running")
	output, err := cmd.Output()
	if err != nil {
		return services, vulnerabilities
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ".service") && !strings.Contains(line, "LOAD") && !strings.Contains(line, "ACTIVE") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				serviceName := strings.TrimSuffix(fields[0], ".service")
				services = append(services, types.ServiceInfo{
					Name: serviceName,
					Port: 0, // 需要进一步检测端口
				})
			}
		}
	}

	// 检测服务漏洞
	for _, service := range services {
		if strings.Contains(strings.ToLower(service.Name), "ssh") {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "SSH-001",
				Name:        "SSH服务漏洞",
				Severity:    "High",
				Description: "SSH服务存在安全漏洞",
				Solution:    "更新SSH到最新版本",
				CVE:         "CVE-2021-XXXXX",
				Affected:    service.Name,
			})
		}

		if strings.Contains(strings.ToLower(service.Name), "apache") || strings.Contains(strings.ToLower(service.Name), "httpd") {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "HTTPD-001",
				Name:        "Apache HTTP服务漏洞",
				Severity:    "Medium",
				Description: "Apache HTTP服务存在安全漏洞",
				Solution:    "更新Apache到最新版本",
				CVE:         "CVE-2021-XXXXX",
				Affected:    service.Name,
			})
		}
	}

	return services, vulnerabilities
}

// scanLinuxPrograms 扫描Linux程序
func scanLinuxPrograms() ([]types.ProgramInfo, []types.Vulnerability) {
	var programs []types.ProgramInfo
	var vulnerabilities []types.Vulnerability

	// 检测安装的程序
	commands := []string{
		"curl", "wget", "python3", "python", "perl", "ruby",
		"php", "node", "npm", "java", "gcc", "g++", "make",
		"git", "svn", "docker", "kubectl", "ansible", "puppet",
	}

	for _, cmdName := range commands {
		cmd := exec.Command("which", cmdName)
		if err := cmd.Run(); err == nil {
			programs = append(programs, types.ProgramInfo{
				Name: cmdName,
				Version: "unknown", // 需要进一步检测版本
			})
		}
	}

	// 检测程序漏洞
	for _, program := range programs {
		if program.Name == "curl" {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "CURL-001",
				Name:        "cURL安全漏洞",
				Severity:    "Medium",
				Description: "cURL存在安全漏洞",
				Solution:    "更新cURL到最新版本",
				CVE:         "CVE-2021-XXXXX",
				Affected:    program.Name,
			})
		}

		if program.Name == "python3" || program.Name == "python" {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "PYTHON-001",
				Name:        "Python安全漏洞",
				Severity:    "Medium",
				Description: "Python存在安全漏洞",
				Solution:    "更新Python到最新版本",
				CVE:         "CVE-2021-XXXXX",
				Affected:    program.Name,
			})
		}
	}

	return programs, vulnerabilities
}

// detectDistributionVulnerabilities 检测发行版专属漏洞
func detectDistributionVulnerabilities(distribution string) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 根据发行版检测专属漏洞
	if strings.Contains(distribution, "Ubuntu") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "UBUNTU-001",
			Name:        "Ubuntu发行版漏洞",
			Severity:    "High",
			Description: "Ubuntu发行版存在安全漏洞",
			Solution:    "更新Ubuntu到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Ubuntu",
		})
	}

	if strings.Contains(distribution, "Debian") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "DEBIAN-001",
			Name:        "Debian发行版漏洞",
			Severity:    "High",
			Description: "Debian发行版存在安全漏洞",
			Solution:    "更新Debian到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Debian",
		})
	}

	if strings.Contains(distribution, "CentOS") || strings.Contains(distribution, "Red Hat") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "REDHAT-001",
			Name:        "Red Hat发行版漏洞",
			Severity:    "High",
			Description: "Red Hat发行版存在安全漏洞",
			Solution:    "更新Red Hat到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Red Hat",
		})
	}

	return vulnerabilities
}