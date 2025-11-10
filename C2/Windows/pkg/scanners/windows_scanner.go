package scanners

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

// detectWindowsSystemVulnerabilities 检测Windows系统漏洞
func detectWindowsSystemVulnerabilities() []Vulnerability {
	var vulnerabilities []Vulnerability

	// 获取Windows版本信息
	version := getWindowsVersion()
	
	// 根据Windows版本检测相应的漏洞
	switch {
	case strings.Contains(version, "Windows Vista"):
		vulnerabilities = append(vulnerabilities, detectVistaVulnerabilities()...)
	case strings.Contains(version, "Windows 7"):
		vulnerabilities = append(vulnerabilities, detectWindows7Vulnerabilities()...)
	case strings.Contains(version, "Windows 8"):
		vulnerabilities = append(vulnerabilities, detectWindows8Vulnerabilities()...)
	case strings.Contains(version, "Windows 10"):
		vulnerabilities = append(vulnerabilities, detectWindows10Vulnerabilities()...)
	case strings.Contains(version, "Windows 11"):
		vulnerabilities = append(vulnerabilities, detectWindows11Vulnerabilities()...)
	}

	// 检测通用Windows漏洞
	vulnerabilities = append(vulnerabilities, detectCommonWindowsVulnerabilities()...)

	// 检测实际存在的服务漏洞
	vulnerabilities = append(vulnerabilities, detectActualServiceVulnerabilities()...)

	return vulnerabilities
}

// getWindowsVersion 获取Windows版本信息
func getWindowsVersion() string {
	// 使用PowerShell命令获取Windows版本信息
	cmd := exec.Command("powershell", "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption")
	output, err := cmd.Output()
	if err != nil {
		// 备用方法：使用systeminfo命令
		cmd = exec.Command("systeminfo")
		output, err = cmd.Output()
		if err != nil {
			return "Unknown Windows Version"
		}
		return string(output)
	}
	return string(output)
}

// detectVistaVulnerabilities 检测Windows Vista漏洞
func detectVistaVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "VISTA-001",
			Name:        "Windows Vista SMB漏洞",
			Severity:    "Critical",
			Description: "Windows Vista SMB协议存在远程代码执行漏洞",
			Solution:    "安装MS08-067安全更新",
			CVE:         "CVE-2008-4250",
			Affected:    "Windows Vista",
		},
	}
}

// detectWindows7Vulnerabilities 检测Windows 7漏洞
func detectWindows7Vulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "WIN7-001",
			Name:        "Windows 7 SMB Ghost漏洞",
			Severity:    "Critical",
			Description: "Windows 7 SMBv3协议存在远程代码执行漏洞",
			Solution:    "安装KB4557957安全更新",
			CVE:         "CVE-2020-0796",
			Affected:    "Windows 7",
		},
		{
			ID:          "WIN7-002",
			Name:        "Windows 7 EternalBlue漏洞",
			Severity:    "Critical", 
			Description: "Windows 7 SMBv1协议存在远程代码执行漏洞",
			Solution:    "禁用SMBv1协议，安装MS17-010更新",
			CVE:         "CVE-2017-0144",
			Affected:    "Windows 7",
		},
	}
}

// detectWindows8Vulnerabilities 检测Windows 8漏洞
func detectWindows8Vulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "WIN8-001",
			Name:        "Windows 8 SMB漏洞",
			Severity:    "Critical",
			Description: "Windows 8 SMB协议存在远程代码执行漏洞",
			Solution:    "安装MS17-010安全更新",
			CVE:         "CVE-2017-0144",
			Affected:    "Windows 8",
		},
	}
}

// detectWindows10Vulnerabilities 检测Windows 10漏洞
func detectWindows10Vulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "WIN10-001",
			Name:        "Windows 10 SMBv3漏洞",
			Severity:    "Critical",
			Description: "Windows 10 SMBv3协议存在远程代码执行漏洞",
			Solution:    "安装KB4557957安全更新",
			CVE:         "CVE-2020-0796",
			Affected:    "Windows 10",
		},
		{
			ID:          "WIN10-002",
			Name:        "Windows 10 PrintNightmare漏洞",
			Severity:    "Critical",
			Description: "Windows打印后台处理程序存在权限提升漏洞",
			Solution:    "安装KB5004945安全更新",
			CVE:         "CVE-2021-34527",
			Affected:    "Windows 10",
		},
		{
			ID:          "WIN10-003",
			Name:        "Windows 10 Zerologon漏洞",
			Severity:    "Critical",
			Description: "Netlogon协议存在特权提升漏洞",
			Solution:    "安装KB4557957安全更新",
			CVE:         "CVE-2020-1472",
			Affected:    "Windows 10",
		},
	}
}

// detectWindows11Vulnerabilities 检测Windows 11漏洞
func detectWindows11Vulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "WIN11-001",
			Name:        "Windows 11 PrintNightmare漏洞",
			Severity:    "Critical",
			Description: "Windows 11打印后台处理程序存在权限提升漏洞",
			Solution:    "安装KB5004945安全更新",
			CVE:         "CVE-2021-34527",
			Affected:    "Windows 11",
		},
		{
			ID:          "WIN11-002",
			Name:        "Windows 11 SMB漏洞",
			Severity:    "High",
			Description: "Windows 11 SMB协议存在信息泄露漏洞",
			Solution:    "安装最新的安全更新",
			CVE:         "CVE-2023-21715",
			Affected:    "Windows 11",
		},
	}
}

// detectCommonWindowsVulnerabilities 检测通用Windows漏洞
func detectCommonWindowsVulnerabilities() []Vulnerability {
	return []Vulnerability{
		{
			ID:          "WIN-COMMON-001",
			Name:        "BlueKeep RDP漏洞",
			Severity:    "Critical",
			Description: "Windows远程桌面服务存在远程代码执行漏洞，无需用户交互即可被利用",
			Solution:    "安装KB4499175、KB4499180等安全更新",
			CVE:         "CVE-2019-0708",
			Affected:    "Windows 7, Windows Server 2008 R2, Windows Server 2008, Windows XP",
		},
		{
			ID:          "WIN-COMMON-002",
			Name:        "SIGRed Windows DNS漏洞",
			Severity:    "Critical",
			Description: "Windows DNS服务器存在远程代码执行漏洞，可导致域控服务器被完全控制",
			Solution:    "安装KB4569509安全更新",
			CVE:         "CVE-2020-1350",
			Affected:    "Windows Server 2008-2019",
		},
		{
			ID:          "WIN-COMMON-003",
			Name:        "EternalBlue SMB漏洞",
			Severity:    "Critical",
			Description: "SMBv1协议存在远程代码执行漏洞，被WannaCry勒索软件利用",
			Solution:    "禁用SMBv1协议，安装MS17-010安全更新",
			CVE:         "CVE-2017-0144",
			Affected:    "Windows Vista到Windows 10",
		},
		{
			ID:          "WIN-COMMON-004",
			Name:        "SMBGhost漏洞",
			Severity:    "Critical",
			Description: "SMBv3协议存在预认证远程代码执行漏洞",
			Solution:    "安装KB4557957安全更新",
			CVE:         "CVE-2020-0796",
			Affected:    "Windows 10 1903-1909",
		},
		{
			ID:          "WIN-COMMON-005",
			Name:        "PetitPotam NTLM中继漏洞",
			Severity:    "High",
			Description: "LSARPC接口存在NTLM中继攻击漏洞，可导致域控被控制",
			Solution:    "禁用NTLM认证，启用SMB签名",
			CVE:         "CVE-2021-36942",
			Affected:    "Windows 8.1到Windows 11",
		},
	}
}

// detectActualServiceVulnerabilities 检测实际存在的服务漏洞
func detectActualServiceVulnerabilities() []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检测IIS服务漏洞
	if isIISInstalled() {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "IIS-REAL-001",
			Name:        "IIS WebDAV远程代码执行",
			Severity:    "Critical",
			Description: "IIS WebDAV组件存在远程代码执行漏洞",
			Solution:    "禁用WebDAV或安装安全更新",
			CVE:         "CVE-2017-7269",
			Affected:    "IIS 6.0",
		})
	}

	// 检测SQL Server漏洞
	if isSQLServerInstalled() {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "SQL-REAL-001",
			Name:        "SQL Server远程代码执行",
			Severity:    "Critical",
			Description: "SQL Server存在远程代码执行漏洞",
			Solution:    "安装最新的SQL Server安全更新",
			CVE:         "CVE-2021-1636",
			Affected:    "SQL Server 2012-2019",
		})
	}

	// 检测Exchange Server漏洞
	if isExchangeInstalled() {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "EXCHANGE-REAL-001",
			Name:        "ProxyShell Exchange漏洞",
			Severity:    "Critical",
			Description: "Exchange Server存在权限提升和远程代码执行漏洞链",
			Solution:    "安装Exchange Server累积更新",
			CVE:         "CVE-2021-34473",
			Affected:    "Exchange Server 2013-2019",
		})
	}

	// 检测RDP服务状态
	if isRDPEnabled() {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "RDP-REAL-001",
			Name:        "RDP服务启用",
			Severity:    "Medium",
			Description: "RDP服务已启用，存在潜在安全风险",
			Solution:    "如非必要，请禁用RDP服务",
			CVE:         "",
			Affected:    "RDP服务",
		})
	}

	return vulnerabilities
}

// isIISInstalled 检测IIS是否安装
func isIISInstalled() bool {
	cmd := exec.Command("powershell", "Get-WindowsFeature", "-Name", "Web-Server")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Installed")
}

// isSQLServerInstalled 检测SQL Server是否安装
func isSQLServerInstalled() bool {
	cmd := exec.Command("powershell", "Get-Service", "-Name", "MSSQL*")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Running")
}

// isExchangeInstalled 检测Exchange Server是否安装
func isExchangeInstalled() bool {
	cmd := exec.Command("powershell", "Get-Service", "-Name", "MSExchange*")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Running")
}

// isRDPEnabled 检测RDP服务是否启用
func isRDPEnabled() bool {
	cmd := exec.Command("reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "0x0")
}