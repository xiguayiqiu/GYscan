package internal

import (
	"os/exec"
	"strings"
)

// scanWindowsPrograms 扫描Windows程序
func scanWindowsPrograms() ([]ProgramInfo, []Vulnerability) {
	var programs []ProgramInfo
	var vulnerabilities []Vulnerability

	// 1. 通过Windows注册表获取已安装程序列表
	installedPrograms := getInstalledProgramsFromRegistry()
	programs = append(programs, installedPrograms...)

	// 2. 通过系统路径检测常见程序
	commonPrograms := []string{
		"notepad.exe", "calc.exe", "mspaint.exe", "winword.exe", "excel.exe",
		"powerpnt.exe", "acrord32.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
		"java.exe", "python.exe", "node.exe", "git.exe", "putty.exe",
		"vncserver.exe", "teamviewer.exe", "anydesk.exe", "winscp.exe", "filezilla.exe",
		"mysql.exe", "postgres.exe", "mongod.exe", "redis-server.exe", "apache.exe",
		"nginx.exe", "iisexpress.exe", "tomcat.exe", "jenkins.exe", "docker.exe",
	}

	for _, prog := range commonPrograms {
		cmd := exec.Command("where", prog)
		output, err := cmd.Output()
		if err == nil {
			path := strings.TrimSpace(string(output))
			if path != "" {
				// 检查是否已存在于注册表程序列表中
				found := false
				for _, p := range programs {
					if p.Name == prog {
						found = true
						break
					}
				}
				if !found {
				program := ProgramInfo{
					Name:    prog,
					Path:    path,
					Version: getProgramVersion(path),
				}
				programs = append(programs, program)
			}
			}
		}
	}

	// 3. 通过包管理器检测程序（如Chocolatey、Scoop）
	packageManagerPrograms := getProgramsFromPackageManagers()
	programs = append(programs, packageManagerPrograms...)

	// 4. 检测Windows程序漏洞（基于实际版本信息）
	vulnerabilities = append(vulnerabilities, detectWindowsProgramVulnerabilities(programs)...)

	return programs, vulnerabilities
}

// getInstalledProgramsFromRegistry 从注册表获取已安装程序列表
func getInstalledProgramsFromRegistry() []ProgramInfo {
	var programs []ProgramInfo

	// 通过PowerShell查询注册表中的已安装程序
	cmd := exec.Command("powershell", "Get-ItemProperty", "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*", 
		"| Select-Object DisplayName, DisplayVersion, InstallLocation", 
		"| Where-Object {$_.DisplayName -ne $null}")
	
	output, err := cmd.Output()
	if err != nil {
		return programs
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "DisplayName") && strings.Contains(line, "DisplayVersion") {
			// 解析程序信息
			name := extractValue(line, "DisplayName")
			version := extractValue(line, "DisplayVersion")
			path := extractValue(line, "InstallLocation")
			
			if name != "" {
				program := ProgramInfo{
					Name:    name,
					Version: version,
					Path:    path,
				}
				programs = append(programs, program)
			}
		}
	}

	return programs
}

// getProgramsFromPackageManagers 从包管理器获取程序列表
func getProgramsFromPackageManagers() []ProgramInfo {
	var programs []ProgramInfo

	// 检测Chocolatey包管理器
	if isChocolateyInstalled() {
		chocoPrograms := getChocolateyPrograms()
		programs = append(programs, chocoPrograms...)
	}

	// 检测Scoop包管理器
	if isScoopInstalled() {
		scoopPrograms := getScoopPrograms()
		programs = append(programs, scoopPrograms...)
	}

	return programs
}

// getProgramVersion 获取程序版本
func getProgramVersion(path string) string {
	// 使用PowerShell获取文件版本信息
	cmd := exec.Command("powershell", "(Get-Item '"+path+"').VersionInfo.FileVersion")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown Version"
	}
	
	version := strings.TrimSpace(string(output))
	if version == "" {
		return "Unknown Version"
	}
	return version
}

// extractValue 从PowerShell输出中提取值
func extractValue(line, key string) string {
	start := strings.Index(line, key+" : ")
	if start == -1 {
		return ""
	}
	
	start += len(key) + 3
	end := strings.Index(line[start:], "\r")
	if end == -1 {
		end = len(line)
	} else {
		end += start
	}
	
	value := strings.TrimSpace(line[start:end])
	return value
}

// isChocolateyInstalled 检测Chocolatey是否安装
func isChocolateyInstalled() bool {
	cmd := exec.Command("choco", "--version")
	_, err := cmd.Output()
	return err == nil
}

// isScoopInstalled 检测Scoop是否安装
func isScoopInstalled() bool {
	cmd := exec.Command("scoop", "--version")
	_, err := cmd.Output()
	return err == nil
}

// getChocolateyPrograms 获取Chocolatey安装的程序
func getChocolateyPrograms() []ProgramInfo {
	var programs []ProgramInfo
	
	cmd := exec.Command("choco", "list", "--local-only")
	output, err := cmd.Output()
	if err != nil {
		return programs
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "packages installed") {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			program := ProgramInfo{
				Name:    fields[0],
				Version: fields[1],
				Path:    "Chocolatey Package",
			}
			programs = append(programs, program)
		}
	}
	
	return programs
}

// getScoopPrograms 获取Scoop安装的程序
func getScoopPrograms() []ProgramInfo {
	var programs []ProgramInfo
	
	cmd := exec.Command("scoop", "list")
	output, err := cmd.Output()
	if err != nil {
		return programs
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Installed apps") || strings.TrimSpace(line) == "" {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			program := ProgramInfo{
				Name:    fields[0],
				Version: "Scoop Package",
				Path:    "Scoop Package",
			}
			programs = append(programs, program)
		}
	}
	
	return programs
}

// detectWindowsProgramVulnerabilities 检测Windows程序漏洞
func detectWindowsProgramVulnerabilities(programs []ProgramInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, program := range programs {
		// 基于实际程序版本检测漏洞
		vulns := detectVulnerabilitiesByProgramVersion(program)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities
}

// detectVulnerabilitiesByProgramVersion 根据程序版本检测漏洞
func detectVulnerabilitiesByProgramVersion(program ProgramInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Chrome浏览器漏洞检测
	if strings.Contains(strings.ToLower(program.Name), "chrome") {
		if isChromeVulnerable(program.Version) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "CHROME-001",
				Name:        "Chrome V8引擎漏洞",
				Severity:    "High",
				Description: "Chrome V8 JavaScript引擎存在远程代码执行漏洞",
				Solution:    "更新到最新版本的Chrome浏览器",
				CVE:         "CVE-2021-30551",
				Affected:    "Google Chrome " + program.Version,
			})
		}
	}
	
	// Firefox浏览器漏洞检测
	if strings.Contains(strings.ToLower(program.Name), "firefox") {
		if isFirefoxVulnerable(program.Version) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "FIREFOX-001",
				Name:        "Firefox内存损坏漏洞",
				Severity:    "High",
				Description: "Firefox浏览器存在内存损坏漏洞",
				Solution:    "更新到最新版本的Firefox浏览器",
				CVE:         "CVE-2021-29964",
				Affected:    "Mozilla Firefox " + program.Version,
			})
		}
	}
	
	// Java漏洞检测
	if strings.Contains(strings.ToLower(program.Name), "java") {
		if isJavaVulnerable(program.Version) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "JAVA-001",
				Name:        "Java反序列化漏洞",
				Severity:    "Critical",
				Description: "Java存在反序列化远程代码执行漏洞",
				Solution:    "更新到最新版本的Java",
				CVE:         "CVE-2021-44228",
				Affected:    "Java " + program.Version,
			})
		}
	}
	
	return vulnerabilities
}

// isChromeVulnerable 检测Chrome版本是否易受攻击
func isChromeVulnerable(version string) bool {
	// 这里应该实现实际的版本比较逻辑
	// 简化示例：如果版本低于某个安全版本，则认为易受攻击
	return version < "96.0.4664.110"
}

// isFirefoxVulnerable 检测Firefox版本是否易受攻击
func isFirefoxVulnerable(version string) bool {
	// 这里应该实现实际的版本比较逻辑
	return version < "95.0"
}

// isJavaVulnerable 检测Java版本是否易受攻击
func isJavaVulnerable(version string) bool {
	// 这里应该实现实际的版本比较逻辑
	return strings.Contains(version, "8u") && version < "8u322"
}