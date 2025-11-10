package scanners

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// scanWindowsPrograms 扫描Windows安装的程序
func scanWindowsPrograms() ([]ProgramInfo, []Vulnerability) {
	var programs []ProgramInfo
	var vulnerabilities []Vulnerability

	// 从注册表获取已安装程序
	registryPrograms := getInstalledProgramsFromRegistry()
	programs = append(programs, registryPrograms...)

	// 从包管理器获取程序
	packageManagerPrograms := getProgramsFromPackageManagers()
	programs = append(programs, packageManagerPrograms...)

	// 检测程序漏洞
	programVulnerabilities := detectWindowsProgramVulnerabilities(programs)
	vulnerabilities = append(vulnerabilities, programVulnerabilities...)

	return programs, vulnerabilities
}

// getInstalledProgramsFromRegistry 从注册表获取已安装程序
func getInstalledProgramsFromRegistry() []ProgramInfo {
	var programs []ProgramInfo

	// 检查64位系统上的32位程序
	if runtime.GOARCH == "amd64" {
		programs = append(programs, getProgramsFromRegistry("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")...)
	}

	// 检查所有程序
	programs = append(programs, getProgramsFromRegistry("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")...)

	return programs
}

// getProgramsFromRegistry 从指定注册表路径获取程序
func getProgramsFromRegistry(regPath string) []ProgramInfo {
	var programs []ProgramInfo

	// 使用reg命令查询注册表
	cmd := exec.Command("reg", "query", "HKLM\\"+regPath)
	output, err := cmd.Output()
	if err != nil {
		return programs
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HKEY_") {
			// 提取程序键名
			parts := strings.Split(line, "\\")
			if len(parts) > 0 {
				programKey := parts[len(parts)-1]
				
				// 查询程序详细信息
				program := getProgramInfoFromRegistry(regPath + "\\" + programKey)
				if program.Name != "" {
					programs = append(programs, program)
				}
			}
		}
	}

	return programs
}

// getProgramInfoFromRegistry 从注册表获取程序详细信息
func getProgramInfoFromRegistry(regPath string) ProgramInfo {
	program := ProgramInfo{}

	// 查询DisplayName
	cmd := exec.Command("reg", "query", "HKLM\\"+regPath, "/v", "DisplayName")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "REG_SZ") {
				parts := strings.Split(line, "REG_SZ")
				if len(parts) == 2 {
					program.Name = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// 查询DisplayVersion
	cmd = exec.Command("reg", "query", "HKLM\\"+regPath, "/v", "DisplayVersion")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "REG_SZ") {
				parts := strings.Split(line, "REG_SZ")
				if len(parts) == 2 {
					program.Version = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// 查询Publisher
	cmd = exec.Command("reg", "query", "HKLM\\"+regPath, "/v", "Publisher")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "REG_SZ") {
				parts := strings.Split(line, "REG_SZ")
				if len(parts) == 2 {
					program.Publisher = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// 查询InstallDate
	cmd = exec.Command("reg", "query", "HKLM\\"+regPath, "/v", "InstallDate")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "REG_SZ") {
				parts := strings.Split(line, "REG_SZ")
				if len(parts) == 2 {
					program.InstallDate = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// 查询InstallLocation
	cmd = exec.Command("reg", "query", "HKLM\\"+regPath, "/v", "InstallLocation")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "REG_SZ") {
				parts := strings.Split(line, "REG_SZ")
				if len(parts) == 2 {
					program.InstallPath = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return program
}

// getProgramsFromPackageManagers 从包管理器获取程序
func getProgramsFromPackageManagers() []ProgramInfo {
	var programs []ProgramInfo

	// 从Chocolatey获取程序
	chocoPrograms := getChocolateyPrograms()
	programs = append(programs, chocoPrograms...)

	// 从Scoop获取程序
	scoopPrograms := getScoopPrograms()
	programs = append(programs, scoopPrograms...)

	return programs
}

// getChocolateyPrograms 从Chocolatey获取程序
func getChocolateyPrograms() []ProgramInfo {
	var programs []ProgramInfo

	// 检查Chocolatey是否安装
	cmd := exec.Command("choco", "--version")
	_, err := cmd.Output()
	if err != nil {
		return programs
	}

	// 获取已安装的包列表
	cmd = exec.Command("choco", "list", "--local-only")
	output, err := cmd.Output()
	if err != nil {
		return programs
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Chocolatey") && !strings.Contains(line, "packages listed") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				program := ProgramInfo{
					Name:      parts[0],
					Version:   parts[1],
					Publisher: "Chocolatey",
				}
				programs = append(programs, program)
			}
		}
	}

	return programs
}

// getScoopPrograms 从Scoop获取程序
func getScoopPrograms() []ProgramInfo {
	var programs []ProgramInfo

	// 检查Scoop是否安装
	cmd := exec.Command("scoop", "--version")
	_, err := cmd.Output()
	if err != nil {
		return programs
	}

	// 获取已安装的包列表
	cmd = exec.Command("scoop", "list")
	output, err := cmd.Output()
	if err != nil {
		return programs
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Name") && !strings.Contains(line, "installed") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				program := ProgramInfo{
					Name:      parts[0],
					Version:   parts[1],
					Publisher: "Scoop",
				}
				programs = append(programs, program)
			}
		}
	}

	return programs
}

// detectWindowsProgramVulnerabilities 检测Windows程序漏洞
func detectWindowsProgramVulnerabilities(programs []ProgramInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, program := range programs {
		programVulnerabilities := detectVulnerabilitiesByProgramVersion(program)
		vulnerabilities = append(vulnerabilities, programVulnerabilities...)
	}

	return vulnerabilities
}

// detectVulnerabilitiesByProgramVersion 根据程序版本检测漏洞
func detectVulnerabilitiesByProgramVersion(program ProgramInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 检测Chrome漏洞
	if strings.Contains(strings.ToLower(program.Name), "chrome") || strings.Contains(strings.ToLower(program.Name), "google chrome") {
		vulnerabilities = append(vulnerabilities, detectChromeVulnerabilities(program.Version)...)
	}

	// 检测Firefox漏洞
	if strings.Contains(strings.ToLower(program.Name), "firefox") || strings.Contains(strings.ToLower(program.Name), "mozilla firefox") {
		vulnerabilities = append(vulnerabilities, detectFirefoxVulnerabilities(program.Version)...)
	}

	// 检测Java漏洞
	if strings.Contains(strings.ToLower(program.Name), "java") || strings.Contains(strings.ToLower(program.Name), "jre") || strings.Contains(strings.ToLower(program.Name), "jdk") {
		vulnerabilities = append(vulnerabilities, detectJavaVulnerabilities(program.Version)...)
	}

	// 检测Adobe Reader漏洞
	if strings.Contains(strings.ToLower(program.Name), "adobe") && strings.Contains(strings.ToLower(program.Name), "reader") {
		vulnerabilities = append(vulnerabilities, detectAdobeReaderVulnerabilities(program.Version)...)
	}

	// 检测Flash Player漏洞
	if strings.Contains(strings.ToLower(program.Name), "adobe") && strings.Contains(strings.ToLower(program.Name), "flash") {
		vulnerabilities = append(vulnerabilities, detectFlashPlayerVulnerabilities(program.Version)...)
	}

	// 检测Microsoft Office漏洞
	if strings.Contains(strings.ToLower(program.Name), "microsoft office") || strings.Contains(strings.ToLower(program.Name), "office") {
		vulnerabilities = append(vulnerabilities, detectOfficeVulnerabilities(program.Version)...)
	}

	return vulnerabilities
}

// detectChromeVulnerabilities 检测Chrome漏洞
func detectChromeVulnerabilities(version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 解析版本号
	versionParts := strings.Split(version, ".")
	if len(versionParts) < 1 {
		return vulnerabilities
	}

	majorVersion, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return vulnerabilities
	}

	// 检测已知的Chrome漏洞
	if majorVersion < 90 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "CHROME-001",
			Name:        "Chrome V8引擎类型混淆漏洞",
			Severity:    "Critical",
			Description: "Chrome V8 JavaScript引擎存在类型混淆漏洞，可导致远程代码执行",
			Solution:    "升级Chrome到90.0.4430.85或更高版本",
			CVE:         "CVE-2021-21224",
			Affected:    "Chrome < 90.0.4430.85",
		})
	}

	if majorVersion < 88 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "CHROME-002",
			Name:        "Chrome Freetype堆缓冲区溢出漏洞",
			Severity:    "Critical",
			Description: "Chrome Freetype库存在堆缓冲区溢出漏洞",
			Solution:    "升级Chrome到88.0.4324.150或更高版本",
			CVE:         "CVE-2020-15999",
			Affected:    "Chrome < 88.0.4324.150",
		})
	}

	return vulnerabilities
}

// detectFirefoxVulnerabilities 检测Firefox漏洞
func detectFirefoxVulnerabilities(version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 解析版本号
	versionParts := strings.Split(version, ".")
	if len(versionParts) < 1 {
		return vulnerabilities
	}

	majorVersion, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return vulnerabilities
	}

	// 检测已知的Firefox漏洞
	if majorVersion < 88 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "FIREFOX-001",
			Name:        "Firefox JIT编译器漏洞",
			Severity:    "Critical",
			Description: "Firefox JavaScript JIT编译器存在类型混淆漏洞",
			Solution:    "升级Firefox到88.0或更高版本",
			CVE:         "CVE-2021-29964",
			Affected:    "Firefox < 88.0",
		})
	}

	if majorVersion < 78 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "FIREFOX-002",
			Name:        "Firefox内存损坏漏洞",
			Severity:    "Critical",
			Description: "Firefox存在内存损坏漏洞，可导致远程代码执行",
			Solution:    "升级Firefox到78.0或更高版本",
			CVE:         "CVE-2020-15656",
			Affected:    "Firefox < 78.0",
		})
	}

	return vulnerabilities
}

// detectJavaVulnerabilities 检测Java漏洞
func detectJavaVulnerabilities(version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 解析版本号
	versionParts := strings.Split(version, ".")
	if len(versionParts) < 2 {
		return vulnerabilities
	}

	majorVersion, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return vulnerabilities
	}

	updateVersion, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return vulnerabilities
	}

	// 检测已知的Java漏洞
	if majorVersion == 8 && updateVersion < 291 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "JAVA-001",
			Name:        "Java反序列化漏洞",
			Severity:    "Critical",
			Description: "Java存在反序列化漏洞，可导致远程代码执行",
			Solution:    "升级Java到8u291或更高版本",
			CVE:         "CVE-2021-35550",
			Affected:    "Java 8 < 8u291",
		})
	}

	if majorVersion == 8 && updateVersion < 281 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "JAVA-002",
			Name:        "Java Sandbox绕过漏洞",
			Severity:    "High",
			Description: "Java存在Sandbox绕过漏洞",
			Solution:    "升级Java到8u281或更高版本",
			CVE:         "CVE-2021-2163",
			Affected:    "Java 8 < 8u281",
		})
	}

	return vulnerabilities
}

// detectAdobeReaderVulnerabilities 检测Adobe Reader漏洞
func detectAdobeReaderVulnerabilities(version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 解析版本号
	versionParts := strings.Split(version, ".")
	if len(versionParts) < 1 {
		return vulnerabilities
	}

	majorVersion, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return vulnerabilities
	}

	// 检测已知的Adobe Reader漏洞
	if majorVersion < 21 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "ADOBE-READER-001",
			Name:        "Adobe Reader UAF漏洞",
			Severity:    "Critical",
			Description: "Adobe Reader存在释放后使用漏洞，可导致远程代码执行",
			Solution:    "升级Adobe Reader到21.001.20135或更高版本",
			CVE:         "CVE-2021-28550",
			Affected:    "Adobe Reader < 21.001.20135",
		})
	}

	return vulnerabilities
}

// detectFlashPlayerVulnerabilities 检测Flash Player漏洞
func detectFlashPlayerVulnerabilities(version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Flash Player已于2020年底停止支持，任何版本都存在风险
	vulnerabilities = append(vulnerabilities, Vulnerability{
		ID:          "FLASH-001",
		Name:        "Flash Player已停止支持",
		Severity:    "Critical",
		Description: "Adobe Flash Player已于2020年12月31日停止支持，存在严重安全风险",
		Solution:    "立即卸载Flash Player",
		CVE:         "N/A",
		Affected:    "所有Flash Player版本",
	})

	return vulnerabilities
}

// detectOfficeVulnerabilities 检测Microsoft Office漏洞
func detectOfficeVulnerabilities(version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// 解析版本号
	versionParts := strings.Split(version, ".")
	if len(versionParts) < 2 {
		return vulnerabilities
	}

	majorVersion, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return vulnerabilities
	}

	// 检测已知的Office漏洞
	if majorVersion < 16 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "OFFICE-001",
			Name:        "Office内存损坏漏洞",
			Severity:    "Critical",
			Description: "Microsoft Office存在内存损坏漏洞，可导致远程代码执行",
			Solution:    "升级Office到最新版本",
			CVE:         "CVE-2021-40444",
			Affected:    "Office 2010-2019",
		})
	}

	return vulnerabilities
}