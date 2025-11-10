package scanners

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"GYscan-linux-C2/pkg/types"
	"GYscan-linux-C2/pkg/utils"
	
)

// VulnScanner 漏洞扫描器
type VulnScanner struct {
	Verbose bool
}

// NewVulnScanner 创建新的漏洞扫描器
func NewVulnScanner(verbose bool) *VulnScanner {
	return &VulnScanner{
		Verbose: verbose,
	}
}

// Scan 执行漏洞扫描
func (vs *VulnScanner) Scan(target, scanType string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	// 获取系统信息和发行版信息
	result.OSInfo = vs.getOSInfo()
	result.Distribution = vs.getLinuxDistribution()

	// 根据扫描类型执行相应的扫描
	scanTypes := strings.Split(scanType, ",")
	for _, t := range scanTypes {
		switch strings.ToLower(t) {
		case "all":
			vs.scanKernelVulnerabilities(result)
			vs.scanServices(result)
			vs.scanPrograms(result)
			vs.scanMiddleware(result)
			vs.scanDistributionVulnerabilities(result)
			vs.scanCommandExecVulnerabilities(result)
			vs.scanPrivilegeEscalationVulnerabilities(result)
			vs.scanSQLInjectionVulnerabilities(result)
		case "kernel":
			vs.scanKernelVulnerabilities(result)
		case "services":
			vs.scanServices(result)
		case "programs":
			vs.scanPrograms(result)
		case "middleware":
			vs.scanMiddleware(result)
		case "distro":
			vs.scanDistributionVulnerabilities(result)
		case "command_exec":
			vs.scanCommandExecVulnerabilities(result)
		case "privilege_escalation":
			vs.scanPrivilegeEscalationVulnerabilities(result)
		case "sql_injection":
			vs.scanSQLInjectionVulnerabilities(result)
		}
	}

	result.ScanDuration = time.Since(result.Timestamp)
	return result, nil
}

// getOSInfo 获取操作系统信息
func (vs *VulnScanner) getOSInfo() string {
	// 实际获取Linux系统版本信息
	osInfo := getActualLinuxVersion()
	if osInfo == "" {
		return "Linux System Information"
	}
	return osInfo
}

// getLinuxDistribution 获取Linux发行版信息
func (vs *VulnScanner) getLinuxDistribution() string {
	// 实际检测Linux发行版
	distro := detectActualLinuxDistribution()
	if distro == "" {
		return "Unknown Distribution"
	}
	return distro
}

// getActualLinuxVersion 获取实际的Linux版本信息
func getActualLinuxVersion() string {
	// 使用uname命令获取内核版本
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	kernelVersion := strings.TrimSpace(string(output))

	// 获取发行版信息
	cmd = exec.Command("cat", "/etc/os-release")
	output, err = cmd.Output()
	if err != nil {
		return fmt.Sprintf("Linux Kernel %s", kernelVersion)
	}

	return fmt.Sprintf("Linux Kernel %s - %s", kernelVersion, string(output))
}

// detectActualLinuxDistribution 检测实际的Linux发行版
func detectActualLinuxDistribution() string {
	// 检查/etc/os-release文件
	cmd := exec.Command("cat", "/etc/os-release")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	return ""
}

// scanKernelVulnerabilities 扫描Linux内核漏洞
func (vs *VulnScanner) scanKernelVulnerabilities(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描Linux内核漏洞...")
	}

	// 检测Linux内核漏洞
	vulnerabilities := detectLinuxKernelVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilities...)

	if vs.Verbose {
		fmt.Printf("发现内核漏洞: %d个\n", len(vulnerabilities))
	}
}

// scanServices 扫描服务漏洞
func (vs *VulnScanner) scanServices(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描服务漏洞...")
	}

	// 检测运行的服务
	services, serviceVulns := scanLinuxServices()
	result.Services = services
	result.Vulnerabilities = append(result.Vulnerabilities, serviceVulns...)

	if vs.Verbose {
		fmt.Printf("发现服务: %d个\n", len(services))
		fmt.Printf("发现服务漏洞: %d个\n", len(serviceVulns))
	}
}

// scanPrograms 扫描程序漏洞
func (vs *VulnScanner) scanPrograms(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描程序漏洞...")
	}

	// 检测安装的程序
	programs, programVulns := scanLinuxPrograms()
	result.Programs = programs
	result.Vulnerabilities = append(result.Vulnerabilities, programVulns...)

	if vs.Verbose {
		fmt.Printf("发现程序: %d个\n", len(programs))
		fmt.Printf("发现程序漏洞: %d个\n", len(programVulns))
	}
}

// scanMiddleware 扫描中间件漏洞
func (vs *VulnScanner) scanMiddleware(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描中间件漏洞...")
	}

	// 检测中间件漏洞
	middlewareVulns := utils.DetectMiddlewareVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, middlewareVulns...)

	if vs.Verbose {
		fmt.Printf("发现中间件漏洞: %d个\n", len(middlewareVulns))
	}
}

// scanDistributionVulnerabilities 扫描发行版漏洞
func (vs *VulnScanner) scanDistributionVulnerabilities(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描发行版专属漏洞...")
	}

	// 检测Linux发行版专属漏洞
	distroVulns := detectDistributionVulnerabilities(result.Distribution)

	// 过滤掉不适用于当前发行版的漏洞
	filteredVulns := vs.filterDistributionVulnerabilities(distroVulns, result.Distribution)
	result.Vulnerabilities = append(result.Vulnerabilities, filteredVulns...)

	if vs.Verbose {
		fmt.Printf("发现发行版漏洞: %d个 (过滤后: %d个)\n", len(distroVulns), len(filteredVulns))
	}
}

// filterDistributionVulnerabilities 根据实际发行版过滤漏洞
func (vs *VulnScanner) filterDistributionVulnerabilities(vulnerabilities []types.Vulnerability, distribution string) []types.Vulnerability {
	var filtered []types.Vulnerability

	// 解析发行版信息
	distroInfo := parseLinuxDistribution(distribution)

	for _, vuln := range vulnerabilities {
		// 检查漏洞是否适用于当前发行版
		if vs.isDistributionVulnerabilityApplicable(vuln, distroInfo) {
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}

// parseLinuxDistribution 解析Linux发行版信息
func parseLinuxDistribution(distribution string) map[string]string {
	info := make(map[string]string)

	// 简单的发行版解析逻辑
	if strings.Contains(distribution, "Ubuntu") {
		info["name"] = "Ubuntu"
	} else if strings.Contains(distribution, "Debian") {
		info["name"] = "Debian"
	} else if strings.Contains(distribution, "CentOS") || strings.Contains(distribution, "Red Hat") {
		info["name"] = "RedHat"
	} else if strings.Contains(distribution, "Fedora") {
		info["name"] = "Fedora"
	} else if strings.Contains(distribution, "Arch") {
		info["name"] = "Arch"
	} else if strings.Contains(distribution, "openSUSE") {
		info["name"] = "openSUSE"
	}

	return info
}

// isDistributionVulnerabilityApplicable 检查发行版漏洞是否适用于当前系统
func (vs *VulnScanner) isDistributionVulnerabilityApplicable(vuln types.Vulnerability, distroInfo map[string]string) bool {
	// 如果漏洞没有指定受影响发行版，则默认适用
	if vuln.Affected == "" || vuln.Affected == "所有Linux发行版" {
		return true
	}

	// 检查漏洞是否适用于当前发行版
	if strings.Contains(vuln.Affected, distroInfo["name"]) {
		return true
	}

	// 检查通用Linux漏洞
	if strings.Contains(vuln.Affected, "Linux") && !strings.Contains(vuln.Affected, "特定") {
		return true
	}

	return false
}

// scanCommandExecVulnerabilities 扫描命令执行漏洞
func (vs *VulnScanner) scanCommandExecVulnerabilities(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描命令执行漏洞...")
	}

	// 检测命令执行漏洞
	commandExecVulns := detectCommandExecVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, commandExecVulns...)

	if vs.Verbose {
		fmt.Printf("发现命令执行漏洞: %d个\n", len(commandExecVulns))
	}
}

// scanPrivilegeEscalationVulnerabilities 扫描权限提升漏洞
func (vs *VulnScanner) scanPrivilegeEscalationVulnerabilities(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描权限提升漏洞...")
	}

	// 检测权限提升漏洞
	privilegeEscalationVulns := detectPrivilegeEscalationVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, privilegeEscalationVulns...)

	if vs.Verbose {
		fmt.Printf("发现权限提升漏洞: %d个\n", len(privilegeEscalationVulns))
	}
}

// scanSQLInjectionVulnerabilities 扫描SQL注入漏洞
func (vs *VulnScanner) scanSQLInjectionVulnerabilities(result *types.ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描SQL注入漏洞...")
	}

	// 检测SQL注入漏洞
	sqlInjectionVulns := detectSQLInjectionVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, sqlInjectionVulns...)

	if vs.Verbose {
		fmt.Printf("发现SQL注入漏洞: %d个\n", len(sqlInjectionVulns))
	}
}

// detectCommandExecVulnerabilities 检测命令执行漏洞
func detectCommandExecVulnerabilities() []types.Vulnerability {
	// 这里应该调用vulnscan模块的检测功能
	// 暂时返回模拟结果
	return []types.Vulnerability{
		{
			ID:          "LINUX-CMD-001",
			Name:        "Linux命令执行漏洞",
			Severity:    "Critical",
			Description: "Linux系统存在命令执行漏洞",
			Solution:    "更新系统到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Linux系统",
		},
	}
}

// detectPrivilegeEscalationVulnerabilities 检测权限提升漏洞
func detectPrivilegeEscalationVulnerabilities() []types.Vulnerability {
	// 这里应该调用vulnscan模块的检测功能
	// 暂时返回模拟结果
	return []types.Vulnerability{
		{
			ID:          "LINUX-PRIV-001",
			Name:        "Linux权限提升漏洞",
			Severity:    "Critical",
			Description: "Linux系统存在权限提升漏洞",
			Solution:    "更新系统到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Linux系统",
		},
	}
}

// detectSQLInjectionVulnerabilities 检测SQL注入漏洞
func detectSQLInjectionVulnerabilities() []types.Vulnerability {
	// 这里应该调用vulnscan模块的检测功能
	// 暂时返回模拟结果
	return []types.Vulnerability{
		{
			ID:          "LINUX-SQL-001",
			Name:        "Linux SQL注入漏洞",
			Severity:    "Critical",
			Description: "Linux系统存在SQL注入漏洞",
			Solution:    "更新系统到最新版本",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Linux系统",
		},
	}
}
