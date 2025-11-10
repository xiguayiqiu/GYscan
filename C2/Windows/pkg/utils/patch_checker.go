package utils

import (
	"fmt"
	"GYscan-Win-C2/pkg/types"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// PatchInfo 补丁信息
type PatchInfo struct {
	HotFixID    string
	Description string
	InstalledOn string
	InstalledBy string
}

// UpdateInfo 更新信息
type UpdateInfo struct {
	UpdateID    string
	Title       string
	Description string
	Status      string
	Date        string
}

// PatchChecker 补丁检查器
type PatchChecker struct {
	Verbose bool
}

// NewPatchChecker 创建新的补丁检查器
func NewPatchChecker(verbose bool) *PatchChecker {
	return &PatchChecker{
		Verbose: verbose,
	}
}

// CheckSystemPatches 检查系统补丁
func (pc *PatchChecker) CheckSystemPatches() ([]PatchInfo, []types.Vulnerability) {
	var patches []PatchInfo
	var vulnerabilities []types.Vulnerability

	if pc.Verbose {
		fmt.Println("开始检查系统补丁...")
	}

	// 获取已安装的补丁列表
	installedPatches := pc.getInstalledPatches()
	patches = append(patches, installedPatches...)

	// 检查缺失的关键补丁
	missingPatches := pc.checkMissingPatches(installedPatches)
	vulnerabilities = append(vulnerabilities, missingPatches...)

	// 检查更新历史
	updateHistory := pc.getUpdateHistory()
	if pc.Verbose {
		fmt.Printf("获取到 %d 条更新历史记录\n", len(updateHistory))
	}

	if pc.Verbose {
		fmt.Printf("发现 %d 个补丁相关的漏洞\n", len(vulnerabilities))
	}

	return patches, vulnerabilities
}

// getInstalledPatches 获取已安装的补丁列表
func (pc *PatchChecker) getInstalledPatches() []PatchInfo {
	var patches []PatchInfo

	if runtime.GOOS != "windows" {
		return patches
	}

	// 使用wmic获取补丁信息
	cmd := exec.Command("wmic", "qfe", "get", "HotFixID,Description,InstalledOn,InstalledBy", "/format:csv")
	output, err := cmd.Output()
	if err != nil {
		if pc.Verbose {
			fmt.Printf("获取补丁信息失败: %v\n", err)
		}
		return patches
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		// 跳过标题行
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 5 {
			patch := PatchInfo{
				HotFixID:    strings.TrimSpace(fields[1]),
				Description: strings.TrimSpace(fields[2]),
				InstalledOn: strings.TrimSpace(fields[3]),
				InstalledBy: strings.TrimSpace(fields[4]),
			}
			patches = append(patches, patch)
		}
	}

	return patches
}

// getUpdateHistory 获取更新历史
func (pc *PatchChecker) getUpdateHistory() []UpdateInfo {
	var updates []UpdateInfo

	if runtime.GOOS != "windows" {
		return updates
	}

	// 使用PowerShell获取更新历史
	cmd := exec.Command("powershell", "Get-WmiObject", "-Class", "Win32_ReliabilityRecords", "|", 
		"Where-Object", "{$_.SourceName -eq 'Microsoft-Windows-WindowsUpdateClient'}", "|", 
		"Select-Object", "TimeGenerated,Message", "|", "Format-Table", "-AutoSize")
	
	output, err := cmd.Output()
	if err != nil {
		if pc.Verbose {
			fmt.Printf("获取更新历史失败: %v\n", err)
		}
		return updates
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "安装") || strings.Contains(line, "Install") {
			update := UpdateInfo{
				UpdateID:    "",
				Title:       strings.TrimSpace(line),
				Description: "Windows更新",
				Status:      "已安装",
				Date:        time.Now().Format("2006-01-02"),
			}
			updates = append(updates, update)
		}
	}

	return updates
}

// checkMissingPatches 检查缺失的关键补丁
func (pc *PatchChecker) checkMissingPatches(installedPatches []PatchInfo) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 关键补丁列表（基于Windows版本）
	criticalPatches := pc.getCriticalPatchesForCurrentOS()

	// 检查每个关键补丁是否已安装
	for _, criticalPatch := range criticalPatches {
		installed := false
		for _, installedPatch := range installedPatches {
			if strings.Contains(installedPatch.HotFixID, criticalPatch.KB) {
				installed = true
				break
			}
		}

		if !installed {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          fmt.Sprintf("PATCH-%s", criticalPatch.KB),
				Name:        criticalPatch.Name,
				Severity:    criticalPatch.Severity,
				Description: criticalPatch.Description,
				Solution:    fmt.Sprintf("安装Windows更新 %s", criticalPatch.KB),
				CVE:         criticalPatch.CVE,
				Affected:    criticalPatch.Affected,
			})
		}
	}

	return vulnerabilities
}

// getOSInfo 获取操作系统信息
func (pc *PatchChecker) getOSInfo() string {
	// 使用systeminfo命令获取操作系统信息
	cmd := exec.Command("systeminfo")
	output, err := cmd.Output()
	if err != nil {
		if pc.Verbose {
			fmt.Printf("获取系统信息失败: %v\n", err)
		}
		return "Unknown"
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "OS Name") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return "Unknown"
}

// CriticalPatch 关键补丁信息
type CriticalPatch struct {
	KB          string
	Name        string
	Severity    string
	Description string
	CVE         string
	Affected    string
}

// getCriticalPatchesForCurrentOS 获取当前操作系统需要的关键补丁
func (pc *PatchChecker) getCriticalPatchesForCurrentOS() []CriticalPatch {
	var criticalPatches []CriticalPatch

	// 获取Windows版本信息
	osInfo := pc.getOSInfo()

	// 基于Windows版本添加关键补丁
	if strings.Contains(osInfo, "Windows 10") || strings.Contains(osInfo, "Windows 11") {
		criticalPatches = append(criticalPatches, []CriticalPatch{
			{
				KB:          "KB5009543",
				Name:        "Windows Print Spooler远程代码执行漏洞",
				Severity:    "Critical",
				Description: "Windows Print Spooler服务存在远程代码执行漏洞（PrintNightmare）",
				CVE:         "CVE-2021-34527",
				Affected:    "Windows 10/11",
			},
			{
				KB:          "KB5006670",
				Name:        "Windows TCP/IP远程代码执行漏洞",
				Severity:    "Critical",
				Description: "Windows TCP/IP协议栈存在远程代码执行漏洞",
				CVE:         "CVE-2021-24086",
				Affected:    "Windows 10/11",
			},
			{
				KB:          "KB5005565",
				Name:        "Windows MSHTML远程代码执行漏洞",
				Severity:    "Critical",
				Description: "Windows MSHTML组件存在远程代码执行漏洞",
				CVE:         "CVE-2021-40444",
				Affected:    "Windows 10/11",
			},
		}...)
	}

	if strings.Contains(osInfo, "Windows Server") {
		criticalPatches = append(criticalPatches, []CriticalPatch{
			{
				KB:          "KB5007247",
				Name:        "Windows Kerberos安全漏洞",
				Severity:    "Critical",
				Description: "Windows Kerberos协议存在安全漏洞",
				CVE:         "CVE-2021-42287",
				Affected:    "Windows Server",
			},
			{
				KB:          "KB5005565",
				Name:        "Windows DNS服务器远程代码执行漏洞",
				Severity:    "Critical",
				Description: "Windows DNS服务器存在远程代码执行漏洞（SIGRed）",
				CVE:         "CVE-2020-1350",
				Affected:    "Windows Server",
			},
		}...)
	}

	// 添加通用关键补丁
	criticalPatches = append(criticalPatches, []CriticalPatch{
		{
			KB:          "KB5005033",
			Name:        "Windows SMB远程代码执行漏洞",
			Severity:    "Critical",
			Description: "Windows SMB协议存在远程代码执行漏洞",
			CVE:         "CVE-2021-31166",
			Affected:    "Windows系统",
		},
		{
			KB:          "KB4577586",
			Name:        "Adobe Flash Player安全更新",
			Severity:    "High",
			Description: "Adobe Flash Player存在安全漏洞",
			CVE:         "CVE-2021-XXXXX",
			Affected:    "Windows系统",
		},
	}...)

	return criticalPatches
}

// CheckFileVersions 检查关键系统文件的版本
func (pc *PatchChecker) CheckFileVersions() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	if pc.Verbose {
		fmt.Println("开始检查关键系统文件版本...")
	}

	// 检查关键系统文件
	criticalFiles := []struct {
		Path        string
		MinVersion  string
		Vulnerability types.Vulnerability
	}{
		{
			Path:       "C:\\Windows\\System32\\ntdll.dll",
			MinVersion: "10.0.19041.1202",
			Vulnerability: types.Vulnerability{
				ID:          "FILE-NTDLL-001",
				Name:        "ntdll.dll版本过旧",
				Severity:    "High",
				Description: "ntdll.dll文件版本过旧，可能存在安全漏洞",
				Solution:    "安装最新的Windows更新",
				CVE:         "CVE-2021-XXXXX",
				Affected:    "Windows系统",
			},
		},
		{
			Path:       "C:\\Windows\\System32\\kernel32.dll",
			MinVersion: "10.0.19041.1202",
			Vulnerability: types.Vulnerability{
				ID:          "FILE-KERNEL32-001",
				Name:        "kernel32.dll版本过旧",
				Severity:    "High",
				Description: "kernel32.dll文件版本过旧，可能存在安全漏洞",
				Solution:    "安装最新的Windows更新",
				CVE:         "CVE-2021-XXXXX",
				Affected:    "Windows系统",
			},
		},
	}

	for _, file := range criticalFiles {
		version := pc.getFileVersion(file.Path)
		if version != "" && pc.isVersionOlder(version, file.MinVersion) {
			vulnerabilities = append(vulnerabilities, file.Vulnerability)
		}
	}

	return vulnerabilities
}

// getFileVersion 获取文件版本
func (pc *PatchChecker) getFileVersion(filePath string) string {
	if runtime.GOOS != "windows" {
		return ""
	}

	cmd := exec.Command("powershell", "Get-Item", filePath, "|", "Select-Object", "-ExpandProperty", "VersionInfo", "|", 
		"Select-Object", "ProductVersion")
	
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// isVersionOlder 比较版本号
func (pc *PatchChecker) isVersionOlder(currentVersion, minVersion string) bool {
	// 简单的版本比较逻辑
	return currentVersion < minVersion
}

// CheckSecurityUpdates 检查安全更新状态
func (pc *PatchChecker) CheckSecurityUpdates() []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	if pc.Verbose {
		fmt.Println("开始检查安全更新状态...")
	}

	// 检查Windows更新服务状态
	if !pc.isWindowsUpdateEnabled() {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "UPDATE-001",
			Name:        "Windows更新服务已禁用",
			Severity:    "Medium",
			Description: "Windows更新服务已禁用，系统可能无法获取最新的安全更新",
			Solution:    "启用Windows更新服务",
			CVE:         "",
			Affected:    "Windows系统",
		})
	}

	// 检查最后更新时间
	lastUpdateTime := pc.getLastUpdateTime()
	if lastUpdateTime.IsZero() || time.Since(lastUpdateTime) > 90*24*time.Hour {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "UPDATE-002",
			Name:        "系统长时间未更新",
			Severity:    "High",
			Description: "系统超过90天未安装安全更新，存在安全风险",
			Solution:    "立即检查并安装Windows更新",
			CVE:         "",
			Affected:    "Windows系统",
		})
	}

	return vulnerabilities
}

// isWindowsUpdateEnabled 检查Windows更新服务是否启用
func (pc *PatchChecker) isWindowsUpdateEnabled() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	cmd := exec.Command("sc", "query", "wuauserv")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "RUNNING")
}

// getLastUpdateTime 获取最后更新时间
func (pc *PatchChecker) getLastUpdateTime() time.Time {
	if runtime.GOOS != "windows" {
		return time.Time{}
	}

	cmd := exec.Command("powershell", "Get-HotFix", "|", "Sort-Object", "InstalledOn", "|", 
		"Select-Object", "-Last", "1", "|", "Select-Object", "-ExpandProperty", "InstalledOn")
	
	output, err := cmd.Output()
	if err != nil {
		return time.Time{}
	}

	dateStr := strings.TrimSpace(string(output))
	if dateStr == "" {
		return time.Time{}
	}

	// 解析日期格式
	lastUpdate, err := time.Parse("1/2/2006", dateStr)
	if err != nil {
		return time.Time{}
	}

	return lastUpdate
}