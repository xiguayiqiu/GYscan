package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	
	"GYscan-Win-C2/pkg/types"
)

// FileSystemChecker 文件系统检查器
type FileSystemChecker struct {
	Verbose bool
}

// FileInfo 文件信息
type FileInfo struct {
	Path        string
	Size        int64
	Version     string
	MD5Hash     string
	SHA1Hash    string
	SHA256Hash  string
	ModifiedTime string
}

// RegistryKeyInfo 注册表键信息
type RegistryKeyInfo struct {
	Path    string
	Value   string
	Type    string
	Data    string
}

// NewFileSystemChecker 创建新的文件系统检查器
func NewFileSystemChecker(verbose bool) *FileSystemChecker {
	return &FileSystemChecker{
		Verbose: verbose,
	}
}

// CheckSystemFiles 检查系统关键文件
func (fsc *FileSystemChecker) CheckSystemFiles() ([]FileInfo, []types.Vulnerability) {
	var files []FileInfo
	var vulnerabilities []types.Vulnerability

	if fsc.Verbose {
		fmt.Println("开始检查系统关键文件...")
	}

	// 定义需要检查的关键系统文件
	criticalFiles := []string{
		"C:\\Windows\\System32\\win32spl.dll",      // Print Spooler
		"C:\\Windows\\System32\\ntoskrnl.exe",      // Windows Kernel
		"C:\\Windows\\System32\\lsass.exe",         // Local Security Authority
		"C:\\Windows\\System32\\svchost.exe",       // Service Host
		"C:\\Windows\\System32\\kernel32.dll",     // Kernel32
		"C:\\Windows\\System32\\user32.dll",       // User32
		"C:\\Windows\\System32\\advapi32.dll",     // Advanced API
		"C:\\Windows\\System32\\netapi32.dll",     // Network API
	}

	for _, filePath := range criticalFiles {
		if fsc.Verbose {
			fmt.Printf("检查文件: %s\n", filePath)
		}

		fileInfo, err := fsc.getFileInfo(filePath)
		if err != nil {
			if fsc.Verbose {
				fmt.Printf("文件不存在或无法访问: %s\n", filePath)
			}
			continue
		}

		files = append(files, fileInfo)

		// 检查文件版本相关的漏洞
		fileVulns := fsc.checkFileVulnerabilities(fileInfo)
		vulnerabilities = append(vulnerabilities, fileVulns...)
	}

	return files, vulnerabilities
}

// CheckRegistryKeys 检查关键注册表项
func (fsc *FileSystemChecker) CheckRegistryKeys() ([]RegistryKeyInfo, []types.Vulnerability) {
	var registryKeys []RegistryKeyInfo
	var vulnerabilities []types.Vulnerability

	if fsc.Verbose {
		fmt.Println("开始检查关键注册表项...")
	}

	// 定义需要检查的关键注册表路径
	criticalRegistryPaths := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		"HKLM\\SYSTEM\\CurrentControlSet\\Services",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	}

	for _, registryPath := range criticalRegistryPaths {
		if fsc.Verbose {
			fmt.Printf("检查注册表: %s\n", registryPath)
		}

		keyInfo, err := fsc.getRegistryKeyInfo(registryPath)
		if err != nil {
			if fsc.Verbose {
				fmt.Printf("注册表项不存在或无法访问: %s\n", registryPath)
			}
			continue
		}

		registryKeys = append(registryKeys, keyInfo)

		// 检查注册表相关的漏洞
		registryVulns := fsc.checkRegistryVulnerabilities(keyInfo)
		vulnerabilities = append(vulnerabilities, registryVulns...)
	}

	return registryKeys, vulnerabilities
}

// getFileInfo 获取文件详细信息
func (fsc *FileSystemChecker) getFileInfo(filePath string) (FileInfo, error) {
	var fileInfo FileInfo

	// 检查文件是否存在
	file, err := os.Stat(filePath)
	if err != nil {
		return fileInfo, err
	}

	fileInfo.Path = filePath
	fileInfo.Size = file.Size()
	fileInfo.ModifiedTime = file.ModTime().String()

	// 获取文件版本
	version, err := fsc.getFileVersion(filePath)
	if err == nil {
		fileInfo.Version = version
	}

	// 计算文件哈希
	md5Hash, err := fsc.calculateFileHash(filePath, "md5")
	if err == nil {
		fileInfo.MD5Hash = md5Hash
	}

	sha1Hash, err := fsc.calculateFileHash(filePath, "sha1")
	if err == nil {
		fileInfo.SHA1Hash = sha1Hash
	}

	sha256Hash, err := fsc.calculateFileHash(filePath, "sha256")
	if err == nil {
		fileInfo.SHA256Hash = sha256Hash
	}

	return fileInfo, nil
}

// getFileVersion 获取文件版本信息
func (fsc *FileSystemChecker) getFileVersion(filePath string) (string, error) {
	// 使用PowerShell获取文件版本信息
	cmd := exec.Command("powershell", fmt.Sprintf("(Get-Item '%s').VersionInfo.FileVersion", filePath))
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		return "未知版本", nil
	}

	return version, nil
}

// calculateFileHash 计算文件哈希值
func (fsc *FileSystemChecker) calculateFileHash(filePath string, hashType string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hash string
	switch hashType {
	case "md5":
		hasher := md5.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(hasher.Sum(nil))
	case "sha1":
		hasher := sha1.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(hasher.Sum(nil))
	case "sha256":
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", err
		}
		hash = hex.EncodeToString(hasher.Sum(nil))
	default:
		return "", fmt.Errorf("不支持的哈希类型: %s", hashType)
	}

	return hash, nil
}

// getRegistryKeyInfo 获取注册表键信息
func (fsc *FileSystemChecker) getRegistryKeyInfo(registryPath string) (RegistryKeyInfo, error) {
	var keyInfo RegistryKeyInfo

	// 使用PowerShell获取注册表信息
	cmd := exec.Command("powershell", fmt.Sprintf("Get-ItemProperty -Path 'Registry::%s' -ErrorAction SilentlyContinue | ConvertTo-Json", registryPath))
	output, err := cmd.Output()
	if err != nil {
		return keyInfo, err
	}

	keyInfo.Path = registryPath
	keyInfo.Data = string(output)

	return keyInfo, nil
}

// checkFileVulnerabilities 检查文件相关的漏洞
func (fsc *FileSystemChecker) checkFileVulnerabilities(fileInfo FileInfo) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 根据文件名和版本检查特定漏洞
	fileName := filepath.Base(fileInfo.Path)

	// PrintNightmare漏洞检查
	if fileName == "win32spl.dll" {
		if fsc.isVulnerablePrintNightmare(fileInfo.Version) {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "CVE-2021-34527",
				Name:        "PrintNightmare 远程代码执行漏洞",
				Severity:    "高危",
				Description: "Windows Print Spooler 远程代码执行漏洞",
				Solution:    "安装KB5004945或更高版本的补丁",
				CVE:         "CVE-2021-34527",
				Affected:    "Windows Server 2012 R2, Windows 8.1, Windows Server 2016, Windows 10, Windows Server 2019, Windows Server 2022",
			})
		}
	}

	// SMBGhost漏洞检查
	if fileName == "ntoskrnl.exe" {
		if fsc.isVulnerableSMBGhost(fileInfo.Version) {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "CVE-2020-0796",
				Name:        "SMBGhost 远程代码执行漏洞",
				Severity:    "高危",
				Description: "Windows SMBv3 服务器远程代码执行漏洞",
				Solution:    "禁用SMBv3压缩或安装相关补丁",
				CVE:         "CVE-2020-0796",
				Affected:    "Windows 10 Version 1903, Windows 10 Version 1909, Windows Server Version 1903, Windows Server Version 1909",
			})
		}
	}

	return vulnerabilities
}

// checkRegistryVulnerabilities 检查注册表相关的漏洞
func (fsc *FileSystemChecker) checkRegistryVulnerabilities(keyInfo RegistryKeyInfo) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 检查自动启动项中的可疑程序
	if strings.Contains(keyInfo.Path, "Run") {
		if fsc.containsSuspiciousAutoRun(keyInfo.Data) {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "AUTO-RUN-SUSPICIOUS",
				Name:        "可疑的自动启动项",
				Severity:    "中危",
				Description: "发现可疑的自动启动程序",
				Solution:    "检查并清理可疑的自动启动项",
				CVE:         "",
				Affected:    "所有Windows系统",
			})
		}
	}

	// 检查安全策略配置
	if strings.Contains(keyInfo.Path, "Policies") {
		if fsc.hasWeakSecurityPolicies(keyInfo.Data) {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "WEAK-SECURITY-POLICY",
				Name:        "弱安全策略配置",
				Severity:    "中危",
				Description: "发现弱安全策略配置",
				Solution:    "加强安全策略配置",
				CVE:         "",
				Affected:    "所有Windows系统",
			})
		}
	}

	return vulnerabilities
}

// isVulnerablePrintNightmare 检查PrintNightmare漏洞
func (fsc *FileSystemChecker) isVulnerablePrintNightmare(version string) bool {
	// 简化的版本检查逻辑
	// 实际应用中应该使用更精确的版本比较
	if version == "" || version == "未知版本" {
		return true // 无法获取版本信息时，假设存在漏洞
	}

	// 检查是否包含已知的安全版本
	safeVersions := []string{
		"10.0.19041.1081", // Windows 10 2004
		"10.0.19042.1081", // Windows 10 20H2
		"10.0.19043.1081", // Windows 10 21H1
		"10.0.20348.0",    // Windows Server 2022
	}

	for _, safeVersion := range safeVersions {
		if strings.Contains(version, safeVersion) {
			return false
		}
	}

	return true
}

// isVulnerableSMBGhost 检查SMBGhost漏洞
func (fsc *FileSystemChecker) isVulnerableSMBGhost(version string) bool {
	// 简化的版本检查逻辑
	if version == "" || version == "未知版本" {
		return true
	}

	// 检查是否包含已知的安全版本
	safeVersions := []string{
		"10.0.18362.720",  // Windows 10 1903
		"10.0.18363.720",  // Windows 10 1909
	}

	for _, safeVersion := range safeVersions {
		if strings.Contains(version, safeVersion) {
			return false
		}
	}

	return true
}

// containsSuspiciousAutoRun 检查是否包含可疑的自动启动项
func (fsc *FileSystemChecker) containsSuspiciousAutoRun(data string) bool {
	// 简化的检查逻辑
	suspiciousPatterns := []string{
		"powershell",
		"cmd",
		"wscript",
		"cscript",
		"rundll32",
		"regsvr32",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(data), pattern) {
			return true
		}
	}

	return false
}

// hasWeakSecurityPolicies 检查是否有弱安全策略
func (fsc *FileSystemChecker) hasWeakSecurityPolicies(data string) bool {
	// 简化的检查逻辑
	weakPatterns := []string{
		"PasswordComplexity=0",
		"MinimumPasswordLength=0",
		"AuditPolicyChange=0",
	}

	for _, pattern := range weakPatterns {
		if strings.Contains(data, pattern) {
			return true
		}
	}

	return false
}