package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// EvidenceType 证据类型
type EvidenceType string

const (
	EvidenceFileVersion    EvidenceType = "file_version"
	EvidenceFileHash       EvidenceType = "file_hash"
	EvidenceRegistryKey    EvidenceType = "registry_key"
	EvidenceServiceStatus  EvidenceType = "service_status"
	EvidenceProcessInfo    EvidenceType = "process_info"
	EvidencePackageInfo    EvidenceType = "package_info"
	EvidenceConfigValue    EvidenceType = "config_value"
)

// Evidence 证据信息
type Evidence struct {
	Type        EvidenceType
	Source      string
	Value       string
	Description string
	Confidence  int
}

// EvidenceChain 证据链
type EvidenceChain struct {
	VulnerabilityID string
	Evidences       []Evidence
	Conclusion      string
	Confidence      int
}

// EvidenceChainAnalyzer 证据链分析器
type EvidenceChainAnalyzer struct {
	Verbose bool
}

// NewEvidenceChainAnalyzer 创建新的证据链分析器
func NewEvidenceChainAnalyzer(verbose bool) *EvidenceChainAnalyzer {
	return &EvidenceChainAnalyzer{
		Verbose: verbose,
	}
}

// AnalyzeVulnerability 分析特定漏洞的证据链
func (eca *EvidenceChainAnalyzer) AnalyzeVulnerability(vulnID string) *EvidenceChain {
	chain := &EvidenceChain{
		VulnerabilityID: vulnID,
		Evidences:       []Evidence{},
		Conclusion:      "未知",
		Confidence:      0,
	}

	if eca.Verbose {
		fmt.Printf("开始分析漏洞 %s 的证据链...\n", vulnID)
	}

	// 根据漏洞ID选择相应的分析方法
	switch vulnID {
	case "CVE-2021-34527": // PrintNightmare
		eca.analyzePrintNightmare(chain)
	case "CVE-2020-1350": // SIGRed
		eca.analyzeSIGRed(chain)
	case "CVE-2017-0144": // EternalBlue
		eca.analyzeEternalBlue(chain)
	case "CVE-2020-0796": // SMBGhost
		eca.analyzeSMBGhost(chain)
	case "CVE-2021-44228": // Log4Shell
		eca.analyzeLog4Shell(chain)
	default:
		// 通用漏洞分析
		eca.analyzeGenericVulnerability(chain)
	}

	return chain
}

// analyzePrintNightmare 分析PrintNightmare漏洞的证据链
func (eca *EvidenceChainAnalyzer) analyzePrintNightmare(chain *EvidenceChain) {
	// 证据1：检查Print Spooler服务状态
	if eca.isServiceRunning("Spooler") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceServiceStatus,
			Source:      "Spooler服务",
			Value:       "运行中",
			Description: "Print Spooler服务正在运行",
			Confidence:  90,
		})
	}

	// 证据2：检查关键文件版本
	spoolsvVersion := eca.getFileVersion("C:\\Windows\\System32\\spoolsv.exe")
	if spoolsvVersion != "" {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceFileVersion,
			Source:      "spoolsv.exe",
			Value:       spoolsvVersion,
			Description: "Print Spooler服务文件版本",
			Confidence:  95,
		})
	}

	// 证据3：检查补丁安装状态
	if !eca.isPatchInstalled("KB5004945") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceRegistryKey,
			Source:      "Windows更新",
			Value:       "KB5004945未安装",
			Description: "PrintNightmare安全补丁未安装",
			Confidence:  85,
		})
	}

	// 基于证据得出结论
	eca.concludePrintNightmare(chain)
}

// analyzeSIGRed 分析SIGRed漏洞的证据链
func (eca *EvidenceChainAnalyzer) analyzeSIGRed(chain *EvidenceChain) {
	// 证据1：检查DNS服务状态
	if eca.isServiceRunning("DNS") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceServiceStatus,
			Source:      "DNS服务",
			Value:       "运行中",
			Description: "DNS服务正在运行",
			Confidence:  90,
		})
	}

	// 证据2：检查DNS服务器文件版本
	dnsVersion := eca.getFileVersion("C:\\Windows\\System32\\dns.exe")
	if dnsVersion != "" {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceFileVersion,
			Source:      "dns.exe",
			Value:       dnsVersion,
			Description: "DNS服务器文件版本",
			Confidence:  95,
		})
	}

	// 证据3：检查补丁安装状态
	if !eca.isPatchInstalled("KB4565349") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceRegistryKey,
			Source:      "Windows更新",
			Value:       "KB4565349未安装",
			Description: "SIGRed安全补丁未安装",
			Confidence:  85,
		})
	}

	eca.concludeSIGRed(chain)
}

// analyzeEternalBlue 分析EternalBlue漏洞的证据链
func (eca *EvidenceChainAnalyzer) analyzeEternalBlue(chain *EvidenceChain) {
	// 证据1：检查SMB服务状态
	if eca.isServiceRunning("LanmanServer") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceServiceStatus,
			Source:      "SMB服务",
			Value:       "运行中",
			Description: "SMB服务正在运行",
			Confidence:  90,
		})
	}

	// 证据2：检查SMB文件版本
	srvVersion := eca.getFileVersion("C:\\Windows\\System32\\srv.sys")
	if srvVersion != "" {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceFileVersion,
			Source:      "srv.sys",
			Value:       srvVersion,
			Description: "SMB驱动文件版本",
			Confidence:  95,
		})
	}

	// 证据3：检查补丁安装状态
	if !eca.isPatchInstalled("KB4012212") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceRegistryKey,
			Source:      "Windows更新",
			Value:       "KB4012212未安装",
			Description: "EternalBlue安全补丁未安装",
			Confidence:  85,
		})
	}

	eca.concludeEternalBlue(chain)
}

// analyzeSMBGhost 分析SMBGhost漏洞的证据链
func (eca *EvidenceChainAnalyzer) analyzeSMBGhost(chain *EvidenceChain) {
	// 证据1：检查SMB服务状态
	if eca.isServiceRunning("LanmanServer") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceServiceStatus,
			Source:      "SMB服务",
			Value:       "运行中",
			Description: "SMB服务正在运行",
			Confidence:  90,
		})
	}

	// 证据2：检查SMB文件版本
	srvVersion := eca.getFileVersion("C:\\Windows\\System32\\srv2.sys")
	if srvVersion != "" {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceFileVersion,
			Source:      "srv2.sys",
			Value:       srvVersion,
			Description: "SMBv2驱动文件版本",
			Confidence:  95,
		})
	}

	// 证据3：检查补丁安装状态
	if !eca.isPatchInstalled("KB4551762") {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceRegistryKey,
			Source:      "Windows更新",
			Value:       "KB4551762未安装",
			Description: "SMBGhost安全补丁未安装",
			Confidence:  85,
		})
	}

	eca.concludeSMBGhost(chain)
}

// analyzeLog4Shell 分析Log4Shell漏洞的证据链
func (eca *EvidenceChainAnalyzer) analyzeLog4Shell(chain *EvidenceChain) {
	// 证据1：检查Java应用程序
	javaApps := eca.findJavaApplications()
	if len(javaApps) > 0 {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceProcessInfo,
			Source:      "Java进程",
			Value:       fmt.Sprintf("发现%d个Java应用", len(javaApps)),
			Description: "系统中运行Java应用程序",
			Confidence:  80,
		})
	}

	// 证据2：检查Log4j库文件
	log4jFiles := eca.findLog4jFiles()
	if len(log4jFiles) > 0 {
		for _, file := range log4jFiles {
			fileHash := eca.calculateFileHash(file)
			chain.Evidences = append(chain.Evidences, Evidence{
				Type:        EvidenceFileHash,
				Source:      file,
				Value:       fileHash,
				Description: "Log4j库文件哈希值",
				Confidence:  95,
			})
		}
	}

	// 证据3：检查Log4j版本
	log4jVersion := eca.getLog4jVersion()
	if log4jVersion != "" {
		chain.Evidences = append(chain.Evidences, Evidence{
			Type:        EvidenceFileVersion,
			Source:      "Log4j",
			Value:       log4jVersion,
			Description: "Log4j库版本信息",
			Confidence:  90,
		})
	}

	eca.concludeLog4Shell(chain)
}

// analyzeGenericVulnerability 通用漏洞分析
func (eca *EvidenceChainAnalyzer) analyzeGenericVulnerability(chain *EvidenceChain) {
	// 通用证据收集逻辑
	chain.Evidences = append(chain.Evidences, Evidence{
		Type:        EvidenceProcessInfo,
		Source:      "系统信息",
		Value:       "通用分析",
		Description: "使用通用方法分析漏洞",
		Confidence:  50,
	})

	chain.Conclusion = "需要更多特定信息进行精确分析"
	chain.Confidence = 50
}

// 结论判断函数
func (eca *EvidenceChainAnalyzer) concludePrintNightmare(chain *EvidenceChain) {
	vulnerable := false
	confidence := 0
	evidenceCount := 0

	for _, evidence := range chain.Evidences {
		evidenceCount++
		confidence += evidence.Confidence

		if evidence.Type == EvidenceRegistryKey && strings.Contains(evidence.Value, "未安装") {
			vulnerable = true
		}
	}

	if evidenceCount > 0 {
		chain.Confidence = confidence / evidenceCount
	}

	if vulnerable && chain.Confidence > 70 {
		chain.Conclusion = "系统存在PrintNightmare漏洞风险"
	} else {
		chain.Conclusion = "系统相对安全，PrintNightmare漏洞风险较低"
	}
}

func (eca *EvidenceChainAnalyzer) concludeSIGRed(chain *EvidenceChain) {
	// 类似的结论判断逻辑
	eca.concludePrintNightmare(chain) // 简化实现
}

func (eca *EvidenceChainAnalyzer) concludeEternalBlue(chain *EvidenceChain) {
	eca.concludePrintNightmare(chain) // 简化实现
}

func (eca *EvidenceChainAnalyzer) concludeSMBGhost(chain *EvidenceChain) {
	eca.concludePrintNightmare(chain) // 简化实现
}

func (eca *EvidenceChainAnalyzer) concludeLog4Shell(chain *EvidenceChain) {
	vulnerable := false
	confidence := 0
	evidenceCount := 0

	for _, evidence := range chain.Evidences {
		evidenceCount++
		confidence += evidence.Confidence

		if evidence.Type == EvidenceFileVersion && strings.Contains(evidence.Value, "2.") {
			// 检查Log4j版本是否易受攻击
			if eca.isVulnerableLog4jVersion(evidence.Value) {
				vulnerable = true
			}
		}
	}

	if evidenceCount > 0 {
		chain.Confidence = confidence / evidenceCount
	}

	if vulnerable && chain.Confidence > 70 {
		chain.Conclusion = "系统存在Log4Shell漏洞风险"
	} else {
		chain.Conclusion = "系统相对安全，Log4Shell漏洞风险较低"
	}
}

// 辅助函数实现
func (eca *EvidenceChainAnalyzer) isServiceRunning(serviceName string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	cmd := exec.Command("sc", "query", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "RUNNING")
}

func (eca *EvidenceChainAnalyzer) getFileVersion(filePath string) string {
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

func (eca *EvidenceChainAnalyzer) isPatchInstalled(kb string) bool {
	if runtime.GOOS != "windows" {
		return false
	}

	cmd := exec.Command("wmic", "qfe", "get", "HotFixID")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), kb)
}

func (eca *EvidenceChainAnalyzer) findJavaApplications() []string {
	var javaApps []string

	// 检查Java进程
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq java.exe")
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "java.exe") {
		javaApps = append(javaApps, "java.exe")
	}

	return javaApps
}

func (eca *EvidenceChainAnalyzer) findLog4jFiles() []string {
	var log4jFiles []string

	// 在常见目录中搜索Log4j文件
	searchPaths := []string{
		"C:\\Program Files",
		"C:\\Program Files (x86)",
		"C:\\Users",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			// 在实际实现中，这里应该递归搜索文件
			// 简化实现：只检查是否存在log4j相关文件
			testFile := filepath.Join(path, "log4j-core-*.jar")
			matches, _ := filepath.Glob(testFile)
			log4jFiles = append(log4jFiles, matches...)
		}
	}

	return log4jFiles
}

func (eca *EvidenceChainAnalyzer) calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func (eca *EvidenceChainAnalyzer) getLog4jVersion() string {
	// 简化实现：通过文件搜索获取版本信息
	log4jFiles := eca.findLog4jFiles()
	if len(log4jFiles) > 0 {
		// 从文件名中提取版本信息
		fileName := filepath.Base(log4jFiles[0])
		if strings.Contains(fileName, "log4j-core-") {
			version := strings.TrimPrefix(fileName, "log4j-core-")
			version = strings.TrimSuffix(version, ".jar")
			return version
		}
	}
	return ""
}

func (eca *EvidenceChainAnalyzer) isVulnerableLog4jVersion(version string) bool {
	// 检查Log4j版本是否易受Log4Shell攻击
	// 易受攻击的版本：2.0-beta9 到 2.14.1
	return strings.HasPrefix(version, "2.") && version < "2.15.0"
}

// GenerateEvidenceReport 生成证据链报告
func (eca *EvidenceChainAnalyzer) GenerateEvidenceReport(chains []*EvidenceChain) string {
	var report strings.Builder

	report.WriteString("=== 漏洞证据链分析报告 ===\n\n")

	for _, chain := range chains {
		report.WriteString(fmt.Sprintf("漏洞ID: %s\n", chain.VulnerabilityID))
		report.WriteString(fmt.Sprintf("结论: %s (置信度: %d%%)\n", chain.Conclusion, chain.Confidence))
		report.WriteString("证据链:\n")

		for i, evidence := range chain.Evidences {
			report.WriteString(fmt.Sprintf("  %d. [%s] %s: %s (置信度: %d%%)\n", 
				i+1, evidence.Type, evidence.Source, evidence.Description, evidence.Confidence))
		}

		report.WriteString("\n")
	}

	return report.String()
}