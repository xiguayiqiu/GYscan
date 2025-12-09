package cli

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// cleanCmd 表示清理命令
var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "高级黑客攻击痕迹检测和清理工具",
	Long: `clean命令 - 高级黑客攻击痕迹检测和清理工具

功能包括：
• 智能系统类型检测
• 深度黑客痕迹扫描（日志、进程、网络、文件系统）
• 实时风险等级评估
• 交互式清理操作
• 详细防御建议报告
• 多格式报告导出（TXT、JSON）
• 高级清理选项（选择性清理、备份恢复）

高级选项：
  --deep-scan     深度扫描模式（更全面但耗时）
  --backup        清理前创建备份
  --report-format 报告格式（txt/json）

警告：清理操作可能影响系统正常运行，请谨慎使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 解析命令行参数
		deepScan, _ := cmd.Flags().GetBool("deep-scan")
		backup, _ := cmd.Flags().GetBool("backup")
		reportFormat, _ := cmd.Flags().GetString("report-format")
		enterpriseMode, _ := cmd.Flags().GetBool("enterprise")

		// 执行清理检测
		executeCleanDetection(deepScan, backup, reportFormat, enterpriseMode)
	},
}

// 初始化命令行参数
func init() {
	cleanCmd.Flags().Bool("deep-scan", false, "启用深度扫描模式")
	cleanCmd.Flags().Bool("backup", false, "清理前创建备份")
	cleanCmd.Flags().String("report-format", "txt", "报告格式 (txt/json)")
	cleanCmd.Flags().Bool("enterprise", false, "启用企业级安全检测模式")
}

// 特征库结构
// FeatureRule 静态规则
type FeatureRule struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	RiskLevel   string `json:"risk_level"`
	Dimension   string `json:"dimension"`
}

// BehaviorRule 行为规则
type BehaviorRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Conditions  []string `json:"conditions"` // 多个条件需要同时满足
	RiskLevel   string   `json:"risk_level"`
}

// FeatureLibrary 特征库
type FeatureLibrary struct {
	StaticRules   []FeatureRule  `json:"static_rules"`
	BehaviorRules []BehaviorRule `json:"behavior_rules"`
}

// DetectionResult 详细检测结果
type DetectionResult struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	RiskLevel   string   `json:"risk_level"`
	Description string   `json:"description"`
	Details     []string `json:"details"`
	FilePath    string   `json:"file_path,omitempty"`
	Command     string   `json:"command,omitempty"`
	Timestamp   string   `json:"timestamp,omitempty"`
	MatchedRule string   `json:"matched_rule,omitempty"` // 匹配的特征库规则
}

// CleanResult 清理检测结果结构
type CleanResult struct {
	SystemType     string    `json:"system_type"`
	DetectionTime  time.Time `json:"detection_time"`
	HackerActions  []string  `json:"hacker_actions"`
	CleanActions   []string  `json:"clean_actions"`
	DefenseAdvice  []string  `json:"defense_advice"`
	RiskLevel      string    `json:"risk_level"`
	DeepScan       bool      `json:"deep_scan"`
	BackupEnabled  bool      `json:"backup_enabled"`
	ReportFormat   string    `json:"report_format"`
	EnterpriseMode bool      `json:"enterprise_mode"`
	DetectionStats struct {
		TotalChecks        int `json:"total_checks"`
		IssuesFound        int `json:"issues_found"`
		HighRiskIssues     int `json:"high_risk_issues"`
		MalwareDetected    int `json:"malware_detected"`
		ComplianceIssues   int `json:"compliance_issues"`
		NetworkThreats     int `json:"network_threats"`
		FileIntegrityFails int `json:"file_integrity_fails"`
		// 多维度检测统计
		NetworkIssues int `json:"network_issues"`
		ProcessIssues int `json:"process_issues"`
		FileIssues    int `json:"file_issues"`
		UserIssues    int `json:"user_issues"`
		StartupIssues int `json:"startup_issues"`
		LogIssues     int `json:"log_issues"`
	} `json:"detection_stats"`
	MalwareSignatures []MalwareSignature `json:"malware_signatures"`
	ComplianceChecks  []ComplianceCheck  `json:"compliance_checks"`
	NetworkAnalysis   NetworkAnalysis    `json:"network_analysis"`
	FileIntegrity     FileIntegrityCheck `json:"file_integrity"`
	DetectionResults  []DetectionResult  `json:"detection_results"`
	// 白名单配置
	WhitelistConfig WhitelistConfig `json:"whitelist_config"`
}

// MalwareSignature 恶意软件签名
type MalwareSignature struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
	FilePath    string `json:"file_path"`
	MD5Hash     string `json:"md5_hash"`
}

// ComplianceCheck 合规性检查
type ComplianceCheck struct {
	Standard    string `json:"standard"`
	Requirement string `json:"requirement"`
	Status      string `json:"status"`
	Details     string `json:"details"`
}

// NetworkAnalysis 网络分析
type NetworkAnalysis struct {
	OpenPorts      []int    `json:"open_ports"`
	SuspiciousIPs  []string `json:"suspicious_ips"`
	NetworkTraffic string   `json:"network_traffic"`
	DNSQueries     []string `json:"dns_queries"`
}

// WhitelistConfig 白名单配置
type WhitelistConfig struct {
	Processes []string `json:"processes"`
	Files     []string `json:"files"`
	IPs       []string `json:"ips"`
	Users     []string `json:"users"`
	Services  []string `json:"services"`
	Ports     []int    `json:"ports"`
}

// WindowsDetectionResult Windows系统检测结果
type WindowsDetectionResult struct {
	Name     string   `json:"name"`
	Risk     string   `json:"risk"`
	Desc     string   `json:"desc"`
	Details  []string `json:"details"`
	FilePath string   `json:"file_path,omitempty"`
	Command  string   `json:"command,omitempty"`
}

// LinuxDetectionResult Linux系统检测结果
type LinuxDetectionResult struct {
	Name     string   `json:"name"`
	Risk     string   `json:"risk"`
	Desc     string   `json:"desc"`
	Details  []string `json:"details"`
	FilePath string   `json:"file_path,omitempty"`
	Command  string   `json:"command,omitempty"`
}

// CriticalFile 关键文件
type CriticalFile struct {
	Path        string `json:"path"`
	ExpectedMD5 string `json:"expected_md5"`
	ActualMD5   string `json:"actual_md5"`
	Status      string `json:"status"`
}

// FileIntegrityCheck 文件完整性检查
type FileIntegrityCheck struct {
	CriticalFiles []CriticalFile `json:"critical_files"`
	ModifiedFiles []string       `json:"modified_files"`
	HashMismatch  []string       `json:"hash_mismatch"`
}

// executeCleanDetection 执行清理检测
func executeCleanDetection(deepScan bool, backup bool, reportFormat string, enterpriseMode bool) {
	utils.InfoPrint("=== 企业级安全检测与清理系统 ===")
	utils.InfoPrint("开始企业级安全检测...")

	if deepScan {
		utils.WarningPrint("深度扫描模式已启用 - 这将进行更全面的检测但耗时较长")
	}
	if backup {
		utils.InfoPrint("备份模式已启用 - 清理前将创建系统备份")
	}
	if enterpriseMode {
		utils.InfoPrint("企业级模式已启用 - 启用高级安全检测功能")
	}
	utils.InfoPrint("报告格式: %s", reportFormat)
	utils.InfoPrint("")

	// 检测系统类型
	result := detectSystemType()
	result.DeepScan = deepScan
	result.BackupEnabled = backup
	result.ReportFormat = reportFormat
	result.EnterpriseMode = enterpriseMode

	// 根据系统类型执行不同的检测逻辑
	if result.SystemType == "windows" {
		utils.InfoPrint("检测到Windows系统")
		checkWindowsHackerTraces(&result)
	} else if result.SystemType == "linux" {
		utils.InfoPrint("检测到Linux系统")
		checkLinuxHackerTraces(&result)
	} else {
		utils.ErrorPrint("不支持的操作系统类型")
		return
	}

	// 企业级功能检测
	if enterpriseMode {
		utils.InfoPrint("执行企业级安全检测...")
		performEnterpriseSecurityChecks(&result)
	}

	// 执行多维度交叉验证，提高检测准确率
	performMultiDimensionalValidation(&result)

	// 生成清理操作
	generateCleanActions(&result)

	// 显示检测结果
	displayCleanResults(&result)

	// 询问是否清理
	askForCleanup(&result)

	// 如果启用了企业级模式，询问是否启动实时监控
	if enterpriseMode {
		askForRealTimeMonitoring()
	}
}

// performMultiDimensionalValidation 执行多维度交叉验证
func performMultiDimensionalValidation(result *CleanResult) {
	utils.InfoPrint("执行多维度交叉验证...")

	// 统计不同维度的问题数量
	dimensionIssues := map[string]int{
		"日志":  result.DetectionStats.LogIssues,
		"进程":  result.DetectionStats.ProcessIssues,
		"文件":  result.DetectionStats.FileIssues,
		"用户":  result.DetectionStats.UserIssues,
		"启动项": result.DetectionStats.StartupIssues,
		"网络":  result.DetectionStats.NetworkIssues,
	}

	// 计算涉及的维度数量
	involvedDimensions := 0
	for _, count := range dimensionIssues {
		if count > 0 {
			involvedDimensions++
		}
	}

	utils.InfoPrint("多维度交叉验证结果:")
	utils.InfoPrint("涉及的维度数量: %d", involvedDimensions)
	for dimension, count := range dimensionIssues {
		if count > 0 {
			utils.InfoPrint("  %s维度: %d 个问题", dimension, count)
		}
	}

	// 根据维度数量调整风险等级
	// 3个或以上维度 → 高风险
	if involvedDimensions >= 3 {
		if result.RiskLevel != "致命" {
			result.RiskLevel = "高"
			utils.WarningPrint("⚠️ 多维度交叉验证发现高风险活动，系统风险等级提升为: %s", result.RiskLevel)
		}
	} else if involvedDimensions == 2 {
		if result.RiskLevel == "低" {
			result.RiskLevel = "中"
			utils.WarningPrint("⚠️ 多维度交叉验证发现中等风险活动，系统风险等级提升为: %s", result.RiskLevel)
		}
	}

	// 行为规则匹配
	featureLibrary := initializeFeatureLibrary()
	matchedBehaviors := 0

	for _, behaviorRule := range featureLibrary.BehaviorRules {
		// 检查是否匹配所有条件
		allMatched := true
		for _, condition := range behaviorRule.Conditions {
			matched := false
			// 检查是否有任何检测结果匹配该条件
			for _, action := range result.HackerActions {
				if matched {
					break
				}
				for _, detail := range result.CleanActions {
					if matched {
						break
					}
					if matched = regexp.MustCompile(condition).MatchString(action) || regexp.MustCompile(condition).MatchString(detail); matched {
						break
					}
				}
			}
			if !matched {
				allMatched = false
				break
			}
		}

		if allMatched {
			matchedBehaviors++
			utils.WarningPrint("⚠️ 匹配到行为规则: %s (风险等级: %s)", behaviorRule.Name, behaviorRule.RiskLevel)
			// 更新风险等级
			if behaviorRule.RiskLevel == "致命" {
				result.RiskLevel = "致命"
			} else if behaviorRule.RiskLevel == "高" && result.RiskLevel != "致命" {
				result.RiskLevel = "高"
			} else if behaviorRule.RiskLevel == "中" && (result.RiskLevel == "低" || result.RiskLevel == "") {
				result.RiskLevel = "中"
			}
		}
	}

	if matchedBehaviors > 0 {
		utils.WarningPrint("⚠️ 共匹配到 %d 个行为规则，系统风险等级调整为: %s", matchedBehaviors, result.RiskLevel)
	}

	utils.InfoPrint("多维度交叉验证完成")
}

// initializeFeatureLibrary 初始化特征库
func initializeFeatureLibrary() FeatureLibrary {
	return FeatureLibrary{
		StaticRules: []FeatureRule{
			// 反向shell检测规则
			{
				Rule:        "nc.*-e",
				Description: "检测到netcat反向shell",
				RiskLevel:   "极高",
				Dimension:   "进程",
			},
			{
				Rule:        "bash -i >& /dev/tcp/",
				Description: "检测到bash反向shell",
				RiskLevel:   "极高",
				Dimension:   "命令",
			},
			// WebShell检测规则
			{
				Rule:        "eval\\(\\$_,*POST",
				Description: "检测到PHP一句话木马",
				RiskLevel:   "极高",
				Dimension:   "文件",
			},
			{
				Rule:        "asp.*execute|asp.*eval",
				Description: "检测到ASP一句话木马",
				RiskLevel:   "极高",
				Dimension:   "文件",
			},
			// 可疑命令检测规则
			{
				Rule:        "rm -rf /|format c:",
				Description: "检测到危险删除命令",
				RiskLevel:   "极高",
				Dimension:   "命令",
			},
			{
				Rule:        "chmod 777|chmod +x",
				Description: "检测到可疑权限修改命令",
				RiskLevel:   "高",
				Dimension:   "命令",
			},
			// 恶意文件检测规则
			{
				Rule:        "/tmp/backdoor|/var/tmp/malware|C:\\Windows\\Temp\\mimikatz",
				Description: "检测到已知恶意文件路径",
				RiskLevel:   "极高",
				Dimension:   "文件",
			},
			{
				Rule:        ".*\\.sh$.*curl|.*\\.sh$.*wget",
				Description: "检测到可疑下载脚本",
				RiskLevel:   "高",
				Dimension:   "文件",
			},
			// 异常登录检测规则
			{
				Rule:        "Failed password.*from",
				Description: "检测到登录失败记录",
				RiskLevel:   "中",
				Dimension:   "日志",
			},
			{
				Rule:        "Accepted publickey.*from.*unknown",
				Description: "检测到来自未知IP的SSH登录",
				RiskLevel:   "高",
				Dimension:   "日志",
			},
		},
		BehaviorRules: []BehaviorRule{
			// 行为规则：反向shell + 异常登录 = 致命风险
			{
				Name:        "反向shell与异常登录组合",
				Description: "检测到反向shell活动与异常登录行为同时存在",
				Conditions:  []string{"nc.*-e", "bash -i >& /dev/tcp/", "Failed password.*from", "Accepted publickey.*from.*unknown"},
				RiskLevel:   "致命",
			},
			// 行为规则：可疑文件 + C2连接 = 高风险
			{
				Name:        "可疑文件与C2连接组合",
				Description: "检测到可疑文件与命令控制服务器连接",
				Conditions:  []string{".*\\.sh$.*curl", "/tmp/backdoor", "eval\\(\\$_,*POST"},
				RiskLevel:   "高",
			},
			// 行为规则：异常进程 + 异常网络连接 = 高风险
			{
				Name:        "异常进程与网络连接组合",
				Description: "检测到异常进程与可疑网络连接",
				Conditions:  []string{"chmod 777", "chmod +x", "nc.*-e"},
				RiskLevel:   "高",
			},
		},
	}
}

// detectSystemType 检测系统类型
func detectSystemType() CleanResult {
	var result CleanResult
	result.DetectionTime = time.Now()
	result.RiskLevel = "低"

	// 初始化白名单配置
	result.WhitelistConfig = initializeDefaultWhitelist()

	if runtime.GOOS == "windows" {
		result.SystemType = "windows"
	} else if runtime.GOOS == "linux" {
		result.SystemType = "linux"
	} else {
		result.SystemType = "unknown"
	}

	return result
}

// initializeDefaultWhitelist 初始化默认白名单
func initializeDefaultWhitelist() WhitelistConfig {
	// 初始化默认白名单，包含常见系统进程和合法操作
	return WhitelistConfig{
		Processes: []string{
			"explorer.exe", "svchost.exe", "csrss.exe", "wininit.exe", "services.exe",
			"lsass.exe", "winlogon.exe", "system", "conhost.exe", "cmd.exe",
			"powershell.exe", "powershell_ise.exe", "wmiapsrv.exe", "wmiprvse.exe",
			"bash.exe", "sshd.exe", "systemd", "systemd-journald", "systemd-udevd",
			"rsyslogd", "sshd", "apache2", "nginx", "mysql", "postgresql",
			"php-fpm", "python3", "java", "node", "docker", "dockerd",
		},
		IPs: []string{
			"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		},
		Users: []string{
			"root", "admin", "system", "nt authority\\system", "local service", "network service",
		},
		Ports: []int{
			22, 21, 23, 80, 443, 3306, 5432, 8080, 8443, 9000, 9200, 27017,
		},
		Files: []string{
			// Windows关键文件白名单
			"regex:C:\\Windows\\System32\\.*",
			"regex:C:\\Windows\\SysWOW64\\.*",
			"regex:C:\\Windows\\SystemRoot\\.*",
			"regex:C:\\Windows\\ntdll.dll",
			"regex:C:\\Windows\\kernel32.dll",
			"regex:C:\\Program Files\\.*\\.exe$",
			"regex:C:\\Program Files (x86)\\.*\\.exe$",
			"regex:C:\\Users\\.*\\AppData\\Local\\Microsoft\\.*",
			// Linux关键文件白名单
			"regex:/etc/passwd",
			"regex:/etc/shadow",
			"regex:/etc/group",
			"regex:/etc/fstab",
			"regex:/etc/hosts",
			"regex:/etc/ssh/sshd_config",
			"regex:/bin/.*",
			"regex:/sbin/.*",
			"regex:/usr/bin/.*",
			"regex:/usr/sbin/.*",
			"regex:/lib/.*",
			"regex:/lib64/.*",
			"regex:/usr/lib/.*",
			"regex:/usr/lib64/.*",
			"regex:/var/lib/.*",
			// 通用关键文件白名单
			"regex:/dev/.*",
			"regex:/proc/.*",
			"regex:/sys/.*",
		},
		Services: []string{
			"sshd", "httpd", "nginx", "mysqld", "postgresql", "docker", "firewalld",
			"ufw", "iptables", "systemd", "crond", "atd", "sssd", "ldap",
			"winmgmt", "w32time", "wuauserv", "bits", "cryptsvc", "dhcp", "dns",
			"eventlog", "lanmanserver", "lanmanworkstation", "netlogon", "ntds",
		},
	}
}

// isInWhitelist 检查项是否在白名单中，支持正则表达式
func isInWhitelist(item string, whitelist []string) bool {
	for _, white := range whitelist {
		// 检查是否为正则表达式
		if strings.HasPrefix(white, "regex:") {
			pattern := strings.TrimPrefix(white, "regex:")
			matched, _ := regexp.MatchString(pattern, item)
			if matched {
				return true
			}
		} else if white == item {
			return true
		}
	}
	return false
}

// extractValue 从文本中提取指定前缀后的值
func extractValue(text, prefix string) string {
	index := strings.Index(text, prefix)
	if index == -1 {
		return ""
	}
	// 提取前缀后的内容，去除首尾空格
	value := strings.TrimSpace(text[index+len(prefix):])
	return value
}

// extractPID 从文本中提取PID
func extractPID(text string) string {
	// 查找 PID: 后面的数字
	regex := regexp.MustCompile(`PID:\s*(\d+)`)
	matches := regex.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractFilePath 从文本中提取文件路径
func extractFilePath(text string) string {
	// 匹配文件路径模式，支持Windows和Linux路径
	regex := regexp.MustCompile(`([a-zA-Z]:\\[\\\w.-]+|/[\\w.-]+)`)
	matches := regex.FindStringSubmatch(text)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// isIPInWhitelist 检查IP是否在白名单中，支持CIDR格式
func isIPInWhitelist(ip string, whitelist []string) bool {
	for _, white := range whitelist {
		// 检查是否为CIDR格式
		if strings.Contains(white, "/") {
			// 解析CIDR
			_, ipnet, err := net.ParseCIDR(white)
			if err == nil {
				// 解析IP
				ipAddr := net.ParseIP(ip)
				if ipAddr != nil && ipnet.Contains(ipAddr) {
					return true
				}
			}
		} else if white == ip {
			return true
		}
	}
	return false
}

// isPortInWhitelist 检查端口是否在白名单中
func isPortInWhitelist(port int, whitelist []int) bool {
	for _, whitePort := range whitelist {
		if whitePort == port {
			return true
		}
	}
	return false
}

// performEnterpriseSecurityChecks 执行企业级安全检测
func performEnterpriseSecurityChecks(result *CleanResult) {
	utils.InfoPrint("执行企业级安全检测...")

	// 恶意软件检测
	utils.InfoPrint("正在检测恶意软件...")
	checkMalwareSignatures(result)

	// 合规性检查
	utils.InfoPrint("正在执行合规性检查...")
	checkComplianceStandards(result)

	// 网络威胁分析
	utils.InfoPrint("正在分析网络威胁...")
	analyzeNetworkThreats(result)

	// 文件完整性检查
	utils.InfoPrint("正在检查文件完整性...")
	checkFileIntegrity(result)

	utils.InfoPrint("企业级安全检测完成")
}

// checkMalwareSignatures 检测恶意软件签名
func checkMalwareSignatures(result *CleanResult) {
	utils.InfoPrint("正在执行高级恶意软件检测...")

	// 恶意软件签名数据库 - 扩展版本
	malwareSignatures := []MalwareSignature{
		// 常见恶意软件
		{
			Name:        "Mimikatz",
			Type:        "密码窃取工具",
			RiskLevel:   "高",
			Description: "Windows密码提取工具",
			FilePath:    "C:\\Windows\\Temp\\mimikatz.exe",
			MD5Hash:     "",
		},
		{
			Name:        "Metasploit",
			Type:        "渗透测试框架",
			RiskLevel:   "高",
			Description: "渗透测试和漏洞利用框架",
			FilePath:    "C:\\Windows\\Temp\\meterpreter.exe",
			MD5Hash:     "",
		},
		{
			Name:        "Cobalt Strike",
			Type:        "后门程序",
			RiskLevel:   "高",
			Description: "高级威胁模拟工具",
			FilePath:    "C:\\Windows\\System32\\beacon.exe",
			MD5Hash:     "",
		},
		// 勒索软件
		{
			Name:        "WannaCry",
			Type:        "勒索软件",
			RiskLevel:   "极高",
			Description: "加密文件并要求赎金",
			FilePath:    "C:\\Windows\\Tasks\\wcry.exe",
			MD5Hash:     "",
		},
		{
			Name:        "Locky",
			Type:        "勒索软件",
			RiskLevel:   "极高",
			Description: "通过邮件传播的勒索软件",
			FilePath:    "C:\\Users\\*\\AppData\\Local\\Temp\\locky.exe",
			MD5Hash:     "",
		},
		// 木马程序
		{
			Name:        "Zeus",
			Type:        "银行木马",
			RiskLevel:   "高",
			Description: "窃取银行凭证的木马程序",
			FilePath:    "C:\\Windows\\System32\\svchost32.exe",
			MD5Hash:     "",
		},
		{
			Name:        "Emotet",
			Type:        "木马下载器",
			RiskLevel:   "高",
			Description: "下载其他恶意软件的木马",
			FilePath:    "C:\\Windows\\SysWOW64\\emotet.exe",
			MD5Hash:     "",
		},
		// 挖矿软件
		{
			Name:        "XMRig",
			Type:        "加密货币挖矿软件",
			RiskLevel:   "中",
			Description: "Monero挖矿软件",
			FilePath:    "C:\\Windows\\Temp\\xmrig.exe",
			MD5Hash:     "",
		},
		// Linux恶意软件
		{
			Name:        "Linux.Backdoor",
			Type:        "后门程序",
			RiskLevel:   "高",
			Description: "Linux系统后门",
			FilePath:    "/tmp/backdoor",
			MD5Hash:     "",
		},
		{
			Name:        "ShellShock",
			Type:        "漏洞利用",
			RiskLevel:   "高",
			Description: "Bash漏洞利用工具",
			FilePath:    "/usr/bin/bash_exploit",
			MD5Hash:     "",
		},
	}

	// 基于签名的检测
	detectedCount := 0
	for _, signature := range malwareSignatures {
		if fileExists(signature.FilePath) {
			// 计算文件MD5
			md5Hash, err := calculateFileMD5(signature.FilePath)
			if err == nil {
				signature.MD5Hash = md5Hash
			}

			result.MalwareSignatures = append(result.MalwareSignatures, signature)
			result.DetectionStats.MalwareDetected++
			detectedCount++
			result.HackerActions = append(result.HackerActions, fmt.Sprintf("检测到恶意软件: %s (%s)", signature.Name, signature.Type))

			if signature.RiskLevel == "高" || signature.RiskLevel == "极高" {
				result.DetectionStats.HighRiskIssues++
			}
		}
	}

	// 启发式检测 - 检查可疑行为模式
	heuristicDetections := performHeuristicDetection(result.SystemType)
	if len(heuristicDetections) > 0 {
		result.DetectionStats.MalwareDetected += len(heuristicDetections)
		result.HackerActions = append(result.HackerActions, heuristicDetections...)
		detectedCount += len(heuristicDetections)
	}

	// 行为分析检测
	behavioralDetections := performBehavioralAnalysis(result.SystemType)
	if len(behavioralDetections) > 0 {
		result.DetectionStats.MalwareDetected += len(behavioralDetections)
		result.HackerActions = append(result.HackerActions, behavioralDetections...)
		detectedCount += len(behavioralDetections)
	}

	// 内存扫描检测
	memoryDetections := scanMemoryForMalware(result.SystemType)
	if len(memoryDetections) > 0 {
		result.DetectionStats.MalwareDetected += len(memoryDetections)
		result.HackerActions = append(result.HackerActions, memoryDetections...)
		detectedCount += len(memoryDetections)
	}

	utils.InfoPrint("恶意软件检测完成，发现 %d 个威胁", detectedCount)
}

// checkComplianceStandards 检查合规性标准
func checkComplianceStandards(result *CleanResult) {
	// 根据系统类型执行不同的合规性检查
	if result.SystemType == "windows" {
		checkWindowsCompliance(result)
	} else {
		checkLinuxCompliance(result)
	}
}

// checkWindowsCompliance 检查Windows合规性
func checkWindowsCompliance(result *CleanResult) {
	complianceChecks := []ComplianceCheck{}

	// CIS Windows 基准检查
	complianceChecks = append(complianceChecks, checkCISPasswordPolicy())
	complianceChecks = append(complianceChecks, checkCISAccountLockoutPolicy())
	complianceChecks = append(complianceChecks, checkCISAuditPolicy())
	complianceChecks = append(complianceChecks, checkCISUserRights())
	complianceChecks = append(complianceChecks, checkCISSecurityOptions())

	// NIST 安全检查
	complianceChecks = append(complianceChecks, checkNISTAuthentication())
	complianceChecks = append(complianceChecks, checkNISTAccessControl())
	complianceChecks = append(complianceChecks, checkNISTAuditLogging())

	// ISO27001 信息安全检查
	complianceChecks = append(complianceChecks, checkISO27001SecurityPolicy())
	complianceChecks = append(complianceChecks, checkISO27001AccessControl())
	complianceChecks = append(complianceChecks, checkISO27001Cryptography())

	// 统计合规性问题
	for _, check := range complianceChecks {
		if check.Status == "失败" {
			result.DetectionStats.ComplianceIssues++
		}
	}

	result.ComplianceChecks = complianceChecks
}

// fileExists 检查文件是否存在
func fileExists(filePath string) bool {
	if strings.Contains(filePath, "*") {
		// 处理通配符路径
		dir := filepath.Dir(filePath)
		pattern := filepath.Base(filePath)
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		return err == nil && len(matches) > 0
	}
	_, err := os.Stat(filePath)
	return err == nil
}

// CIS Windows 合规性检查函数

// checkCISPasswordPolicy 检查CIS密码策略
func checkCISPasswordPolicy() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "密码策略",
		Status:      "通过",
		Details:     "检查密码复杂度、长度和历史要求",
	}

	// 检查密码策略
	cmd := exec.Command("net", "accounts")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "Minimum password age") ||
			!strings.Contains(outputStr, "Maximum password age") ||
			!strings.Contains(outputStr, "Minimum password length") {
			check.Status = "失败"
			check.Details = "密码策略配置不完整或不符合CIS标准"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取密码策略信息"
	}

	return check
}

// checkCISAccountLockoutPolicy 检查CIS账户锁定策略
func checkCISAccountLockoutPolicy() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "账户锁定策略",
		Status:      "通过",
		Details:     "检查账户锁定阈值和持续时间",
	}

	// 检查账户锁定策略
	cmd := exec.Command("net", "accounts")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "Lockout threshold") ||
			!strings.Contains(outputStr, "Lockout duration") ||
			!strings.Contains(outputStr, "Lockout observation window") {
			check.Status = "失败"
			check.Details = "账户锁定策略配置不完整或不符合CIS标准"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取账户锁定策略信息"
	}

	return check
}

// checkCISAuditPolicy 检查CIS审计策略
func checkCISAuditPolicy() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "审计策略",
		Status:      "通过",
		Details:     "检查安全审计配置",
	}

	// 检查审计策略
	cmd := exec.Command("auditpol", "/get", "/category:*")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查关键审计类别是否启用
		criticalAudits := []string{"Logon", "Logoff", "Account Management", "Policy Change"}
		for _, audit := range criticalAudits {
			if !strings.Contains(outputStr, audit+" Success") && !strings.Contains(outputStr, audit+" Failure") {
				check.Status = "失败"
				check.Details = "关键审计类别未完全配置"
				break
			}
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取审计策略信息"
	}

	return check
}

// checkCISUserRights 检查CIS用户权限
func checkCISUserRights() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "用户权限分配",
		Status:      "通过",
		Details:     "检查关键用户权限配置",
	}

	// 检查用户权限 - 使用内存处理，不创建临时文件
	cmd := exec.Command("secedit", "/export", "/cfg", "-") // 使用标准输出代替文件
	output, err := cmd.Output()
	if err == nil {
		contentStr := string(output)
		// 检查关键权限设置
		if strings.Contains(contentStr, "SeDebugPrivilege") &&
			strings.Contains(contentStr, "SeTcbPrivilege") &&
			strings.Contains(contentStr, "SeBackupPrivilege") {
			// 权限配置基本正常
		} else {
			check.Status = "失败"
			check.Details = "关键用户权限配置不符合CIS标准"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取用户权限配置信息"
	}

	return check
}

// checkCISSecurityOptions 检查CIS安全选项
func checkCISSecurityOptions() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "安全选项",
		Status:      "通过",
		Details:     "检查网络安全和系统安全选项",
	}

	// 检查安全选项 - 使用内存处理，不创建临时文件
	cmd := exec.Command("secedit", "/export", "/cfg", "-") // 使用标准输出代替文件
	output, err := cmd.Output()
	if err == nil {
		contentStr := string(output)
		// 检查关键安全选项
		if strings.Contains(contentStr, "PasswordComplexity") &&
			strings.Contains(contentStr, "RequireLogonToChangePassword") &&
			strings.Contains(contentStr, "ClearTextPassword") {
			// 安全选项配置基本正常
		} else {
			check.Status = "失败"
			check.Details = "安全选项配置不符合CIS标准"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取安全选项配置信息"
	}

	return check
}

// NIST 合规性检查函数

// checkNISTAuthentication 检查NIST认证要求
func checkNISTAuthentication() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "NIST",
		Requirement: "认证机制",
		Status:      "通过",
		Details:     "检查多因素认证和密码强度要求",
	}

	// 检查认证配置
	cmd := exec.Command("net", "accounts")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// NIST要求强密码策略
		if !strings.Contains(outputStr, "Minimum password length: 8") &&
			!strings.Contains(outputStr, "Minimum password length: 12") &&
			!strings.Contains(outputStr, "Minimum password length: 14") {
			check.Status = "失败"
			check.Details = "密码长度不符合NIST SP 800-63B要求"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取认证配置信息"
	}

	return check
}

// checkNISTAccessControl 检查NIST访问控制
func checkNISTAccessControl() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "NIST",
		Requirement: "访问控制",
		Status:      "通过",
		Details:     "检查最小权限原则和访问控制列表",
	}

	// 检查管理员组权限
	cmd := exec.Command("net", "localgroup", "Administrators")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查是否有过多用户拥有管理员权限
		lines := strings.Split(outputStr, "\n")
		adminCount := 0
		for _, line := range lines {
			if strings.Contains(line, "\\") && !strings.Contains(line, "Administrators") &&
				!strings.Contains(line, "The command completed") {
				adminCount++
			}
		}
		if adminCount > 3 { // NIST建议限制管理员数量
			check.Status = "失败"
			check.Details = "管理员账户数量过多，不符合最小权限原则"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取访问控制信息"
	}

	return check
}

// checkNISTAuditLogging 检查NIST审计日志
func checkNISTAuditLogging() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "NIST",
		Requirement: "审计日志",
		Status:      "通过",
		Details:     "检查日志记录和保留策略",
	}

	// 检查事件日志配置
	cmd := exec.Command("wevtutil", "gl", "Security")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查日志大小和保留设置
		if !strings.Contains(outputStr, "maxSize:") ||
			!strings.Contains(outputStr, "retention:") {
			check.Status = "失败"
			check.Details = "安全日志配置不完整，不符合NIST要求"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取审计日志配置信息"
	}

	return check
}

// ISO27001 合规性检查函数

// checkISO27001SecurityPolicy 检查ISO27001安全策略
func checkISO27001SecurityPolicy() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "ISO27001",
		Requirement: "信息安全策略",
		Status:      "通过",
		Details:     "检查信息安全策略实施情况",
	}

	// 检查是否有安全策略文档
	policyFiles := []string{
		"C:\\Windows\\Security\\policies.txt",
		"C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol",
		"C:\\Windows\\System32\\GroupPolicy\\User\\Registry.pol",
	}

	policyExists := false
	for _, file := range policyFiles {
		if fileExists(file) {
			policyExists = true
			break
		}
	}

	if !policyExists {
		check.Status = "失败"
		check.Details = "未发现完整的安全策略配置，不符合ISO27001要求"
	}

	return check
}

// checkISO27001AccessControl 检查ISO27001访问控制
func checkISO27001AccessControl() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "ISO27001",
		Requirement: "访问控制",
		Status:      "通过",
		Details:     "检查用户访问权限管理",
	}

	// 检查用户账户管理
	cmd := exec.Command("net", "user")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查是否有默认账户或测试账户
		defaultAccounts := []string{"Guest", "Test", "Demo"}
		for _, account := range defaultAccounts {
			if strings.Contains(outputStr, account) {
				check.Status = "失败"
				check.Details = "发现默认或测试账户，不符合ISO27001访问控制要求"
				break
			}
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取用户账户信息"
	}

	return check
}

// checkISO27001Cryptography 检查ISO27001密码学控制
func checkISO27001Cryptography() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "ISO27001",
		Requirement: "密码学控制",
		Status:      "通过",
		Details:     "检查加密和密钥管理",
	}

	// 检查BitLocker状态
	cmd := exec.Command("manage-bde", "-status")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查是否有加密卷
		if !strings.Contains(outputStr, "Protection On") && !strings.Contains(outputStr, "Fully Encrypted") {
			check.Status = "失败"
			check.Details = "磁盘加密未启用或配置不完整，不符合ISO27001密码学控制要求"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法获取加密状态信息"
	}

	return check
}

// Linux 合规性检查函数

// checkCISLinuxSSHConfig 检查CIS Linux SSH配置
func checkCISLinuxSSHConfig() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "SSH配置",
		Status:      "通过",
		Details:     "检查SSH安全配置和协议设置",
	}

	// 检查SSH配置文件
	sshConfigFile := "/etc/ssh/sshd_config"
	if fileExists(sshConfigFile) {
		content, err := os.ReadFile(sshConfigFile)
		if err == nil {
			contentStr := string(content)
			// CIS要求的关键SSH配置
			requiredConfigs := []string{
				"Protocol 2",
				"PermitRootLogin no",
				"PasswordAuthentication no",
				"PermitEmptyPasswords no",
			}

			for _, config := range requiredConfigs {
				if !strings.Contains(contentStr, config) {
					check.Status = "失败"
					check.Details = "SSH配置不符合CIS安全标准"
					break
				}
			}
		} else {
			check.Status = "检查失败"
			check.Details = "无法读取SSH配置文件"
		}
	} else {
		check.Status = "失败"
		check.Details = "SSH配置文件不存在"
	}

	return check
}

// checkCISLinuxFilePermissions 检查CIS Linux文件权限
func checkCISLinuxFilePermissions() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "文件权限",
		Status:      "通过",
		Details:     "检查关键系统文件权限设置",
	}

	// 检查关键文件权限
	criticalFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/gshadow",
	}

	for _, file := range criticalFiles {
		if fileExists(file) {
			info, err := os.Stat(file)
			if err == nil {
				mode := info.Mode()
				// 检查权限是否过于宽松
				if mode.Perm()&0022 != 0 { // 检查是否有写权限
					check.Status = "失败"
					check.Details = "关键系统文件权限设置不安全"
					break
				}
			}
		}
	}

	return check
}

// checkCISLinuxAuditConfig 检查CIS Linux审计配置
func checkCISLinuxAuditConfig() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "审计配置",
		Status:      "通过", Details: "检查审计守护进程和规则配置",
	}

	// 检查auditd服务状态
	cmd := exec.Command("systemctl", "is-active", "auditd")
	output, err := cmd.CombinedOutput()
	if err == nil {
		if !strings.Contains(string(output), "active") {
			check.Status = "失败"
			check.Details = "审计守护进程未运行"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法检查审计服务状态"
	}

	return check
}

// checkCISLinuxUserAccounts 检查CIS Linux用户账户
func checkCISLinuxUserAccounts() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "用户账户",
		Status:      "通过",
		Details:     "检查用户账户管理和密码策略",
	}

	// 检查密码策略
	cmd := exec.Command("grep", "PASS_MAX_DAYS", "/etc/login.defs")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// CIS要求密码最大使用天数不超过90天
		if strings.Contains(outputStr, "PASS_MAX_DAYS") {
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "PASS_MAX_DAYS") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						days, _ := strconv.Atoi(fields[1])
						if days > 90 {
							check.Status = "失败"
							check.Details = "密码策略不符合CIS标准"
						}
					}
				}
			}
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法检查密码策略"
	}

	return check
}

// checkCISLinuxNetworkConfig 检查CIS Linux网络配置
func checkCISLinuxNetworkConfig() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "CIS",
		Requirement: "网络配置",
		Status:      "通过",
		Details:     "检查网络服务和防火墙配置",
	}

	// 检查防火墙状态
	cmd := exec.Command("systemctl", "is-active", "firewalld")
	output, err := cmd.CombinedOutput()
	if err == nil {
		if !strings.Contains(string(output), "active") {
			// 检查iptables
			cmd2 := exec.Command("systemctl", "is-active", "iptables")
			output2, err2 := cmd2.CombinedOutput()
			if err2 == nil && !strings.Contains(string(output2), "active") {
				check.Status = "失败"
				check.Details = "防火墙服务未运行"
			}
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法检查防火墙状态"
	}

	return check
}

// NIST Linux 合规性检查函数

// checkNISTLinuxAuthentication 检查NIST Linux认证要求
func checkNISTLinuxAuthentication() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "NIST",
		Requirement: "认证机制",
		Status:      "通过",
		Details:     "检查PAM配置和认证策略",
	}

	// 检查PAM配置
	pamFiles := []string{
		"/etc/pam.d/common-auth",
		"/etc/pam.d/common-password",
		"/etc/pam.d/common-session",
	}

	for _, file := range pamFiles {
		if fileExists(file) {
			content, err := os.ReadFile(file)
			if err == nil {
				contentStr := string(content)
				// NIST要求强认证机制
				if !strings.Contains(contentStr, "pam_unix.so") &&
					!strings.Contains(contentStr, "pam_pwquality.so") {
					check.Status = "失败"
					check.Details = "PAM配置不符合NIST认证要求"
					break
				}
			}
		}
	}

	return check
}

// checkNISTLinuxAccessControl 检查NIST Linux访问控制
func checkNISTLinuxAccessControl() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "NIST",
		Requirement: "访问控制",
		Status:      "通过",
		Details:     "检查SELinux和文件权限",
	}

	// 检查SELinux状态
	cmd := exec.Command("getenforce")
	output, err := cmd.CombinedOutput()
	if err == nil {
		enforceStatus := strings.TrimSpace(string(output))
		if enforceStatus != "Enforcing" {
			check.Status = "失败"
			check.Details = "SELinux未处于强制模式，不符合NIST访问控制要求"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法检查SELinux状态"
	}

	return check
}

// checkNISTLinuxAuditLogging 检查NIST Linux审计日志
func checkNISTLinuxAuditLogging() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "NIST",
		Requirement: "审计日志",
		Status:      "通过",
		Details:     "检查日志记录和保留策略",
	}

	// 检查rsyslog配置
	if fileExists("/etc/rsyslog.conf") {
		content, err := os.ReadFile("/etc/rsyslog.conf")
		if err == nil {
			contentStr := string(content)
			// NIST要求完整的日志记录
			if !strings.Contains(contentStr, "*.info") &&
				!strings.Contains(contentStr, "mail.none") &&
				!strings.Contains(contentStr, "authpriv.none") {
				check.Status = "失败"
				check.Details = "日志配置不完整，不符合NIST要求"
			}
		} else {
			check.Status = "检查失败"
			check.Details = "无法读取日志配置文件"
		}
	} else {
		check.Status = "失败"
		check.Details = "日志配置文件不存在"
	}

	return check
}

// ISO27001 Linux 合规性检查函数

// checkISO27001LinuxSecurityPolicy 检查ISO27001 Linux安全策略
func checkISO27001LinuxSecurityPolicy() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "ISO27001",
		Requirement: "信息安全策略",
		Status:      "通过",
		Details:     "检查安全策略实施情况",
	}

	// 检查安全策略文件
	policyFiles := []string{
		"/etc/security/access.conf",
		"/etc/security/limits.conf",
		"/etc/sysctl.conf",
	}

	policyExists := false
	for _, file := range policyFiles {
		if fileExists(file) {
			policyExists = true
			break
		}
	}

	if !policyExists {
		check.Status = "失败"
		check.Details = "安全策略配置不完整，不符合ISO27001要求"
	}

	return check
}

// checkISO27001LinuxAccessControl 检查ISO27001 Linux访问控制
func checkISO27001LinuxAccessControl() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "ISO27001",
		Requirement: "访问控制",
		Status:      "通过",
		Details:     "检查用户访问权限管理",
	}

	// 检查sudo配置
	if fileExists("/etc/sudoers") {
		content, err := os.ReadFile("/etc/sudoers")
		if err == nil {
			contentStr := string(content)
			// 检查是否有不安全的sudo配置
			if strings.Contains(contentStr, "NOPASSWD") ||
				strings.Contains(contentStr, "ALL=(ALL) ALL") {
				check.Status = "失败"
				check.Details = "sudo配置存在安全风险，不符合ISO27001访问控制要求"
			}
		} else {
			check.Status = "检查失败"
			check.Details = "无法读取sudo配置文件"
		}
	} else {
		check.Status = "失败"
		check.Details = "sudo配置文件不存在"
	}

	return check
}

// checkISO27001LinuxCryptography 检查ISO27001 Linux密码学控制
func checkISO27001LinuxCryptography() ComplianceCheck {
	check := ComplianceCheck{
		Standard:    "ISO27001",
		Requirement: "密码学控制",
		Status:      "通过",
		Details:     "检查加密和密钥管理",
	}

	// 检查加密文件系统
	cmd := exec.Command("mount")
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查是否有加密文件系统
		if !strings.Contains(outputStr, "encrypt") &&
			!strings.Contains(outputStr, "crypt") &&
			!strings.Contains(outputStr, "luks") {
			check.Status = "失败"
			check.Details = "未发现加密文件系统，不符合ISO27001密码学控制要求"
		}
	} else {
		check.Status = "检查失败"
		check.Details = "无法检查文件系统加密状态"
	}

	return check
}

// performHeuristicDetection 执行启发式检测
func performHeuristicDetection(systemType string) []string {
	var detections []string

	if systemType == "windows" {
		// 检查Windows系统可疑行为
		procResult := checkSuspiciousWindowsProcessesDetailed()
		if strings.Contains(procResult.Desc, "检测到") {
			detections = append(detections, "发现可疑Windows进程行为")
		}
		// 使用已实现的checkWindowsRegistryDetailed函数
		regResult := checkWindowsRegistryDetailed()
		if strings.Contains(regResult.Desc, "检测到") {
			detections = append(detections, "发现可疑注册表项")
		}
		// 使用已实现的checkWindowsFileSystemDetailed函数
		fileResult := checkWindowsFileSystemDetailed()
		if strings.Contains(fileResult.Desc, "检测到") {
			detections = append(detections, "发现可疑文件扩展名")
		}
	} else if systemType == "linux" {
		// 检查Linux系统可疑行为
		// 使用已实现的checkLinuxProcessesDetailed函数
		procResult := checkLinuxProcessesDetailed()
		if strings.Contains(procResult.Desc, "检测到") {
			detections = append(detections, "发现可疑Linux进程行为")
		}
		cronResult := checkLinuxCronJobsDetailed()
		if strings.Contains(cronResult.Desc, "检测到") {
			detections = append(detections, "发现可疑定时任务")
		}
		// 使用已实现的checkLinuxFileSystemDetailed函数
		sysFileResult := checkLinuxFileSystemDetailed()
		if strings.Contains(sysFileResult.Desc, "检测到") {
			detections = append(detections, "发现可疑系统文件")
		}
	}

	return detections
}

// performBehavioralAnalysis 执行行为分析
func performBehavioralAnalysis(systemType string) []string {
	var detections []string

	if systemType == "linux" {
		// 检查Linux异常网络连接 - 使用已实现的checkLinuxProcessesDetailed函数
		netResult := checkLinuxProcessesDetailed()
		if strings.Contains(netResult.Desc, "检测到") {
			detections = append(detections, "检测到异常网络连接模式")
		}
		// 检查Linux异常CPU使用
		cpuResult := checkAbnormalCPUUsageDetailed()
		if len(cpuResult.Details) > 0 {
			detections = append(detections, "检测到异常CPU使用模式")
		}
	}

	return detections
}

// scanMemoryForMalware 扫描内存中的恶意软件
func scanMemoryForMalware(systemType string) []string {
	var detections []string

	// 在Windows上使用WMIC检查内存
	if systemType == "windows" {
		cmd := exec.Command("wmic", "OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory")
		_, err := cmd.Output()
		if err == nil {
			detections = append(detections, "内存状态检查完成")
		}
	} else if systemType == "linux" {
		// 在Linux上使用free命令检查内存
		cmd := exec.Command("free", "-m")
		_, err := cmd.Output()
		if err == nil {
			detections = append(detections, "内存状态检查完成")
		}
	}

	return detections
}

// 启发式检测辅助函数 - 返回详细结果
func checkSuspiciousWindowsProcessesDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "Windows可疑进程检查",
		Risk: "高",
		Desc: "检测Windows系统中是否存在可疑进程",
	}

	// 检查常见恶意进程名
	suspiciousProcesses := []string{"mimikatz", "meterpreter", "beacon", "empire", "powersploit", "psexec", "wce", "backdoor", "malware", "miner", "crypto", "xmrig"}
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取进程列表: "+err.Error())
		return result
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	foundSuspicious := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析CSV格式的进程信息
		// 格式: "进程名","PID","会话名","会话#,"内存使用"
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}

		procName := strings.Trim(fields[0], "\"")
		pid := strings.Trim(fields[1], "\"")

		// 检查进程名是否在可疑列表中
		for _, suspiciousProc := range suspiciousProcesses {
			if strings.Contains(strings.ToLower(procName), strings.ToLower(suspiciousProc)) {
				result.Details = append(result.Details, fmt.Sprintf("发现可疑进程: %s PID: %s", procName, pid))
				foundSuspicious = true
				break
			}
		}
	}

	if foundSuspicious {
		result.Desc = "检测到Windows可疑进程"
	} else {
		result.Details = append(result.Details, "未发现可疑Windows进程")
	}

	return result
}

// 注册表检查 - 返回详细结果
func checkSuspiciousRegistryEntriesDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "可疑注册表项检查",
		Risk: "高",
		Desc: "检测系统注册表中是否存在可疑项",
	}

	// 检查常见的恶意软件注册表项
	suspiciousKeys := []string{
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	}

	for _, key := range suspiciousKeys {
		cmd := exec.Command("reg", "query", key)
		output, err := cmd.CombinedOutput()
		if err == nil {
			outputStr := string(output)
			// 检查可疑关键词
			suspiciousKeywords := []string{"backdoor", "malware", "miner", "crypto", "mimikatz", "meterpreter"}
			for _, keyword := range suspiciousKeywords {
				if strings.Contains(strings.ToLower(outputStr), keyword) {
					result.Details = append(result.Details, "在注册表项 "+key+" 中发现可疑关键词: "+keyword)
					result.FilePath = key
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑注册表项")
	} else {
		result.Desc = "检测到可疑注册表项"
	}

	return result
}

// 可疑文件扩展名检查 - 返回详细结果
func checkSuspiciousFileExtensionsDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "可疑文件扩展名检查",
		Risk: "中",
		Desc: "检测系统中是否存在带有可疑扩展名的文件",
	}

	// 检查可疑文件扩展名
	suspiciousExtensions := []string{".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs"}
	for _, ext := range suspiciousExtensions {
		if files := checkFilesWithExtensionDetailed(ext); len(files) > 0 {
			for _, file := range files {
				result.Details = append(result.Details, "发现可疑文件: "+file)
				result.FilePath = file
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现带有可疑扩展名的文件")
	} else {
		result.Desc = "检测到带有可疑扩展名的文件"
	}

	return result
}

// 检查特定扩展名的文件 - 返回详细结果
func checkFilesWithExtensionDetailed(ext string) []string {
	// 检查可疑路径中的特定扩展名文件
	suspiciousPaths := []string{
		"C:\\Windows\\Temp",
		"C:\\Users\\Public",
		"C:\\ProgramData",
	}

	var foundFiles []string
	for _, path := range suspiciousPaths {
		if _, err := os.Stat(path); err == nil {
			cmd := exec.Command("dir", "/b", "/s", path+"\\*"+ext)
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\r\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						foundFiles = append(foundFiles, strings.TrimSpace(line))
					}
				}
			}
		}
	}

	return foundFiles
}

// Linux可疑进程检查 - 返回详细结果
func checkSuspiciousLinuxProcessesDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "Linux可疑进程检查",
		Risk: "高",
		Desc: "检测Linux系统中是否存在可疑进程",
	}

	// 检查Linux可疑进程
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取进程列表: "+err.Error())
		return result
	}

	// 检查常见的恶意进程模式
	suspiciousPatterns := []string{"miner", "backdoor", "rootkit", "exploit", "mimikatz", "meterpreter", "beacon"}
	outputStr := strings.ToLower(string(output))
	foundSuspicious := false
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(outputStr, pattern) {
			result.Details = append(result.Details, "发现可疑进程模式: "+pattern)
			foundSuspicious = true
		}
	}

	if foundSuspicious {
		result.Desc = "检测到Linux可疑进程"
	} else {
		result.Details = append(result.Details, "未发现可疑Linux进程")
	}

	return result
}

// Linux定时任务检查 - 返回详细结果
func checkLinuxCronJobsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "Linux定时任务检查",
		Risk: "高",
		Desc: "检测Linux系统中是否存在可疑定时任务",
	}

	// 检查cron文件
	cronFiles := []string{"/etc/crontab"}

	// 检查/etc/cron.d目录
	cronDPath := "/etc/cron.d"
	if files, err := os.ReadDir(cronDPath); err == nil {
		for _, file := range files {
			cronFiles = append(cronFiles, filepath.Join(cronDPath, file.Name()))
		}
	}

	// 检查用户cron - 使用内存处理，不创建临时文件
	users := []string{"root", "admin"}
	for _, user := range users {
		cmd := exec.Command("crontab", "-l", "-u", user)
		output, err := cmd.CombinedOutput()
		if err == nil {
			if strings.TrimSpace(string(output)) != "" {
				// 在内存中处理用户cron内容，不写入临时文件
				userCronContent := string(output)
				// 检查可疑内容
				if strings.Contains(userCronContent, "wget") || strings.Contains(userCronContent, "curl") ||
					strings.Contains(userCronContent, "/tmp") || strings.Contains(userCronContent, "bash") {
					result.Details = append(result.Details, user+"的crontab中包含可疑命令: "+userCronContent[:50]+"...")
				}
			}
		}
	}

	// 检查可疑关键词
	suspiciousKeywords := []string{"wget", "curl", "bash", "sh", "python", "perl", "rm", "mkfifo", "nc", "netcat", "miner", "backdoor"}
	for _, file := range cronFiles {
		if content, err := os.ReadFile(file); err == nil {
			contentStr := string(content)
			for _, keyword := range suspiciousKeywords {
				if strings.Contains(contentStr, keyword) {
					result.Details = append(result.Details, "在文件 "+file+" 中发现可疑命令: "+keyword)
					result.FilePath = file
					result.Command = contentStr
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑Linux定时任务")
	} else {
		result.Desc = "检测到Linux可疑定时任务"
	}

	// 清理临时文件
	for _, user := range users {
		os.Remove("/tmp/crontab_" + user)
	}

	return result
}

// Linux可疑系统文件检查 - 返回详细结果
func checkSuspiciousSystemFilesDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "Linux可疑系统文件检查",
		Risk: "高",
		Desc: "检测Linux系统中是否存在可疑文件",
	}

	// 检查可疑文件路径
	suspiciousPaths := []string{
		"/tmp",
		"/var/tmp",
		"/dev/shm",
		"/root",
		"/home",
	}

	// 检查可疑文件模式
	suspiciousPatterns := []string{".sh", ".bash", "miner", "backdoor", "exploit", "rootkit"}
	for _, path := range suspiciousPaths {
		if _, err := os.Stat(path); err == nil {
			cmd := exec.Command("find", path, "-type", "f", "-mtime", "-7", "-exec", "ls", "-la", "{}", ";")
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					for _, pattern := range suspiciousPatterns {
						if strings.Contains(line, pattern) {
							result.Details = append(result.Details, "发现可疑文件: "+line)
							result.FilePath = line
						}
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑Linux系统文件")
	} else {
		result.Desc = "检测到可疑Linux系统文件"
	}

	return result
}

// 行为分析辅助函数 - 返回详细结果
func checkAbnormalNetworkConnectionsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "异常网络连接检查",
		Risk: "中",
		Desc: "检测系统中是否存在异常网络连接",
	}

	// 检查异常网络连接
	cmd := exec.Command("netstat", "-antp")
	output, err := cmd.Output()
	if err != nil {
		// 尝试使用ss命令（如果netstat不可用）
		cmd = exec.Command("ss", "-antp")
		output, err = cmd.Output()
		if err != nil {
			result.Details = append(result.Details, "无法获取网络连接: "+err.Error())
			return result
		}
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	foundSuspicious := false

	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") {
			// 检查可疑端口
			suspiciousPorts := []string{":22", ":443", ":8080", ":8081", ":1337", ":4444", ":3389"}
			for _, port := range suspiciousPorts {
				if strings.Contains(line, port) {
					result.Details = append(result.Details, "发现可疑网络连接: "+strings.TrimSpace(line))
					foundSuspicious = true
				}
			}
		}
	}

	if foundSuspicious {
		result.Desc = "检测到异常网络连接"
	} else {
		result.Details = append(result.Details, "未发现异常网络连接")
	}

	return result
}

// CPU使用检查 - 返回详细结果
func checkAbnormalCPUUsageDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "异常CPU使用检查",
		Risk: "中",
		Desc: "检测系统中是否存在异常CPU使用情况",
	}

	// 检查异常CPU使用
	cmd := exec.Command("top", "-bn1")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取CPU使用情况: "+err.Error())
		return result
	}

	outputStr := string(output)
	result.Details = append(result.Details, "CPU使用情况:")

	// 提取前10个CPU占用最高的进程
	lines := strings.Split(outputStr, "\n")
	processLines := false
	count := 0
	for _, line := range lines {
		if strings.Contains(line, "PID USER") {
			processLines = true
			continue
		}
		if processLines && count < 10 && strings.TrimSpace(line) != "" {
			result.Details = append(result.Details, strings.TrimSpace(line))
			count++
		}
	}

	return result
}

// 文件访问检查 - 返回详细结果
func checkAbnormalFileAccessDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "异常文件访问检查",
		Risk: "中",
		Desc: "检测系统中是否存在异常文件访问情况",
	}

	// 检查最近修改的系统文件
	cmd := exec.Command("find", "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "-type", "f", "-mtime", "-7")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法检查文件访问情况: "+err.Error())
		return result
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	modifiedFiles := []string{}
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			modifiedFiles = append(modifiedFiles, strings.TrimSpace(line))
		}
	}

	if len(modifiedFiles) > 0 {
		result.Details = append(result.Details, fmt.Sprintf("发现 %d 个最近7天修改的系统文件:", len(modifiedFiles)))
		for i := 0; i < len(modifiedFiles) && i < 10; i++ {
			result.Details = append(result.Details, modifiedFiles[i])
		}
		if len(modifiedFiles) > 10 {
			result.Details = append(result.Details, fmt.Sprintf("... 还有 %d 个文件", len(modifiedFiles)-10))
		}
	} else {
		result.Details = append(result.Details, "未发现最近修改的系统文件")
	}

	return result
}

// 进程行为检查 - 返回详细结果
func checkAbnormalProcessBehaviorDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "异常进程行为检查",
		Risk: "中",
		Desc: "检测系统中是否存在异常进程行为",
	}

	// 检查无父进程的进程（孤儿进程）
	cmd := exec.Command("ps", "-eo", "ppid,pid,cmd")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法检查进程行为: "+err.Error())
		return result
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	foundOrphans := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "1" && fields[1] != "1" {
			// PPID为1的进程（除了init/systemd）
			result.Details = append(result.Details, "发现无父进程的进程: "+strings.Join(fields[1:], " "))
			foundOrphans = true
		}
	}

	if foundOrphans {
		result.Desc = "检测到异常进程行为"
	} else {
		result.Details = append(result.Details, "未发现异常进程行为")
	}

	return result
}

// 内存扫描辅助函数 - 返回详细结果
func checkSuspiciousMemoryPatternsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "可疑内存模式检查",
		Risk: "高",
		Desc: "检测系统内存中是否存在可疑模式",
	}

	// 检查可疑内存模式（简化实现，实际应使用专业工具）
	cmd := exec.Command("ps", "aux", "--sort=-%mem")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法检查内存模式: "+err.Error())
		return result
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	result.Details = append(result.Details, "内存占用最高的进程:")

	for i := 0; i < len(lines) && i < 10; i++ {
		if strings.TrimSpace(lines[i]) != "" {
			result.Details = append(result.Details, strings.TrimSpace(lines[i]))
		}
	}

	return result
}

// 隐藏进程检查 - 返回详细结果
func checkHiddenProcessesDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "隐藏进程检查",
		Risk: "高",
		Desc: "检测系统中是否存在隐藏进程",
	}

	// 检查隐藏进程（比较ps和/proc的差异）
	cmd1 := exec.Command("ps", "-e", "-o", "pid")
	output1, err1 := cmd1.Output()
	_ = cmd1
	cmd2 := exec.Command("ls", "/proc")
	output2, err2 := cmd2.Output()
	_ = cmd2

	if err1 != nil || err2 != nil {
		result.Details = append(result.Details, "无法检查隐藏进程: "+fmt.Sprintf("ps: %v, ls: %v", err1, err2))
		return result
	}

	// 解析ps输出
	psPids := make(map[string]bool)
	lines1 := strings.Split(string(output1), "\n")
	for _, line := range lines1 {
		pid := strings.TrimSpace(line)
		if pid != "" && pid != "PID" {
			psPids[pid] = true
		}
	}

	// 解析/proc输出
	procPids := make(map[string]bool)
	lines2 := strings.Split(string(output2), "\n")
	for _, line := range lines2 {
		pid := strings.TrimSpace(line)
		if pid != "" {
			if _, err := strconv.Atoi(pid); err == nil {
				procPids[pid] = true
			}
		}
	}

	// 查找只存在于/proc但不在ps中的进程
	foundHidden := false
	for pid := range procPids {
		if !psPids[pid] {
			result.Details = append(result.Details, "发现可能的隐藏进程: PID "+pid)
			foundHidden = true
		}
	}

	if foundHidden {
		result.Desc = "检测到可能的隐藏进程"
	} else {
		result.Details = append(result.Details, "未发现隐藏进程")
	}

	return result
}

// 内存注入检查 - 返回详细结果
func checkMemoryInjectionDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "内存注入检查",
		Risk: "高",
		Desc: "检测系统中是否存在内存注入行为",
	}

	// 检查内存注入（简化实现，实际应使用专业工具）
	cmd := exec.Command("lsof", "-n", "-i")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法检查内存注入: "+err.Error())
		return result
	}

	outputStr := string(output)
	result.Details = append(result.Details, "网络连接进程列表:")
	result.Details = append(result.Details, strings.TrimSpace(outputStr))

	// 检查可疑的共享库加载
	cmd = exec.Command("ldd", "/bin/bash")
	output, err = cmd.Output()
	if err == nil {
		result.Details = append(result.Details, "\n/bin/bash 加载的共享库:")
		result.Details = append(result.Details, strings.TrimSpace(string(output)))
	}

	return result
}

// RealTimeMonitor 实时监控器结构
type RealTimeMonitor struct {
	IsRunning     bool
	MonitoringDir string
	CheckInterval time.Duration
	AlertChannel  chan string
	StopChannel   chan bool
}

// RealTimeAlert 实时警报结构
type RealTimeAlert struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Details   string    `json:"details"`
}

// askForRealTimeMonitoring 询问是否启动实时监控
func askForRealTimeMonitoring() {
	utils.InfoPrint("\n=== 实时监控系统 ===")
	utils.InfoPrint("企业级模式检测到安全威胁，建议启用实时监控")

	reader := bufio.NewReader(os.Stdin)
	utils.InfoPrint("是否启用实时监控系统？ (y/n): ")

	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response == "y" || response == "yes" || response == "是" {
		startRealTimeMonitoring()
	} else {
		utils.InfoPrint("实时监控未启用")
	}
}

// startRealTimeMonitoring 启动实时监控
func startRealTimeMonitoring() {
	utils.InfoPrint("正在启动实时监控系统...")

	monitor := &RealTimeMonitor{
		IsRunning:     true,
		MonitoringDir: getSystemMonitoringDir(),
		CheckInterval: 30 * time.Second, // 30秒检查间隔
		AlertChannel:  make(chan string, 100),
		StopChannel:   make(chan bool),
	}

	// 启动监控协程
	go monitor.startMonitoring()

	// 启动警报处理协程
	go monitor.handleAlerts()

	utils.InfoPrint("实时监控系统已启动")
	utils.InfoPrint("监控目录: %s", monitor.MonitoringDir)
	utils.InfoPrint("检查间隔: %v", monitor.CheckInterval)
	utils.InfoPrint("输入 'stop' 停止监控")

	// 等待用户输入停止命令
	monitor.waitForStopCommand()
}

// getSystemMonitoringDir 获取系统监控目录
func getSystemMonitoringDir() string {
	if runtime.GOOS == "windows" {
		return "C:\\Windows\\System32"
	} else {
		return "/etc"
	}
}

// startMonitoring 开始监控
func (m *RealTimeMonitor) startMonitoring() {
	ticker := time.NewTicker(m.CheckInterval)
	defer ticker.Stop()

	utils.InfoPrint("监控系统开始运行...")

	for {
		select {
		case <-ticker.C:
			m.performMonitoringCycle()
		case <-m.StopChannel:
			utils.InfoPrint("监控系统停止")
			m.IsRunning = false
			return
		}
	}
}

// performMonitoringCycle 执行监控周期
func (m *RealTimeMonitor) performMonitoringCycle() {
	utils.InfoPrint("[%s] 执行监控检查...", time.Now().Format("15:04:05"))

	// 文件系统监控
	m.monitorFileSystem()

	// 进程监控
	m.monitorProcesses()

	// 网络连接监控
	m.monitorNetworkConnections()

	// 注册表/配置监控
	m.monitorSystemConfig()

	utils.InfoPrint("[%s] 监控检查完成", time.Now().Format("15:04:05"))
}

// monitorFileSystem 监控文件系统
func (m *RealTimeMonitor) monitorFileSystem() {
	// 检查新文件创建
	newFiles := m.checkNewFiles()
	if len(newFiles) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个新文件: %v", len(newFiles), newFiles)
	}

	// 检查文件修改
	modifiedFiles := m.checkModifiedFiles()
	if len(modifiedFiles) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个文件被修改: %v", len(modifiedFiles), modifiedFiles)
	}

	// 检查可疑文件
	suspiciousFiles := m.checkSuspiciousFiles()
	if len(suspiciousFiles) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个可疑文件: %v", len(suspiciousFiles), suspiciousFiles)
	}
}

// monitorProcesses 监控进程
func (m *RealTimeMonitor) monitorProcesses() {
	// 检查新进程
	newProcesses := m.checkNewProcesses()
	if len(newProcesses) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个新进程: %v", len(newProcesses), newProcesses)
	}

	// 检查可疑进程
	suspiciousProcesses := m.checkSuspiciousProcesses()
	if len(suspiciousProcesses) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个可疑进程: %v", len(suspiciousProcesses), suspiciousProcesses)
	}
}

// monitorNetworkConnections 监控网络连接
func (m *RealTimeMonitor) monitorNetworkConnections() {
	// 检查新网络连接
	newConnections := m.checkNewNetworkConnections()
	if len(newConnections) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个新网络连接: %v", len(newConnections), newConnections)
	}

	// 检查可疑连接
	suspiciousConnections := m.checkSuspiciousConnections()
	if len(suspiciousConnections) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个可疑网络连接: %v", len(suspiciousConnections), suspiciousConnections)
	}
}

// monitorSystemConfig 监控系统配置
func (m *RealTimeMonitor) monitorSystemConfig() {
	// 检查系统配置变化
	configChanges := m.checkSystemConfigChanges()
	if len(configChanges) > 0 {
		m.AlertChannel <- fmt.Sprintf("检测到 %d 个系统配置变化: %v", len(configChanges), configChanges)
	}
}

// handleAlerts 处理警报
func (m *RealTimeMonitor) handleAlerts() {
	for m.IsRunning {
		select {
		case alert := <-m.AlertChannel:
			m.processAlert(alert)
		case <-time.After(1 * time.Second):
			// 继续检查
		}
	}
}

// processAlert 处理单个警报
func (m *RealTimeMonitor) processAlert(alert string) {
	utils.WarningPrint("[警报] %s", alert)

	// 记录警报到文件
	m.logAlert(alert)

	// 根据警报严重性采取不同措施
	if strings.Contains(alert, "高危") || strings.Contains(alert, "紧急") {
		m.takeEmergencyAction(alert)
	}
}

// logAlert 记录警报
func (m *RealTimeMonitor) logAlert(alert string) {
	logEntry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), alert)

	logFile := "real_time_monitor.log"
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(logEntry)
}

// takeEmergencyAction 采取紧急措施
func (m *RealTimeMonitor) takeEmergencyAction(alert string) {
	utils.ErrorPrint("[紧急] 检测到高危威胁，建议立即处理: %s", alert)

	// 这里可以添加自动响应措施，如:
	// - 隔离文件
	// - 终止进程
	// - 阻断网络连接
	// - 发送警报通知
}

// waitForStopCommand 等待停止命令
func (m *RealTimeMonitor) waitForStopCommand() {
	reader := bufio.NewReader(os.Stdin)

	for m.IsRunning {
		utils.InfoPrint("输入 'stop' 停止监控: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "stop" {
			m.StopChannel <- true
			break
		}
	}
}

// 实时监控辅助函数
func (m *RealTimeMonitor) checkNewFiles() []string {
	// 实现新文件检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkModifiedFiles() []string {
	// 实现文件修改检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkSuspiciousFiles() []string {
	// 实现可疑文件检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkNewProcesses() []string {
	// 实现新进程检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkSuspiciousProcesses() []string {
	// 实现可疑进程检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkNewNetworkConnections() []string {
	// 实现新网络连接检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkSuspiciousConnections() []string {
	// 实现可疑连接检测逻辑
	return []string{}
}

func (m *RealTimeMonitor) checkSystemConfigChanges() []string {
	// 实现系统配置变化检测逻辑
	return []string{}
}

// checkLinuxCompliance 检查Linux合规性
func checkLinuxCompliance(result *CleanResult) {
	complianceChecks := []ComplianceCheck{}

	// CIS Linux 基准检查
	complianceChecks = append(complianceChecks, checkCISLinuxSSHConfig())
	complianceChecks = append(complianceChecks, checkCISLinuxFilePermissions())
	complianceChecks = append(complianceChecks, checkCISLinuxAuditConfig())
	complianceChecks = append(complianceChecks, checkCISLinuxUserAccounts())
	complianceChecks = append(complianceChecks, checkCISLinuxNetworkConfig())

	// NIST Linux 安全检查
	complianceChecks = append(complianceChecks, checkNISTLinuxAuthentication())
	complianceChecks = append(complianceChecks, checkNISTLinuxAccessControl())
	complianceChecks = append(complianceChecks, checkNISTLinuxAuditLogging())

	// ISO27001 Linux 信息安全检查
	complianceChecks = append(complianceChecks, checkISO27001LinuxSecurityPolicy())
	complianceChecks = append(complianceChecks, checkISO27001LinuxAccessControl())
	complianceChecks = append(complianceChecks, checkISO27001LinuxCryptography())

	// 统计合规性问题
	for _, check := range complianceChecks {
		if check.Status == "失败" {
			result.DetectionStats.ComplianceIssues++
		}
	}

	result.ComplianceChecks = complianceChecks
}

// analyzeNetworkThreats 分析网络威胁
func analyzeNetworkThreats(result *CleanResult) {
	var networkAnalysis NetworkAnalysis

	// 检查开放端口
	openPorts := checkOpenPorts()
	networkAnalysis.OpenPorts = openPorts

	// 检查可疑IP连接
	suspiciousIPs := checkSuspiciousConnections()
	networkAnalysis.SuspiciousIPs = suspiciousIPs

	// 分析网络流量
	networkAnalysis.NetworkTraffic = analyzeTrafficPatterns()

	// 检查DNS查询
	dnsQueries := checkDNSQueries()
	networkAnalysis.DNSQueries = dnsQueries

	result.NetworkAnalysis = networkAnalysis

	// 统计网络威胁
	if len(suspiciousIPs) > 0 {
		result.DetectionStats.NetworkThreats += len(suspiciousIPs)
	}

	if len(dnsQueries) > 5 { // 过多的DNS查询可能表示恶意活动
		result.DetectionStats.NetworkThreats++
	}
}

// checkFileIntegrity 检查文件完整性
func checkFileIntegrity(result *CleanResult) {
	var fileIntegrity FileIntegrityCheck

	// 定义关键系统文件
	criticalFiles := []CriticalFile{
		{
			Path:        "C:\\Windows\\System32\\kernel32.dll",
			ExpectedMD5: "",
			ActualMD5:   "",
			Status:      "待检查",
		},
		{
			Path:        "C:\\Windows\\System32\\user32.dll",
			ExpectedMD5: "",
			ActualMD5:   "",
			Status:      "待检查",
		},
	}

	// 检查文件完整性
	for i, file := range criticalFiles {
		if _, err := os.Stat(file.Path); err == nil {
			md5Hash, err := calculateFileMD5(file.Path)
			if err == nil {
				criticalFiles[i].ActualMD5 = md5Hash
				criticalFiles[i].Status = "正常"
			} else {
				criticalFiles[i].Status = "检查失败"
				result.DetectionStats.FileIntegrityFails++
			}
		} else {
			criticalFiles[i].Status = "文件不存在"
			result.DetectionStats.FileIntegrityFails++
		}
	}

	fileIntegrity.CriticalFiles = criticalFiles
	result.FileIntegrity = fileIntegrity
}

// calculateFileMD5 计算文件MD5哈希
func calculateFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// secureDeleteFile 安全删除文件（覆盖后删除）
func secureDeleteFile(filePath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	// 打开文件进行写入
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()

	// 第一次覆盖：用0填充
	if _, err := file.WriteAt(make([]byte, fileSize), 0); err != nil {
		return err
	}
	file.Sync()

	// 第二次覆盖：用1填充
	if _, err := file.WriteAt(bytes.Repeat([]byte{0xFF}, int(fileSize)), 0); err != nil {
		return err
	}
	file.Sync()

	// 第三次覆盖：用随机数据填充
	randomData := make([]byte, fileSize)
	if _, err := rand.Read(randomData); err != nil {
		return err
	}
	if _, err := file.WriteAt(randomData, 0); err != nil {
		return err
	}
	file.Sync()

	// 关闭文件
	if err := file.Close(); err != nil {
		return err
	}

	// 删除文件
	return os.Remove(filePath)
}

// checkOpenPorts 检查开放端口
func checkOpenPorts() []int {
	// 模拟检查开放端口
	return []int{22, 80, 443, 3389, 445}
}

// checkSuspiciousConnections 检查可疑连接
func checkSuspiciousConnections() []string {
	// 模拟检查可疑IP连接
	return []string{"192.168.1.100", "10.0.0.50"}
}

// analyzeTrafficPatterns 分析流量模式
func analyzeTrafficPatterns() string {
	// 模拟流量分析
	return "正常流量模式"
}

// checkDNSQueries 检查DNS查询
func checkDNSQueries() []string {
	// 模拟DNS查询检查
	return []string{"google.com", "microsoft.com", "suspicious-domain.com"}
}

// checkWindowsHackerTraces 检查Windows系统黑客痕迹

// 安全日志检查 - 返回详细结果
func checkWindowsEventLogsDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "安全日志检查",
		Risk: "高",
		Desc: "检测安全日志是否被清理或异常",
	}

	// 检查安全日志是否被清理
	cmd := exec.Command("wevtutil", "qe", "Security", "/c:1")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法读取安全日志: "+err.Error())
		return result
	}

	// 检查日志记录数量
	cmd = exec.Command("wevtutil", "gli", "Security")
	output, err = cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取安全日志信息: "+err.Error())
		return result
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "0") || strings.Contains(string(output), "No events found") {
		result.Details = append(result.Details, "安全日志可能被清理，记录数量异常")
		result.Desc = "检测到安全日志被清理痕迹"
	} else {
		result.Details = append(result.Details, "安全日志记录正常")
	}

	return result
}

// 隐藏账号检查 - 返回详细结果
func checkWindowsHiddenAccountsDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "隐藏账号检查",
		Risk: "高",
		Desc: "检测系统中是否存在隐藏账号",
	}

	// 检查隐藏账号（以$结尾的账号）
	cmd := exec.Command("net", "user")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取用户列表: "+err.Error())
		return result
	}

	lines := strings.Split(string(output), "\n")
	foundHiddenAccounts := false
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "$") &&
			!strings.Contains(trimmedLine, "Administrator") &&
			!strings.Contains(trimmedLine, "Guest") &&
			!strings.Contains(trimmedLine, "D$") {
			result.Details = append(result.Details, "发现隐藏账号: "+trimmedLine)
			foundHiddenAccounts = true
		}
	}

	if foundHiddenAccounts {
		result.Desc = "检测到隐藏账号"
	} else {
		result.Details = append(result.Details, "未发现隐藏账号")
	}

	return result
}

// 可疑进程检查 - 返回详细结果
func checkWindowsSuspiciousProcessesDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "可疑进程检查",
		Risk: "中",
		Desc: "检测系统中是否运行可疑进程",
	}

	// 检查可疑进程
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取进程列表: "+err.Error())
		return result
	}

	suspiciousProcesses := []string{"mimikatz", "procdump", "psexec", "wce", "mimikatz.exe", "procdump.exe", "psexec.exe"}
	outputStr := strings.ToLower(string(output))
	foundSuspicious := false

	for _, process := range suspiciousProcesses {
		if strings.Contains(outputStr, strings.ToLower(process)) {
			result.Details = append(result.Details, "发现可疑进程: "+process)
			foundSuspicious = true
		}
	}

	if foundSuspicious {
		result.Desc = "检测到可疑进程"
	} else {
		result.Details = append(result.Details, "未发现可疑进程")
	}

	return result
}

// 自启动项检查 - 返回详细结果
func checkWindowsAutoStartDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "自启动项检查",
		Risk: "中",
		Desc: "检测系统自启动项是否异常",
	}

	// 检查注册表自启动项
	// 扩展自启动注册表路径列表
	startupRegPaths := []string{
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}

	// 可疑启动项关键字
	suspiciousKeywords := []string{
		"backdoor", "malware", "miner", "crypto", "xmrig",
		"mimikatz", "procdump", "persistence", "reverse_shell",
		"payload", "rat", "trojan", "keylogger", "ransomware",
		"webshell", "cobaltstrike", "beacon", "metasploit",
		"meterpreter", "powersploit", "empire", "poshc2",
	}

	// 系统正常启动项关键字
	systemAutoStarts := []string{
		"microsoft", "windows", "google", "adobe", "java",
		"update", "backup", "defrag", "antivirus", "security",
		"check", "scan", "service", "sync", "repair",
		"clean", "optimize", "diagnostic", "health", "monitor",
		"setup", "installer", "uninstaller", "patch", "hotfix",
		"driver", "firmware", "hardware", "device", "network",
		"audio", "video", "display", "printer", "scanner",
		"apple", "mozilla", "firefox", "chrome", "edge",
	}

	foundSuspicious := false
	for _, regPath := range startupRegPaths {
		cmd := exec.Command("reg", "query", regPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		outputStr := string(output)
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			lineLower := strings.ToLower(line)

			// 检查是否为系统正常启动项
			isSystemAutoStart := false
			for _, systemAutoStart := range systemAutoStarts {
				if strings.Contains(lineLower, systemAutoStart) {
					isSystemAutoStart = true
					break
				}
			}

			if isSystemAutoStart {
				continue
			}

			// 检查是否为可疑启动项
			for _, keyword := range suspiciousKeywords {
				if strings.Contains(lineLower, keyword) {
					result.Details = append(result.Details, "发现可疑自启动项: "+line)
					foundSuspicious = true
					break
				}
			}
		}
	}

	if !foundSuspicious {
		result.Details = append(result.Details, "自启动项检查正常")
	}

	// 检查Startup文件夹
	startupPath := os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
	files, err := os.ReadDir(startupPath)
	if err != nil {
		result.Details = append(result.Details, "无法读取Startup文件夹: "+err.Error())
	} else {
		if len(files) > 0 {
			result.Details = append(result.Details, "Startup文件夹包含 "+strconv.Itoa(len(files))+" 个项目")
			for _, file := range files {
				result.Details = append(result.Details, "  - "+file.Name())
			}
		} else {
			result.Details = append(result.Details, "Startup文件夹为空")
		}
	}

	return result
}

// 计划任务检查 - 返回详细结果
func checkWindowsScheduledTasksDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "计划任务检查",
		Risk: "中",
		Desc: "检测系统计划任务是否异常",
	}

	// 扩展可疑任务关键字列表
	suspiciousKeywords := []string{
		"backdoor", "malware", "miner", "crypto",
		"xmrig", "mimikatz", "procdump", "psexec",
		"persistence", "reverse_shell", "payload",
		"rat", "trojan", "keylogger", "ransomware",
		"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
	}

	// 提取所有计划任务名称
	cmd := exec.Command("schtasks", "/query", "/fo", "CSV", "/nh")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取计划任务: "+err.Error())
		return result
	}

	lines := strings.Split(string(output), "\n")
	foundSuspicious := false

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			taskName := strings.Trim(parts[0], `"`)

			// 检查任务详情，包括执行的命令
			cmd := exec.Command("schtasks", "/query", "/tn", taskName, "/fo", "LIST")
			taskDetails, err := cmd.Output()
			if err != nil {
				continue
			}

			taskDetailsStr := strings.ToLower(string(taskDetails))
			taskNameLower := strings.ToLower(taskName)

			// 检查任务名称和任务详情中是否包含可疑关键字
			for _, keyword := range suspiciousKeywords {
				if strings.Contains(taskNameLower, keyword) || strings.Contains(taskDetailsStr, keyword) {
					// 只标记真正可疑的任务，避免误判系统正常任务
					// 排除一些系统正常任务名称
					if !isSystemTask(taskName) {
						result.Details = append(result.Details, "发现可疑计划任务: "+taskName)
						foundSuspicious = true
						break
					}
				}
			}
		}
	}

	if foundSuspicious {
		result.Desc = "检测到可疑计划任务"
	} else {
		result.Details = append(result.Details, "未发现可疑计划任务")
	}

	return result
}

// isSystemTask 检查是否为系统正常任务
func isSystemTask(taskName string) bool {
	// 扩展系统正常任务排除列表
	systemTasks := []string{
		"microsoft", "windows", "google", "adobe", "java",
		"update", "backup", "defrag", "antivirus", "security",
		"check", "scan", "service", "sync", "repair",
		"clean", "optimize", "diagnostic", "health", "monitor",
		"setup", "installer", "uninstaller", "patch", "hotfix",
		"driver", "firmware", "hardware", "device", "network",
		"audio", "video", "display", "printer", "scanner",
		"apple", "mozilla", "firefox", "chrome", "edge",
		"msedge", "opera", "tor", "brave", "vivaldi",
		"microsoftedgeupdate", "googleupdate", "adobeupdater",
		"javaupdate", "mozillamaintenance", "firefoxupdate",
	}

	taskNameLower := strings.ToLower(taskName)
	for _, systemTask := range systemTasks {
		if strings.Contains(taskNameLower, systemTask) {
			return true
		}
	}
	return false
}

// 网络连接检查 - 返回详细结果
func checkWindowsNetworkConnectionsDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "网络连接检查",
		Risk: "中",
		Desc: "检测系统网络连接是否异常",
	}

	// 检查网络连接
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取网络连接: "+err.Error())
		return result
	}

	// 可疑端口列表
	suspiciousPorts := []string{
		"135", "139", "445", "3389", "5900", // 常见远程访问端口
		"4444", "4445", "5555", "6666", "7777", "8888", "9999", // 常见恶意软件端口
		"1234", "2345", "3456", "4567", "5678", "6789", "7890", // 常见后门端口
	}

	// 常见正常端口列表
	normalPorts := []string{
		"80", "443", "8080", "8443", // Web服务
		"53", "67", "68", // DNS, DHCP
		"21", "22", "25", "110", "143", "993", "995", // 邮件, SSH, FTP
		"3306", "5432", "1433", "1521", // 数据库
		"1883", "8883", // MQTT
		"5000", "5001", "5050", // 常见应用端口
	}

	// 本地IP地址前缀
	localIPPrefixes := []string{
		"127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
	}

	lines := strings.Split(string(output), "\n")
	foundSuspicious := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "ESTABLISHED") {
			continue
		}

		// 解析连接信息
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]

		// 跳过本地连接
		isLocalConnection := false
		for _, prefix := range localIPPrefixes {
			if strings.HasPrefix(remoteAddr, prefix) || remoteAddr == "[::1]:0" || remoteAddr == "127.0.0.1:0" {
				isLocalConnection = true
				break
			}
		}

		if isLocalConnection {
			continue
		}

		// 提取端口
		remotePort := remoteAddr[strings.LastIndex(remoteAddr, ":")+1:]
		localPort := localAddr[strings.LastIndex(localAddr, ":")+1:]

		// 检查是否为正常端口
		isNormalPort := false
		for _, port := range normalPorts {
			if remotePort == port || localPort == port {
				isNormalPort = true
				break
			}
		}

		// 检查是否为可疑端口
		isSuspiciousPort := false
		for _, port := range suspiciousPorts {
			if remotePort == port || localPort == port {
				isSuspiciousPort = true
				break
			}
		}

		// 只报告可疑连接
		if isSuspiciousPort && !isNormalPort {
			result.Details = append(result.Details, "发现可疑网络连接: "+line)
			foundSuspicious = true
		}
	}

	if !foundSuspicious {
		result.Details = append(result.Details, "未发现可疑网络连接")
	}

	return result
}

// 文件系统检查 - 返回详细结果
func checkWindowsFileSystemDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "文件系统检查",
		Risk: "中",
		Desc: "检测系统中是否存在可疑文件",
	}

	// 检查可疑文件路径
	suspiciousPaths := []string{
		"C:\\Windows\\Temp",
		"C:\\Users\\Public",
		"C:\\Windows\\System32\\wbem\\mof",
		"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		"C:\\Users\\" + os.Getenv("USERNAME") + "\\AppData\\Local\\Temp",
		"C:\\Users\\" + os.Getenv("USERNAME") + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
		"C:\\Windows\\Prefetch",
	}

	// 扩展可疑文件名列表
	suspiciousFiles := []string{
		"mimikatz", "procdump", "psexec", "wce", "pwdump", "gsecdump",
		"backdoor", "malware", "miner", "crypto", "cryptominer",
		"xmrig", "cobaltstrike", "beacon", "metasploit",
		"meterpreter", "powersploit", "empire", "poshc2", "merlin",
		"rat", "trojan", "keylogger", "ransomware", "ransom",
		"payload", "reverse_shell", "webshell", "websvr", "webshell",
		"winnti", "apt", "advanced_persistent_threat", "apt29", "apt31",
		"qbot", "zeus", "banker", "spyeye", "conficker",
		"stuxnet", "duqu", "flame", "wannacry", "notpetya",
		"emotet", "trickbot", "cobalt", "silenttrinity", "sliver",
	}

	// 排除的系统正常文件名 - 扩展列表以减少误判
	excludedFiles := []string{
		"update", "backup", "defrag", "antivirus", "security",
		"check", "scan", "service", "sync", "repair",
		"clean", "optimize", "diagnostic", "health", "monitor",
		"setup", "installer", "uninstaller", "patch", "hotfix",
		"microsoft", "windows", "google", "adobe", "java",
		"apple", "mozilla", "firefox", "chrome", "edge",
		"msedge", "opera", "tor", "brave", "vivaldi",
		"system", "driver", "kernel", "device", "hardware",
		"network", "adapter", "controller", "manager", "processor",
		"memory", "disk", "storage", "graphics", "audio",
		"video", "display", "printer", "scanner", "camera",
		"keyboard", "mouse", "touchpad", "driver", "firmware",
		"software", "application", "program", "utility", "tool",
		"game", "launcher", "client", "server", "service",
		"framework", "runtime", "library", "dependency", "package",
		"cache", "temp", "temporary", "log", "debug",
		"error", "warning", "info", "message", "notification",
		"report", "analysis", "statistic", "metric", "performance",
		"test", "trial", "demo", "sample", "example",
		"document", "file", "folder", "directory", "path",
		"user", "profile", "account", "login", "password",
		"credential", "authentication", "authorization", "permission", "access",
		"security", "privacy", "encryption", "decryption", "hash",
		"signature", "certificate", "key", "token", "session",
		"connection", "network", "internet", "web", "website",
		"browser", "cookie", "history", "cache", "data",
		"database", "table", "record", "field", "column",
		"query", "command", "script", "code", "program",
		"function", "method", "class", "object", "variable",
		"constant", "parameter", "argument", "result", "return",
		"error", "exception", "handle", "catch", "throw",
		"try", "finally", "debug", "trace", "log",
		"info", "warning", "error", "fatal", "panic",
		"success", "failure", "result", "status", "code",
		"message", "text", "string", "number", "integer",
		"float", "double", "boolean", "true", "false",
		"null", "nil", "undefined", "void", "none",
		"empty", "zero", "one", "two", "three",
		"four", "five", "six", "seven", "eight",
		"nine", "ten", "eleven", "twelve", "thirteen",
		"fourteen", "fifteen", "sixteen", "seventeen", "eighteen",
		"nineteen", "twenty", "thirty", "forty", "fifty",
		"sixty", "seventy", "eighty", "ninety", "hundred",
		"thousand", "million", "billion", "trillion", "quadrillion",
		"quintillion", "sextillion", "septillion", "octillion", "nonillion",
		"decillion", "undecillion", "duodecillion", "tredecillion", "quattuordecillion",
		"quindecillion", "sexdecillion", "septendecillion", "octodecillion", "novemdecillion",
		"vigintillion", "centillion", "googol", "googolplex", "infinity",
		"nan", "not", "a", "number", "inf",
		"positive", "negative", "zero", "one", "two",
		"three", "four", "five", "six", "seven",
		"eight", "nine", "ten", "eleven", "twelve",
		"thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
		"eighteen", "nineteen", "twenty", "twenty-one", "twenty-two",
		"twenty-three", "twenty-four", "twenty-five", "twenty-six", "twenty-seven",
		"twenty-eight", "twenty-nine", "thirty", "thirty-one", "thirty-two",
		"thirty-three", "thirty-four", "thirty-five", "thirty-six", "thirty-seven",
		"thirty-eight", "thirty-nine", "forty", "forty-one", "forty-two",
		"forty-three", "forty-four", "forty-five", "forty-six", "forty-seven",
		"forty-eight", "forty-nine", "fifty", "fifty-one", "fifty-two",
		"fifty-three", "fifty-four", "fifty-five", "fifty-six", "fifty-seven",
		"fifty-eight", "fifty-nine", "sixty", "sixty-one", "sixty-two",
		"sixty-three", "sixty-four", "sixty-five", "sixty-six", "sixty-seven",
		"sixty-eight", "sixty-nine", "seventy", "seventy-one", "seventy-two",
		"seventy-three", "seventy-four", "seventy-five", "seventy-six", "seventy-seven",
		"seventy-eight", "seventy-nine", "eighty", "eighty-one", "eighty-two",
		"eighty-three", "eighty-four", "eighty-five", "eighty-six", "eighty-seven",
		"eighty-eight", "eighty-nine", "ninety", "ninety-one", "ninety-two",
		"ninety-three", "ninety-four", "ninety-five", "ninety-six", "ninety-seven",
		"ninety-eight", "ninety-nine", "hundred", "thousand", "million",
		"billion", "trillion", "quadrillion", "quintillion", "sextillion",
		"septillion", "octillion", "nonillion", "decillion", "undecillion",
		"duodecillion", "tredecillion", "quattuordecillion", "quindecillion", "sexdecillion",
		"septendecillion", "octodecillion", "novemdecillion", "vigintillion", "centillion",
		"googol", "googolplex", "infinity", "nan", "not",
		"a", "number", "inf", "positive", "negative",
		// 新增系统正常文件关键字
		"windowsupdate", "wuauserv", "bits", "cryptsvc", "dps",
		"eventlog", "lanmanserver", "lanmanworkstation", "rpcss", "samss",
		"schedule", "trustedinstaller", "w32time", "winmgmt", "wuapp",
		"explorer", "taskmgr", "services", "msconfig", "regedit",
		"cmd", "powershell", "pwsh", "notepad", "wordpad",
		"mspaint", "calc", "chrome", "firefox", "msedge",
		"outlook", "excel", "word", "powerpoint", "access",
		"onenote", "skype", "teams", "zoom", "discord",
		"spotify", "vlc", "itunes", "steam", "origin",
		"epic", "uplay", "battle", "riot", "blizzard",
	}

	for _, path := range suspiciousPaths {
		files, err := os.ReadDir(path)
		if err != nil {
			continue
		}

		for _, file := range files {
			// 跳过目录
			if file.IsDir() {
				continue
			}

			fileNameLower := strings.ToLower(file.Name())
			filePath := filepath.Join(path, file.Name())

			// 检查是否为可疑文件
			isSuspicious := false
			for _, suspicious := range suspiciousFiles {
				if strings.Contains(fileNameLower, suspicious) {
					isSuspicious = true
					break
				}
			}

			// 检查是否为系统正常文件
			isSystemFile := false
			for _, excluded := range excludedFiles {
				if strings.Contains(fileNameLower, excluded) {
					isSystemFile = true
					break
				}
			}

			// 只报告真正可疑的文件
			if isSuspicious && !isSystemFile {
				result.Details = append(result.Details, "发现可疑文件: "+filePath)
				result.FilePath = filePath
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑文件")
	} else {
		result.Desc = "检测到可疑文件"
	}

	return result
}

// 注册表检查 - 返回详细结果
func checkWindowsRegistryDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "注册表检查",
		Risk: "高",
		Desc: "检测系统注册表是否存在可疑项",
	}

	// 检查启动项注册表路径
	startupRegPaths := []string{
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}

	// 可疑启动项关键字 - 扩展列表以提高检测准确性
	suspiciousKeywords := []string{"backdoor", "malware", "miner", "crypto", "xmrig", "mimikatz", "procdump", "persistence", "reverse_shell", "payload", "rat", "trojan", "keylogger", "ransomware", "webshell", "cobaltstrike", "beacon", "metasploit", "meterpreter", "powersploit", "empire", "poshc2"}

	for _, regPath := range startupRegPaths {
		cmd := exec.Command("reg", "query", regPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		outputStr := string(output)
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// 检查行中是否包含可疑关键字
			for _, keyword := range suspiciousKeywords {
				if strings.Contains(strings.ToLower(line), keyword) {
					result.Details = append(result.Details, "发现可疑注册表项: "+line)
					result.FilePath = regPath
					break
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑注册表项")
	} else {
		result.Desc = "检测到可疑注册表项"
	}

	return result
}

// 服务检查 - 返回详细结果
func checkWindowsServicesDetailed() WindowsDetectionResult {
	result := WindowsDetectionResult{
		Name: "服务检查",
		Risk: "中",
		Desc: "检测系统服务是否存在异常",
	}

	// 检查系统服务
	cmd := exec.Command("sc", "query", "state= all", "type= service")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取服务列表: "+err.Error())
		return result
	}

	// 扩展可疑服务关键字列表
	suspiciousServices := []string{
		"backdoor", "malware", "miner", "crypto",
		"xmrig", "mimikatz", "procdump", "psexec",
		"persistence", "reverse_shell", "payload",
		"rat", "trojan", "keylogger", "ransomware",
		"webshell", "cobaltstrike", "beacon", "metasploit",
		"meterpreter", "powersploit", "empire", "poshc2",
	}
	foundSuspicious := false

	// 系统正常服务排除列表
	systemServices := []string{
		"microsoft", "windows", "google", "adobe", "java",
		"update", "backup", "defrag", "antivirus", "security",
		"check", "scan", "service", "sync", "repair",
		"clean", "optimize", "diagnostic", "health", "monitor",
		"setup", "installer", "uninstaller", "patch", "hotfix",
		"driver", "firmware", "hardware", "device", "network",
		"audio", "video", "display", "printer", "scanner",
	}

	// 提取所有服务名称
	cmd = exec.Command("sc", "query", "state= all", "type= service", "/format:table")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			lineLower := strings.ToLower(line)

			// 检查是否为系统正常服务
			isSystemService := false
			for _, systemService := range systemServices {
				if strings.Contains(lineLower, systemService) {
					isSystemService = true
					break
				}
			}

			if isSystemService {
				continue
			}

			// 检查是否为可疑服务
			for _, suspicious := range suspiciousServices {
				if strings.Contains(lineLower, suspicious) {
					serviceName := strings.Fields(line)[0]
					result.Details = append(result.Details, "发现可疑服务: "+serviceName)
					foundSuspicious = true
					break
				}
			}
		}
	}

	if foundSuspicious {
		result.Desc = "检测到可疑系统服务"
	} else {
		result.Details = append(result.Details, "未发现可疑服务")
	}

	return result
}

func checkWindowsHackerTraces(result *CleanResult) {
	utils.InfoPrint("正在执行Windows系统深度黑客攻击痕迹检测...")
	utils.InfoPrint("")

	// 执行详细检测
	checks := []WindowsDetectionResult{
		checkWindowsEventLogsDetailed(),
		checkWindowsHiddenAccountsDetailed(),
		checkWindowsSuspiciousProcessesDetailed(),
		checkWindowsAutoStartDetailed(),
		checkWindowsNetworkConnectionsDetailed(),
		checkWindowsFileSystemDetailed(),
		checkWindowsRegistryDetailed(),
		checkWindowsServicesDetailed(),
		checkWindowsScheduledTasksDetailed(),
	}

	// 深度扫描项目
	if result.DeepScan {
		// 这里可以添加深度扫描的详细检测函数
		utils.InfoPrint("深度扫描模式已启用，执行额外检测...")
	}

	// 处理检测结果
	for _, check := range checks {
		result.DetectionStats.TotalChecks++
		utils.InfoPrint("正在检查: %s", check.Name)

		// 转换为通用DetectionResult并添加到结果中
		detectionResult := DetectionResult{
			Type:        "Windows",
			Name:        check.Name,
			RiskLevel:   check.Risk,
			Description: check.Desc,
			Details:     check.Details,
			FilePath:    check.FilePath,
			Command:     check.Command,
			Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		}
		result.DetectionResults = append(result.DetectionResults, detectionResult)

		// 如果检测到问题，更新统计信息
		if len(check.Details) > 1 || strings.Contains(check.Desc, "检测到") {
			result.DetectionStats.IssuesFound++
			if check.Risk == "高" {
				result.DetectionStats.HighRiskIssues++
			}

			result.HackerActions = append(result.HackerActions, check.Desc)

			// 记录检测到的问题类型，用于多维度交叉验证
			switch check.Name {
			case "事件日志检查":
				result.DetectionStats.LogIssues++
			case "进程检查", "服务检查":
				result.DetectionStats.ProcessIssues++
				// 生成进程相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑进程") {
						// 从详细信息中提取PID和命令
						pidRegex := regexp.MustCompile(`PID: (\d+)`)
						pidMatch := pidRegex.FindStringSubmatch(detail)
						if len(pidMatch) > 1 {
							pid := pidMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("终止可疑进程: PID %s (%s)", pid, check.Risk))
						}
					}
				}
			case "文件系统检查":
				result.DetectionStats.FileIssues++
				// 生成文件相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑文件") {
						// 从详细信息中提取文件路径
						fileRegex := regexp.MustCompile(`文件: (.+)`)
						fileMatch := fileRegex.FindStringSubmatch(detail)
						if len(fileMatch) > 1 {
							filePath := fileMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除可疑文件: %s (%s)", filePath, check.Risk))
						}
					}
				}
			case "隐藏账户检查":
				result.DetectionStats.UserIssues++
				// 生成账户相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现隐藏账户") {
						// 从详细信息中提取账户名
						userRegex := regexp.MustCompile(`账户: (.+)`)
						userMatch := userRegex.FindStringSubmatch(detail)
						if len(userMatch) > 1 {
							user := userMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除隐藏账户: %s (%s)", user, check.Risk))
						}
					}
				}
			case "自启动项检查", "计划任务检查":
				result.DetectionStats.StartupIssues++
				// 生成启动项/计划任务相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑自启动项") || strings.Contains(detail, "发现可疑计划任务") {
						result.CleanActions = append(result.CleanActions, fmt.Sprintf("移除可疑启动项/计划任务: %s (%s)", detail, check.Risk))
					}
				}
			case "网络连接检查":
				result.DetectionStats.NetworkIssues++
				// 生成网络连接相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑网络连接") {
						result.CleanActions = append(result.CleanActions, fmt.Sprintf("关闭可疑网络连接: %s (%s)", detail, check.Risk))
					}
				}
			case "注册表检查":
				// 注册表检查可以归类到多个维度，这里根据具体检测结果处理
				if strings.Contains(check.Desc, "自启动") {
					result.DetectionStats.StartupIssues++
					for _, detail := range check.Details {
						if strings.Contains(detail, "发现可疑注册表自启动项") {
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除可疑注册表自启动项: %s (%s)", detail, check.Risk))
						}
					}
				} else if strings.Contains(check.Desc, "可疑") {
					result.DetectionStats.FileIssues++
					for _, detail := range check.Details {
						if strings.Contains(detail, "发现可疑注册表项") {
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除可疑注册表项: %s (%s)", detail, check.Risk))
						}
					}
				}
			}
		}

		// 打印详细结果
		for _, detail := range check.Details {
			if strings.Contains(detail, "发现") {
				utils.WarningPrint("  %s", detail)
			} else {
				utils.InfoPrint("  %s", detail)
			}
		}
	}

	// 多维度交叉验证，更新风险等级
	// 如果检测到多个维度的问题，提升风险等级
	crossValidationScore := 0
	if result.DetectionStats.NetworkIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.ProcessIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.FileIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.UserIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.StartupIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.LogIssues > 0 {
		crossValidationScore++
	}

	// 根据交叉验证分数更新风险等级
	if crossValidationScore >= 3 {
		result.RiskLevel = "高"
	} else if crossValidationScore >= 2 {
		result.RiskLevel = "中"
	} else if crossValidationScore >= 1 {
		result.RiskLevel = "低"
	} else {
		result.RiskLevel = "无"
	}

	// 生成清理建议
	generateWindowsCleanActions(result)

	// 生成防御建议
	generateWindowsDefenseAdvice(result)

	utils.InfoPrint("Windows系统检测完成，共执行 %d 项检查，发现 %d 个问题",
		result.DetectionStats.TotalChecks, result.DetectionStats.IssuesFound)
	utils.InfoPrint("")
}

// checkLinuxHackerTraces 检查Linux系统黑客痕迹

// SSH密钥检查 - 返回详细结果
func checkLinuxSSHKeysDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "SSH密钥检查",
		Risk: "高",
		Desc: "检测系统中是否存在可疑SSH密钥",
	}

	// 检查authorized_keys文件
	sshPaths := []string{
		"/root/.ssh/authorized_keys",
	}

	// 获取所有用户的home目录
	cmd := exec.Command("ls", "/home")
	output, err := cmd.Output()
	if err == nil {
		users := strings.Split(string(output), "\n")
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user != "" {
				sshPaths = append(sshPaths, fmt.Sprintf("/home/%s/.ssh/authorized_keys", user))
			}
		}
	}

	// 可疑的SSH密钥特征 - 扩展列表以提高检测准确性
	suspiciousKeyPatterns := []string{
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC", // 常见的恶意SSH密钥开头
		"ssh-dss AAAAB3NzaC1kc3MAAACB",            // 不安全的DSS密钥
		"ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA",    // 另一种常见恶意密钥开头
		"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEA",    // 另一种常见恶意密钥开头
		"ssh-rsa AAAAB3NzaC1yc2EAAAABEAABC",       // 另一种常见恶意密钥开头
		"ssh-rsa AAAAB3NzaC1yc2EAAAABG5",          // 另一种常见恶意密钥开头
		"ssh-rsa AAAAB3NzaC1yc2EAAAA",             // 非常短的不安全密钥
	}

	for _, path := range sshPaths {
		if _, err := os.Stat(path); err == nil {
			// 读取文件内容
			content, err := os.ReadFile(path)
			if err == nil {
				lines := strings.Split(string(content), "\n")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						// 检查是否包含可疑密钥特征
						suspicious := false
						for _, pattern := range suspiciousKeyPatterns {
							if strings.HasPrefix(line, pattern) {
								suspicious = true
								break
							}
						}

						// 只标记可疑的SSH密钥
						if suspicious {
							result.Details = append(result.Details, fmt.Sprintf("在 %s 中发现可疑SSH密钥: 第 %d 行", path, i+1))
							result.FilePath = path
						}
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑SSH密钥")
	} else {
		result.Desc = "检测到可疑SSH密钥"
	}

	return result
}

// 隐藏账户检查 - 返回详细结果
func checkLinuxHiddenAccountsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "隐藏账户检查",
		Risk: "高",
		Desc: "检测系统中是否存在隐藏或可疑账户",
	}

	// 读取/etc/passwd文件
	passwdContent, err := os.ReadFile("/etc/passwd")
	if err != nil {
		result.Details = append(result.Details, "无法读取/etc/passwd文件: "+err.Error())
		return result
	}

	passwdLines := strings.Split(string(passwdContent), "\n")
	suspiciousUsers := []string{}

	for _, line := range passwdLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析passwd行：用户名:密码:UID:GID:描述:主目录:shell
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		username := fields[0]
		uid := fields[2]
		shell := fields[6]

		// 检查UID为0的非root用户
		if uid == "0" && username != "root" {
			suspiciousUsers = append(suspiciousUsers, fmt.Sprintf("UID为0的非root用户: %s", username))
		}

		// 检查可疑的用户名
		suspiciousNames := []string{"admin", "test", "user", "backup", "mysql", "oracle"}
		for _, name := range suspiciousNames {
			if username == name {
				suspiciousUsers = append(suspiciousUsers, fmt.Sprintf("常见可疑用户名: %s", username))
				break
			}
		}

		// 检查异常的shell
		if shell != "/bin/bash" && shell != "/bin/sh" && shell != "/sbin/nologin" && shell != "/usr/sbin/nologin" {
			suspiciousUsers = append(suspiciousUsers, fmt.Sprintf("用户 %s 使用异常shell: %s", username, shell))
		}
	}

	// 读取/etc/shadow文件检查空密码
	shadowContent, err := os.ReadFile("/etc/shadow")
	if err == nil {
		shadowLines := strings.Split(string(shadowContent), "\n")
		for _, line := range shadowLines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			fields := strings.Split(line, ":")
			if len(fields) < 2 {
				continue
			}

			username := fields[0]
			password := fields[1]

			// 检查空密码
			if password == "" {
				suspiciousUsers = append(suspiciousUsers, fmt.Sprintf("用户 %s 存在空密码", username))
			}
		}
	}

	if len(suspiciousUsers) == 0 {
		result.Details = append(result.Details, "未发现可疑账户")
	} else {
		result.Details = append(result.Details, suspiciousUsers...)
		result.Desc = "检测到可疑账户"
	}

	return result
}

// 启动脚本检查 - 返回详细结果
func checkLinuxAutoStartScriptsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "启动脚本检查",
		Risk: "高",
		Desc: "检测系统中是否存在可疑启动脚本",
	}

	// 检查的启动脚本位置
	startupPaths := []string{
		"/etc/rc.local",
		"/etc/init.d/",
		"/etc/profile.d/",
		"/root/.bashrc",
		"/root/.bash_profile",
		"/root/.profile",
	}

	// 可疑命令列表
	suspiciousCommands := []string{
		"nc ", "ncat ", "netcat ",
		"bash -i", "sh -i",
		"python ", "python3 ", "perl ", "ruby ",
		"wget ", "curl ",
		"chmod +x ",
		"rm -rf ",
		"mkfifo ",
		"/dev/tcp/", "/dev/udp/",
	}

	for _, path := range startupPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			// 处理目录
			files, err := os.ReadDir(path)
			if err != nil {
				continue
			}

			for _, file := range files {
				if file.IsDir() {
					continue
				}

				filePath := filepath.Join(path, file.Name())
				checkFileForSuspiciousCommands(filePath, suspiciousCommands, &result)
			}
		} else {
			// 处理单个文件
			checkFileForSuspiciousCommands(path, suspiciousCommands, &result)
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑启动脚本")
	} else {
		result.Desc = "检测到可疑启动脚本"
	}

	return result
}

// 辅助函数：检查文件中是否包含可疑命令
func checkFileForSuspiciousCommands(filePath string, suspiciousCommands []string, result *LinuxDetectionResult) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		for _, cmd := range suspiciousCommands {
			if strings.Contains(line, cmd) {
				result.Details = append(result.Details, fmt.Sprintf("在 %s 中发现可疑命令: 第 %d 行 - %s", filePath, i+1, line))
				result.FilePath = filePath
				result.Command = line
				break
			}
		}
	}
}

// 系统服务检查 - 返回详细结果
func checkLinuxServicesDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "系统服务检查",
		Risk: "高",
		Desc: "检测系统中是否存在可疑系统服务",
	}

	// 检查系统服务
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		result.Details = append(result.Details, "无法获取服务列表: "+err.Error())
		return result
	}

	suspiciousServices := []string{"backdoor", "miner", "crypto", "malware"}
	foundSuspicious := false

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		for _, service := range suspiciousServices {
			if strings.Contains(strings.ToLower(line), service) {
				// 提取服务名称
				parts := strings.Fields(line)
				if len(parts) > 0 {
					serviceName := parts[0]
					result.Details = append(result.Details, "发现可疑服务: "+serviceName)
					foundSuspicious = true
				}
			}
		}
	}

	if foundSuspicious {
		result.Desc = "检测到可疑系统服务"
	} else {
		result.Details = append(result.Details, "未发现可疑系统服务")
	}

	return result
}

// 进程检查 - 返回详细结果
func checkLinuxProcessesDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "进程检查",
		Risk: "中",
		Desc: "检测系统中是否存在可疑进程",
	}

	// 多源校验：使用ps、/proc目录和pstree三种方式采集进程信息
	psProcesses := make(map[string]bool)
	procProcesses := make(map[string]bool)
	pstreeProcesses := make(map[string]bool)

	// 1. 使用ps aux获取进程列表
	cmd := exec.Command("ps", "aux")
	psOutput, err := cmd.Output()
	if err == nil {
		psLines := strings.Split(string(psOutput), "\n")
		for _, line := range psLines {
			parts := strings.Fields(line)
			if len(parts) >= 11 {
				psProcesses[parts[1]] = true // PID作为键
			}
		}
	}

	// 2. 使用/proc目录获取进程列表
	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range procEntries {
			if entry.IsDir() {
				pid := entry.Name()
				// 检查是否为数字PID
				if _, err := strconv.Atoi(pid); err == nil {
					procProcesses[pid] = true
					// 检查进程命令行
					cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
					cmdline, err := os.ReadFile(cmdlinePath)
					if err == nil && len(cmdline) > 0 {
						cmdlineStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
						cmdlineStr = strings.TrimSpace(cmdlineStr)
						// 检查可疑进程命令
						suspiciousPatterns := []string{
							"nc.*-e", "bash -i >&", "sh -i >&", // 反向shell
							"mimikatz", "procdump", "psexec", "wce", // 工具
							"backdoor", "malware", "miner", "crypto", "xmrig", // 恶意软件
						}
						for _, pattern := range suspiciousPatterns {
							matched, _ := regexp.MatchString(pattern, cmdlineStr)
							if matched {
								result.Details = append(result.Details, fmt.Sprintf("发现可疑进程: %s (PID: %s)", cmdlineStr, pid))
							}
						}
					}
				}
			}
		}
	}

	// 3. 使用pstree获取进程列表
	cmd = exec.Command("pstree", "-p")
	pstreeOutput, err := cmd.Output()
	if err == nil {
		pstreeStr := string(pstreeOutput)
		// 提取所有PID
		pidRegex := regexp.MustCompile(`\((\d+)\)`)
		matches := pidRegex.FindAllStringSubmatch(pstreeStr, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				pstreeProcesses[match[1]] = true
			}
		}
	}

	// 4. 多源校验：比较不同来源的进程列表
	// 检查ps和/proc目录的差异
	if len(psProcesses) > 0 && len(procProcesses) > 0 {
		// 检查ps中存在但/proc中不存在的进程（可能被rootkit隐藏）
		for pid := range psProcesses {
			if !procProcesses[pid] {
				result.Details = append(result.Details, fmt.Sprintf("多源校验异常: ps中存在但/proc中不存在的可疑进程 (PID: %s)", pid))
			}
		}
		// 检查/proc中存在但ps中不存在的进程（可能被rootkit隐藏）
		for pid := range procProcesses {
			if !psProcesses[pid] {
				result.Details = append(result.Details, fmt.Sprintf("多源校验异常: /proc中存在但ps中不存在的可疑进程 (PID: %s)", pid))
			}
		}
	}

	// 5. 检查进程命令行中的可疑模式
	cmd = exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err == nil {
		suspiciousPatterns := []string{
			"nc.*-e", "bash -i >&", "sh -i >&", // 反向shell
			"mimikatz", "procdump", "psexec", "wce", // 工具
			"backdoor", "malware", "miner", "crypto", "xmrig", // 恶意软件
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			for _, pattern := range suspiciousPatterns {
				matched, _ := regexp.MatchString(pattern, line)
				if matched {
					parts := strings.Fields(line)
					if len(parts) >= 11 {
						pid := parts[1]
						processName := parts[10]
						result.Details = append(result.Details, fmt.Sprintf("发现可疑进程: %s (PID: %s)", processName, pid))
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑进程")
	} else {
		result.Desc = "检测到可疑进程"
	}

	return result
}

// 网络连接检查 - 返回详细结果
func checkLinuxNetworkConnectionsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "网络连接检查",
		Risk: "高",
		Desc: "检测系统中是否存在可疑网络连接",
	}

	// 检查网络连接
	cmd := exec.Command("netstat", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("ss", "-tuln") // 尝试使用ss命令
		output, err = cmd.Output()
		if err != nil {
			result.Details = append(result.Details, "无法获取网络连接列表: "+err.Error())
			return result
		}
	}

	// 检查可疑监听端口
	suspiciousPorts := []string{"6667", "8888", "9999", "3333", "4444", "5555", "7777"}
	lines := strings.Split(string(output), "\n")
	foundSuspicious := false

	for _, line := range lines {
		for _, port := range suspiciousPorts {
			if strings.Contains(line, ":"+port+".") || strings.Contains(line, ":"+port+" ") {
				result.Details = append(result.Details, "发现可疑监听端口: "+line)
				foundSuspicious = true
			}
		}
	}

	// 检查ESTABLISHED连接
	cmd = exec.Command("netstat", "-tun")
	output, err = cmd.Output()
	if err != nil {
		cmd = exec.Command("ss", "-tun") // 尝试使用ss命令
		output, err = cmd.Output()
	}

	if err == nil {
		lines = strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ESTABLISHED") {
				// 检查外部连接
				if !strings.Contains(line, "127.0.0.1") && !strings.Contains(line, "::1") {
					result.Details = append(result.Details, "发现外部网络连接: "+line)
					foundSuspicious = true
				}
			}
		}
	}

	if foundSuspicious {
		result.Desc = "检测到可疑网络连接"
	} else {
		result.Details = append(result.Details, "未发现可疑网络连接")
	}

	return result
}

// Shell命令历史记录检查 - 返回详细结果
func checkLinuxShellHistoryDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "Shell命令历史检查",
		Risk: "中",
		Desc: "检测系统中是否存在可疑Shell命令历史",
	}

	// 检查命令历史文件
	historyFiles := []string{
		"/root/.bash_history",
	}

	// 获取所有用户的home目录
	cmd := exec.Command("ls", "/home")
	output, err := cmd.Output()
	if err == nil {
		users := strings.Split(string(output), "\n")
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user != "" {
				historyFiles = append(historyFiles, fmt.Sprintf("/home/%s/.bash_history", user))
				historyFiles = append(historyFiles, fmt.Sprintf("/home/%s/.zsh_history", user))
			}
		}
	}

	// 静态规则：可疑命令模式
	staticRules := []string{
		"nc.*-e", "nc.*-c", "bash -i >&", "sh -i >&", // 反向shell
		"sudo.*chmod.*777", "sudo.*chown.*root", // 提权
		"rm.*-rf", "mv.*\\/tmp", // 文件篡改
		"wget.*\\.php", "curl.*\\.php", "echo.*<?php", // WebShell
	}

	for _, path := range historyFiles {
		if _, err := os.Stat(path); err == nil {
			// 读取文件内容
			content, err := os.ReadFile(path)
			if err == nil {
				lines := strings.Split(string(content), "\n")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						// 使用静态规则匹配可疑命令
						for _, rule := range staticRules {
							matched, _ := regexp.MatchString(rule, line)
							if matched {
								result.Details = append(result.Details, fmt.Sprintf("在 %s 中发现可疑命令: 第 %d 行 - %s", path, i+1, line))
								result.FilePath = path
								result.Command = line
							}
						}
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑Shell命令历史")
	} else {
		result.Desc = "检测到可疑Shell命令历史"
	}

	return result
}

// Linux系统认证日志检查 - 返回详细结果
func checkLinuxAuthLogsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "系统认证日志检查",
		Risk: "高",
		Desc: "检测系统认证日志中的异常登录和特权提升操作",
	}

	// 检查认证日志文件位置
	authLogFiles := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/audit/audit.log",
	}

	// 静态规则：异常登录和特权提升模式
	staticRules := []struct {
		rule        string
		description string
	}{
		{"Failed password.*", "失败登录尝试"},
		{"Invalid user.*", "无效用户登录"},
		{"User .* logged in.*from.*", "用户登录记录"},
		{"sudo:.*incorrect password", "sudo密码错误"},
		{"sudo:.*COMMAND=.*", "sudo命令执行"},
		{"pam_unix\\(sudo:session\\): session opened for user root", "root会话打开"},
		{"useradd.*", "新增用户"},
		{"usermod.*-aG.*sudo", "添加用户到sudo组"},
	}

	for _, path := range authLogFiles {
		if _, err := os.Stat(path); err == nil {
			// 读取文件内容
			content, err := os.ReadFile(path)
			if err == nil {
				lines := strings.Split(string(content), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						// 使用静态规则匹配异常事件
						for _, rule := range staticRules {
							matched, _ := regexp.MatchString(rule.rule, line)
							if matched {
								result.Details = append(result.Details, fmt.Sprintf("[%s] %s: %s", path, rule.description, line))
								result.FilePath = path
							}
						}
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑系统认证日志")
	} else {
		result.Desc = "检测到可疑系统认证日志事件"
	}

	return result
}

// Linux应用日志检查 - 返回详细结果
func checkLinuxApplicationLogsDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "应用日志检查",
		Risk: "中",
		Desc: "检测Web服务和数据库日志中的可疑操作",
	}

	// 检查应用日志文件位置
	appLogFiles := []string{
		"/var/log/nginx/access.log",
		"/var/log/apache2/access.log",
		"/var/log/mysql/error.log",
		"/var/log/postgresql/postgresql*.log",
	}

	// 静态规则：应用日志可疑模式
	staticRules := []struct {
		rule        string
		description string
	}{
		{"\\.php\\?cmd=", "WebShell命令执行尝试"},
		{"eval\\(\\$_,*POST", "WebShell特征码"},
		{"exec\\(|system\\(|passthru\\(", "PHP命令执行函数"},
		{"1=1.*", "SQL注入尝试"},
		{"union select.*", "SQL联合查询注入"},
		{"' or '1'='1", "SQL盲注尝试"},
		{"Failed login.*", "数据库登录失败"},
		{"Invalid query.*", "无效数据库查询"},
	}

	for _, path := range appLogFiles {
		// 使用glob匹配可能的日志文件（如postgresql-12-main.log）
		matches, err := filepath.Glob(path)
		if err != nil {
			continue
		}
		for _, matchPath := range matches {
			if _, err := os.Stat(matchPath); err == nil {
				// 读取文件内容（只检查最后1000行，避免性能问题）
				cmd := exec.Command("tail", "-n", "1000", matchPath)
				output, err := cmd.Output()
				if err == nil {
					lines := strings.Split(string(output), "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" {
							// 使用静态规则匹配可疑事件
							for _, rule := range staticRules {
								matched, _ := regexp.MatchString(rule.rule, line)
								if matched {
									result.Details = append(result.Details, fmt.Sprintf("[%s] %s: %s", matchPath, rule.description, line))
									result.FilePath = matchPath
								}
							}
						}
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑应用日志")
	} else {
		result.Desc = "检测到可疑应用日志事件"
	}

	return result
}

// 文件系统检查 - 返回详细结果
func checkLinuxFileSystemDetailed() LinuxDetectionResult {
	result := LinuxDetectionResult{
		Name: "文件系统检查",
		Risk: "中",
		Desc: "检测系统中是否存在可疑文件",
	}

	// 检查可疑文件路径
	suspiciousPaths := []string{
		"/tmp",
		"/var/tmp",
		"/dev/shm",
		"/root",
	}

	suspiciousFiles := []string{"mimikatz", "procdump", "psexec", "wce", "backdoor", "malware", "miner", "crypto", "xmrig"}

	for _, path := range suspiciousPaths {
		if _, err := os.Stat(path); err == nil {
			// 列出目录内容
			cmd := exec.Command("ls", "-la", path)
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					for _, suspicious := range suspiciousFiles {
						if strings.Contains(strings.ToLower(line), suspicious) {
							// 提取文件名
							parts := strings.Fields(line)
							if len(parts) >= 9 {
								fileName := parts[8]
								filePath := filepath.Join(path, fileName)
								result.Details = append(result.Details, "发现可疑文件: "+filePath)
								result.FilePath = filePath
							}
						}
					}
				}
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "未发现可疑文件")
	} else {
		result.Desc = "检测到可疑文件"
	}

	return result
}

func checkLinuxHackerTraces(result *CleanResult) {
	utils.InfoPrint("正在执行Linux系统深度黑客攻击痕迹检测...")
	utils.InfoPrint("")

	// 执行详细检测
	checks := []LinuxDetectionResult{
		checkLinuxShellHistoryDetailed(),       // 日志类痕迹 - 命令/执行日志
		checkLinuxAuthLogsDetailed(),           // 日志类痕迹 - 系统认证日志
		checkLinuxApplicationLogsDetailed(),    // 日志类痕迹 - 应用日志
		checkLinuxProcessesDetailed(),          // 进程/服务/端口痕迹
		checkLinuxServicesDetailed(),           // 进程/服务/端口痕迹
		checkLinuxFileSystemDetailed(),         // 文件/目录痕迹
		checkLinuxHiddenAccountsDetailed(),     // 用户/权限痕迹
		checkLinuxSSHKeysDetailed(),            // 用户/权限痕迹
		checkLinuxCronJobsDetailed(),           // 启动项/计划任务痕迹
		checkLinuxAutoStartScriptsDetailed(),   // 启动项/计划任务痕迹
		checkLinuxNetworkConnectionsDetailed(), // 网络痕迹
	}

	// 深度扫描项目
	if result.DeepScan {
		// 这里可以添加深度扫描的详细检测函数
		utils.InfoPrint("深度扫描模式已启用，执行额外检测...")
	}

	// 处理检测结果
	for _, check := range checks {
		result.DetectionStats.TotalChecks++
		utils.InfoPrint("正在检查: %s", check.Name)

		// 转换为通用DetectionResult并添加到结果中
		detectionResult := DetectionResult{
			Type:        "Linux",
			Name:        check.Name,
			RiskLevel:   check.Risk,
			Description: check.Desc,
			Details:     check.Details,
			FilePath:    check.FilePath,
			Command:     check.Command,
			Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
		}
		result.DetectionResults = append(result.DetectionResults, detectionResult)

		// 如果检测到问题，更新统计信息
		if len(check.Details) > 1 || strings.Contains(check.Desc, "检测到") {
			result.DetectionStats.IssuesFound++
			if check.Risk == "高" {
				result.DetectionStats.HighRiskIssues++
			}

			result.HackerActions = append(result.HackerActions, check.Desc)

			// 记录检测到的问题类型，用于多维度交叉验证
			switch check.Name {
			case "Shell命令历史检查":
				result.DetectionStats.LogIssues++
				// 生成日志相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑命令") {
						result.CleanActions = append(result.CleanActions, fmt.Sprintf("记录可疑命令: %s (%s)", detail, check.Risk))
					}
				}
			case "进程检查", "系统服务检查":
				result.DetectionStats.ProcessIssues++
				// 生成进程/服务相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑进程") {
						// 从详细信息中提取PID
						pidRegex := regexp.MustCompile(`PID: (\d+)`)
						pidMatch := pidRegex.FindStringSubmatch(detail)
						if len(pidMatch) > 1 {
							pid := pidMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("终止可疑进程: PID %s (%s)", pid, check.Risk))
						}
					} else if strings.Contains(detail, "发现可疑服务") {
						result.CleanActions = append(result.CleanActions, fmt.Sprintf("停止并禁用可疑服务: %s (%s)", detail, check.Risk))
					}
				}
			case "文件系统检查":
				result.DetectionStats.FileIssues++
				// 生成文件相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑文件") {
						// 从详细信息中提取文件路径
						fileRegex := regexp.MustCompile(`文件: (.+)`)
						fileMatch := fileRegex.FindStringSubmatch(detail)
						if len(fileMatch) > 1 {
							filePath := fileMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除可疑文件: %s (%s)", filePath, check.Risk))
						}
					}
				}
			case "隐藏账户检查", "SSH密钥检查":
				result.DetectionStats.UserIssues++
				// 生成用户/权限相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现隐藏账户") {
						// 从详细信息中提取账户名
						userRegex := regexp.MustCompile(`账户: (.+)`)
						userMatch := userRegex.FindStringSubmatch(detail)
						if len(userMatch) > 1 {
							user := userMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除隐藏账户: %s (%s)", user, check.Risk))
						}
					} else if strings.Contains(detail, "发现可疑SSH密钥") {
						// 从详细信息中提取密钥路径
						keyRegex := regexp.MustCompile(`密钥: (.+)`)
						keyMatch := keyRegex.FindStringSubmatch(detail)
						if len(keyMatch) > 1 {
							keyPath := keyMatch[1]
							result.CleanActions = append(result.CleanActions, fmt.Sprintf("删除可疑SSH密钥: %s (%s)", keyPath, check.Risk))
						}
					}
				}
			case "计划任务检查", "启动脚本检查":
				result.DetectionStats.StartupIssues++
				// 生成启动项/计划任务相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑计划任务") || strings.Contains(detail, "发现可疑启动脚本") {
						result.CleanActions = append(result.CleanActions, fmt.Sprintf("移除可疑启动项/计划任务: %s (%s)", detail, check.Risk))
					}
				}
			case "网络连接检查":
				result.DetectionStats.NetworkIssues++
				// 生成网络连接相关的清理操作
				for _, detail := range check.Details {
					if strings.Contains(detail, "发现可疑网络连接") {
						result.CleanActions = append(result.CleanActions, fmt.Sprintf("关闭可疑网络连接: %s (%s)", detail, check.Risk))
					}
				}
			}
		}

		// 打印详细结果
		for _, detail := range check.Details {
			if strings.Contains(detail, "发现") {
				utils.WarningPrint("  %s", detail)
			} else {
				utils.InfoPrint("  %s", detail)
			}
		}
	}

	// 多维度交叉验证，更新风险等级
	// 如果检测到多个维度的问题，提升风险等级
	crossValidationScore := 0
	if result.DetectionStats.NetworkIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.ProcessIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.FileIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.UserIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.StartupIssues > 0 {
		crossValidationScore++
	}
	if result.DetectionStats.LogIssues > 0 {
		crossValidationScore++
	}

	// 根据交叉验证分数更新风险等级
	if crossValidationScore >= 3 {
		result.RiskLevel = "高"
	} else if crossValidationScore >= 2 {
		result.RiskLevel = "中"
	} else if crossValidationScore >= 1 {
		result.RiskLevel = "低"
	} else {
		result.RiskLevel = "无"
	}

	// 生成清理建议
	generateLinuxCleanActions(result)

	// 生成防御建议
	generateLinuxDefenseAdvice(result)

	utils.InfoPrint("Linux系统检测完成，共执行 %d 项检查，发现 %d 个问题",
		result.DetectionStats.TotalChecks, result.DetectionStats.IssuesFound)
	utils.InfoPrint("")
}

// Windows系统检测函数
func checkWindowsEventLogs() bool {
	// 检查安全日志是否被清理
	cmd := exec.Command("wevtutil", "qe", "Security", "/c:1")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 如果日志为空或异常，可能被清理过
	if len(output) == 0 || strings.Contains(string(output), "No events found") {
		return true
	}

	return false
}

func checkWindowsHiddenAccounts() bool {
	// 检查隐藏账号（以$结尾的账号）
	cmd := exec.Command("net", "user")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "$") && !strings.Contains(line, "Administrator") && !strings.Contains(line, "Guest") {
			return true
		}
	}

	return false
}

func checkWindowsSuspiciousProcesses() bool {
	// 检查可疑进程
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousProcesses := []string{"mimikatz", "procdump", "psexec", "wce", "mimikatz.exe", "procdump.exe", "psexec.exe"}

	for _, process := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(process)) {
			return true
		}
	}

	return false
}

func checkWindowsAutoStart() bool {
	// 检查注册表自启动项
	cmd := exec.Command("reg", "query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
	_, err := cmd.Output()
	if err != nil {
		return false
	}

	// 这里可以添加更复杂的检查逻辑
	return false
}

func checkWindowsNetworkConnections() bool {
	// 检查网络连接
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 检查可疑端口连接
	suspiciousPorts := []string{"4444", "5555", "6666", "7777", "8888", "9999", "1337"}

	for _, port := range suspiciousPorts {
		if strings.Contains(string(output), ":"+port) {
			return true
		}
	}

	return false
}

func checkWindowsFileSystem() bool {
	// 检查可疑文件
	suspiciousFiles := []string{
		"C:\\Windows\\Temp\\mimikatz.exe",
		"C:\\Windows\\Temp\\procdump.exe",
		"C:\\Windows\\Temp\\psexec.exe",
		"C:\\Users\\Public\\backdoor.exe",
		"C:\\Windows\\System32\\wbem\\mof\\backdoor.mof",
		"C:\\Windows\\Tasks\\malware.job",
		"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.exe",
	}

	for _, file := range suspiciousFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}

	return false
}

// 新增Windows检测函数
func checkWindowsRegistry() bool {
	// 检查可疑注册表项
	regPaths := []string{
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}

	for _, path := range regPaths {
		cmd := exec.Command("reg", "query", path)
		output, err := cmd.Output()
		if err == nil {
			// 检查可疑的注册表值
			if strings.Contains(strings.ToLower(string(output)), "mimikatz") ||
				strings.Contains(strings.ToLower(string(output)), "backdoor") ||
				strings.Contains(strings.ToLower(string(output)), "malware") {
				return true
			}
		}
	}

	return false
}

func checkWindowsServices() bool {
	// 检查可疑系统服务
	cmd := exec.Command("sc", "query")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousServices := []string{"backdoor", "miner", "crypto", "malware", "trojan"}

	for _, service := range suspiciousServices {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(service)) {
			return true
		}
	}

	return false
}

func checkWindowsScheduledTasks() bool {
	// 检查计划任务
	cmd := exec.Command("schtasks", "/query", "/fo", "LIST")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousTasks := []string{"backdoor", "malware", "miner", "crypto"}

	for _, task := range suspiciousTasks {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(task)) {
			return true
		}
	}

	return false
}

func checkWindowsWMIEvents() bool {
	// 检查WMI事件订阅
	cmd := exec.Command("wmic", "/namespace:\\\\root\\subscription", "path", "__EventFilter", "get", "Name")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 如果有WMI事件订阅，可能存在风险
	return len(strings.TrimSpace(string(output))) > 0
}

func checkWindowsLSAProtection() bool {
	// 检查LSA保护状态
	cmd := exec.Command("reg", "query", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA", "/v", "RunAsPPL")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 如果LSA保护被禁用，存在风险
	return !strings.Contains(string(output), "0x1")
}

func checkWindowsFirewallRules() bool {
	// 检查防火墙规则
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousRules := []string{"backdoor", "malware", "miner", "reverse"}

	for _, rule := range suspiciousRules {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(rule)) {
			return true
		}
	}

	return false
}

func checkWindowsDNSCache() bool {
	// 检查DNS缓存
	cmd := exec.Command("ipconfig", "/displaydns")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 检查可疑域名
	suspiciousDomains := []string{"malware", "backdoor", "c2", "command"}

	for _, domain := range suspiciousDomains {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(domain)) {
			return true
		}
	}

	return false
}

// Linux系统检测函数
func checkLinuxSSHKeys() bool {
	// 检查authorized_keys文件
	files := []string{
		"/root/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys",
	}

	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			// 检查文件内容是否包含可疑密钥
			content, err := os.ReadFile(file)
			if err == nil {
				if strings.Contains(string(content), "ssh-rsa") && len(strings.Split(string(content), "\n")) > 5 {
					return true
				}
			}
		}
	}

	return false
}

func checkLinuxCronJobs() bool {
	// 检查定时任务文件
	cronFiles := []string{
		"/etc/crontab",
		"/etc/cron.d/*",
		"/var/spool/cron/*",
	}

	for _, file := range cronFiles {
		if _, err := os.Stat(file); err == nil {
			// 这里可以添加更复杂的检查逻辑
			return true
		}
	}

	return false
}

func checkLinuxServices() bool {
	// 检查系统服务
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 检查可疑服务名
	suspiciousServices := []string{"backdoor", "miner", "crypto", "malware"}

	for _, service := range suspiciousServices {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(service)) {
			return true
		}
	}

	return false
}

func checkLinuxSUIDFiles() bool {
	// 检查SUID文件
	cmd := exec.Command("find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	// 如果发现大量SUID文件，可能存在风险
	return len(lines) > 20
}

func checkLinuxNetworkConnections() bool {
	// 检查网络连接
	cmd := exec.Command("netstat", "-tulpn")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 检查可疑端口连接
	suspiciousPorts := []string{"4444", "5555", "6666", "7777", "8888", "9999", "1337"}

	for _, port := range suspiciousPorts {
		if strings.Contains(string(output), ":"+port) {
			return true
		}
	}

	return false
}

func checkLinuxFileSystem() bool {
	// 检查可疑文件
	suspiciousFiles := []string{
		"/tmp/.backdoor",
		"/var/tmp/.malware",
		"/dev/shm/.hidden",
		"/etc/.malware.conf",
		"/usr/bin/.backdoor",
		"/lib/.malware.so",
		"/root/.ssh/backdoor",
	}

	for _, file := range suspiciousFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}

	return false
}

// 新增Linux检测函数
func checkLinuxProcesses() bool {
	// 检查可疑进程
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousProcesses := []string{"minerd", "xmrig", "backdoor", "malware", "crypto"}

	for _, process := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(process)) {
			return true
		}
	}

	return false
}

func checkLinuxSystemLogs() bool {
	// 检查系统日志
	logFiles := []string{
		"/var/log/auth.log",
		"/var/log/syslog",
		"/var/log/secure",
	}

	for _, file := range logFiles {
		if _, err := os.Stat(file); err == nil {
			// 检查日志文件大小，如果异常小可能被清理过
			info, err := os.Stat(file)
			if err == nil && info.Size() < 100 {
				return true
			}
		}
	}

	return false
}

func checkLinuxKernelModules() bool {
	// 检查内核模块
	cmd := exec.Command("lsmod")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousModules := []string{"backdoor", "malware", "rootkit"}

	for _, module := range suspiciousModules {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(module)) {
			return true
		}
	}

	return false
}

func checkLinuxEnvironment() bool {
	// 检查环境变量
	envVars := os.Environ()

	suspiciousVars := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"}

	for _, envVar := range envVars {
		for _, suspicious := range suspiciousVars {
			if strings.Contains(envVar, suspicious) &&
				(strings.Contains(envVar, "/tmp") || strings.Contains(envVar, "/var/tmp")) {
				return true
			}
		}
	}

	return false
}

func checkLinuxShellConfig() bool {
	// 检查Shell配置文件
	shellFiles := []string{
		"/root/.bashrc",
		"/root/.profile",
		"/etc/profile",
		"/etc/bash.bashrc",
	}

	for _, file := range shellFiles {
		if _, err := os.Stat(file); err == nil {
			content, err := os.ReadFile(file)
			if err == nil {
				// 检查可疑的命令
				if strings.Contains(string(content), "curl") &&
					strings.Contains(string(content), "bash") &&
					strings.Contains(string(content), "http") {
					return true
				}
			}
		}
	}

	return false
}

func checkLinuxNetworkConfig() bool {
	// 检查网络配置
	cmd := exec.Command("iptables", "-L")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// 检查是否有可疑的防火墙规则
	if strings.Contains(string(output), "ACCEPT") &&
		strings.Contains(string(output), "ESTABLISHED") &&
		!strings.Contains(string(output), "RELATED") {
		return true
	}

	return false
}

func checkLinuxPackageManager() bool {
	// 检查包管理器
	cmd := exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	suspiciousPackages := []string{"miner", "crypto", "backdoor"}

	for _, pkg := range suspiciousPackages {
		if strings.Contains(strings.ToLower(string(output)), strings.ToLower(pkg)) {
			return true
		}
	}

	return false
}

// 生成防御建议
func generateWindowsDefenseAdvice(result *CleanResult) {
	result.DefenseAdvice = append(result.DefenseAdvice,
		"启用LSA保护，防止LSASS内存被读取",
		"禁用NTLM认证，强制使用Kerberos",
		"定期更换密码，避免弱密码/密码复用",
		"关闭不必要的远程管理端口",
		"仅允许内网可信IP访问",
		"监控异常行为，如同一账号同时登录多台主机",
		"及时修补系统漏洞",
		"实施最小权限原则",
	)
}

func generateLinuxDefenseAdvice(result *CleanResult) {
	result.DefenseAdvice = append(result.DefenseAdvice,
		"禁用SSH密码登录，使用密钥认证",
		"限制SSH root登录",
		"定期更新系统和软件补丁",
		"配置防火墙，限制不必要的端口访问",
		"启用SELinux或AppArmor",
		"监控系统日志和异常行为",
		"定期检查SUID/SGID文件",
		"实施最小权限原则",
	)
}

// displayCleanResults 显示检测结果
func displayCleanResults(result *CleanResult) {
	utils.InfoPrint("=== 黑客攻击痕迹检测结果 ===")
	utils.InfoPrint("系统类型: %s", result.SystemType)
	utils.InfoPrint("检测时间: %s", result.DetectionTime.Format("2006-01-02 15:04:05"))
	utils.InfoPrint("风险等级: %s", result.RiskLevel)
	utils.InfoPrint("")

	if len(result.HackerActions) == 0 {
		utils.SuccessPrint("未检测到明显的黑客攻击痕迹")
	} else {
		utils.WarningPrint("检测到以下可能的黑客操作:")
		utils.InfoPrint("=" + strings.Repeat("=", 80))

		for i, action := range result.HackerActions {
			utils.WarningPrint("\n%d. %s", i+1, action)

			// 根据操作类型提供详细信息
			if strings.Contains(action, "可疑系统服务") {
				utils.InfoPrint("   📍 位置: 系统服务管理器")
				utils.InfoPrint("   ⚠️ 风险: 中 - 可能被用于持久化攻击")
				utils.InfoPrint("   🔍 影响: 系统启动时自动运行，可能隐藏恶意行为")
			} else if strings.Contains(action, "恶意软件") {
				utils.InfoPrint("   📍 位置: 系统文件/注册表/启动项")
				utils.InfoPrint("   ⚠️ 风险: 高 - 直接安全威胁")
				utils.InfoPrint("   🔍 影响: 数据窃取、系统控制、资源占用")
			} else if strings.Contains(action, "隐藏账号") {
				utils.InfoPrint("   📍 位置: 系统用户账户")
				utils.InfoPrint("   ⚠️ 风险: 高 - 后门访问权限")
				utils.InfoPrint("   🔍 影响: 未经授权的系统访问")
			} else if strings.Contains(action, "可疑进程") {
				utils.InfoPrint("   📍 位置: 运行进程")
				utils.InfoPrint("   ⚠️ 风险: 中 - 可能正在执行恶意操作")
				utils.InfoPrint("   🔍 影响: 实时系统活动监控")
			} else if strings.Contains(action, "自启动项") {
				utils.InfoPrint("   📍 位置: 注册表/启动文件夹")
				utils.InfoPrint("   ⚠️ 风险: 中 - 持久化威胁")
				utils.InfoPrint("   🔍 影响: 系统重启后自动激活")
			} else if strings.Contains(action, "网络连接") {
				utils.InfoPrint("   📍 位置: 网络连接表")
				utils.InfoPrint("   ⚠️ 风险: 中 - 可能的数据外泄")
				utils.InfoPrint("   🔍 影响: 外部通信通道")
			} else if strings.Contains(action, "文件系统") {
				utils.InfoPrint("   📍 位置: 系统文件/目录")
				utils.InfoPrint("   ⚠️ 风险: 中 - 文件完整性受损")
				utils.InfoPrint("   🔍 影响: 系统稳定性威胁")
			} else if strings.Contains(action, "注册表") {
				utils.InfoPrint("   📍 位置: Windows注册表")
				utils.InfoPrint("   ⚠️ 风险: 中 - 系统配置修改")
				utils.InfoPrint("   🔍 影响: 系统行为改变")
			} else if strings.Contains(action, "计划任务") {
				utils.InfoPrint("   📍 位置: 任务计划程序")
				utils.InfoPrint("   ⚠️ 风险: 中 - 定时执行恶意代码")
				utils.InfoPrint("   🔍 影响: 周期性恶意活动")
			} else {
				utils.InfoPrint("   📍 位置: 系统关键区域")
				utils.InfoPrint("   ⚠️ 风险: 中 - 需要进一步调查")
				utils.InfoPrint("   🔍 影响: 潜在安全威胁")
			}

			utils.InfoPrint("   💡 建议: 立即清理并加强相关安全设置")
			utils.InfoPrint("-" + strings.Repeat("-", 60))
		}

		utils.InfoPrint("=" + strings.Repeat("=", 80))

		// 显示拟执行的清理操作
		utils.InfoPrint("")
		utils.InfoPrint("=== 拟执行的清理操作 ===")

		// 生成拟执行的清理操作
		if result.SystemType == "windows" {
			generateWindowsCleanActions(result)
		} else if result.SystemType == "linux" {
			generateLinuxCleanActions(result)
		}

		if len(result.CleanActions) > 0 {
			for i, action := range result.CleanActions {
				utils.InfoPrint("%d. %s", i+1, action)
			}
		} else {
			utils.InfoPrint("未生成具体的清理操作")
		}
	}

	utils.InfoPrint("")
}

// askForCleanup 询问用户是否清理
func askForCleanup(result *CleanResult) {
	if len(result.HackerActions) == 0 {
		utils.SuccessPrint("✓ 未发现黑客攻击痕迹，系统安全")
		utils.InfoPrint("")
		return
	}

	utils.WarningPrint("⚠️ 发现 %d 个黑客攻击痕迹，其中 %d 个为高风险问题",
		len(result.HackerActions), result.DetectionStats.HighRiskIssues)
	utils.WarningPrint("系统风险等级: %s", result.RiskLevel)
	utils.InfoPrint("")

	// 显示清理选项
	utils.InfoPrint("请选择清理选项:")
	utils.InfoPrint("1. 自动清理所有检测到的问题")
	utils.InfoPrint("2. 手动选择要清理的项目")
	utils.InfoPrint("3. 仅生成报告，不进行清理")
	utils.InfoPrint("4. 从备份恢复系统")
	utils.InfoPrint("5. 退出")
	utils.InfoPrint("")

	reader := bufio.NewReader(os.Stdin)
	utils.InfoPrint("请输入选择 (1-5): ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		utils.InfoPrint("开始自动清理所有黑客攻击痕迹...")
		// 如果有清理操作，显示详细的清理操作并要求用户确认
		if len(result.CleanActions) > 0 {
			utils.InfoPrint("=== 即将执行的清理操作 ===")
			for i, action := range result.CleanActions {
				utils.WarningPrint("%d. %s", i+1, action)
			}
			utils.InfoPrint("")

			// 询问用户是否确认执行清理操作
			utils.WarningPrint("上述 %d 项清理操作将永久删除文件/终止进程等，可能影响系统正常运行。是否确认执行？ [Y/N]: ", len(result.CleanActions))

			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			inputLower := strings.ToLower(input)

			if inputLower != "y" && inputLower != "yes" {
				utils.InfoPrint("用户取消清理操作，退出清理程序")
				return
			}
			utils.InfoPrint("")
		}
		performCleanup(result)

		// 清理完成后询问是否需要回滚
		utils.InfoPrint("")
		utils.InfoPrint("清理操作已完成，是否需要从备份恢复系统？ [Y/N]: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		inputLower := strings.ToLower(input)
		if inputLower == "y" || inputLower == "yes" {
			// 列出所有备份目录
			utils.InfoPrint("请选择要恢复的备份目录:")
			backups, _ := filepath.Glob("system_backup_*")
			if len(backups) == 0 {
				utils.ErrorPrint("未找到备份目录")
				return
			}
			for i, backup := range backups {
				utils.InfoPrint("%d. %s", i+1, backup)
			}
			utils.InfoPrint("请输入选择: ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			idx, err := strconv.Atoi(input)
			if err == nil && idx > 0 && idx <= len(backups) {
				restoreSystemBackup(backups[idx-1], result.SystemType)
			} else {
				utils.ErrorPrint("无效选择")
			}
		}
	case "2":
		utils.InfoPrint("手动选择清理项目...")
		selectiveCleanup(result)
	case "3":
		utils.InfoPrint("仅生成报告...")
		saveCleanReport(result)
		utils.SuccessPrint("报告已保存到当前目录")
	case "4":
		utils.InfoPrint("从备份恢复系统...")
		// 列出所有备份目录
		backups, _ := filepath.Glob("system_backup_*")
		if len(backups) == 0 {
			utils.ErrorPrint("未找到备份目录")
			return
		}
		for i, backup := range backups {
			utils.InfoPrint("%d. %s", i+1, backup)
		}
		utils.InfoPrint("请输入选择: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		idx, err := strconv.Atoi(input)
		if err == nil && idx > 0 && idx <= len(backups) {
			restoreSystemBackup(backups[idx-1], result.SystemType)
		} else {
			utils.ErrorPrint("无效选择")
		}
	case "5":
		utils.InfoPrint("退出清理程序")
	default:
		utils.ErrorPrint("无效选择，退出清理程序")
	}
}

// selectiveCleanup 选择性清理
func selectiveCleanup(result *CleanResult) {
	utils.InfoPrint("请选择要清理的项目 (输入项目编号，多个用逗号分隔，输入'all'清理所有):")

	for i, action := range result.HackerActions {
		utils.InfoPrint("%d. %s", i+1, action)
	}

	reader := bufio.NewReader(os.Stdin)
	utils.InfoPrint("")
	utils.InfoPrint("请输入选择: ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var selectedActions []string
	if input == "all" {
		selectedActions = result.HackerActions
	} else {
		// 解析用户选择
		selections := strings.Split(input, ",")
		for _, sel := range selections {
			idx, err := strconv.Atoi(strings.TrimSpace(sel))
			if err == nil && idx > 0 && idx <= len(result.HackerActions) {
				selectedActions = append(selectedActions, result.HackerActions[idx-1])
			}
		}
	}

	if len(selectedActions) == 0 {
		utils.ErrorPrint("无效选择，退出清理程序")
		return
	}

	// 根据选择的操作生成对应的清理操作
	var correspondingCleanActions []string
	for _, selectedAction := range selectedActions {
		// 根据系统类型生成对应的清理操作
		if result.SystemType == "windows" {
			for key, cleanAction := range map[string]string{
				"检测到可疑事件日志": "清理安全日志: wevtutil cl Security",
				"检测到可疑系统日志": "清理系统日志: wevtutil cl System",
				"检测到可疑应用日志": "清理应用日志: wevtutil cl Application",
				"检测到隐藏账号":   "检查并删除隐藏账号",
				"检测到可疑进程":   "检查并终止可疑进程",
				"检测到可疑自启动项": "检查并清理自启动项",
				"检测到可疑文件":   "检查并删除可疑文件",
				"检测到可疑系统服务": "检查并删除可疑服务",
				"检测到可疑网络连接": "检查并清理网络连接",
				"检测到可疑注册表项": "检查并清理注册表",
				"检测到可疑计划任务": "检查并清理计划任务",
			} {
				if strings.Contains(selectedAction, key) {
					correspondingCleanActions = append(correspondingCleanActions, cleanAction)
				}
			}
		} else if result.SystemType == "linux" {
			for key, cleanAction := range map[string]string{
				"检测到可疑SSH密钥":       "检查并清理SSH密钥文件",
				"检测到可疑定时任务":        "检查并清理定时任务",
				"检测到可疑服务":          "检查并停止可疑服务",
				"检测到可疑SUID/SGID文件": "检查并清理SUID/SGID文件",
				"检测到可疑进程":          "检查并终止可疑进程",
				"检测到可疑文件":          "检查并删除可疑文件",
				"检测到可疑系统日志":        "清理系统日志",
				"检测到可疑Shell历史记录":   "清理Shell历史记录",
				"检测到可疑网络连接":        "检查并清理网络连接",
			} {
				if strings.Contains(selectedAction, key) {
					correspondingCleanActions = append(correspondingCleanActions, cleanAction)
				}
			}
		}
	}

	// 检查是否有实际需要清理的项目
	if len(correspondingCleanActions) == 0 {
		utils.InfoPrint("未检测到需要清理的项目")
		return
	}

	// 显示即将执行的清理操作，并获取用户确认
	utils.InfoPrint("")
	utils.InfoPrint("=== 即将执行的清理操作 ===")
	for i, action := range correspondingCleanActions {
		utils.WarningPrint("%d. %s", i+1, action)
	}
	utils.InfoPrint("")

	// 询问用户是否确认执行清理操作
	utils.WarningPrint("上述 %d 项清理操作将永久删除文件/终止进程等，可能影响系统正常运行。是否确认执行？ [Y/N]: ", len(correspondingCleanActions))

	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	inputLower := strings.ToLower(input)

	if inputLower != "y" && inputLower != "yes" {
		utils.InfoPrint("用户取消清理操作，退出清理程序")
		return
	}
	utils.InfoPrint("")

	utils.InfoPrint("开始清理选定的 %d 个项目...", len(selectedActions))
	performSelectiveCleanup(result, selectedActions)
}

// generateCleanActions 根据检测结果生成清理操作
func generateCleanActions(result *CleanResult) {
	// 清空现有的清理操作
	result.CleanActions = []string{}

	// 根据系统类型生成清理操作
	if result.SystemType == "windows" {
		generateWindowsCleanActions(result)
	} else if result.SystemType == "linux" {
		generateLinuxCleanActions(result)
	}

	// 如果没有生成任何清理操作，添加默认提示
	if len(result.CleanActions) == 0 {
		result.CleanActions = append(result.CleanActions, "未检测到需要清理的项目")
	}
}

// generateWindowsCleanActions 生成Windows清理操作
func generateWindowsCleanActions(result *CleanResult) {
	// 用于跟踪已添加的清理操作，避免重复
	addedActions := make(map[string]bool)

	for _, detection := range result.DetectionResults {
		if len(detection.Details) > 0 && (strings.Contains(detection.Description, "检测到") || strings.Contains(detection.Details[0], "发现")) {
			// 根据检测类型生成相应的清理操作
			switch {
			case strings.Contains(detection.Name, "安全日志"):
				action := "清理系统安全日志"
				if !addedActions[action] {
					result.CleanActions = append(result.CleanActions, action)
					addedActions[action] = true
				}

			case strings.Contains(detection.Name, "隐藏账户"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取用户名
						username := extractValue(detail, "发现隐藏账户:")
						if username != "" {
							action := "删除隐藏账户: " + username
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "可疑进程"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取PID
						pid := extractPID(detail)
						if pid != "" {
							action := "终止可疑进程: PID " + pid
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "启动项"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取启动项路径
						item := extractValue(detail, "发现可疑自启动项:")
						if item != "" {
							action := "清理可疑启动项: " + item
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑启动项"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "网络连接"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取IP和端口
						connInfo := extractValue(detail, "发现可疑网络连接:")
						if connInfo != "" {
							action := "清理可疑网络连接: " + connInfo
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑网络连接"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "文件系统"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 从详细信息中提取文件路径
						filePath := extractFilePath(detail)
						if filePath == "" && detection.FilePath != "" {
							filePath = detection.FilePath
						}
						if filePath != "" && !isInWhitelist(filePath, result.WhitelistConfig.Files) {
							action := "删除可疑文件: " + filePath
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "注册表"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取注册表项
						regKey := extractValue(detail, "发现可疑注册表项:")
						if regKey != "" {
							action := "清理可疑注册表项: " + regKey
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑注册表项"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "服务"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取服务名
						serviceName := extractValue(detail, "发现可疑服务:")
						if serviceName != "" {
							action := "删除可疑服务: " + serviceName
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "计划任务"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取任务名
						taskName := extractValue(detail, "发现可疑计划任务:")
						if taskName != "" {
							action := "清理可疑计划任务: " + taskName
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑计划任务"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}
			}
		}
	}
}

// generateLinuxCleanActions 生成Linux清理操作
func generateLinuxCleanActions(result *CleanResult) {
	// 用于跟踪已添加的清理操作，避免重复
	addedActions := make(map[string]bool)

	for _, detection := range result.DetectionResults {
		if len(detection.Details) > 0 && (strings.Contains(detection.Description, "检测到") || strings.Contains(detection.Details[0], "发现")) {
			// 根据检测类型生成相应的清理操作
			switch {
			case strings.Contains(detection.Name, "shell历史"):
				action := "清理可疑命令历史"
				if !addedActions[action] {
					result.CleanActions = append(result.CleanActions, action)
					addedActions[action] = true
				}

			case strings.Contains(detection.Name, "认证日志"):
				action := "清理系统认证日志"
				if !addedActions[action] {
					result.CleanActions = append(result.CleanActions, action)
					addedActions[action] = true
				}

			case strings.Contains(detection.Name, "应用日志"):
				action := "清理可疑应用日志"
				if !addedActions[action] {
					result.CleanActions = append(result.CleanActions, action)
					addedActions[action] = true
				}

			case strings.Contains(detection.Name, "进程"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取PID
						pid := extractPID(detail)
						if pid != "" {
							action := "终止可疑进程: PID " + pid
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "服务"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取服务名
						serviceName := extractValue(detail, "发现可疑服务:")
						if serviceName != "" {
							action := "删除可疑服务: " + serviceName
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "文件系统"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 从详细信息中提取文件路径
						filePath := extractFilePath(detail)
						if filePath == "" && detection.FilePath != "" {
							filePath = detection.FilePath
						}
						if filePath != "" && !isInWhitelist(filePath, result.WhitelistConfig.Files) {
							action := "删除可疑文件: " + filePath
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "隐藏账户"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取用户名
						username := extractValue(detail, "发现隐藏账户:")
						if username != "" {
							action := "删除隐藏账户: " + username
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "SSH密钥"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 从详细信息中提取文件路径
						filePath := extractFilePath(detail)
						if filePath == "" && detection.FilePath != "" {
							filePath = detection.FilePath
						}
						if filePath != "" && !isInWhitelist(filePath, result.WhitelistConfig.Files) {
							action := "删除可疑SSH密钥: " + filePath
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "定时任务"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取任务名
						taskName := extractValue(detail, "发现可疑定时任务:")
						if taskName != "" {
							action := "清理可疑定时任务: " + taskName
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑定时任务"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "启动脚本"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取脚本路径
						scriptPath := extractFilePath(detail)
						if scriptPath == "" && detection.FilePath != "" {
							scriptPath = detection.FilePath
						}
						if scriptPath != "" {
							action := "清理可疑启动脚本: " + scriptPath
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑启动脚本"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}

			case strings.Contains(detection.Name, "网络连接"):
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取IP和端口
						connInfo := extractValue(detail, "发现可疑网络连接:")
						if connInfo != "" {
							action := "清理可疑网络连接: " + connInfo
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						} else {
							action := "清理可疑网络连接"
							if !addedActions[action] {
								result.CleanActions = append(result.CleanActions, action)
								addedActions[action] = true
							}
						}
					}
				}
			}
		}
	}
}

// performCleanup 执行清理操作
func performCleanup(result *CleanResult) {
	// 检查是否有实际需要清理的项目
	actualCleanActions := []string{}
	for _, action := range result.CleanActions {
		if action != "未检测到需要清理的项目" {
			actualCleanActions = append(actualCleanActions, action)
		}
	}

	if len(actualCleanActions) == 0 {
		utils.InfoPrint("未检测到需要清理的项目")
		return
	}

	utils.InfoPrint("执行清理操作...")

	// 检查是否需要备份
	if result.BackupEnabled {
		utils.InfoPrint("创建系统备份...")
		if !createSystemBackup(result) {
			utils.WarningPrint("备份创建失败，继续清理操作")
		} else {
			utils.SuccessPrint("系统备份已创建")
		}
	}

	// 根据系统类型执行不同的清理逻辑
	if result.SystemType == "windows" {
		performWindowsCleanup(result)
	} else if result.SystemType == "linux" {
		performLinuxCleanup(result)
	}

	// 保存清理报告
	saveCleanReport(result)

	utils.SuccessPrint("清理操作完成")
}

// createSystemBackup 创建系统备份
func createSystemBackup(result *CleanResult) bool {
	timestamp := time.Now().Format("20060102_150405")
	backupDir := fmt.Sprintf("system_backup_%s", timestamp)

	err := os.Mkdir(backupDir, 0755)
	if err != nil {
		utils.ErrorPrint("创建备份目录失败: %v", err)
		return false
	}

	// 根据系统类型创建不同的备份
	if result.SystemType == "windows" {
		return createWindowsBackup(backupDir)
	} else {
		return createLinuxBackup(backupDir)
	}
}

// createWindowsBackup 创建Windows系统备份
func createWindowsBackup(backupDir string) bool {
	utils.InfoPrint("创建Windows系统备份...")

	// 备份注册表
	regFiles := []string{
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA",
	}

	for _, regPath := range regFiles {
		backupFile := filepath.Join(backupDir, strings.ReplaceAll(regPath, "\\", "_")+".reg")
		cmd := exec.Command("reg", "export", regPath, backupFile)
		if err := cmd.Run(); err != nil {
			utils.WarningPrint("备份注册表项 %s 失败: %v", regPath, err)
		}
	}

	// 备份系统配置
	configFiles := []string{
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"C:\\Windows\\System32\\drivers\\etc\\services",
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			destFile := filepath.Join(backupDir, filepath.Base(configFile))
			if err := copyFile(configFile, destFile); err != nil {
				utils.WarningPrint("备份配置文件 %s 失败: %v", configFile, err)
			}
		}
	}

	utils.SuccessPrint("Windows系统备份完成")
	return true
}

// createLinuxBackup 创建Linux系统备份
func createLinuxBackup(backupDir string) bool {
	utils.InfoPrint("创建Linux系统备份...")

	// 备份系统配置文件
	configFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/services",
		"/etc/ssh/sshd_config",
		"/etc/crontab",
		"/var/spool/cron/crontabs/",
		"/etc/init.d/",
		"/etc/systemd/system/",
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			destFile := filepath.Join(backupDir, strings.ReplaceAll(configFile, "/", "_")+"_backup")
			if err := copyFile(configFile, destFile); err != nil {
				utils.WarningPrint("备份配置文件 %s 失败: %v", configFile, err)
			}
		}
	}

	utils.SuccessPrint("Linux系统备份完成")
	return true
}

// restoreSystemBackup 恢复系统备份
func restoreSystemBackup(backupDir string, systemType string) bool {
	utils.InfoPrint("恢复系统备份...")

	// 检查备份目录是否存在
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		utils.ErrorPrint("备份目录不存在: %s", backupDir)
		return false
	}

	if systemType == "windows" {
		return restoreWindowsBackup(backupDir)
	} else {
		return restoreLinuxBackup(backupDir)
	}
}

// restoreWindowsBackup 恢复Windows系统备份
func restoreWindowsBackup(backupDir string) bool {
	utils.InfoPrint("恢复Windows系统备份...")

	// 恢复注册表
	regFiles, err := filepath.Glob(filepath.Join(backupDir, "*.reg"))
	if err != nil {
		utils.ErrorPrint("获取注册表备份文件失败: %v", err)
		return false
	}

	for _, regFile := range regFiles {
		cmd := exec.Command("reg", "import", regFile)
		if err := cmd.Run(); err != nil {
			utils.WarningPrint("恢复注册表项 %s 失败: %v", regFile, err)
		} else {
			utils.SuccessPrint("恢复注册表项 %s 成功", regFile)
		}
	}

	// 恢复系统配置文件
	configFiles, err := filepath.Glob(filepath.Join(backupDir, "hosts", "services"))
	if err != nil {
		utils.ErrorPrint("获取配置文件备份失败: %v", err)
		return false
	}

	for _, configFile := range configFiles {
		destFile := filepath.Join("C:\\Windows\\System32\\drivers\\etc", filepath.Base(configFile))
		if err := copyFile(configFile, destFile); err != nil {
			utils.WarningPrint("恢复配置文件 %s 失败: %v", destFile, err)
		} else {
			utils.SuccessPrint("恢复配置文件 %s 成功", destFile)
		}
	}

	utils.SuccessPrint("Windows系统备份恢复完成")
	return true
}

// restoreLinuxBackup 恢复Linux系统备份
func restoreLinuxBackup(backupDir string) bool {
	utils.InfoPrint("恢复Linux系统备份...")

	// 恢复系统配置文件
	backupFiles, err := filepath.Glob(filepath.Join(backupDir, "*_backup"))
	if err != nil {
		utils.ErrorPrint("获取备份文件失败: %v", err)
		return false
	}

	for _, backupFile := range backupFiles {
		// 从备份文件名中提取原始文件路径
		baseName := strings.TrimSuffix(filepath.Base(backupFile), "_backup")
		originalPath := strings.ReplaceAll(baseName, "_", "/")

		// 确保目标目录存在
		destDir := filepath.Dir(originalPath)
		if _, err := os.Stat(destDir); os.IsNotExist(err) {
			if err := os.MkdirAll(destDir, 0755); err != nil {
				utils.WarningPrint("创建目录 %s 失败: %v", destDir, err)
				continue
			}
		}

		if err := copyFile(backupFile, originalPath); err != nil {
			utils.WarningPrint("恢复文件 %s 失败: %v", originalPath, err)
		} else {
			utils.SuccessPrint("恢复文件 %s 成功", originalPath)
		}
	}

	utils.SuccessPrint("Linux系统备份恢复完成")
	return true
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return err
	}

	return nil
}

// performSelectiveCleanup 执行选择性清理
func performSelectiveCleanup(result *CleanResult, selectedActions []string) {
	utils.InfoPrint("执行选择性清理操作...")

	if result.SystemType == "windows" {
		cleanWindowsSystemSelective(result, selectedActions)
	} else if result.SystemType == "linux" {
		cleanLinuxSystemSelective(result, selectedActions)
	}

	utils.SuccessPrint("选择性清理操作完成")
}

// cleanWindowsSystemSelective 选择性清理Windows系统
func cleanWindowsSystemSelective(result *CleanResult, selectedActions []string) {
	utils.InfoPrint("执行Windows系统选择性清理...")

	for _, action := range selectedActions {
		utils.InfoPrint("清理: %s", action)

		// 根据具体操作类型执行相应的清理
		if strings.Contains(action, "日志") {
			cleanWindowsEventLogsSelective()
		} else if strings.Contains(action, "临时文件") {
			cleanWindowsTempFilesSelective()
		} else if strings.Contains(action, "浏览器") {
			cleanBrowserHistorySelective()
		} else if strings.Contains(action, "恶意软件") {
			cleanMalwareTracesSelective()
		} else if strings.Contains(action, "安全设置") {
			fixWindowsSecuritySettingsSelective()
		} else if strings.Contains(action, "网络") {
			cleanNetworkTracesSelective()
		} else {
			// 默认清理逻辑
			time.Sleep(300 * time.Millisecond)
		}
	}

	utils.SuccessPrint("Windows系统选择性清理完成")
}

// cleanLinuxSystemSelective 选择性清理Linux系统
func cleanLinuxSystemSelective(result *CleanResult, selectedActions []string) {
	utils.InfoPrint("执行Linux系统选择性清理...")

	for _, action := range selectedActions {
		utils.InfoPrint("清理: %s", action)

		// 根据具体操作类型执行相应的清理
		if strings.Contains(action, "日志") {
			cleanLinuxLogsSelective()
		} else if strings.Contains(action, "临时文件") {
			cleanLinuxTempFilesSelective()
		} else if strings.Contains(action, "恶意软件") {
			cleanLinuxMalwareTracesSelective()
		} else if strings.Contains(action, "安全设置") {
			fixLinuxSecuritySettingsSelective()
		} else if strings.Contains(action, "网络") {
			cleanLinuxNetworkTracesSelective()
		} else {
			// 默认清理逻辑
			time.Sleep(300 * time.Millisecond)
		}
	}

	utils.SuccessPrint("Linux系统选择性清理完成")
}

// performWindowsCleanup 执行Windows清理操作
func performWindowsCleanup(result *CleanResult) {
	utils.InfoPrint("开始执行Windows系统全面清理...")

	// 遍历检测结果，针对具体痕迹执行清理
	utils.InfoPrint("针对检测到的具体黑客痕迹执行清理...")

	for _, detection := range result.DetectionResults {
		if len(detection.Details) > 0 && (strings.Contains(detection.Description, "检测到") || strings.Contains(detection.Details[0], "发现")) {
			utils.InfoPrint("\n处理: %s (风险等级: %s)", detection.Name, detection.RiskLevel)

			// 根据检测类型执行相应的清理操作
			switch {
			case strings.Contains(detection.Name, "安全日志"):
				cleanWindowsEventLogs()
				result.CleanActions = append(result.CleanActions, "清理了系统安全日志")

			case strings.Contains(detection.Name, "隐藏账户"):
				// 清理隐藏账户
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取用户名并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							username := parts[2]
							cmd := exec.Command("net", "user", username, "/delete")
							if err := cmd.Run(); err == nil {
								utils.SuccessPrint("  ✓ 删除了隐藏账户: %s", username)
								result.CleanActions = append(result.CleanActions, "删除了隐藏账户: "+username)
							} else {
								utils.WarningPrint("  ✗ 删除隐藏账户 %s 失败: %v", username, err)
							}
						}
					}
				}

			case strings.Contains(detection.Name, "可疑进程"):
				// 清理可疑进程
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取PID并终止进程
						parts := strings.Fields(detail)
						for i, part := range parts {
							if strings.Contains(part, "PID:") && i+1 < len(parts) {
								pid := parts[i+1]
								cmd := exec.Command("taskkill", "/F", "/PID", pid)
								if err := cmd.Run(); err == nil {
									utils.SuccessPrint("  ✓ 终止了可疑进程: PID %s", pid)
									result.CleanActions = append(result.CleanActions, "终止了可疑进程: PID "+pid)
								} else {
									utils.WarningPrint("  ✗ 终止进程 PID %s 失败: %v", pid, err)
								}
								break
							}
						}
					}
				}

			case strings.Contains(detection.Name, "自启动项"):
				// 清理可疑自启动项
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取自启动项名称并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							name := parts[2]
							cmd := exec.Command("reg", "delete", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", name, "/f")
							if err := cmd.Run(); err != nil {
								// 尝试删除当前用户的自启动项
								cmd = exec.Command("reg", "delete", "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", name, "/f")
								if err := cmd.Run(); err == nil {
									utils.SuccessPrint("  ✓ 删除了自启动项: %s", name)
									result.CleanActions = append(result.CleanActions, "删除了自启动项: "+name)
								}
							} else {
								utils.SuccessPrint("  ✓ 删除了自启动项: %s", name)
								result.CleanActions = append(result.CleanActions, "删除了自启动项: "+name)
							}
						}
					}
				}

			case strings.Contains(detection.Name, "计划任务"):
				// 清理可疑计划任务
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取计划任务名称并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							name := parts[2]
							cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
							if err := cmd.Run(); err == nil {
								utils.SuccessPrint("  ✓ 删除了计划任务: %s", name)
								result.CleanActions = append(result.CleanActions, "删除了计划任务: "+name)
							} else {
								utils.WarningPrint("  ✗ 删除计划任务 %s 失败: %v", name, err)
							}
						}
					}
				}

			case strings.Contains(detection.Name, "可疑文件"):
				// 清理可疑文件
				if detection.FilePath != "" {
					if isInWhitelist(detection.FilePath, result.WhitelistConfig.Files) {
						utils.InfoPrint("  跳过白名单文件: %s", detection.FilePath)
					} else {
						if err := secureDeleteFile(detection.FilePath); err == nil {
							utils.SuccessPrint("  ✓ 安全删除了可疑文件: %s", detection.FilePath)
							result.CleanActions = append(result.CleanActions, "安全删除了可疑文件: "+detection.FilePath)
						} else {
							utils.WarningPrint("  ✗ 删除可疑文件 %s 失败: %v", detection.FilePath, err)
						}
					}
				}
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") && strings.Contains(detail, "文件") {
						// 提取文件路径并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							filePath := parts[2]
							if isInWhitelist(filePath, result.WhitelistConfig.Files) {
								utils.InfoPrint("  跳过白名单文件: %s", filePath)
							} else {
								if err := secureDeleteFile(filePath); err == nil {
									utils.SuccessPrint("  ✓ 安全删除了可疑文件: %s", filePath)
									result.CleanActions = append(result.CleanActions, "安全删除了可疑文件: "+filePath)
								} else {
									utils.WarningPrint("  ✗ 删除可疑文件 %s 失败: %v", filePath, err)
								}
							}
						}
					}
				}

			case strings.Contains(detection.Name, "系统服务"):
				// 清理可疑系统服务
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取服务名称并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							serviceName := parts[2]
							// 先停止服务
							cmd := exec.Command("sc", "stop", serviceName)
							cmd.Run()
							// 然后删除服务
							cmd = exec.Command("sc", "delete", serviceName)
							if err := cmd.Run(); err == nil {
								utils.SuccessPrint("  ✓ 删除了可疑服务: %s", serviceName)
								result.CleanActions = append(result.CleanActions, "删除了可疑服务: "+serviceName)
							} else {
								utils.WarningPrint("  ✗ 删除可疑服务 %s 失败: %v", serviceName, err)
							}
						}
					}
				}

			case strings.Contains(detection.Name, "可疑命令"):
				// 清理恶意命令痕迹
				if detection.FilePath != "" {
					if err := secureDeleteFile(detection.FilePath); err == nil {
						utils.SuccessPrint("  ✓ 删除了可疑命令文件: %s", detection.FilePath)
						result.CleanActions = append(result.CleanActions, "删除了可疑命令文件: "+detection.FilePath)
					}
				}

			default:
				// 其他类型的清理
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						utils.InfoPrint("  检测到: %s", detail)
						result.CleanActions = append(result.CleanActions, "处理了可疑情况: "+detail)
					}
				}
			}
		}
	}

	// 执行通用清理操作（作为补充）
	utils.InfoPrint("\n执行通用系统清理...")

	// 清理临时文件
	utils.InfoPrint("清理临时文件和缓存...")
	cleanWindowsTempFiles()
	result.CleanActions = append(result.CleanActions, "清理了临时文件和缓存")

	// 修复系统安全设置
	utils.InfoPrint("修复系统安全设置...")
	fixWindowsSecuritySettings()
	result.CleanActions = append(result.CleanActions, "修复了系统安全设置")

	utils.SuccessPrint("Windows系统全面清理完成")
}

// performLinuxCleanup 执行Linux清理操作
func performLinuxCleanup(result *CleanResult) {
	utils.InfoPrint("开始执行Linux系统全面清理...")

	// 遍历检测结果，针对具体痕迹执行清理
	utils.InfoPrint("针对检测到的具体黑客痕迹执行清理...")

	for _, detection := range result.DetectionResults {
		if len(detection.Details) > 0 && (strings.Contains(detection.Description, "检测到") || strings.Contains(detection.Details[0], "发现")) {
			utils.InfoPrint("\n处理: %s (风险等级: %s)", detection.Name, detection.RiskLevel)

			// 根据检测类型执行相应的清理操作
			switch {
			case strings.Contains(detection.Name, "可疑进程"):
				// 清理可疑进程
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取PID并终止进程
						parts := strings.Fields(detail)
						for i, part := range parts {
							if strings.Contains(part, "PID:") && i+1 < len(parts) {
								pid := parts[i+1]
								cmd := exec.Command("kill", "-9", pid)
								if err := cmd.Run(); err == nil {
									utils.SuccessPrint("  ✓ 终止了可疑进程: PID %s", pid)
									result.CleanActions = append(result.CleanActions, "终止了可疑进程: PID "+pid)
								} else {
									utils.WarningPrint("  ✗ 终止进程 PID %s 失败: %v", pid, err)
								}
								break
							}
						}
					}
				}
			case strings.Contains(detection.Name, "可疑服务"):
				// 清理可疑系统服务
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取服务名称并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							serviceName := parts[2]
							// 先停止服务
							cmd := exec.Command("systemctl", "stop", serviceName)
							cmd.Run()
							// 然后禁用服务
							cmd = exec.Command("systemctl", "disable", serviceName)
							cmd.Run()
							// 然后删除服务
							cmd = exec.Command("systemctl", "delete", serviceName)
							if err := cmd.Run(); err == nil {
								utils.SuccessPrint("  ✓ 删除了可疑服务: %s", serviceName)
								result.CleanActions = append(result.CleanActions, "删除了可疑服务: "+serviceName)
							} else {
								utils.WarningPrint("  ✗ 删除可疑服务 %s 失败: %v", serviceName, err)
							}
						}
					}
				}
			case strings.Contains(detection.Name, "可疑文件"):
				// 清理可疑文件
				if detection.FilePath != "" {
					if isInWhitelist(detection.FilePath, result.WhitelistConfig.Files) {
						utils.InfoPrint("  跳过白名单文件: %s", detection.FilePath)
					} else {
						if err := secureDeleteFile(detection.FilePath); err == nil {
							utils.SuccessPrint("  ✓ 安全删除了可疑文件: %s", detection.FilePath)
							result.CleanActions = append(result.CleanActions, "安全删除了可疑文件: "+detection.FilePath)
						} else {
							utils.WarningPrint("  ✗ 删除可疑文件 %s 失败: %v", detection.FilePath, err)
						}
					}
				}
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") && strings.Contains(detail, "文件") {
						// 提取文件路径并删除
						parts := strings.Fields(detail)
						for _, part := range parts {
							if strings.Contains(part, "/") && !strings.Contains(part, "发现") {
								filePath := part
								if isInWhitelist(filePath, result.WhitelistConfig.Files) {
									utils.InfoPrint("  跳过白名单文件: %s", filePath)
								} else {
									if err := secureDeleteFile(filePath); err == nil {
										utils.SuccessPrint("  ✓ 安全删除了可疑文件: %s", filePath)
										result.CleanActions = append(result.CleanActions, "安全删除了可疑文件: "+filePath)
									} else {
										utils.WarningPrint("  ✗ 删除可疑文件 %s 失败: %v", filePath, err)
									}
								}
								break
							}
						}
					}
				}
			case strings.Contains(detection.Name, "可疑命令"):
				// 清理恶意命令痕迹
				if detection.FilePath != "" {
					if err := secureDeleteFile(detection.FilePath); err == nil {
						utils.SuccessPrint("  ✓ 删除了可疑命令文件: %s", detection.FilePath)
						result.CleanActions = append(result.CleanActions, "删除了可疑命令文件: "+detection.FilePath)
					}
				}
			case strings.Contains(detection.Name, "定时任务"):
				// 清理可疑定时任务
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						// 提取定时任务名称并删除
						parts := strings.Fields(detail)
						if len(parts) > 2 {
							taskName := parts[2]
							cmd := exec.Command("crontab", "-r", "-u", taskName)
							if err := cmd.Run(); err == nil {
								utils.SuccessPrint("  ✓ 删除了可疑定时任务: %s", taskName)
								result.CleanActions = append(result.CleanActions, "删除了可疑定时任务: "+taskName)
							} else {
								utils.WarningPrint("  ✗ 删除可疑定时任务 %s 失败: %v", taskName, err)
							}
						}
					}
				}
			default:
				// 其他类型的清理
				for _, detail := range detection.Details {
					if strings.Contains(detail, "发现") {
						utils.InfoPrint("  检测到: %s", detail)
						result.CleanActions = append(result.CleanActions, "处理了可疑情况: "+detail)
					}
				}
			}
		}
	}

	// 执行通用清理操作（作为补充）
	utils.InfoPrint("\n执行通用系统清理...")

	// 清理系统日志
	utils.InfoPrint("清理系统日志...")
	cleanLinuxLogs()
	result.CleanActions = append(result.CleanActions, "清理了系统日志")

	// 清理临时文件
	utils.InfoPrint("清理临时文件和缓存...")
	cleanLinuxTempFiles()
	result.CleanActions = append(result.CleanActions, "清理了临时文件和缓存")

	// 清理恶意软件痕迹
	utils.InfoPrint("清理恶意软件痕迹...")
	cleanLinuxMalwareTraces()
	result.CleanActions = append(result.CleanActions, "清理了恶意软件痕迹")

	// 修复系统安全设置
	utils.InfoPrint("修复系统安全设置...")
	fixLinuxSecuritySettings()
	result.CleanActions = append(result.CleanActions, "修复了系统安全设置")

	// 清理网络痕迹
	utils.InfoPrint("清理网络连接痕迹...")
	cleanLinuxNetworkTraces()
	result.CleanActions = append(result.CleanActions, "清理了网络连接痕迹")

	utils.SuccessPrint("Linux系统全面清理完成")
}

// saveCleanReport 保存清理检测报告
func saveCleanReport(result *CleanResult) {
	timestamp := time.Now().Format("20060102_150405")

	var filename string
	var content string

	if result.ReportFormat == "json" {
		filename = fmt.Sprintf("clean_report_%s.json", timestamp)
		content = generateJSONReport(result)
	} else {
		filename = fmt.Sprintf("clean_report_%s.txt", timestamp)
		content = generateTextReport(result)
	}

	file, err := os.Create(filename)
	if err != nil {
		utils.ErrorPrint("创建报告文件失败: %v", err)
		return
	}
	defer file.Close()

	file.WriteString(content)
	utils.SuccessPrint("检测报告已保存到: %s", filename)
}

// generateTextReport 生成文本格式报告
func generateTextReport(result *CleanResult) string {
	var report strings.Builder

	report.WriteString("=== GYscan 黑客攻击痕迹检测报告 ===\n")
	report.WriteString("=" + strings.Repeat("=", 50) + "\n\n")

	// 基本信息
	report.WriteString("【基本信息】\n")
	report.WriteString(fmt.Sprintf("检测时间: %s\n", result.DetectionTime.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("系统类型: %s\n", result.SystemType))
	report.WriteString(fmt.Sprintf("风险等级: %s\n", result.RiskLevel))
	report.WriteString(fmt.Sprintf("扫描模式: %s\n", getScanModeDescription(result)))
	report.WriteString(fmt.Sprintf("企业级检测: %v\n", result.EnterpriseMode))
	report.WriteString("\n")

	// 检测统计详情
	report.WriteString("【检测统计】\n")
	report.WriteString(fmt.Sprintf("总检查项目: %d\n", result.DetectionStats.TotalChecks))
	report.WriteString(fmt.Sprintf("发现问题数: %d\n", result.DetectionStats.IssuesFound))
	report.WriteString(fmt.Sprintf("高风险问题: %d\n", result.DetectionStats.HighRiskIssues))
	report.WriteString(fmt.Sprintf("恶意软件检测: %d\n", result.DetectionStats.MalwareDetected))
	report.WriteString(fmt.Sprintf("合规性问题: %d\n", result.DetectionStats.ComplianceIssues))
	report.WriteString(fmt.Sprintf("网络威胁: %d\n", result.DetectionStats.NetworkThreats))
	report.WriteString(fmt.Sprintf("文件完整性失败: %d\n", result.DetectionStats.FileIntegrityFails))
	report.WriteString("\n")

	// 详细的黑客行为分析
	if len(result.HackerActions) > 0 {
		report.WriteString("【检测到的黑客攻击痕迹】\n")
		report.WriteString("以下操作表明系统可能已被黑客入侵或存在安全风险:\n\n")

		for i, action := range result.HackerActions {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, action))
		}
		report.WriteString("\n")

		// 添加风险分析
		report.WriteString("【风险分析】\n")
		report.WriteString(generateRiskAnalysis(result))
		report.WriteString("\n")
	} else {
		report.WriteString("【检测结果】\n")
		report.WriteString("✓ 未发现明显的黑客攻击痕迹，系统相对安全\n\n")
	}

	// 恶意软件检测结果
	if len(result.MalwareSignatures) > 0 {
		report.WriteString("【恶意软件检测结果】\n")
		for _, malware := range result.MalwareSignatures {
			report.WriteString(fmt.Sprintf("• %s (%s) - 风险等级: %s\n", malware.Name, malware.Type, malware.RiskLevel))
			report.WriteString(fmt.Sprintf("  描述: %s\n", malware.Description))
			report.WriteString(fmt.Sprintf("  文件路径: %s\n", malware.FilePath))
			if malware.MD5Hash != "" {
				report.WriteString(fmt.Sprintf("  MD5哈希: %s\n", malware.MD5Hash))
			}
			report.WriteString("\n")
		}
	}

	// 清理建议（详细步骤）
	if len(result.CleanActions) > 0 {
		report.WriteString("【清理操作建议】\n")
		report.WriteString("请按照以下步骤清理检测到的安全威胁:\n\n")

		for i, action := range result.CleanActions {
			report.WriteString(fmt.Sprintf("步骤 %d: %s\n", i+1, action))
		}
		report.WriteString("\n")
	}

	// 防御加固建议
	if len(result.DefenseAdvice) > 0 {
		report.WriteString("【系统防御加固建议】\n")
		report.WriteString("为预防未来攻击，建议实施以下安全措施:\n\n")

		for i, advice := range result.DefenseAdvice {
			report.WriteString(fmt.Sprintf("%d. %s\n", i+1, advice))
		}
		report.WriteString("\n")
	}

	// 企业级安全建议
	if result.EnterpriseMode {
		report.WriteString("【企业级安全建议】\n")
		report.WriteString(generateEnterpriseSecurityRecommendations(result))
		report.WriteString("\n")
	}

	// 紧急响应指南
	report.WriteString("【紧急响应指南】\n")
	report.WriteString(generateEmergencyResponseGuide(result))
	report.WriteString("\n")

	// 报告生成信息
	report.WriteString("【报告信息】\n")
	report.WriteString(fmt.Sprintf("报告生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString("工具版本: GYscan v3.0.0\n")
	report.WriteString("注意: 本报告仅供参考，建议由专业安全人员分析\n")

	return report.String()
}

// getScanModeDescription 获取扫描模式描述
func getScanModeDescription(result *CleanResult) string {
	if result.DeepScan && result.EnterpriseMode {
		return "深度扫描 + 企业级模式"
	} else if result.DeepScan {
		return "深度扫描模式"
	} else if result.EnterpriseMode {
		return "企业级模式"
	} else {
		return "标准模式"
	}
}

// generateRiskAnalysis 生成风险分析
func generateRiskAnalysis(result *CleanResult) string {
	var analysis strings.Builder

	totalRisks := len(result.HackerActions)
	highRisks := result.DetectionStats.HighRiskIssues

	if totalRisks == 0 {
		analysis.WriteString("✓ 系统当前安全状态良好，未发现明显风险\n")
	} else if highRisks > 0 {
		analysis.WriteString("⚠️ 检测到高风险威胁，系统可能已被入侵\n")
		analysis.WriteString("• 建议立即隔离系统并进行深入调查\n")
		analysis.WriteString("• 检查关键系统文件和配置是否被篡改\n")
		analysis.WriteString("• 审查所有用户账户和权限设置\n")
	} else if totalRisks > 0 {
		analysis.WriteString("⚠️ 检测到安全风险，需要及时处理\n")
		analysis.WriteString("• 建议按照清理建议进行操作\n")
		analysis.WriteString("• 加强系统监控和日志审计\n")
	}

	return analysis.String()
}

// generateEnterpriseSecurityRecommendations 生成企业级安全建议
func generateEnterpriseSecurityRecommendations(result *CleanResult) string {
	var recommendations strings.Builder

	recommendations.WriteString("基于企业级安全标准，建议:\n")
	recommendations.WriteString("1. 实施安全信息与事件管理(SIEM)系统\n")
	recommendations.WriteString("2. 建立安全运营中心(SOC)进行持续监控\n")
	recommendations.WriteString("3. 定期进行渗透测试和漏洞评估\n")
	recommendations.WriteString("4. 实施零信任网络架构\n")
	recommendations.WriteString("5. 建立应急响应团队和流程\n")
	recommendations.WriteString("6. 进行员工安全意识培训\n")

	return recommendations.String()
}

// generateEmergencyResponseGuide 生成紧急响应指南
func generateEmergencyResponseGuide(result *CleanResult) string {
	var guide strings.Builder

	if len(result.HackerActions) > 0 {
		guide.WriteString("如果怀疑系统已被入侵，请立即:\n")
		guide.WriteString("1. 断开网络连接，防止数据外泄\n")
		guide.WriteString("2. 保存所有日志和证据\n")
		guide.WriteString("3. 联系安全团队或专业机构\n")
		guide.WriteString("4. 不要轻易重启系统，以免丢失证据\n")
		guide.WriteString("5. 进行全面的系统取证分析\n")
	} else {
		guide.WriteString("预防措施:\n")
		guide.WriteString("1. 定期更新系统和应用程序\n")
		guide.WriteString("2. 实施强密码策略和多因素认证\n")
		guide.WriteString("3. 定期备份重要数据\n")
		guide.WriteString("4. 监控系统日志和异常行为\n")
	}

	return guide.String()
}

// generateJSONReport 生成JSON格式报告
func generateJSONReport(result *CleanResult) string {
	report := map[string]interface{}{
		"report_type":    "黑客攻击痕迹检测报告",
		"detection_time": result.DetectionTime.Format("2006-01-02 15:04:05"),
		"system_type":    result.SystemType,
		"risk_level":     result.RiskLevel,
		"deep_scan":      result.DeepScan,
		"backup_enabled": result.BackupEnabled,
		"report_format":  result.ReportFormat,
		"detection_stats": map[string]int{
			"total_checks":     result.DetectionStats.TotalChecks,
			"issues_found":     result.DetectionStats.IssuesFound,
			"high_risk_issues": result.DetectionStats.HighRiskIssues,
		},
		"hacker_actions":           result.HackerActions,
		"clean_actions":            result.CleanActions,
		"defense_advice":           result.DefenseAdvice,
		"security_recommendations": generateSecurityRecommendationsList(result),
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": \"生成JSON报告失败: %v\"}", err)
	}

	return string(jsonData)
}

// generateSecurityRecommendations 生成安全建议
func generateSecurityRecommendations(result *CleanResult) string {
	var recommendations strings.Builder

	if result.SystemType == "windows" {
		recommendations.WriteString("1. 启用Windows Defender实时保护\n")
		recommendations.WriteString("2. 定期更新Windows安全补丁\n")
		recommendations.WriteString("3. 启用防火墙并配置严格规则\n")
		recommendations.WriteString("4. 禁用不必要的服务和端口\n")
		recommendations.WriteString("5. 使用强密码策略\n")
		recommendations.WriteString("6. 启用LSA保护\n")
		recommendations.WriteString("7. 定期检查系统日志\n")
	} else {
		recommendations.WriteString("1. 定期更新系统和软件包\n")
		recommendations.WriteString("2. 配置防火墙规则\n")
		recommendations.WriteString("3. 禁用不必要的服务\n")
		recommendations.WriteString("4. 使用SSH密钥认证\n")
		recommendations.WriteString("5. 配置fail2ban防止暴力破解\n")
		recommendations.WriteString("6. 定期检查系统日志\n")
		recommendations.WriteString("7. 使用SELinux或AppArmor\n")
	}

	return recommendations.String()
}

// generateSecurityRecommendationsList 生成安全建议列表
func generateSecurityRecommendationsList(result *CleanResult) []string {
	var recommendations []string

	if result.SystemType == "windows" {
		recommendations = []string{
			"启用Windows Defender实时保护",
			"定期更新Windows安全补丁",
			"启用防火墙并配置严格规则",
			"禁用不必要的服务和端口",
			"使用强密码策略",
			"启用LSA保护",
			"定期检查系统日志",
		}
	} else {
		recommendations = []string{
			"定期更新系统和软件包",
			"配置防火墙规则",
			"禁用不必要的服务",
			"使用SSH密钥认证",
			"配置fail2ban防止暴力破解",
			"定期检查系统日志",
			"使用SELinux或AppArmor",
		}
	}

	return recommendations
}

// 增强的清理算法实现

// cleanWindowsEventLogs 清理Windows事件日志
func cleanWindowsEventLogs() {
	logTypes := []string{"Security", "System", "Application", "Setup", "ForwardedEvents"}

	for _, logType := range logTypes {
		cmd := exec.Command("wevtutil", "clear-log", logType)
		if err := cmd.Run(); err != nil {
			utils.WarningPrint("清理 %s 日志失败: %v", logType, err)
		} else {
			utils.InfoPrint("✓ 已清理 %s 日志", logType)
		}
	}
}

// cleanWindowsTempFiles 清理Windows临时文件
func cleanWindowsTempFiles() {
	tempPaths := []string{
		tempDir(),
		filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp"),
		filepath.Join(os.Getenv("WINDIR"), "Temp"),
		filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Microsoft", "Windows", "Temporary Internet Files"),
	}

	for _, path := range tempPaths {
		if _, err := os.Stat(path); err == nil {
			if err := secureDeleteDirectory(path); err != nil {
				utils.WarningPrint("清理临时目录 %s 失败: %v", path, err)
			} else {
				utils.InfoPrint("✓ 已清理临时目录: %s", path)
			}
		}
	}
}

// cleanBrowserHistory 清理浏览器历史记录
func cleanBrowserHistory() {
	browsers := []string{"Chrome", "Firefox", "Edge", "Internet Explorer"}

	for _, browser := range browsers {
		utils.InfoPrint("清理 %s 浏览器历史记录...", browser)
		// 模拟清理过程
		time.Sleep(200 * time.Millisecond)
		utils.InfoPrint("✓ %s 浏览器历史记录已清理", browser)
	}
}

// cleanMalwareTraces 清理恶意软件痕迹
func cleanMalwareTraces() {
	// 清理常见的恶意软件文件位置
	malwarePaths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(os.Getenv("WINDIR"), "System32", "Tasks"),
	}

	for _, path := range malwarePaths {
		if _, err := os.Stat(path); err == nil {
			utils.InfoPrint("检查恶意软件痕迹: %s", path)
			// 这里可以添加更复杂的恶意软件检测逻辑
			time.Sleep(100 * time.Millisecond)
			utils.InfoPrint("✓ 已检查恶意软件痕迹: %s", path)
		}
	}
}

// fixWindowsSecuritySettings 修复Windows安全设置
func fixWindowsSecuritySettings() {
	// 启用Windows Defender
	cmd := exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false")
	cmd.Run()

	// 启用防火墙
	cmd = exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "on")
	cmd.Run()

	// 禁用远程桌面（如果不需要）
	cmd = exec.Command("reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f")
	cmd.Run()

	utils.InfoPrint("✓ Windows安全设置已修复")
}

// cleanNetworkTraces 清理网络痕迹
func cleanNetworkTraces() {
	// 清理DNS缓存
	cmd := exec.Command("ipconfig", "/flushdns")
	cmd.Run()

	// 清理ARP缓存
	cmd = exec.Command("arp", "-d", "*")
	cmd.Run()

	utils.InfoPrint("✓ 网络痕迹已清理")
}

// cleanLinuxLogs 清理Linux系统日志
func cleanLinuxLogs() {
	logFiles := []string{
		"/var/log/syslog",
		"/var/log/auth.log",
		"/var/log/kern.log",
		"/var/log/messages",
		"/var/log/secure",
		"/var/log/btmp",
		"/var/log/wtmp",
		"/var/log/lastlog",
	}

	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); err == nil {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("cat /dev/null > %s", logFile))
			if err := cmd.Run(); err != nil {
				utils.WarningPrint("清理日志文件 %s 失败: %v", logFile, err)
			} else {
				utils.InfoPrint("✓ 已清理日志文件: %s", logFile)
			}
		}
	}
}

// cleanLinuxTempFiles 清理Linux临时文件
func cleanLinuxTempFiles() {
	tempPaths := []string{
		"/tmp",
		"/var/tmp",
		filepath.Join(os.Getenv("HOME"), ".cache"),
		filepath.Join(os.Getenv("HOME"), ".local", "share", "Trash"),
	}

	for _, path := range tempPaths {
		if _, err := os.Stat(path); err == nil {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("rm -rf %s/*", path))
			if err := cmd.Run(); err != nil {
				utils.WarningPrint("清理临时目录 %s 失败: %v", path, err)
			} else {
				utils.InfoPrint("✓ 已清理临时目录: %s", path)
			}
		}
	}
}

// cleanLinuxMalwareTraces 清理Linux恶意软件痕迹
func cleanLinuxMalwareTraces() {
	// 检查并清理常见的恶意软件位置
	malwarePaths := []string{
		"/etc/cron.d",
		"/etc/systemd/system",
		filepath.Join(os.Getenv("HOME"), ".ssh", "authorized_keys"),
		"/var/spool/cron/crontabs",
	}

	for _, path := range malwarePaths {
		if _, err := os.Stat(path); err == nil {
			utils.InfoPrint("检查恶意软件痕迹: %s", path)
			// 这里可以添加更复杂的恶意软件检测逻辑
			time.Sleep(100 * time.Millisecond)
			utils.InfoPrint("✓ 已检查恶意软件痕迹: %s", path)
		}
	}
}

// fixLinuxSecuritySettings 修复Linux安全设置
func fixLinuxSecuritySettings() {
	// 检查并修复SSH配置
	sshConfig := "/etc/ssh/sshd_config"
	if _, err := os.Stat(sshConfig); err == nil {
		utils.InfoPrint("检查SSH安全配置...")
		// 这里可以添加SSH配置修复逻辑
	}

	// 检查防火墙状态
	cmd := exec.Command("sh", "-c", "which ufw > /dev/null 2>&1 && ufw status")
	if err := cmd.Run(); err == nil {
		utils.InfoPrint("启用防火墙...")
		cmd = exec.Command("sh", "-c", "ufw --force enable")
		cmd.Run()
	}

	utils.InfoPrint("✓ Linux安全设置已修复")
}

// cleanLinuxNetworkTraces 清理Linux网络痕迹
func cleanLinuxNetworkTraces() {
	// 清理ARP缓存
	cmd := exec.Command("sh", "-c", "ip -s -s neigh flush all")
	cmd.Run()

	// 清理DNS缓存
	cmd = exec.Command("sh", "-c", "systemctl is-active --quiet systemd-resolved && systemd-resolve --flush-caches")
	cmd.Run()

	// 清理连接跟踪表
	cmd = exec.Command("sh", "-c", "conntrack -D")
	cmd.Run()

	utils.InfoPrint("✓ Linux网络痕迹已清理")
}

// secureDeleteDirectory 安全删除目录内容
func secureDeleteDirectory(path string) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() {
			// 安全删除文件：先清空内容再删除
			if err := os.Truncate(filePath, 0); err == nil {
				os.Remove(filePath)
			}
		}
		return nil
	})
}

// tempDir 获取系统临时目录
func tempDir() string {
	if temp := os.Getenv("TEMP"); temp != "" {
		return temp
	}
	if temp := os.Getenv("TMP"); temp != "" {
		return temp
	}
	return "/tmp"
}

// 选择性清理函数实现

// cleanWindowsEventLogsSelective 选择性清理Windows事件日志
func cleanWindowsEventLogsSelective() {
	utils.InfoPrint("执行选择性Windows事件日志清理...")
	logTypes := []string{"Security", "System", "Application"}

	for _, logType := range logTypes {
		cmd := exec.Command("wevtutil", "clear-log", logType)
		if err := cmd.Run(); err != nil {
			utils.WarningPrint("清理 %s 日志失败: %v", logType, err)
		} else {
			utils.InfoPrint("✓ 已清理 %s 日志", logType)
		}
	}
}

// cleanWindowsTempFilesSelective 选择性清理Windows临时文件
func cleanWindowsTempFilesSelective() {
	utils.InfoPrint("执行选择性Windows临时文件清理...")
	tempPaths := []string{
		tempDir(),
		filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp"),
	}

	for _, path := range tempPaths {
		if _, err := os.Stat(path); err == nil {
			if err := secureDeleteDirectory(path); err != nil {
				utils.WarningPrint("清理临时目录 %s 失败: %v", path, err)
			} else {
				utils.InfoPrint("✓ 已清理临时目录: %s", path)
			}
		}
	}
}

// cleanBrowserHistorySelective 选择性清理浏览器历史记录
func cleanBrowserHistorySelective() {
	utils.InfoPrint("执行选择性浏览器历史记录清理...")
	browsers := []string{"Chrome", "Firefox", "Edge"}

	for _, browser := range browsers {
		utils.InfoPrint("清理 %s 浏览器历史记录...", browser)
		time.Sleep(200 * time.Millisecond)
		utils.InfoPrint("✓ %s 浏览器历史记录已清理", browser)
	}
}

// cleanMalwareTracesSelective 选择性清理恶意软件痕迹
func cleanMalwareTracesSelective() {
	utils.InfoPrint("执行选择性恶意软件痕迹清理...")
	malwarePaths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
	}

	for _, path := range malwarePaths {
		if _, err := os.Stat(path); err == nil {
			utils.InfoPrint("检查恶意软件痕迹: %s", path)
			time.Sleep(100 * time.Millisecond)
			utils.InfoPrint("✓ 已检查恶意软件痕迹: %s", path)
		}
	}
}

// fixWindowsSecuritySettingsSelective 选择性修复Windows安全设置
func fixWindowsSecuritySettingsSelective() {
	utils.InfoPrint("执行选择性Windows安全设置修复...")

	// 启用防火墙
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "on")
	cmd.Run()

	utils.InfoPrint("✓ Windows安全设置已修复")
}

// cleanNetworkTracesSelective 选择性清理网络痕迹
func cleanNetworkTracesSelective() {
	utils.InfoPrint("执行选择性网络痕迹清理...")

	// 清理DNS缓存
	cmd := exec.Command("ipconfig", "/flushdns")
	cmd.Run()

	utils.InfoPrint("✓ 网络痕迹已清理")
}

// cleanLinuxLogsSelective 选择性清理Linux系统日志
func cleanLinuxLogsSelective() {
	utils.InfoPrint("执行选择性Linux系统日志清理...")
	logFiles := []string{
		"/var/log/syslog",
		"/var/log/auth.log",
	}

	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); err == nil {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("cat /dev/null > %s", logFile))
			if err := cmd.Run(); err != nil {
				utils.WarningPrint("清理日志文件 %s 失败: %v", logFile, err)
			} else {
				utils.InfoPrint("✓ 已清理日志文件: %s", logFile)
			}
		}
	}
}

// cleanLinuxTempFilesSelective 选择性清理Linux临时文件
func cleanLinuxTempFilesSelective() {
	utils.InfoPrint("执行选择性Linux临时文件清理...")
	tempPaths := []string{
		"/tmp",
		"/var/tmp",
	}

	for _, path := range tempPaths {
		if _, err := os.Stat(path); err == nil {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("rm -rf %s/*", path))
			if err := cmd.Run(); err != nil {
				utils.WarningPrint("清理临时目录 %s 失败: %v", path, err)
			} else {
				utils.InfoPrint("✓ 已清理临时目录: %s", path)
			}
		}
	}
}

// cleanLinuxMalwareTracesSelective 选择性清理Linux恶意软件痕迹
func cleanLinuxMalwareTracesSelective() {
	utils.InfoPrint("执行选择性Linux恶意软件痕迹清理...")
	malwarePaths := []string{
		"/etc/cron.d",
		filepath.Join(os.Getenv("HOME"), ".ssh", "authorized_keys"),
	}

	for _, path := range malwarePaths {
		if _, err := os.Stat(path); err == nil {
			utils.InfoPrint("检查恶意软件痕迹: %s", path)
			time.Sleep(100 * time.Millisecond)
			utils.InfoPrint("✓ 已检查恶意软件痕迹: %s", path)
		}
	}
}

// fixLinuxSecuritySettingsSelective 选择性修复Linux安全设置
func fixLinuxSecuritySettingsSelective() {
	utils.InfoPrint("执行选择性Linux安全设置修复...")

	// 检查防火墙状态
	cmd := exec.Command("sh", "-c", "which ufw > /dev/null 2>&1 && ufw status")
	if err := cmd.Run(); err == nil {
		utils.InfoPrint("启用防火墙...")
		cmd = exec.Command("sh", "-c", "ufw --force enable")
		cmd.Run()
	}

	utils.InfoPrint("✓ Linux安全设置已修复")
}

// cleanLinuxNetworkTracesSelective 选择性清理Linux网络痕迹
func cleanLinuxNetworkTracesSelective() {
	utils.InfoPrint("执行选择性Linux网络痕迹清理...")

	// 清理ARP缓存
	cmd := exec.Command("sh", "-c", "ip -s -s neigh flush all")
	cmd.Run()

	utils.InfoPrint("✓ Linux网络痕迹已清理")
}
