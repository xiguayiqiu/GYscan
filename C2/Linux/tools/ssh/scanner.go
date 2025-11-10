package ssh

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

// ScanResult 包含SSH扫描结果
type ScanResult struct {
	Target          string                 `json:"target"`
	ScanTime        time.Time              `json:"scan_time"`
	OverallScore    int                    `json:"overall_score"`
	RiskLevel       string                 `json:"risk_level"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	Recommendations []string               `json:"recommendations"`
	RawOutput       string                 `json:"raw_output"`
	Details         map[string]interface{} `json:"details"`
}

// Vulnerability 表示SSH配置中的安全漏洞
type Vulnerability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // high, medium, low
	Risk        string `json:"risk"`
	Remediation string `json:"remediation"`
}

// Scanner SSH扫描器结构体
type Scanner struct {
	config *Config
	logger *logrus.Logger
	verbose bool
}

// NewScanner 创建新的SSH扫描器
func NewScanner(config *Config, verbose bool) *Scanner {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	
	return &Scanner{
		config: config,
		logger: logger,
		verbose: verbose,
	}
}

// Scan 执行SSH配置安全扫描
func (s *Scanner) Scan() (*ScanResult, error) {
	s.logger.Infof("开始SSH配置安全扫描: %s", s.config.Target)
	
	result := &ScanResult{
		Target:       s.config.Target,
		ScanTime:     time.Now(),
		Vulnerabilities: []Vulnerability{},
		Recommendations: []string{},
		Details:      make(map[string]interface{}),
	}

	// 检查ssh-audit是否安装，如果未安装则自动安装
	if !s.isSSHAuditInstalled() {
		if s.verbose {
			s.logger.Info("ssh-audit未安装，开始自动安装...")
		}
		
		// 检查网络连接
		if !s.checkNetworkConnection() {
			return nil, fmt.Errorf("网络连接不可用，无法自动安装ssh-audit")
		}
		
		// 自动安装ssh-audit
		if err := s.installSSHAudit(); err != nil {
			return nil, fmt.Errorf("自动安装ssh-audit失败: %v", err)
		}
		
		if s.verbose {
			s.logger.Info("ssh-audit安装完成")
		}
	}

	// 执行ssh-audit扫描
	output, err := s.runSSHAudit()
	if err != nil {
		return nil, fmt.Errorf("SSH扫描失败: %v", err)
	}

	result.RawOutput = output

	// 解析扫描结果
	err = s.parseSSHAuditOutput(output, result)
	if err != nil {
		s.logger.Warnf("解析SSH扫描结果时出错: %v", err)
	}

	// 计算总体评分和风险等级
	s.calculateScoreAndRisk(result)

	s.logger.Infof("SSH扫描完成，发现 %d 个安全问题", len(result.Vulnerabilities))
	
	return result, nil
}

// isSSHAuditInstalled 检查ssh-audit是否已安装
func (s *Scanner) isSSHAuditInstalled() bool {
	cmd := exec.Command("ssh-audit", "--version")
	err := cmd.Run()
	return err == nil
}

// runSSHAudit 执行ssh-audit命令
func (s *Scanner) runSSHAudit() (string, error) {
	args := []string{s.config.Target}
	
	if s.config.Verbose {
		args = append(args, "-v")
	}
	
	cmd := exec.Command("ssh-audit", args...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-audit执行失败: %v, 输出: %s", err, string(output))
	}
	
	return string(output), nil
}

// checkNetworkConnection 检查网络连接是否可用
func (s *Scanner) checkNetworkConnection() bool {
	if s.verbose {
		s.logger.Info("检查网络连接...")
	}

	// 尝试连接Google DNS服务器来检查网络
	cmd := exec.Command("ping", "-c", "1", "-W", "3", "8.8.8.8")
	if err := cmd.Run(); err != nil {
		// 如果ping失败，尝试curl检查
		cmd = exec.Command("curl", "-s", "--connect-timeout", "5", "http://www.google.com")
		if err := cmd.Run(); err != nil {
			if s.verbose {
				s.logger.Info("网络连接检查失败")
			}
			return false
		}
	}

	if s.verbose {
		s.logger.Info("网络连接正常")
	}
	return true
}

// installSSHAudit 自动安装ssh-audit工具
func (s *Scanner) installSSHAudit() error {
	if s.verbose {
		s.logger.Info("开始自动安装ssh-audit...")
	}

	// 检测Linux发行版
	distro, err := s.detectLinuxDistribution()
	if err != nil {
		return fmt.Errorf("无法检测Linux发行版: %v", err)
	}

	if s.verbose {
		s.logger.Infof("检测到Linux发行版: %s", distro)
	}

	// 根据发行版执行相应的安装命令
	switch distro {
	case "debian", "ubuntu":
		return s.installSSHAuditDebian()
	case "redhat", "centos", "fedora":
		return s.installSSHAuditRedhat()
	case "arch":
		return s.installSSHAuditArch()
	case "opensuse", "suse":
		return s.installSSHAuditOpenSUSE()
	default:
		return s.installSSHAuditGeneric()
	}
}

// detectLinuxDistribution 检测Linux发行版
func (s *Scanner) detectLinuxDistribution() (string, error) {
	// 检查/etc/os-release文件
	if _, err := os.Stat("/etc/os-release"); err == nil {
		content, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return "", err
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ID=") {
				distro := strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
				return distro, nil
			}
		}
	}

	// 检查其他发行版标识文件
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian", nil
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "redhat", nil
	}
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch", nil
	}
	if _, err := os.Stat("/etc/SuSE-release"); err == nil {
		return "opensuse", nil
	}

	return "", fmt.Errorf("无法检测Linux发行版")
}

// installSSHAuditDebian 在Debian/Ubuntu系统上安装ssh-audit
func (s *Scanner) installSSHAuditDebian() error {
	if s.verbose {
		s.logger.Info("在Debian/Ubuntu系统上安装ssh-audit...")
	}

	// 更新包管理器
	cmd := exec.Command("apt-get", "update")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("更新包列表失败: %v", err)
	}

	// 安装ssh-audit
	cmd = exec.Command("apt-get", "install", "-y", "ssh-audit")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装ssh-audit失败: %v", err)
	}

	return nil
}

// installSSHAuditRedhat 在Redhat/CentOS/Fedora系统上安装ssh-audit
func (s *Scanner) installSSHAuditRedhat() error {
	if s.verbose {
		s.logger.Info("在Redhat/CentOS/Fedora系统上安装ssh-audit...")
	}

	// 检测具体的Redhat系发行版
	distro, _ := s.detectLinuxDistribution()
	
	if distro == "fedora" {
		// Fedora使用dnf
		cmd := exec.Command("dnf", "install", "-y", "ssh-audit")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("安装ssh-audit失败: %v", err)
		}
	} else {
		// CentOS/RHEL使用yum
		cmd := exec.Command("yum", "install", "-y", "epel-release")
		if err := cmd.Run(); err != nil {
			// 如果EPEL安装失败，尝试直接安装ssh-audit
			cmd = exec.Command("yum", "install", "-y", "ssh-audit")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("安装ssh-audit失败: %v", err)
			}
		} else {
			// 安装EPEL后安装ssh-audit
			cmd = exec.Command("yum", "install", "-y", "ssh-audit")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("安装ssh-audit失败: %v", err)
			}
		}
	}

	return nil
}

// installSSHAuditArch 在Arch Linux系统上安装ssh-audit
func (s *Scanner) installSSHAuditArch() error {
	if s.verbose {
		s.logger.Info("在Arch Linux系统上安装ssh-audit...")
	}

	// 更新包数据库
	cmd := exec.Command("pacman", "-Sy")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("更新包数据库失败: %v", err)
	}

	// 安装ssh-audit
	cmd = exec.Command("pacman", "-S", "--noconfirm", "ssh-audit")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装ssh-audit失败: %v", err)
	}

	return nil
}

// installSSHAuditOpenSUSE 在OpenSUSE系统上安装ssh-audit
func (s *Scanner) installSSHAuditOpenSUSE() error {
	if s.verbose {
		s.logger.Info("在OpenSUSE系统上安装ssh-audit...")
	}

	// 更新包管理器
	cmd := exec.Command("zypper", "refresh")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("更新包列表失败: %v", err)
	}

	// 安装ssh-audit
	cmd = exec.Command("zypper", "install", "-y", "ssh-audit")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装ssh-audit失败: %v", err)
	}

	return nil
}

// installSSHAuditGeneric 通用安装方法（使用pip安装）
func (s *Scanner) installSSHAuditGeneric() error {
	if s.verbose {
		s.logger.Info("使用pip安装ssh-audit...")
	}

	// 检查pip是否可用
	cmd := exec.Command("pip", "--version")
	if err := cmd.Run(); err != nil {
		// 如果pip不可用，尝试安装pip
		cmd = exec.Command("python3", "-m", "ensurepip", "--default-pip")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("pip不可用且安装失败: %v", err)
		}
	}

	// 使用pip安装ssh-audit
	cmd = exec.Command("pip", "install", "ssh-audit")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("使用pip安装ssh-audit失败: %v", err)
	}

	return nil
}

// parseSSHAuditOutput 解析ssh-audit的输出
func (s *Scanner) parseSSHAuditOutput(output string, result *ScanResult) error {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// 检测协议版本安全问题
		if strings.Contains(line, "SSH-1") && strings.Contains(line, "enabled") {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:          "SSH-001",
				Title:       "不安全的SSHv1协议已启用",
				Description: "检测到SSHv1协议已启用，该协议存在严重安全漏洞",
				Severity:    "high",
				Risk:        "中间人攻击、协议漏洞利用",
				Remediation: "禁用SSHv1协议，仅使用SSHv2",
			})
		}
		
		// 检测弱加密算法
		if strings.Contains(line, "weak") && (strings.Contains(line, "cipher") || strings.Contains(line, "algorithm")) {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:          "SSH-002",
				Title:       "弱加密算法检测",
				Description: "检测到使用不安全的加密算法",
				Severity:    "medium",
				Risk:        "加密数据可能被破解",
				Remediation: "禁用弱加密算法，使用AES-256-GCM等强加密算法",
			})
		}
		
		// 检测密码认证风险
		if strings.Contains(line, "password authentication") && strings.Contains(line, "enabled") {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:          "SSH-003",
				Title:       "密码认证已启用",
				Description: "密码认证存在暴力破解风险",
				Severity:    "medium",
				Risk:        "暴力破解攻击",
				Remediation: "禁用密码认证，使用公钥认证",
			})
		}
		
		// 检测root登录风险
		if strings.Contains(line, "root login") && strings.Contains(line, "permitted") {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:          "SSH-004",
				Title:       "允许root用户远程登录",
				Description: "直接允许root用户登录存在安全风险",
				Severity:    "high",
				Risk:        "特权账户直接暴露",
				Remediation: "禁用root远程登录，使用普通用户登录后切换",
			})
		}
	}
	
	// 添加通用建议
	result.Recommendations = append(result.Recommendations,
		"使用SSHv2协议，禁用SSHv1",
		"禁用密码认证，使用公钥认证",
		"禁用root用户直接远程登录",
		"使用非默认SSH端口",
		"配置失败登录次数限制",
		"定期更新SSH服务端软件",
	)
	
	return nil
}

// calculateScoreAndRisk 计算总体评分和风险等级
func (s *Scanner) calculateScoreAndRisk(result *ScanResult) {
	highCount := 0
	mediumCount := 0
	lowCount := 0
	
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}
	
	// 计算评分（满分100）
	result.OverallScore = 100 - (highCount*20 + mediumCount*10 + lowCount*5)
	if result.OverallScore < 0 {
		result.OverallScore = 0
	}
	
	// 确定风险等级
	switch {
	case highCount > 0:
		result.RiskLevel = "高危"
	case mediumCount > 0:
		result.RiskLevel = "中危"
	case lowCount > 0:
		result.RiskLevel = "低危"
	default:
		result.RiskLevel = "安全"
		result.OverallScore = 100
	}
}

// PrintResult 打印扫描结果
func (s *Scanner) PrintResult(result *ScanResult) {
	fmt.Printf("\n=== SSH配置安全扫描结果 ===\n")
	fmt.Printf("目标: %s\n", result.Target)
	fmt.Printf("扫描时间: %s\n", result.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("总体评分: %d/100\n", result.OverallScore)
	
	// 根据风险等级显示不同颜色
	switch result.RiskLevel {
	case "高危":
		color.Red("风险等级: %s\n", result.RiskLevel)
	case "中危":
		color.Yellow("风险等级: %s\n", result.RiskLevel)
	case "低危":
		color.Blue("风险等级: %s\n", result.RiskLevel)
	default:
		color.Green("风险等级: %s\n", result.RiskLevel)
	}
	
	fmt.Printf("发现的安全问题: %d 个\n\n", len(result.Vulnerabilities))
	
	// 显示安全问题详情
	for i, vuln := range result.Vulnerabilities {
		fmt.Printf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.Title)
		fmt.Printf("   描述: %s\n", vuln.Description)
		fmt.Printf("   风险: %s\n", vuln.Risk)
		fmt.Printf("   修复建议: %s\n\n", vuln.Remediation)
	}
	
	// 显示修复建议
	if len(result.Recommendations) > 0 {
		fmt.Printf("=== 修复建议 ===\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
	}
}

// SaveResult 保存扫描结果到文件
func (s *Scanner) SaveResult(result *ScanResult) error {
	// 保存JSON格式结果
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	
	jsonFile := strings.TrimSuffix(s.config.OutputFile, ".html") + ".json"
	err = os.WriteFile(jsonFile, jsonData, 0644)
	if err != nil {
		return err
	}
	
	s.logger.Infof("JSON结果已保存到: %s", jsonFile)
	
	// 生成HTML报告
	return s.generateHTMLReport(result)
}