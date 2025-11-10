package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ScanResult 扫描结果结构体
type ScanResult struct {
	Target        string          `json:"target"`
	Timestamp     time.Time       `json:"timestamp"`
	ScanDuration  time.Duration   `json:"scan_duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Error         string          `json:"error,omitempty"`
}

// Vulnerability 漏洞信息结构体
type Vulnerability struct {
	VulnerabilityID  string            `json:"vulnerability_id"`
	PkgName          string            `json:"pkg_name"`
	InstalledVersion string            `json:"installed_version"`
	FixedVersion     string            `json:"fixed_version"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Severity         string            `json:"severity"`
	CVSS             map[string]float64 `json:"cvss"`
	References       []string          `json:"references"`
	PublishedDate    string            `json:"published_date"`
	LastModifiedDate string            `json:"last_modified_date"`
}

// Scanner Trivy扫描器结构体
type Scanner struct {
	config *Config
	verbose bool
}

// NewScanner 创建新的Trivy扫描器
func NewScanner(config *Config, verbose bool) *Scanner {
	return &Scanner{
		config: config,
		verbose: verbose,
	}
}

// Scan 执行Trivy扫描
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Target:    s.config.Target,
		Timestamp: time.Now(),
	}

	if s.verbose {
		fmt.Printf("开始Trivy扫描: %s\n", s.config.Target)
	}

	// 检查Trivy是否安装
	if !s.isTrivyInstalled() {
		if s.verbose {
			fmt.Println("Trivy未安装，尝试自动安装...")
		}
		
		// 检查网络连接
		if !s.checkNetworkConnection() {
			result.Error = "Trivy未安装且无法连接到网络，请手动安装Trivy"
			return result, fmt.Errorf("Trivy未安装且无法连接到网络")
		}
		
		// 自动安装Trivy
		if err := s.installTrivy(); err != nil {
			result.Error = fmt.Sprintf("Trivy自动安装失败: %v", err)
			return result, fmt.Errorf("Trivy自动安装失败: %v", err)
		}
		
		if s.verbose {
			fmt.Println("Trivy安装成功，继续扫描...")
		}
	}

	// 构建Trivy命令参数
	args := s.buildTrivyArgs()

	if s.verbose {
		fmt.Printf("执行命令: trivy %s\n", strings.Join(args, " "))
	}

	// 执行Trivy命令
	cmd := exec.Command("trivy", args...)
	output, err := cmd.CombinedOutput()

	result.ScanDuration = time.Since(result.Timestamp)

	if err != nil {
		if s.verbose {
			fmt.Printf("Trivy扫描错误: %v\n", err)
			fmt.Printf("输出: %s\n", string(output))
		}
		result.Error = fmt.Sprintf("Trivy执行错误: %v", err)
		return result, err
	}

	// 解析Trivy输出
	if err := s.parseTrivyOutput(output, result); err != nil {
		if s.verbose {
			fmt.Printf("解析Trivy输出错误: %v\n", err)
		}
		result.Error = fmt.Sprintf("解析输出错误: %v", err)
		return result, err
	}

	if s.verbose {
		fmt.Printf("Trivy扫描完成，发现 %d 个漏洞，耗时 %v\n", 
			len(result.Vulnerabilities), result.ScanDuration)
	}

	return result, nil
}

// isTrivyInstalled 检查Trivy是否安装
func (s *Scanner) isTrivyInstalled() bool {
	cmd := exec.Command("trivy", "--version")
	return cmd.Run() == nil
}

// buildTrivyArgs 构建Trivy命令参数
func (s *Scanner) buildTrivyArgs() []string {
	args := []string{}

	// 添加目标
	args = append(args, s.config.Target)

	// 添加格式参数
	args = append(args, "--format", s.config.Format)

	// 添加严重性过滤
	if s.config.Severity != "" {
		args = append(args, "--severity", s.config.Severity)
	}

	// 添加超时参数
	if s.config.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%ds", s.config.Timeout))
	}

	// 添加漏洞类型
	if s.config.VulnType != "" {
		args = append(args, "--vuln-type", s.config.VulnType)
	}

	// 添加扫描器
	if len(s.config.Scanners) > 0 {
		args = append(args, "--scanners", strings.Join(s.config.Scanners, ","))
	}

	// 添加跳过更新
	if s.config.SkipUpdate {
		args = append(args, "--skip-update")
	}

	// 添加静默模式
	if s.config.Quiet {
		args = append(args, "--quiet")
	}

	// 添加调试模式
	if s.config.Debug {
		args = append(args, "--debug")
	}

	// 添加忽略文件
	if s.config.IgnoreFile != "" {
		args = append(args, "--ignorefile", s.config.IgnoreFile)
	}

	// 添加缓存目录
	if s.config.CacheDir != "" {
		args = append(args, "--cache-dir", s.config.CacheDir)
	}

	return args
}

// parseTrivyOutput 解析Trivy输出
func (s *Scanner) parseTrivyOutput(output []byte, result *ScanResult) error {
	// Trivy的JSON输出格式
	var trivyResult struct {
		Results []struct {
			Target          string `json:"Target"`
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				VulnerabilityID  string            `json:"VulnerabilityID"`
				PkgName          string            `json:"PkgName"`
				InstalledVersion string            `json:"InstalledVersion"`
				FixedVersion     string            `json:"FixedVersion"`
				Title            string            `json:"Title"`
				Description      string            `json:"Description"`
				Severity         string            `json:"Severity"`
				CVSS             map[string]float64 `json:"CVSS"`
				References       []string          `json:"References"`
				PublishedDate    string            `json:"PublishedDate"`
				LastModifiedDate string            `json:"LastModifiedDate"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(output, &trivyResult); err != nil {
		return fmt.Errorf("解析JSON输出失败: %v", err)
	}

	// 转换Trivy结果到我们的格式
	for _, r := range trivyResult.Results {
		for _, vuln := range r.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				VulnerabilityID:  vuln.VulnerabilityID,
				PkgName:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Title:            vuln.Title,
				Description:      vuln.Description,
				Severity:         vuln.Severity,
				CVSS:             vuln.CVSS,
				References:       vuln.References,
				PublishedDate:    vuln.PublishedDate,
				LastModifiedDate: vuln.LastModifiedDate,
			})
		}
	}

	return nil
}

// GetResults 获取扫描结果
func (s *Scanner) GetResults() ([]Vulnerability, error) {
	result, err := s.Scan()
	if err != nil {
		return nil, err
	}
	return result.Vulnerabilities, nil
}

// GenerateReport 生成报告
func (s *Scanner) GenerateReport(outputPath string) error {
	result, err := s.Scan()
	if err != nil {
		return err
	}

	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 生成JSON报告
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化报告失败: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("写入报告文件失败: %v", err)
	}

	if s.verbose {
		fmt.Printf("报告已生成: %s\n", outputPath)
	}

	return nil
}

// checkNetworkConnection 检查网络连接
func (s *Scanner) checkNetworkConnection() bool {
	if s.verbose {
		fmt.Println("检查网络连接...")
	}

	// 尝试ping Google DNS
	cmd := exec.Command("ping", "-c", "1", "-W", "5", "114.114.114.114")
	if err := cmd.Run(); err == nil {
		if s.verbose {
			fmt.Println("网络连接正常 (ping)")
		}
		return true
	}

	// 如果ping失败，尝试curl下载小文件
	cmd = exec.Command("curl", "-s", "--connect-timeout", "10", "--max-time", "30", 
		"-o", "/dev/null", "-w", "%{http_code}", "https://www.baidu.com")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "200" {
		if s.verbose {
			fmt.Println("网络连接正常 (curl)")
		}
		return true
	}

	if s.verbose {
		fmt.Println("网络连接检查失败")
	}
	return false
}

// installTrivy 自动安装Trivy
func (s *Scanner) installTrivy() error {
	if s.verbose {
		fmt.Println("开始自动安装Trivy...")
	}

	// 检测Linux发行版
	distro := s.detectLinuxDistribution()
	if s.verbose {
		fmt.Printf("检测到Linux发行版: %s\n", distro)
	}

	// 根据发行版选择安装方法
	switch distro {
	case "debian", "ubuntu":
		return s.installTrivyOnDebian()
	case "redhat", "centos", "fedora", "rhel":
		return s.installTrivyOnRedhat()
	case "arch":
		return s.installTrivyOnArch()
	case "opensuse", "suse":
		return s.installTrivyOnOpenSUSE()
	default:
		return s.installTrivyGeneric()
	}
}

// detectLinuxDistribution 检测Linux发行版
func (s *Scanner) detectLinuxDistribution() string {
	// 检查/etc/os-release文件
	if _, err := os.Stat("/etc/os-release"); err == nil {
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			content := string(data)
			if strings.Contains(strings.ToLower(content), "debian") {
				return "debian"
			} else if strings.Contains(strings.ToLower(content), "ubuntu") {
				return "ubuntu"
			} else if strings.Contains(strings.ToLower(content), "centos") || 
				strings.Contains(strings.ToLower(content), "redhat") || 
				strings.Contains(strings.ToLower(content), "rhel") {
				return "redhat"
			} else if strings.Contains(strings.ToLower(content), "fedora") {
				return "fedora"
			} else if strings.Contains(strings.ToLower(content), "arch") {
				return "arch"
			} else if strings.Contains(strings.ToLower(content), "opensuse") || 
				strings.Contains(strings.ToLower(content), "suse") {
				return "opensuse"
			}
		}
	}

	// 检查其他发行版标识文件
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	} else if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "redhat"
	} else if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch"
	} else if _, err := os.Stat("/etc/SuSE-release"); err == nil {
		return "opensuse"
	}

	return "unknown"
}

// installTrivyOnDebian 在Debian/Ubuntu系统上安装Trivy
func (s *Scanner) installTrivyOnDebian() error {
	if s.verbose {
		fmt.Println("在Debian/Ubuntu系统上安装Trivy...")
	}

	// 更新包管理器
	cmd := exec.Command("sudo", "apt-get", "update")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("更新包列表失败: %v", err)
	}

	// 安装依赖
	cmd = exec.Command("sudo", "apt-get", "install", "-y", "wget", "gnupg", "lsb-release")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装依赖失败: %v", err)
	}

	// 下载并安装Trivy
	cmd = exec.Command("wget", "-qO", "/tmp/trivy.deb", 
		"https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_linux-64.deb")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("下载Trivy失败: %v", err)
	}

	cmd = exec.Command("sudo", "dpkg", "-i", "/tmp/trivy.deb")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装Trivy失败: %v", err)
	}

	// 清理临时文件
	os.Remove("/tmp/trivy.deb")

	if s.verbose {
		fmt.Println("Trivy安装成功 (Debian/Ubuntu)")
	}
	return nil
}

// installTrivyOnRedhat 在Redhat/CentOS/Fedora系统上安装Trivy
func (s *Scanner) installTrivyOnRedhat() error {
	if s.verbose {
		fmt.Println("在Redhat/CentOS/Fedora系统上安装Trivy...")
	}

	// 检测包管理器类型
	var pkgManager string
	if _, err := exec.LookPath("dnf"); err == nil {
		pkgManager = "dnf"
	} else {
		pkgManager = "yum"
	}

	// 安装依赖
	cmd := exec.Command("sudo", pkgManager, "install", "-y", "wget")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装依赖失败: %v", err)
	}

	// 下载并安装Trivy RPM包
	cmd = exec.Command("wget", "-qO", "/tmp/trivy.rpm", 
		"https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_linux-64.rpm")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("下载Trivy失败: %v", err)
	}

	cmd = exec.Command("sudo", "rpm", "-ivh", "/tmp/trivy.rpm")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装Trivy失败: %v", err)
	}

	// 清理临时文件
	os.Remove("/tmp/trivy.rpm")

	if s.verbose {
		fmt.Println("Trivy安装成功 (Redhat/CentOS/Fedora)")
	}
	return nil
}

// installTrivyOnArch 在Arch Linux系统上安装Trivy
func (s *Scanner) installTrivyOnArch() error {
	if s.verbose {
		fmt.Println("在Arch Linux系统上安装Trivy...")
	}

	// 更新包管理器
	cmd := exec.Command("sudo", "pacman", "-Sy")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("更新包列表失败: %v", err)
	}

	// 从AUR安装Trivy
	cmd = exec.Command("sudo", "pacman", "-S", "--noconfirm", "trivy")
	if err := cmd.Run(); err != nil {
		// 如果pacman安装失败，尝试使用yay
		cmd = exec.Command("yay", "-S", "--noconfirm", "trivy")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("安装Trivy失败: %v", err)
		}
	}

	if s.verbose {
		fmt.Println("Trivy安装成功 (Arch Linux)")
	}
	return nil
}

// installTrivyOnOpenSUSE 在OpenSUSE系统上安装Trivy
func (s *Scanner) installTrivyOnOpenSUSE() error {
	if s.verbose {
		fmt.Println("在OpenSUSE系统上安装Trivy...")
	}

	// 更新包管理器
	cmd := exec.Command("sudo", "zypper", "refresh")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("更新包列表失败: %v", err)
	}

	// 安装依赖
	cmd = exec.Command("sudo", "zypper", "install", "-y", "wget")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装依赖失败: %v", err)
	}

	// 下载并安装Trivy RPM包
	cmd = exec.Command("wget", "-qO", "/tmp/trivy.rpm", 
		"https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_linux-64.rpm")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("下载Trivy失败: %v", err)
	}

	cmd = exec.Command("sudo", "rpm", "-ivh", "/tmp/trivy.rpm")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装Trivy失败: %v", err)
	}

	// 清理临时文件
	os.Remove("/tmp/trivy.rpm")

	if s.verbose {
		fmt.Println("Trivy安装成功 (OpenSUSE)")
	}
	return nil
}

// installTrivyGeneric 通用安装方法（使用curl和tar）
func (s *Scanner) installTrivyGeneric() error {
	if s.verbose {
		fmt.Println("使用通用方法安装Trivy...")
	}

	// 下载Trivy二进制文件
	cmd := exec.Command("curl", "-sfL", "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh")
	installScript := exec.Command("sh", "-s", "--", "-b", "/usr/local/bin", "v0.50.1")
	installScript.Stdin, _ = cmd.StdoutPipe()

	if err := installScript.Start(); err != nil {
		return fmt.Errorf("启动安装脚本失败: %v", err)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("下载安装脚本失败: %v", err)
	}

	if err := installScript.Wait(); err != nil {
		return fmt.Errorf("执行安装脚本失败: %v", err)
	}

	if s.verbose {
		fmt.Println("Trivy安装成功 (通用方法)")
	}
	return nil
}