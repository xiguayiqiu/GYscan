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

// ScanResult 定义Trivy扫描结果结构
type ScanResult struct {
	Target          string          `json:"target"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScanTime        time.Time       `json:"scan_time"`
	ScanDuration    string          `json:"scan_duration"`
	TotalVulns      int             `json:"total_vulnerabilities"`
}

// Vulnerability 定义漏洞信息结构
type Vulnerability struct {
	VulnerabilityID  string   `json:"vulnerability_id"`
	PkgName          string   `json:"pkg_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	References       []string `json:"references"`
}

// Scanner 定义Trivy扫描器
type Scanner struct {
	config  *Config
	verbose bool
	results *ScanResult
}

// NewScanner 创建新的Trivy扫描器
func NewScanner(config *Config, verbose bool) *Scanner {
	return &Scanner{
		config:  config,
		verbose: verbose,
		results: &ScanResult{
			ScanTime: time.Now(),
		},
	}
}

// Scan 执行Trivy扫描
func (s *Scanner) Scan() error {
	// 检查Trivy是否安装
	if !s.isTrivyInstalled() {
		return fmt.Errorf("Trivy未安装，请先安装Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
	}

	// 构建Trivy命令参数
	args := s.buildTrivyArgs()

	// 执行Trivy命令
	cmd := exec.Command("trivy", args...)
	
	if s.verbose {
		fmt.Printf("执行命令: trivy %s\n", strings.Join(args, " "))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("Trivy命令输出: %s\n", string(output))
		}
		return fmt.Errorf("Trivy扫描失败: %v", err)
	}

	// 解析Trivy输出
	s.results, err = s.parseTrivyOutput(output)
	if err != nil {
		return fmt.Errorf("解析Trivy输出失败: %v", err)
	}

	s.results.ScanDuration = time.Since(s.results.ScanTime).String()
	s.results.TotalVulns = len(s.results.Vulnerabilities)

	if s.verbose {
		fmt.Printf("扫描完成，发现 %d 个漏洞\n", s.results.TotalVulns)
	}

	return nil
}

// isTrivyInstalled 检查Trivy是否安装
func (s *Scanner) isTrivyInstalled() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
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
		args = append(args, "--timeout", s.config.Timeout.String())
	}

	// 静默模式
	if s.config.Quiet {
		args = append(args, "--quiet")
	}

	// 调试模式
	if s.config.Debug {
		args = append(args, "--debug")
	}

	// 添加输出到文件（如果指定了输出文件）
	if s.config.Output != "" {
		args = append(args, "--output", s.config.Output)
	}

	return args
}

// parseTrivyOutput 解析Trivy JSON输出
func (s *Scanner) parseTrivyOutput(output []byte) (*ScanResult, error) {
	var result ScanResult
	
	// 如果输出为空，返回空结果
	if len(output) == 0 {
		return &result, nil
	}

	// 尝试解析JSON输出
	err := json.Unmarshal(output, &result)
	if err != nil {
		// 如果JSON解析失败，可能是表格格式或其他格式
		// 在这种情况下，我们创建一个基本的结果结构
		result.Target = s.config.Target
		result.Vulnerabilities = []Vulnerability{}
		
		if s.verbose {
			fmt.Printf("警告: 无法解析Trivy输出为JSON，使用空结果: %v\n", err)
		}
	}

	return &result, nil
}

// GetResults 获取扫描结果
func (s *Scanner) GetResults() *ScanResult {
	return s.results
}

// GenerateReport 生成JSON格式报告
func (s *Scanner) GenerateReport(outputPath string) error {
	// 如果已经通过命令行参数生成了输出文件，直接返回
	if s.config.Output != "" && s.config.Output == outputPath {
		return nil
	}

	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 生成JSON报告
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化扫描结果失败: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("写入报告文件失败: %v", err)
	}

	return nil
}