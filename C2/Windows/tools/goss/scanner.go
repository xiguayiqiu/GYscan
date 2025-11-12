package goss

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"golang.org/x/sys/windows/registry"
)

// ScanResult 扫描结果结构体
type ScanResult struct {
	Target        string          `json:"target"`
	Timestamp     time.Time       `json:"timestamp"`
	ScanDuration  time.Duration   `json:"scan_duration"`
	Summary       Summary         `json:"summary"`
	Results       []TestResult    `json:"results"`
	Error         string          `json:"error,omitempty"`
}

// Summary 扫描摘要
type Summary struct {
	TestCount    int `json:"test_count"`
	FailedCount  int `json:"failed_count"`
	SkippedCount int `json:"skipped_count"`
	TotalCount   int `json:"total_count"`
}

// TestResult 测试结果
type TestResult struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Meta        Meta   `json:"meta"`
	Duration    int64  `json:"duration"`
	Result      int    `json:"result"`
	Successful  bool   `json:"successful"`
	Skipped     bool   `json:"skipped"`
}

// Meta 测试元数据
type Meta struct {
	Property string `json:"property"`
	Pattern  string `json:"pattern"`
}

// Scanner Goss扫描器结构体
type Scanner struct {
	config  *Config
	verbose bool
}

// NewScanner 创建新的Goss扫描器
func NewScanner(config *Config, verbose bool) *Scanner {
	return &Scanner{
		config:  config,
		verbose: verbose,
	}
}

// Scan 执行Goss扫描
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Target:    s.config.Target,
		Timestamp: time.Now(),
	}

	if s.verbose {
		fmt.Printf("开始Goss扫描: %s\n", s.config.Target)
	}

	// 检查Goss是否安装
	if !s.isGossInstalled() {
		// 如果Goss未安装，使用内置的Windows配置审计
		return s.performBuiltinWindowsAudit(result)
	}

	// 构建Goss命令参数
	args := s.buildGossArgs()

	if s.verbose {
		fmt.Printf("执行命令: goss %s\n", strings.Join(args, " "))
	}

	// 执行Goss命令
	cmd := exec.Command("goss", args...)
	output, err := cmd.CombinedOutput()

	result.ScanDuration = time.Since(result.Timestamp)

	if err != nil {
		if s.verbose {
			fmt.Printf("Goss扫描错误: %v\n", err)
			fmt.Printf("输出: %s\n", string(output))
		}
		result.Error = fmt.Sprintf("Goss执行错误: %v", err)
		return result, err
	}

	// 解析Goss输出
	if err := s.parseGossOutput(output, result); err != nil {
		if s.verbose {
			fmt.Printf("解析Goss输出错误: %v\n", err)
		}
		result.Error = fmt.Sprintf("解析输出错误: %v", err)
		return result, err
	}

	if s.verbose {
		fmt.Printf("Goss扫描完成，执行 %d 个测试，失败 %d 个，跳过 %d 个，耗时 %v\n",
			result.Summary.TotalCount, result.Summary.FailedCount, result.Summary.SkippedCount, result.ScanDuration)
	}

	return result, nil
}

// isGossInstalled 检查Goss是否安装
func (s *Scanner) isGossInstalled() bool {
	cmd := exec.Command("goss", "--version")
	return cmd.Run() == nil
}

// buildGossArgs 构建Goss命令参数
func (s *Scanner) buildGossArgs() []string {
	args := []string{"validate"}

	// 添加配置文件
	if s.config.GossFile != "" {
		args = append(args, "--gossfile", s.config.GossFile)
	}

	// 添加输出格式
	if s.config.Format != "" {
		args = append(args, "--format", s.config.Format)
	}

	// 添加重试超时
	if s.config.RetryTimeout > 0 {
		args = append(args, "--retry-timeout", fmt.Sprintf("%ds", s.config.RetryTimeout))
	}

	// 添加检查间隔
	if s.config.Sleep > 0 {
		args = append(args, "--sleep", fmt.Sprintf("%dms", s.config.Sleep))
	}

	// 添加详细模式
	if s.config.Verbose {
		args = append(args, "--verbose")
	}

	// 添加静默模式
	if s.config.Quiet {
		args = append(args, "--quiet")
	}

	// 添加调试模式
	if s.config.Debug {
		args = append(args, "--debug")
	}

	// 添加输出文件
	if s.config.Output != "" {
		args = append(args, "--output-file", s.config.Output)
	}

	return args
}

// parseGossOutput 解析Goss输出
func (s *Scanner) parseGossOutput(output []byte, result *ScanResult) error {
	// 尝试解析JSON格式的输出
	var gossOutput struct {
		Summary Summary     `json:"summary"`
		Results []TestResult `json:"results"`
	}

	if err := json.Unmarshal(output, &gossOutput); err != nil {
		// 如果不是JSON格式，尝试解析其他格式
		return s.parseTextGossOutput(output, result)
	}

	result.Summary = gossOutput.Summary
	result.Results = gossOutput.Results

	return nil
}

// parseTextGossOutput 解析文本格式的Goss输出
func (s *Scanner) parseTextGossOutput(output []byte, result *ScanResult) error {
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	// 解析摘要信息
	totalCount := 0
	failedCount := 0
	skippedCount := 0
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "Total Duration:") {
			// 解析测试统计信息
			if strings.Contains(line, "Count:") {
				// 简化解析逻辑
				totalCount = len(result.Results)
				failedCount = s.countFailedTests(result.Results)
				skippedCount = s.countSkippedTests(result.Results)
			}
		}
	}

	// 设置摘要信息
	result.Summary = Summary{
		TotalCount:   totalCount,
		FailedCount:  failedCount,
		SkippedCount: skippedCount,
		TestCount:    totalCount,
	}

	return nil
}

// performBuiltinWindowsAudit 执行内置的Windows配置审计
func (s *Scanner) performBuiltinWindowsAudit(result *ScanResult) (*ScanResult, error) {
	if s.verbose {
		fmt.Println("Goss未安装，执行内置Windows配置审计...")
	}

	// 执行Windows系统配置审计
	results := s.auditWindowsConfiguration()
	
	result.Results = results
	result.Summary.TotalCount = len(results)
	result.Summary.FailedCount = s.countFailedTests(results)
	result.Summary.SkippedCount = s.countSkippedTests(results)
	result.ScanDuration = time.Since(result.Timestamp)

	if s.verbose {
		fmt.Printf("内置Windows审计完成，执行 %d 个测试，失败 %d 个，跳过 %d 个，耗时 %v\n",
			result.Summary.TotalCount, result.Summary.FailedCount, result.Summary.SkippedCount, result.ScanDuration)
	}

	return result, nil
}

// auditWindowsConfiguration 审计Windows系统配置
func (s *Scanner) auditWindowsConfiguration() []TestResult {
	var results []TestResult

	// 1. 检查Windows服务配置
	results = append(results, s.auditWindowsServices()...)
	
	// 2. 检查注册表安全配置
	results = append(results, s.auditRegistrySettings()...)
	
	// 3. 检查文件系统权限
	results = append(results, s.auditFilePermissions()...)
	
	// 4. 检查用户和组策略
	results = append(results, s.auditUserAndGroupPolicies()...)
	
	// 5. 检查网络配置
	results = append(results, s.auditNetworkConfiguration()...)

	return results
}

// auditWindowsServices 审计Windows服务配置
func (s *Scanner) auditWindowsServices() []TestResult {
	var results []TestResult
	
	// 检查关键服务状态
	criticalServices := []struct {
		name     string
		shouldRun bool
	}{
		{"WinDefend", true},  // Windows Defender服务的实际名称
		{"MpsSvc", true},     // Windows Firewall服务的实际名称
		{"RemoteRegistry", false},  // Remote Registry服务的实际名称
		{"TlntSvr", false},  // Telnet服务的实际名称
		{"TermService", true},  // Remote Desktop Services服务的实际名称
	}

	for _, service := range criticalServices {
		result := TestResult{
			ID:         fmt.Sprintf("service-%s", strings.ReplaceAll(service.name, " ", "-")),
			Title:      fmt.Sprintf("检查服务 %s 状态", service.name),
			Meta:       Meta{Property: "service", Pattern: service.name},
			Duration:   100,
			Successful: s.checkServiceStatus(service.name, service.shouldRun),
			Skipped:    false,
		}
		results = append(results, result)
	}

	return results
}

// auditRegistrySettings 审计注册表安全配置
func (s *Scanner) auditRegistrySettings() []TestResult {
	var results []TestResult
	
	// 检查关键注册表项
	registryChecks := []struct {
		path    string
		value   string
		expected string
	}{
		{"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "EnableSecuritySignature", "1"},
		{"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", "RequireSignOrSeal", "1"},
		{"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", "1"},
	}

	for _, check := range registryChecks {
		result := TestResult{
			ID:         fmt.Sprintf("registry-%s", strings.ReplaceAll(check.path, "\\", "-")),
			Title:      fmt.Sprintf("检查注册表 %s", check.path),
			Meta:       Meta{Property: "registry", Pattern: check.path},
			Duration:   150,
			Successful: s.checkRegistryValue(check.path, check.value, check.expected),
			Skipped:    false,
		}
		results = append(results, result)
	}

	return results
}

// auditFilePermissions 审计文件系统权限
func (s *Scanner) auditFilePermissions() []TestResult {
	var results []TestResult
	
	// 检查关键目录权限
	criticalPaths := []string{
		"C:\\Windows\\System32",
		"C:\\Windows\\SysWOW64",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
	}

	for _, path := range criticalPaths {
		result := TestResult{
			ID:         fmt.Sprintf("file-permission-%s", strings.ReplaceAll(path, "\\", "-")),
			Title:      fmt.Sprintf("检查目录权限 %s", path),
			Meta:       Meta{Property: "file", Pattern: path},
			Duration:   200,
			Successful: s.checkDirectoryPermissions(path),
			Skipped:    false,
		}
		results = append(results, result)
	}

	return results
}

// auditUserAndGroupPolicies 审计用户和组策略
func (s *Scanner) auditUserAndGroupPolicies() []TestResult {
	var results []TestResult
	
	// 检查用户策略
	userPolicyChecks := []struct {
		title    string
		checkFn  func() bool
	}{
		{"检查密码策略复杂度要求", s.checkPasswordComplexity},
		{"检查账户锁定策略", s.checkAccountLockoutPolicy},
		{"检查管理员账户状态", s.checkAdministratorAccount},
		{"检查Guest账户状态", s.checkGuestAccount},
	}

	for i, check := range userPolicyChecks {
		result := TestResult{
			ID:         fmt.Sprintf("user-policy-%d", i+1),
			Title:      check.title,
			Meta:       Meta{Property: "user-policy", Pattern: check.title},
			Duration:   120,
			Successful: check.checkFn(),
			Skipped:    false,
		}
		results = append(results, result)
	}

	return results
}

// auditNetworkConfiguration 审计网络配置
func (s *Scanner) auditNetworkConfiguration() []TestResult {
	var results []TestResult
	
	// 检查网络配置
	networkChecks := []struct {
		title    string
		checkFn  func() bool
	}{
		{"检查防火墙状态", s.checkFirewallStatus},
		{"检查远程桌面配置", s.checkRemoteDesktopConfig},
		{"检查网络共享配置", s.checkNetworkSharing},
		{"检查UAC状态", s.checkUACStatus},
		{"检查自动运行禁用状态", s.checkAutoRunDisabled},
		{"检查SMBv1禁用状态", s.checkSMBv1Disabled},
	}

	for i, check := range networkChecks {
		result := TestResult{
			ID:         fmt.Sprintf("network-config-%d", i+1),
			Title:      check.title,
			Meta:       Meta{Property: "network", Pattern: check.title},
			Duration:   180,
			Successful: check.checkFn(),
			Skipped:    false,
		}
		results = append(results, result)
	}

	return results
}

// 以下为Windows配置检查的辅助函数（真实实现）

func (s *Scanner) checkServiceStatus(serviceName string, shouldRun bool) bool {
	// 使用sc query命令检查服务状态
	cmd := exec.Command("sc", "query", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 检查错误类型，如果是服务不存在（1060错误），则根据shouldRun判断
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1060 {
				// 服务不存在，如果shouldRun为false，则视为通过（服务不存在且不应该运行）
				if !shouldRun {
					if s.verbose {
						fmt.Printf("服务 %s 不存在，符合预期（不应该运行）\n", serviceName)
					}
					return true
				}
				// 服务不存在但应该运行，视为失败
				if s.verbose {
					fmt.Printf("服务 %s 不存在，但应该运行\n", serviceName)
				}
				return false
			}
		}
		// 其他错误，尝试使用PowerShell作为备用检查方法
		if s.verbose {
			fmt.Printf("检查服务 %s 状态失败，尝试PowerShell备用检查: %v\n", serviceName, err)
		}
		return s.checkServiceStatusWithPowerShell(serviceName, shouldRun)
	}
	
	// 解析服务状态
	statusRegex := regexp.MustCompile(`STATE\s+:\s+(\d+)\s+`)
	matches := statusRegex.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		// 如果正则匹配失败，尝试使用PowerShell备用检查
		if s.verbose {
			fmt.Printf("无法解析服务 %s 状态，尝试PowerShell备用检查\n", serviceName)
		}
		return s.checkServiceStatusWithPowerShell(serviceName, shouldRun)
	}
	
	state, err := strconv.Atoi(matches[1])
	if err != nil {
		// 如果状态解析失败，尝试使用PowerShell备用检查
		if s.verbose {
			fmt.Printf("解析服务 %s 状态失败，尝试PowerShell备用检查: %v\n", serviceName, err)
		}
		return s.checkServiceStatusWithPowerShell(serviceName, shouldRun)
	}
	
	// 状态4表示运行中，状态1表示已停止
	isRunning := state == 4
	
	if s.verbose {
		statusText := "运行中"
		if !isRunning {
			statusText = "已停止"
		}
		expectedText := "应该运行"
		if !shouldRun {
			expectedText = "应该停止"
		}
		fmt.Printf("服务 %s 状态: %s, 期望: %s, 结果: %v\n", 
			serviceName, statusText, expectedText, isRunning == shouldRun)
	}
	
	return isRunning == shouldRun
}

// checkServiceStatusWithPowerShell 使用PowerShell检查服务状态
func (s *Scanner) checkServiceStatusWithPowerShell(serviceName string, shouldRun bool) bool {
	// 使用PowerShell命令检查服务状态
	cmd := exec.Command("powershell", "Get-Service", "-Name", serviceName, "-ErrorAction", "SilentlyContinue", "|", "Select-Object", "Name,Status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果服务不存在，根据shouldRun判断
		if strings.Contains(string(output), "找不到任何服务") || 
		   strings.Contains(string(output), "NoServiceFoundForGivenName") {
			// 服务不存在，如果shouldRun为false，则视为通过（服务不存在且不应该运行）
			if !shouldRun {
				if s.verbose {
					fmt.Printf("服务 %s 不存在，符合预期（不应该运行）\n", serviceName)
				}
				return true
			}
			// 服务不存在但应该运行，视为失败
			if s.verbose {
				fmt.Printf("服务 %s 不存在，但应该运行\n", serviceName)
			}
			return false
		}
		
		if s.verbose {
			fmt.Printf("PowerShell检查服务 %s 状态失败: %v\n", serviceName, err)
		}
		return false
	}
	
	outputStr := string(output)
	if s.verbose {
		fmt.Printf("PowerShell服务检查输出: %s\n", outputStr)
	}
	
	// 检查服务是否存在
	if strings.Contains(outputStr, "找不到任何服务") || 
	   strings.Contains(outputStr, "NoServiceFoundForGivenName") ||
	   strings.TrimSpace(outputStr) == "" {
		// 服务不存在，根据shouldRun判断
		if !shouldRun {
			if s.verbose {
				fmt.Printf("服务 %s 不存在，符合预期（不应该运行）\n", serviceName)
			}
			return true
		}
		// 服务不存在但应该运行，视为失败
		if s.verbose {
			fmt.Printf("服务 %s 不存在，但应该运行\n", serviceName)
		}
		return false
	}
	
	// 检查服务状态
	isRunning := strings.Contains(outputStr, "Running")
	
	if s.verbose {
		statusText := "运行中"
		if !isRunning {
			statusText = "已停止"
		}
		expectedText := "应该运行"
		if !shouldRun {
			expectedText = "应该停止"
		}
		fmt.Printf("PowerShell检查 - 服务 %s 状态: %s, 期望: %s, 结果: %v\n", 
			serviceName, statusText, expectedText, isRunning == shouldRun)
	}
	
	return isRunning == shouldRun
}

func (s *Scanner) checkRegistryValue(path, value, expected string) bool {
	// 解析注册表路径
	parts := strings.Split(path, "\\")
	if len(parts) < 2 {
		return false
	}
	
	var key registry.Key
	var err error
	
	// 打开注册表键
	switch parts[0] {
	case "HKEY_LOCAL_MACHINE":
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, strings.Join(parts[1:], "\\"), registry.READ)
	case "HKEY_CURRENT_USER":
		key, err = registry.OpenKey(registry.CURRENT_USER, strings.Join(parts[1:], "\\"), registry.READ)
	case "HKEY_CLASSES_ROOT":
		key, err = registry.OpenKey(registry.CLASSES_ROOT, strings.Join(parts[1:], "\\"), registry.READ)
	case "HKEY_USERS":
		key, err = registry.OpenKey(registry.USERS, strings.Join(parts[1:], "\\"), registry.READ)
	case "HKEY_CURRENT_CONFIG":
		key, err = registry.OpenKey(registry.CURRENT_CONFIG, strings.Join(parts[1:], "\\"), registry.READ)
	default:
		return false
	}
	
	if err != nil {
		if s.verbose {
			fmt.Printf("打开注册表键 %s 失败: %v\n", path, err)
		}
		return false
	}
	defer key.Close()
	
	// 尝试读取不同类型的注册表值
	
	// 1. 尝试读取字符串值
	if strVal, _, err := key.GetStringValue(value); err == nil {
		return strVal == expected
	}
	
	// 2. 尝试读取整数值
	if intVal, _, err := key.GetIntegerValue(value); err == nil {
		expectedInt, err := strconv.ParseUint(expected, 10, 64)
		if err == nil {
			return intVal == expectedInt
		}
	}
	
	// 3. 尝试读取二进制值（转换为十六进制字符串比较）
	if binVal, _, err := key.GetBinaryValue(value); err == nil {
		expectedBin := []byte(expected)
		return string(binVal) == string(expectedBin)
	}
	
	// 4. 尝试读取多字符串值
	if multiVal, _, err := key.GetStringsValue(value); err == nil {
		expectedMulti := strings.Split(expected, ",")
		if len(multiVal) == len(expectedMulti) {
			for i, val := range multiVal {
				if val != expectedMulti[i] {
					return false
				}
			}
			return true
		}
	}
	
	if s.verbose {
		fmt.Printf("无法读取或匹配注册表值 %s\\%s，期望值: %s\n", path, value, expected)
	}
	
	return false
}

func (s *Scanner) checkDirectoryPermissions(path string) bool {
	// 检查关键目录的权限
	criticalDirs := []struct {
		path          string
		shouldWritable bool
		description   string
	}{
		{"C:\\Windows\\System32", false, "系统目录"},
		{"C:\\Windows\\SysWOW64", false, "系统目录"},
		{"C:\\Program Files", false, "程序目录"},
		{"C:\\Program Files (x86)", false, "程序目录"},
		{"C:\\Users\\Public", true, "公共目录"},
		{"C:\\Temp", true, "临时目录"},
	}

	// 查找匹配的目录配置
	var dirInfo struct {
		path          string
		shouldWritable bool
		description   string
	}
	found := false
	
	for _, d := range criticalDirs {
		if d.path == path {
			dirInfo = d
			found = true
			break
		}
	}
	
	if !found {
		if s.verbose {
			fmt.Printf("未找到目录 %s 的配置信息\n", path)
		}
		return false
	}

	dir := dirInfo.path
	shouldWritable := dirInfo.shouldWritable
	description := dirInfo.description
	
	// 检查目录是否存在
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if s.verbose {
			fmt.Printf("目录 %s (%s) 不存在\n", dir, description)
		}
		// 目录不存在，根据安全要求判断
		// 系统目录应该存在，程序目录可能不存在
		if strings.Contains(dir, "Windows") || strings.Contains(dir, "Program Files") {
			return false  // 系统目录应该存在
		}
		return true  // 其他目录不存在可以接受
	}

	// 检查目录是否可读
	if _, err := os.ReadDir(dir); err != nil {
		if s.verbose {
			fmt.Printf("目录 %s (%s) 不可读: %v\n", dir, description, err)
		}
		return false
	}

	// 检查目录是否可写（尝试创建临时文件）
	testFile := filepath.Join(dir, "goss_test.tmp")
	file, err := os.Create(testFile)
	if err != nil {
		if shouldWritable {
			// 应该可写但不可写，标记失败
			if s.verbose {
				fmt.Printf("目录 %s (%s) 不可写（应该可写）: %v\n", dir, description, err)
			}
			return false
		} else {
			// 不应该可写且不可写，符合预期
			if s.verbose {
				fmt.Printf("目录 %s (%s) 不可写（符合预期）: %v\n", dir, description, err)
			}
			return true
		}
	} else {
		file.Close()
		os.Remove(testFile)
		if !shouldWritable {
			// 不应该可写但可写，标记失败
			if s.verbose {
				fmt.Printf("目录 %s (%s) 可写（不应该可写）\n", dir, description)
			}
			return false
		} else {
			// 应该可写且可写，符合预期
			if s.verbose {
				fmt.Printf("目录 %s (%s) 可写（符合预期）\n", dir, description)
			}
			return true
		}
	}

	// 检查目录是否可执行（尝试列出内容）
	cmd := exec.Command("cmd", "/c", "dir", dir)
	if err := cmd.Run(); err != nil {
		if s.verbose {
			fmt.Printf("目录 %s (%s) 不可执行: %v\n", dir, description, err)
		}
		return false
	} else {
		if s.verbose {
			fmt.Printf("目录 %s (%s) 可执行（符合预期）\n", dir, description)
		}
	}

	// 检查危险权限
	cmd = exec.Command("icacls", dir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)
		// 检查是否存在危险权限
		dangerousPermissions := []string{
			"Everyone:(F)",      // Everyone完全控制
			"Users:(F)",          // Users完全控制
			"Authenticated Users:(F)", // 认证用户完全控制
		}
		
		for _, perm := range dangerousPermissions {
			if strings.Contains(outputStr, perm) {
				if s.verbose {
					fmt.Printf("目录 %s (%s) 存在危险权限: %s\n", dir, description, perm)
				}
				return false
			}
		}

		// 检查安全权限
		safePermissions := []string{
			"SYSTEM:(F)",          // SYSTEM完全控制
			"Administrators:(F)",   // 管理员完全控制
		}
		
		for _, perm := range safePermissions {
			if strings.Contains(outputStr, perm) {
				if s.verbose {
					fmt.Printf("目录 %s (%s) 存在安全权限: %s\n", dir, description, perm)
				}
			}
		}
	}

	return true
}

func (s *Scanner) checkPasswordComplexity() bool {
	// 使用net accounts命令检查密码策略
	cmd := exec.Command("net", "accounts")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查密码策略失败: %v\n", err)
		}
		return false
	}
	
	outputStr := string(output)
	if s.verbose {
		fmt.Printf("密码策略检查输出: %s\n", outputStr)
	}
	
	// 检查是否启用了密码复杂度要求
	if !strings.Contains(outputStr, "Password complexity requirements: Enabled") && 
	   !strings.Contains(outputStr, "密码复杂性要求: 已启用") {
		if s.verbose {
			fmt.Printf("密码复杂度要求未启用\n")
		}
		return false
	}

	// 检查密码最小长度
	if !strings.Contains(outputStr, "Minimum password length:") && 
	   !strings.Contains(outputStr, "密码最短使用期限:") {
		if s.verbose {
			fmt.Printf("未找到密码最小长度设置\n")
		}
		return false
	}

	// 检查密码历史记录
	if !strings.Contains(outputStr, "Length of password history maintained:") && 
	   !strings.Contains(outputStr, "强制密码历史:") {
		if s.verbose {
			fmt.Printf("未找到密码历史记录设置\n")
		}
		return false
	}

	// 检查账户锁定策略
	if !strings.Contains(outputStr, "Lockout threshold:") && 
	   !strings.Contains(outputStr, "锁定阈值:") {
		if s.verbose {
			fmt.Printf("未找到账户锁定阈值设置\n")
		}
		return false
	}

	if s.verbose {
		fmt.Printf("密码策略检查通过\n")
	}
	return true
}

func (s *Scanner) checkAccountLockoutPolicy() bool {
	// 检查账户锁定策略
	cmd := exec.Command("net", "accounts")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查账户锁定策略失败: %v\n", err)
		}
		return false
	}

	outputStr := string(output)
	
	// 检查锁定阈值（中英文系统匹配）
	if !strings.Contains(outputStr, "Lockout threshold:") && 
	   !strings.Contains(outputStr, "锁定阈值:") {
		if s.verbose {
			fmt.Printf("未找到账户锁定阈值设置\n")
		}
		return false
	}

	// 检查锁定持续时间（中英文系统匹配）
	if !strings.Contains(outputStr, "Lockout duration:") && 
	   !strings.Contains(outputStr, "锁定持续时间:") {
		if s.verbose {
			fmt.Printf("未找到锁定持续时间设置\n")
		}
		return false
	}

	// 检查锁定观察窗口（中英文系统匹配）
	if !strings.Contains(outputStr, "Lockout observation window:") && 
	   !strings.Contains(outputStr, "锁定观察窗口:") {
		if s.verbose {
			fmt.Printf("未找到锁定观察窗口设置\n")
		}
		return false
	}

	if s.verbose {
		fmt.Printf("账户锁定策略检查通过\n")
	}
	return true
}

func (s *Scanner) checkAdministratorAccount() bool {
	// 检查管理员账户是否启用
	cmd := exec.Command("net", "user", "administrator")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查管理员账户状态失败: %v\n", err)
		}
		// 如果命令执行失败，可能是账户不存在或权限问题
		// 尝试使用PowerShell命令
		cmd2 := exec.Command("powershell", "Get-LocalUser -Name 'Administrator' | Select-Object Enabled")
		output2, err2 := cmd2.CombinedOutput()
		if err2 == nil {
			outputStr2 := string(output2)
			if s.verbose {
				fmt.Printf("PowerShell管理员账户检查输出: %s\n", outputStr2)
			}
			
			// 检查账户是否禁用
			if strings.Contains(outputStr2, "False") {
				if s.verbose {
					fmt.Println("管理员账户已禁用（通过PowerShell检查）")
				}
				return true
			}
			
			if strings.Contains(outputStr2, "True") {
				if s.verbose {
					fmt.Println("管理员账户已启用（通过PowerShell检查）")
				}
				return false
			}
		}
		
		return false
	}
	
	outputStr := string(output)
	if s.verbose {
		fmt.Printf("管理员账户检查输出: %s\n", outputStr)
	}
	
	// 检查账户状态 - 管理员账户应该被禁用（安全最佳实践）
	// 所以如果账户被禁用，返回true（符合安全要求）
	
	// 中文系统检查
	if strings.Contains(outputStr, "账户启用") && strings.Contains(outputStr, "No") {
		if s.verbose {
			fmt.Println("管理员账户已禁用（符合安全要求）")
		}
		return true
	}
	
	// 英文系统检查
	if strings.Contains(outputStr, "Account active") && strings.Contains(outputStr, "No") {
		if s.verbose {
			fmt.Println("管理员账户已禁用（符合安全要求）")
		}
		return true
	}
	
	// 如果账户启用，检查是否启用了
	if (strings.Contains(outputStr, "账户启用") && strings.Contains(outputStr, "Yes")) || 
	   (strings.Contains(outputStr, "Account active") && strings.Contains(outputStr, "Yes")) {
		if s.verbose {
			fmt.Println("管理员账户已启用（不符合安全要求）")
		}
		return false
	}
	
	if s.verbose {
		fmt.Println("无法确定管理员账户状态")
	}
	
	return false
}

func (s *Scanner) checkFirewallStatus() bool {
	// 检查防火墙状态
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查防火墙状态失败: %v\n", err)
		}
		return false
	}

	outputStr := string(output)
	if s.verbose {
		fmt.Printf("防火墙状态检查输出: %s\n", outputStr)
	}
	
	// 检查防火墙状态 - 使用更灵活的匹配方式
	// 中文系统检查
	if strings.Contains(outputStr, "状态") && strings.Contains(outputStr, "打开") {
		if s.verbose {
			fmt.Println("防火墙已启用（符合安全要求）")
		}
		return true
	}
	
	// 英文系统检查
	if strings.Contains(outputStr, "State") && strings.Contains(outputStr, "ON") {
		if s.verbose {
			fmt.Println("防火墙已启用（符合安全要求）")
		}
		return true
	}
	
	// 检查防火墙是否关闭
	if (strings.Contains(outputStr, "状态") && strings.Contains(outputStr, "关闭")) || 
	   (strings.Contains(outputStr, "State") && strings.Contains(outputStr, "OFF")) {
		if s.verbose {
			fmt.Println("防火墙未启用（不符合安全要求）")
		}
		return false
	}
	
	// 尝试使用PowerShell命令检查防火墙状态
	cmd2 := exec.Command("powershell", "Get-NetFirewallProfile | Select-Object Name, Enabled")
	output2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		outputStr2 := string(output2)
		if s.verbose {
			fmt.Printf("PowerShell防火墙检查输出: %s\n", outputStr2)
		}
		
		// 检查是否有启用的防火墙配置文件
		if strings.Contains(outputStr2, "True") {
			if s.verbose {
				fmt.Println("防火墙已启用（通过PowerShell检查）")
			}
			return true
		}
		
		if strings.Contains(outputStr2, "False") {
			if s.verbose {
				fmt.Println("防火墙未启用（通过PowerShell检查）")
			}
			return false
		}
	}
	
	if s.verbose {
		fmt.Println("无法确定防火墙状态")
	}
	
	return false
}

func (s *Scanner) checkRemoteDesktopConfig() bool {
	// 检查远程桌面配置
	cmd := exec.Command("reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查远程桌面配置失败: %v\n", err)
		}
		return false
	}
	
	outputStr := string(output)
	if s.verbose {
		fmt.Printf("远程桌面配置检查输出: %s\n", outputStr)
	}
	
	// 检查远程桌面是否启用（fDenyTSConnections为0表示启用）
	rdpRegex := regexp.MustCompile(`fDenyTSConnections\s+REG_DWORD\s+0x0`)
	if rdpRegex.MatchString(outputStr) {
		if s.verbose {
			fmt.Println("远程桌面已启用（不符合安全要求）")
		}
		return false
	}
	
	// 检查远程桌面是否禁用（fDenyTSConnections为1表示禁用）
	rdpDisabledRegex := regexp.MustCompile(`fDenyTSConnections\s+REG_DWORD\s+0x1`)
	if rdpDisabledRegex.MatchString(outputStr) {
		if s.verbose {
			fmt.Println("远程桌面已禁用（符合安全要求）")
		}
		return true
	}
	
	if s.verbose {
		fmt.Println("无法确定远程桌面配置状态")
	}
	
	return false
}

func (s *Scanner) checkNetworkSharing() bool {
	// 检查网络共享配置
	cmd := exec.Command("net", "share")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	
	// 如果有共享资源，检查共享权限
	shareRegex := regexp.MustCompile(`共享名\s+资源\s+备注`)
	if shareRegex.MatchString(string(output)) {
		// 有共享资源，需要进一步检查权限
		return s.checkNetworkSharePermissions()
	}
	
	// 没有共享资源，安全性较高
	return true
}

func (s *Scanner) checkNetworkSharePermissions() bool {
	// 简化实现：检查默认共享权限
	// 实际应该检查每个共享的详细权限
	cmd := exec.Command("net", "share")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	
	// 检查是否有默认共享（如C$, ADMIN$等）
	defaultShares := []string{"C$", "ADMIN$", "IPC$"}
	for _, share := range defaultShares {
		if strings.Contains(string(output), share) {
			// 存在默认共享，安全性较低
			return false
		}
	}
	
	return true
}

func (s *Scanner) checkUACStatus() bool {
	// 检查用户账户控制(UAC)状态
	cmd := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	
	// UAC启用时EnableLUA为1
	uacRegex := regexp.MustCompile(`EnableLUA\s+REG_DWORD\s+0x1`)
	return uacRegex.MatchString(string(output))
}

func (s *Scanner) checkAutoRunDisabled() bool {
	// 检查自动运行是否禁用
	cmd := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "/v", "NoDriveTypeAutoRun")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查自动运行禁用状态失败: %v\n", err)
		}
		return false
	}
	
	outputStr := string(output)
	if s.verbose {
		fmt.Printf("自动运行检查输出: %s\n", outputStr)
	}
	
	// NoDriveTypeAutoRun为255表示禁用所有驱动器的自动运行
	if strings.Contains(outputStr, "NoDriveTypeAutoRun") && strings.Contains(outputStr, "0xff") {
		if s.verbose {
			fmt.Println("自动运行已禁用（符合安全要求）")
		}
		return true
	}
	
	// 检查其他可能的自动运行注册表项
	cmd2 := exec.Command("reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "/v", "NoDriveAutoRun")
	output2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		outputStr2 := string(output2)
		if strings.Contains(outputStr2, "NoDriveAutoRun") && strings.Contains(outputStr2, "0xff") {
			if s.verbose {
				fmt.Println("自动运行已禁用（通过NoDriveAutoRun）")
			}
			return true
		}
	}
	
	if s.verbose {
		fmt.Println("自动运行未禁用（不符合安全要求）")
	}
	return false
}

func (s *Scanner) checkGuestAccount() bool {
	// 检查Guest账户是否启用
	cmd := exec.Command("net", "user", "guest")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if s.verbose {
			fmt.Printf("检查Guest账户状态失败: %v\n", err)
		}
		// 如果命令执行失败，可能是账户不存在或权限问题
		// 尝试使用PowerShell命令
		cmd2 := exec.Command("powershell", "Get-LocalUser -Name 'Guest' | Select-Object Enabled")
		output2, err2 := cmd2.CombinedOutput()
		if err2 == nil {
			outputStr2 := string(output2)
			if s.verbose {
				fmt.Printf("PowerShell Guest账户检查输出: %s\n", outputStr2)
			}
			
			// 检查账户是否禁用
			if strings.Contains(outputStr2, "False") {
				if s.verbose {
					fmt.Println("Guest账户已禁用（通过PowerShell检查）")
				}
				return true
			}
			
			if strings.Contains(outputStr2, "True") {
				if s.verbose {
					fmt.Println("Guest账户已启用（通过PowerShell检查）")
				}
				return false
			}
		}
		
		return false
	}
	
	outputStr := string(output)
	if s.verbose {
		fmt.Printf("Guest账户检查输出: %s\n", outputStr)
	}
	
	// 检查账户状态 - Guest账户应该被禁用（安全最佳实践）
	// 所以如果账户被禁用，返回true（符合安全要求）
	
	// 中文系统检查
	if strings.Contains(outputStr, "账户启用") && strings.Contains(outputStr, "No") {
		if s.verbose {
			fmt.Println("Guest账户已禁用（符合安全要求）")
		}
		return true
	}
	
	// 英文系统检查
	if strings.Contains(outputStr, "Account active") && strings.Contains(outputStr, "No") {
		if s.verbose {
			fmt.Println("Guest账户已禁用（符合安全要求）")
		}
		return true
	}
	
	// 如果账户启用，检查是否启用了
	if (strings.Contains(outputStr, "账户启用") && strings.Contains(outputStr, "Yes")) || 
	   (strings.Contains(outputStr, "Account active") && strings.Contains(outputStr, "Yes")) {
		if s.verbose {
			fmt.Println("Guest账户已启用（不符合安全要求）")
		}
		return false
	}
	
	if s.verbose {
		fmt.Println("无法确定Guest账户状态")
	}
	
	return false
}

func (s *Scanner) checkSMBv1Disabled() bool {
	// 检查SMBv1是否禁用
	cmd := exec.Command("Get-WindowsOptionalFeature", "-Online", "-FeatureName", "SMB1Protocol")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果PowerShell命令失败，尝试使用sc命令
		cmd = exec.Command("sc", "query", "LanmanServer")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return false
		}
		
		// 检查SMB服务状态
		smbRegex := regexp.MustCompile(`STATE\\s+:\\s+4`)
		return !smbRegex.MatchString(string(output))
	}
	
	// SMBv1应该被禁用
	smbRegex := regexp.MustCompile(`State\\s+:\\s+Disabled`)
	return smbRegex.MatchString(string(output))
}

func (s *Scanner) countFailedTests(results []TestResult) int {
	count := 0
	for _, result := range results {
		if !result.Successful && !result.Skipped {
			count++
		}
	}
	return count
}

func (s *Scanner) countSkippedTests(results []TestResult) int {
	count := 0
	for _, result := range results {
		if result.Skipped {
			count++
		}
	}
	return count
}

// String 返回扫描结果的字符串表示
func (r *ScanResult) String() string {
	return fmt.Sprintf("Goss扫描完成 - 目标: %s, 测试总数: %d, 失败: %d, 跳过: %d, 耗时: %v",
		r.Target, r.Summary.TotalCount, r.Summary.FailedCount, r.Summary.SkippedCount, r.ScanDuration)
}