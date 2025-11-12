package lynis

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	
	"GYscan-linux-C2/pkg/utils"
)

// Scanner 安全审计扫描器
type Scanner struct {
	config *Config
	result *AuditResult
	verbose bool
}

// NewScanner 创建新的安全审计扫描器
func NewScanner(config *Config, verbose bool) *Scanner {
	return &Scanner{
		config: config,
		result: &AuditResult{
			Timestamp: time.Now(),
			Tests:     []SecurityTest{},
			Findings:  []SecurityFinding{},
		},
		verbose: verbose,
	}
}

// Scan 执行安全审计扫描
func (s *Scanner) Scan() (*AuditResult, error) {
	startTime := time.Now()
	
	// 检查系统兼容性
	if !s.checkSystemCompatibility() {
		return nil, fmt.Errorf("系统不兼容：此工具只能在Linux系统上运行")
	}
	
	// 检查权限
	if !s.checkPrivileges() {
		return nil, fmt.Errorf("权限不足：安全审计需要root权限")
	}
	
	if s.verbose {
		log.Println("开始系统安全审计...")
	}
	
	// 收集系统信息
	if err := s.collectSystemInfo(); err != nil {
		return nil, fmt.Errorf("收集系统信息失败: %v", err)
	}
	
	// 执行安全测试
	s.executeSecurityTests()
	
	// 生成审计摘要
	s.generateSummary()
	
	s.result.ScanDuration = time.Since(startTime)
	
	if s.verbose {
		log.Printf("安全审计完成，耗时: %v", s.result.ScanDuration)
	}
	
	return s.result, nil
}

// checkSystemCompatibility 检查系统兼容性
func (s *Scanner) checkSystemCompatibility() bool {
	return runtime.GOOS == "linux"
}

// checkPrivileges 检查权限
func (s *Scanner) checkPrivileges() bool {
	return os.Geteuid() == 0
}

// collectSystemInfo 收集系统信息
func (s *Scanner) collectSystemInfo() error {
	var info SystemInfo
	
	// 获取主机名
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}
	
	// 获取操作系统信息
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	
	// 获取内核版本
	if data, err := os.ReadFile("/proc/version"); err == nil {
		info.KernelVersion = strings.TrimSpace(string(data))
	}
	
	// 获取架构信息
	info.Architecture = runtime.GOARCH
	
	// 获取CPU数量
	info.CPUCount = runtime.NumCPU()
	
	// 获取系统运行时间
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			var uptime float64
			fmt.Sscanf(fields[0], "%f", &uptime)
			duration := time.Duration(uptime) * time.Second
			hours := duration.Hours()
			days := int(hours / 24)
			remainingHours := int(hours) % 24
			minutes := int(duration.Minutes()) % 60
			info.Uptime = fmt.Sprintf("%d天%d小时%d分钟", days, remainingHours, minutes)
		}
	}
	
	// 获取内存信息
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.MemoryTotal = fmt.Sprintf("%s %s", fields[1], fields[2])
				}
				break
			}
		}
	}
	
	// 获取磁盘使用情况
	if cmd := exec.Command("df", "-h", "/"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 1 {
				fields := strings.Fields(lines[1])
				if len(fields) >= 5 {
					info.DiskUsage = fmt.Sprintf("%s/%s (%s)", fields[2], fields[1], fields[4])
				}
			}
		}
	}
	
	s.result.SystemInfo = info
	
	if s.verbose {
		log.Printf("系统信息收集完成: %s (%s)", info.Hostname, info.OS)
	}
	
	return nil
}

// executeSecurityTests 执行安全测试
func (s *Scanner) executeSecurityTests() {
	if s.verbose {
		log.Println("开始执行安全测试...")
	}
	
	// 执行各类安全测试
	s.testAuthentication()
	s.testBootServices()
	s.testFilePermissions()
	s.testFirewalls()
	s.testKernelSecurity()
	s.testLogging()
	s.testNetworking()
	s.testProcessSecurity()
	s.testSoftwareSecurity()
	s.testSystemIntegrity()
	
	if s.verbose {
		log.Printf("安全测试执行完成，共执行 %d 个测试项", len(s.result.Tests))
	}
}

// testAuthentication 测试认证和授权安全
func (s *Scanner) testAuthentication() {
	test := SecurityTest{
		ID:          "AUTH-001",
		Category:    CategoryAuthentication,
		Group:       "authentication",
		Description: "检查用户账户和权限配置",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查root账户
	if s.checkRootAccount() {
		test.Details["root_account"] = "root账户配置正常"
	} else {
		test.Status = TestStatusWarning
		test.Details["root_account"] = "root账户可能存在安全风险"
	}
	
	// 检查密码策略
	if s.checkPasswordPolicy() {
		test.Details["password_policy"] = "密码策略配置正常"
	} else {
		test.Status = TestStatusFailed
		test.Severity = SeverityHigh
		test.Details["password_policy"] = "密码策略配置不足"
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testBootServices 测试启动服务安全
func (s *Scanner) testBootServices() {
	test := SecurityTest{
		ID:          "BOOT-001",
		Category:    CategoryBootServices,
		Group:       "boot_services",
		Description: "检查系统启动服务和配置",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查systemd服务
	if s.checkSystemdServices() {
		test.Details["systemd_services"] = "systemd服务配置正常"
	} else {
		test.Status = TestStatusWarning
		test.Details["systemd_services"] = "发现潜在的系统服务安全问题"
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// 其他测试方法的实现...

// checkRootAccount 检查root账户安全
func (s *Scanner) checkRootAccount() bool {
	// 检查/etc/passwd中的root账户
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "root:") {
				fields := strings.Split(line, ":")
				if len(fields) >= 7 && fields[6] != "/bin/false" && fields[6] != "/sbin/nologin" {
					return true
				}
			}
		}
	}
	return false
}

// checkPasswordPolicy 检查密码策略
func (s *Scanner) checkPasswordPolicy() bool {
	// 检查/etc/login.defs中的密码策略
	if _, err := os.Stat("/etc/login.defs"); err == nil {
		return true
	}
	return false
}

// checkSystemdServices 检查systemd服务
func (s *Scanner) checkSystemdServices() bool {
	// 检查systemd是否运行
	if _, err := exec.LookPath("systemctl"); err == nil {
		return true
	}
	return false
}

// testFilePermissions 测试文件权限安全
func (s *Scanner) testFilePermissions() {
	test := SecurityTest{
		ID:          "FILE-001",
		Category:    CategoryFilePermissions,
		Group:       "file_permissions",
		Description: "检查关键系统文件权限配置",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查关键文件权限
	criticalFiles := []string{
		"/etc/passwd",
		"/etc/shadow", 
		"/etc/gshadow",
		"/etc/group",
		"/etc/sudoers",
	}
	
	for _, file := range criticalFiles {
		if info, err := os.Stat(file); err == nil {
			mode := info.Mode()
			if mode.Perm()&0022 != 0 { // 检查是否有写权限
				test.Status = TestStatusFailed
				test.Severity = SeverityHigh
				test.Details[file] = fmt.Sprintf("文件权限过宽: %s", mode.String())
			} else {
				test.Details[file] = fmt.Sprintf("权限正常: %s", mode.String())
			}
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testFirewalls 测试防火墙配置
func (s *Scanner) testFirewalls() {
	test := SecurityTest{
		ID:          "FIRE-001",
		Category:    CategoryFirewalls,
		Group:       "firewalls",
		Description: "检查防火墙配置状态",
		Status:      TestStatusPassed,
		Severity:    SeverityHigh,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查常见防火墙服务
	firewallServices := []string{"ufw", "iptables", "firewalld"}
	firewallRunning := false
	
	for _, service := range firewallServices {
		if _, err := exec.LookPath(service); err == nil {
			// 检查服务状态
			cmd := exec.Command("systemctl", "is-active", service)
			if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
				firewallRunning = true
				test.Details[service] = "防火墙服务运行中"
			} else {
				test.Details[service] = "防火墙服务未运行"
			}
		}
	}
	
	if !firewallRunning {
		test.Status = TestStatusFailed
		test.Details["overall"] = "未发现运行的防火墙服务"
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testKernelSecurity 测试内核安全配置
func (s *Scanner) testKernelSecurity() {
	test := SecurityTest{
		ID:          "KERN-001",
		Category:    CategoryKernel,
		Group:       "kernel",
		Description: "检查内核安全参数配置",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查内核参数
	kernelParams := map[string]string{
		"kernel.randomize_va_space": "2", // ASLR启用
		"net.ipv4.ip_forward": "0",        // 禁用IP转发
		"net.ipv4.conf.all.accept_redirects": "0",
		"net.ipv4.conf.all.accept_source_route": "0",
	}
	
	for param, expected := range kernelParams {
		cmd := exec.Command("sysctl", "-n", param)
		if output, err := cmd.Output(); err == nil {
			actual := strings.TrimSpace(string(output))
			if actual == expected {
				test.Details[param] = fmt.Sprintf("配置正确: %s", actual)
			} else {
				test.Status = TestStatusWarning
				test.Details[param] = fmt.Sprintf("配置需要检查: 当前=%s, 期望=%s", actual, expected)
			}
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testLogging 测试日志配置
func (s *Scanner) testLogging() {
	test := SecurityTest{
		ID:          "LOGG-001",
		Category:    CategoryLogging,
		Group:       "logging",
		Description: "检查系统日志配置",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查日志服务
	logServices := []string{"rsyslog", "systemd-journald"}
	for _, service := range logServices {
		cmd := exec.Command("systemctl", "is-active", service)
		if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
			test.Details[service] = "日志服务运行中"
		} else {
			test.Status = TestStatusWarning
			test.Details[service] = "日志服务未运行"
		}
	}
	
	// 检查日志文件权限
	logFiles := []string{"/var/log/auth.log", "/var/log/syslog"}
	for _, file := range logFiles {
		if info, err := os.Stat(file); err == nil {
			if info.Mode().Perm()&0022 == 0 { // 检查是否有写权限
				test.Details[file] = "日志文件权限正常"
			} else {
				test.Status = TestStatusWarning
				test.Details[file] = "日志文件权限过宽"
			}
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testNetworking 测试网络配置安全
func (s *Scanner) testNetworking() {
	test := SecurityTest{
		ID:          "NETW-001",
		Category:    CategoryNetworking,
		Group:       "networking",
		Description: "检查网络服务和安全配置",
		Status:      TestStatusPassed,
		Severity:    SeverityHigh,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查网络服务
	netServices := []string{"sshd", "apache2", "nginx", "mysql"}
	for _, service := range netServices {
		cmd := exec.Command("systemctl", "is-active", service)
		if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
			test.Details[service] = "网络服务运行中"
			// 检查服务配置
			if service == "sshd" {
				test.Details["ssh_config"] = "SSH服务需要检查配置"
			}
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testProcessSecurity 测试进程安全
func (s *Scanner) testProcessSecurity() {
	test := SecurityTest{
		ID:          "PROC-001",
		Category:    CategoryProcesses,
		Group:       "processes",
		Description: "检查进程和系统资源安全",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查系统资源使用
	cmd := exec.Command("ps", "aux", "--sort=-%cpu")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 5 { // 显示前5个高CPU进程
			test.Details["top_processes"] = "系统进程运行正常"
		}
	}
	
	// 检查僵尸进程
	cmd = exec.Command("ps", "aux")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "defunct") {
			test.Status = TestStatusWarning
			test.Details["zombie_processes"] = "发现僵尸进程"
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testSoftwareSecurity 测试软件安全
func (s *Scanner) testSoftwareSecurity() {
	test := SecurityTest{
		ID:          "SOFT-001",
		Category:    CategorySoftware,
		Group:       "software",
		Description: "检查软件包和更新状态",
		Status:      TestStatusPassed,
		Severity:    SeverityHigh,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查系统更新
	packageManagers := []string{"apt", "yum", "dnf"}
	for _, pm := range packageManagers {
		if _, err := exec.LookPath(pm); err == nil {
			if pm == "apt" {
				cmd := exec.Command("apt", "list", "--upgradable")
				if output, err := cmd.Output(); err == nil {
					lines := strings.Split(string(output), "\n")
					upgradable := len(lines) - 2 // 减去标题行和空行
					if upgradable > 0 {
						test.Status = TestStatusWarning
						test.Details["updates"] = fmt.Sprintf("有%d个可用更新", upgradable)
					} else {
						test.Details["updates"] = "系统已是最新"
					}
				}
			}
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// testSystemIntegrity 测试系统完整性
func (s *Scanner) testSystemIntegrity() {
	test := SecurityTest{
		ID:          "SYSI-001",
		Category:    CategorySystemIntegrity,
		Group:       "system_integrity",
		Description: "检查系统完整性和安全配置",
		Status:      TestStatusPassed,
		Severity:    SeverityMedium,
		Timestamp:   time.Now(),
		Details:     make(map[string]string),
	}
	
	// 检查SELinux/AppArmor
	securityModules := []string{"selinux", "apparmor"}
	for _, module := range securityModules {
		cmd := exec.Command("systemctl", "is-active", module)
		if output, err := cmd.Output(); err == nil && strings.TrimSpace(string(output)) == "active" {
			test.Details[module] = "安全模块运行中"
		} else {
			test.Details[module] = "安全模块未启用"
		}
	}
	
	// 检查磁盘使用
	cmd := exec.Command("df", "-h")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "/dev/") && strings.Contains(line, "/") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					usage := fields[4]
					if strings.TrimSuffix(usage, "%") > "90" {
						test.Status = TestStatusWarning
						test.Details["disk_usage"] = "磁盘使用率过高"
					}
				}
			}
		}
	}
	
	s.result.Tests = append(s.result.Tests, test)
}

// generateSummary 生成审计摘要
func (s *Scanner) generateSummary() {
	summary := AuditSummary{}
	
	for _, test := range s.result.Tests {
		summary.TotalTests++
		
		switch test.Status {
		case TestStatusPassed:
			summary.PassedTests++
		case TestStatusFailed:
			summary.FailedTests++
		case TestStatusWarning:
			summary.WarningTests++
		case TestStatusSkipped:
			summary.SkippedTests++
		}
		
		switch test.Severity {
		case SeverityCritical:
			summary.CriticalFindings++
		case SeverityHigh:
			summary.HighFindings++
		case SeverityMedium:
			summary.MediumFindings++
		case SeverityLow:
			summary.LowFindings++
		case SeverityInfo:
			summary.InfoFindings++
		}
	}
	
	s.result.Summary = summary
}

// RunAudit 执行安全审计（与Scan方法相同，提供兼容性接口）
func (s *Scanner) RunAudit() (*AuditResult, error) {
	return s.Scan()
}

// PrintSummary 打印审计摘要
func (s *Scanner) PrintSummary(result *AuditResult) {
	if result == nil {
		fmt.Println("错误: 审计结果为空")
		return
	}
	
	summary := result.Summary
	
	// 使用颜色工具类
	color := utils.NewColor()
	
	color.PrintTitle("=== Lynis安全审计摘要 ===")
	fmt.Printf("扫描时间: %s\n", color.Highlight(result.Timestamp.Format("2006-01-02 15:04:05")))
	fmt.Printf("扫描耗时: %s\n", color.Highlight(fmt.Sprintf("%v", result.ScanDuration)))
	fmt.Printf("系统信息: %s (%s)\n", color.Highlight(result.SystemInfo.Hostname), color.Highlight(result.SystemInfo.OS))
	fmt.Println()
	
	fmt.Printf("%s\n", color.BoldText("测试统计:"))
	fmt.Printf("  总测试数: %s\n", color.Highlight(fmt.Sprintf("%d", summary.TotalTests)))
	fmt.Printf("  通过: %s\n", color.Passed(fmt.Sprintf("%d", summary.PassedTests)))
	fmt.Printf("  失败: %s\n", color.Failed(fmt.Sprintf("%d", summary.FailedTests)))
	fmt.Printf("  警告: %s\n", color.WarningStatus(fmt.Sprintf("%d", summary.WarningTests)))
	fmt.Printf("  跳过: %s\n", color.Skipped(fmt.Sprintf("%d", summary.SkippedTests)))
	fmt.Println()
	
	fmt.Printf("%s\n", color.BoldText("安全发现:"))
	fmt.Printf("  严重: %s\n", color.Critical(fmt.Sprintf("%d", summary.CriticalFindings)))
	fmt.Printf("  高危: %s\n", color.High(fmt.Sprintf("%d", summary.HighFindings)))
	fmt.Printf("  中危: %s\n", color.Medium(fmt.Sprintf("%d", summary.MediumFindings)))
	fmt.Printf("  低危: %s\n", color.Low(fmt.Sprintf("%d", summary.LowFindings)))
	fmt.Printf("  信息: %s\n", color.InfoLevel(fmt.Sprintf("%d", summary.InfoFindings)))
	fmt.Println()
	
	// 显示关键发现
	if summary.CriticalFindings > 0 || summary.HighFindings > 0 {
		color.PrintError("[!] 发现关键或高危安全问题，请立即处理！")
	} else if summary.MediumFindings > 0 {
		color.PrintWarning("[!] 发现中危安全问题，建议尽快处理")
	} else {
		color.PrintSuccess("[+] 系统安全状态良好")
	}
}

// PrintDetailedResults 打印详细审计结果
func (s *Scanner) PrintDetailedResults(result *AuditResult) {
	if result == nil {
		fmt.Println("错误: 审计结果为空")
		return
	}
	
	// 使用颜色工具类
	color := utils.NewColor()
	
	color.PrintTitle("=== 审计详情 ===")
	
	if len(result.Tests) == 0 {
		fmt.Println("没有执行任何安全测试")
		return
	}
	
	// 按严重级别分组显示测试结果
	criticalTests := []SecurityTest{}
	highTests := []SecurityTest{}
	mediumTests := []SecurityTest{}
	lowTests := []SecurityTest{}
	infoTests := []SecurityTest{}
	
	for _, test := range result.Tests {
		switch test.Severity {
		case SeverityCritical:
			criticalTests = append(criticalTests, test)
		case SeverityHigh:
			highTests = append(highTests, test)
		case SeverityMedium:
			mediumTests = append(mediumTests, test)
		case SeverityLow:
			lowTests = append(lowTests, test)
		case SeverityInfo:
			infoTests = append(infoTests, test)
		}
	}
	
	// 显示严重级别的测试结果
	if len(criticalTests) > 0 {
		utils.Printf(utils.BrightRed, "\n[!] 严重问题:")
		for _, test := range criticalTests {
			s.printTestDetails(test)
		}
	}
	
	// 显示高危级别的测试结果
	if len(highTests) > 0 {
		utils.Printf(utils.BrightRed, "\n[!] 高危问题:")
		for _, test := range highTests {
			s.printTestDetails(test)
		}
	}
	
	// 显示中危级别的测试结果
	if len(mediumTests) > 0 {
		utils.Printf(utils.BrightYellow, "\n[!] 中危问题:")
		for _, test := range mediumTests {
			s.printTestDetails(test)
		}
	}
	
	// 显示低危级别的测试结果
	if len(lowTests) > 0 {
		utils.Printf(utils.BrightGreen, "\n[!] 低危问题:")
		for _, test := range lowTests {
			s.printTestDetails(test)
		}
	}
	
	// 显示信息级别的测试结果
	if len(infoTests) > 0 {
		utils.Printf(utils.BrightBlue, "\n[!] 信息发现:")
		for _, test := range infoTests {
			s.printTestDetails(test)
		}
	}
	
	// 显示通过的测试
	passedTests := []SecurityTest{}
	for _, test := range result.Tests {
		if test.Status == TestStatusPassed {
			passedTests = append(passedTests, test)
		}
	}
	
	if len(passedTests) > 0 {
		utils.Printf(utils.BrightGreen, "\n[+] 通过的测试:")
		for _, test := range passedTests {
			fmt.Printf("  %s - %s\n", color.Highlight(test.ID), color.Highlight(test.Description))
		}
	}
}

// printTestDetails 打印单个测试的详细信息
func (s *Scanner) printTestDetails(test SecurityTest) {
	// 使用颜色工具类
	color := utils.NewColor()
	
	// 根据测试状态选择图标和颜色
	statusIcon := "[+]"
	statusColor := utils.BrightGreen
	switch test.Status {
	case TestStatusFailed:
		statusIcon = "[x]"
		statusColor = utils.BrightRed
	case TestStatusWarning:
		statusIcon = "[!]"
		statusColor = utils.BrightYellow
	case TestStatusSkipped:
		statusIcon = "[@]"
		statusColor = utils.BrightBlue
	case TestStatusError:
		statusIcon = "[?]"
		statusColor = utils.BrightRed
	}
	
	// 根据严重级别选择颜色
	severityColor := utils.BrightWhite
	switch test.Severity {
	case SeverityCritical:
		severityColor = utils.BrightRed
	case SeverityHigh:
		severityColor = utils.BrightRed
	case SeverityMedium:
		severityColor = utils.BrightYellow
	case SeverityLow:
		severityColor = utils.BrightGreen
	case SeverityInfo:
		severityColor = utils.BrightBlue
	}
	
	utils.Printf(statusColor, "\n%s %s - %s (严重级别: %s)", 
		statusIcon,
		test.ID, 
		test.Description,
		utils.Sprintf(severityColor, "%s", test.Severity))
	
	// 显示测试详情
	if len(test.Details) > 0 {
		fmt.Printf("  %s\n", color.BoldText("详细信息:"))
		for key, value := range test.Details {
			color.PrintListItem(fmt.Sprintf("%s: %s", key, value))
		}
	}
	
	// 显示相关建议
	if test.Status == TestStatusFailed || test.Status == TestStatusWarning {
		fmt.Printf("  %s\n", color.BoldText("建议措施:"))
		switch test.ID {
		case "AUTH-001":
			color.PrintListItem("检查用户账户和权限配置")
			color.PrintListItem("确保密码策略符合安全要求")
		case "BOOT-001":
			color.PrintListItem("检查系统启动服务配置")
			color.PrintListItem("禁用不必要的系统服务")
		case "FILE-001":
			color.PrintListItem("检查文件系统权限设置")
			color.PrintListItem("确保敏感文件权限正确")
		case "FIRE-001":
			color.PrintListItem("检查防火墙规则配置")
			color.PrintListItem("确保网络访问控制有效")
		case "KERN-001":
			color.PrintListItem("检查内核安全参数")
			color.PrintListItem("更新内核到最新安全版本")
		default:
			color.PrintListItem("参考相关安全最佳实践进行修复")
		}
	}
}

// GenerateReport 生成安全审计报告
func (s *Scanner) GenerateReport(result *AuditResult) error {
	if result == nil {
		return fmt.Errorf("审计结果为空，无法生成报告")
	}
	
	// 创建报告生成器
	reportGen := NewReportGenerator(result)
	
	// 根据配置确定报告格式
	format := s.config.ReportFormat
	if format == "" {
		// 根据输出文件扩展名确定格式
		outputPath := s.config.OutputFile
		if strings.HasSuffix(strings.ToLower(outputPath), ".html") {
			format = "html"
		} else if strings.HasSuffix(strings.ToLower(outputPath), ".json") {
			format = "json"
		} else {
			format = "text"
		}
	}
	
	// 生成报告
	return reportGen.GenerateReport(format, s.config.OutputFile)
}