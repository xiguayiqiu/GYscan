package lynis

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ShowHandler 处理show命令
type ShowHandler struct {
	verbose bool
}

// NewShowHandler 创建新的show命令处理器
func NewShowHandler(verbose bool) *ShowHandler {
	return &ShowHandler{
		verbose: verbose,
	}
}

// ShowCategories 显示安全测试分类
func (h *ShowHandler) ShowCategories() {
	fmt.Println("=== GYscan-Lynis安全测试分类 ===")
	fmt.Println()

	categories := []struct {
		ID          string
		Name        string
		Description string
	}{
		{CategoryAuthentication, "认证和授权", "用户账户、密码策略、权限控制等"},
		{CategoryBootServices, "启动服务", "系统启动过程、服务管理、init系统等"},
		{CategoryContainers, "容器安全", "Docker、容器运行时、容器编排等"},
		{CategoryCrypto, "加密安全", "SSL/TLS配置、加密算法、证书管理等"},
		{CategoryDatabases, "数据库安全", "数据库配置、访问控制、数据保护等"},
		{CategoryDNS, "DNS安全", "DNS服务器配置、DNS安全扩展等"},
		{CategoryFileIntegrity, "文件完整性", "文件校验、完整性监控等"},
		{CategoryFilePermissions, "文件权限", "文件系统权限、访问控制等"},
		{CategoryFilesystems, "文件系统", "文件系统配置、挂载选项等"},
		{CategoryFirewalls, "防火墙", "防火墙配置、网络访问控制等"},
		{CategoryHardening, "系统加固", "系统安全加固配置"},
		{CategoryHomedirs, "用户目录", "用户主目录安全配置"},
		{CategoryInsecureServices, "不安全服务", "潜在的不安全服务检测"},
		{CategoryKernel, "内核安全", "内核配置、安全模块等"},
		{CategoryLogging, "日志安全", "系统日志、审计日志配置"},
		{CategoryMail, "邮件安全", "邮件服务器安全配置"},
		{CategoryMemoryProtection, "内存保护", "内存保护机制、ASLR等"},
		{CategoryNetworking, "网络安全", "网络配置、协议安全等"},
		{CategoryProcesses, "进程安全", "进程管理、权限控制等"},
		{CategorySoftware, "软件安全", "软件包管理、漏洞管理等"},
		{CategoryStorage, "存储安全", "存储设备、数据保护等"},
		{CategorySystemIntegrity, "系统完整性", "系统完整性检查"},
		{CategoryTime, "时间同步", "时间同步服务配置"},
		{CategoryTools, "安全工具", "安全工具可用性检查"},
		{CategoryVirtualization, "虚拟化安全", "虚拟化平台安全配置"},
		{CategoryWebservers, "Web服务器", "Web服务器安全配置"},
	}

	for _, cat := range categories {
		fmt.Printf("%-25s %-15s %s\n", cat.ID, cat.Name, cat.Description)
	}
	fmt.Println()
}

// ShowChangelog 显示变更日志
func (h *ShowHandler) ShowChangelog() {
	fmt.Println("=== GYscan-Lynis安全审计工具变更日志 ===")
	fmt.Println()

	changelog := []struct {
		Version     string
		Date        string
		Description string
	}{
		{"1.0.0", "2024-01-15", "初始版本发布，基础安全审计功能"},
		{"1.1.0", "2024-02-01", "增加容器安全检测功能"},
		{"1.2.0", "2024-02-15", "增强网络和防火墙检测"},
		{"1.3.0", "2024-03-01", "添加系统完整性检查"},
		{"1.4.0", "2024-03-15", "优化报告生成和输出格式"},
		{"1.5.0", "2024-04-01", "增加show命令功能"},
	}

	for _, change := range changelog {
		fmt.Printf("%-8s %-12s %s\n", change.Version, change.Date, change.Description)
	}
	fmt.Println()
}

// ShowCommands 显示可用命令
func (h *ShowHandler) ShowCommands() {
	fmt.Println("=== GYscan-Lynis可用命令 ===")
	fmt.Println()

	commands := []struct {
		Command     string
		Description string
	}{
		{"audit", "执行完整的安全审计扫描"},
		{"audit quick", "执行快速安全审计扫描"},
		{"audit full", "执行完整详细的安全审计扫描"},
		{"show categories", "显示安全测试分类"},
		{"show changelog", "显示变更日志"},
		{"show commands", "显示可用命令"},
		{"show dbdir", "显示数据库目录"},
		{"show details", "显示详细配置信息"},
		{"show environment", "显示环境变量"},
		{"show eol", "显示EOL信息"},
		{"show groups", "显示测试组"},
		{"show help", "显示帮助信息"},
		{"show hostids", "显示主机标识符"},
		{"show includedir", "显示包含目录"},
		{"show language", "显示语言设置"},
		{"show license", "显示许可证信息"},
		{"show logfile", "显示日志文件路径"},
		{"show man", "显示手册页信息"},
		{"show options", "显示配置选项"},
		{"show os", "显示操作系统信息"},
		{"show pidfile", "显示PID文件路径"},
		{"show plugindir", "显示插件目录"},
		{"show profiles", "显示安全配置文件"},
		{"show release", "显示版本信息"},
		{"show releasedate", "显示发布日期"},
		{"show report", "显示报告信息"},
		{"show settings", "显示设置信息"},
		{"show tests", "显示测试列表"},
		{"show version", "显示版本信息"},
		{"show workdir", "显示工作目录"},
	}

	for _, cmd := range commands {
		fmt.Printf("%-20s %s\n", cmd.Command, cmd.Description)
	}
	fmt.Println()
}

// ShowDBDir 显示数据库目录
func (h *ShowHandler) ShowDBDir() {
	fmt.Println("=== GYscan-Lynis数据库目录 ===")
	fmt.Println()

	dbDirs := []string{
		"/usr/local/share/lynis/db",
		"/usr/share/lynis/db",
		"/opt/lynis/db",
		"~/.lynis/db",
	}

	for _, dir := range dbDirs {
		if expandedDir, err := expandHomeDir(dir); err == nil {
			if _, err := os.Stat(expandedDir); err == nil {
				fmt.Printf("✓ %s\n", expandedDir)
			} else {
				fmt.Printf("✗ %s (不存在)\n", expandedDir)
			}
		}
	}
	fmt.Println()
}

// ShowDetails 显示详细配置信息
func (h *ShowHandler) ShowDetails() {
	fmt.Println("=== GYscan-Lynis详细配置信息 ===")
	fmt.Println()

	// 显示系统信息
	fmt.Println("系统信息:")
	if hostname, err := os.Hostname(); err == nil {
		fmt.Printf("  主机名: %s\n", hostname)
	}
	fmt.Printf("  操作系统: %s\n", runtime.GOOS)
	fmt.Printf("  架构: %s\n", runtime.GOARCH)
	fmt.Printf("  CPU核心数: %d\n", runtime.NumCPU())
	fmt.Println()

	// 显示工具信息
	fmt.Println("工具信息:")
	fmt.Printf("  版本: 1.5.0\n")
	fmt.Printf("  发布日期: 2024-04-01\n")
	fmt.Printf("  语言: Go\n")
	fmt.Printf("  许可证: MIT\n")
	fmt.Println()
}

// ShowEnvironment 显示环境变量
func (h *ShowHandler) ShowEnvironment() {
	fmt.Println("=== GYscan-Lynis环境变量 ===")
	fmt.Println()

	envVars := []string{
		"LYNIS_PATH",
		"LYNIS_DB_DIR",
		"LYNIS_PLUGIN_DIR",
		"LYNIS_PROFILE_DIR",
		"LYNIS_TMP_DIR",
		"LYNIS_LOG_DIR",
		"LYNIS_REPORT_DIR",
	}

	for _, envVar := range envVars {
		value := os.Getenv(envVar)
		if value != "" {
			fmt.Printf("%-20s = %s\n", envVar, value)
		} else {
			fmt.Printf("%-20s = (未设置)\n", envVar)
		}
	}
	fmt.Println()
}

// ShowEOL 显示EOL信息
func (h *ShowHandler) ShowEOL() {
	fmt.Println("=== 操作系统EOL信息 ===")
	fmt.Println()

	eolInfo := []struct {
		OS      string
		Version string
		EOLDate string
		Status  string
	}{
		{"Ubuntu", "18.04", "2023-04-30", "已结束支持"},
		{"Ubuntu", "20.04", "2025-04-30", "支持中"},
		{"Ubuntu", "22.04", "2027-04-30", "支持中"},
		{"CentOS", "7", "2024-06-30", "即将结束"},
		{"CentOS", "8", "2021-12-31", "已结束支持"},
		{"Debian", "9", "2022-06-30", "已结束支持"},
		{"Debian", "10", "2024-06-30", "支持中"},
		{"Debian", "11", "2026-06-30", "支持中"},
		{"RHEL", "7", "2024-06-30", "即将结束"},
		{"RHEL", "8", "2029-05-31", "支持中"},
		{"RHEL", "9", "2032-05-31", "支持中"},
	}

	for _, info := range eolInfo {
		fmt.Printf("%-10s %-8s %-12s %s\n", info.OS, info.Version, info.EOLDate, info.Status)
	}
	fmt.Println()
}

// ShowGroups 显示测试组
func (h *ShowHandler) ShowGroups() {
	fmt.Println("=== GYscan-Lynis测试组 ===")
	fmt.Println()

	groups := []struct {
		Group       string
		Description string
	}{
		{"authentication", "认证和授权测试组"},
		{"boot_services", "启动服务测试组"},
		{"containers", "容器安全测试组"},
		{"file_permissions", "文件权限测试组"},
		{"firewalls", "防火墙测试组"},
		{"kernel", "内核安全测试组"},
		{"logging", "日志安全测试组"},
		{"networking", "网络安全测试组"},
		{"processes", "进程安全测试组"},
		{"software", "软件安全测试组"},
		{"system_integrity", "系统完整性测试组"},
	}

	for _, group := range groups {
		fmt.Printf("%-20s %s\n", group.Group, group.Description)
	}
	fmt.Println()
}

// ShowHelp 显示帮助信息
func (h *ShowHandler) ShowHelp() {
	fmt.Println("=== GYscan-Lynis安全审计工具帮助手册 ===")
	fmt.Println()
	fmt.Println("Lynis是一个全面的Linux系统安全审计工具，用于评估系统安全配置、检测漏洞和合规性问题。")
	fmt.Println()

	fmt.Println(" 基本用法:")
	fmt.Println("  lynis [命令] [选项]")
	fmt.Println()

	fmt.Println(" 主要命令:")
	fmt.Println("  audit [quick|full]    执行安全审计扫描")
	fmt.Println("    quick               快速扫描模式（基本安全检查）")
	fmt.Println("    full                完整扫描模式（全面安全检查）")
	fmt.Println("  show <信息类型>       显示各种系统信息")
	fmt.Println()

	fmt.Println(" show命令可用信息类型:")
	fmt.Println("  categories           显示安全测试分类")
	fmt.Println("  changelog            显示变更日志")
	fmt.Println("  commands             显示可用命令列表")
	fmt.Println("  details              显示详细配置信息")
	fmt.Println("  environment          显示环境变量")
	fmt.Println("  help                 显示此帮助信息")
	fmt.Println("  hostids              显示主机标识符")
	fmt.Println("  license              显示许可证信息")
	fmt.Println("  options              显示配置选项")
	fmt.Println("  os                   显示操作系统信息")
	fmt.Println("  profiles             显示安全配置文件")
	fmt.Println("  release              显示版本信息")
	fmt.Println("  settings             显示设置信息")
	fmt.Println("  tests                显示测试列表")
	fmt.Println("  version              显示版本信息")
	fmt.Println("  workdir              显示工作目录")
	fmt.Println()

	fmt.Println("  常用选项:")
	fmt.Println("  --format <格式>       报告格式 (text, html, json)")
	fmt.Println("  --output <文件>       输出文件路径")
	fmt.Println("  --verbose            详细输出模式")
	fmt.Println("  --help               显示帮助信息")
	fmt.Println()

	fmt.Println(" 使用示例:")
	fmt.Println("  1. 执行快速安全审计:")
	fmt.Println("     lynis audit quick")
	fmt.Println()
	fmt.Println("  2. 显示安全测试分类:")
	fmt.Println("     lynis show categories")
	fmt.Println()
	fmt.Println("  3. 显示可用命令列表:")
	fmt.Println("     lynis show commands")
	fmt.Println()
	fmt.Println("  4. 执行完整审计并生成HTML报告:")
	fmt.Println("     lynis audit full --format html --output /tmp/audit_report.html")
	fmt.Println()

	fmt.Println(" 注意事项:")
	fmt.Println("  • 建议使用root权限运行以获得完整系统信息")
	fmt.Println("  • 完整扫描可能需要较长时间，请耐心等待")
	fmt.Println("  • 报告文件默认保存在当前目录或/tmp目录")
	fmt.Println("  • 使用--verbose选项可查看详细扫描过程")
	fmt.Println()

	fmt.Println(" 更多信息:")
	fmt.Println("  访问项目文档或使用 'lynis show <信息类型>' 获取详细信息")
	fmt.Println()
}

// ShowHostIDs 显示主机标识符
func (h *ShowHandler) ShowHostIDs() {
	fmt.Println("=== 主机标识符 ===")
	fmt.Println()

	if hostname, err := os.Hostname(); err == nil {
		fmt.Printf("主机名: %s\n", hostname)
	}

	// 生成基于主机名的简单哈希
	hostID := generateSimpleHash()
	fmt.Printf("主机ID: %s\n", hostID)
	fmt.Printf("机器ID: %s\n", getMachineID())
	fmt.Println()
}

// ShowIncludeDir 显示包含目录
func (h *ShowHandler) ShowIncludeDir() {
	fmt.Println("=== GYscan-Lynis包含目录 ===")
	fmt.Println()

	includeDirs := []string{
		"/usr/local/include/lynis",
		"/usr/include/lynis",
		"/opt/lynis/include",
	}

	for _, dir := range includeDirs {
		if _, err := os.Stat(dir); err == nil {
			fmt.Printf("✓ %s\n", dir)
		} else {
			fmt.Printf("✗ %s (不存在)\n", dir)
		}
	}
	fmt.Println()
}

// ShowLanguage 显示语言设置
func (h *ShowHandler) ShowLanguage() {
	fmt.Println("=== GYscan-Lynis语言设置 ===")
	fmt.Println()

	lang := os.Getenv("LANG")
	if lang == "" {
		lang = "en_US.UTF-8"
	}

	fmt.Printf("当前语言: %s\n", lang)
	fmt.Printf("支持的语言: en_US.UTF-8, zh_CN.UTF-8\n")
	fmt.Println()
}

// ShowLicense 显示许可证信息
func (h *ShowHandler) ShowLicense() {
	fmt.Println("=== GYscan-Lynis许可证信息 ===")
	fmt.Println()
	fmt.Println("MIT License")
	fmt.Println()
	fmt.Println("版权所有 (c) 2024 GYscan安全团队")
	fmt.Println()
	fmt.Println("特此免费授予任何获得本软件及相关文档文件（以下简称“软件”）副本的人")
	fmt.Println("无限制地处理本软件的权利，包括但不限于使用、复制、修改、合并、发布、")
	fmt.Println("分发、再许可和/或销售本软件的副本，并允许向其提供本软件的人员这样做，")
	fmt.Println("但须符合以下条件：")
	fmt.Println()
	fmt.Println("上述版权声明和本许可声明应包含在本软件的所有副本或重要部分中。")
	fmt.Println()
	fmt.Println("本软件按“原样”提供，不提供任何形式的明示或暗示保证，包括但不限于")
	fmt.Println("适销性、特定用途适用性和非侵权性的保证。在任何情况下，作者或版权")
	fmt.Println("持有人均不对因本软件或本软件的使用或其他交易而引起的任何索赔、损害")
	fmt.Println("或其他责任负责，无论是在合同、侵权还是其他方面。")
	fmt.Println()
}

// ShowLogFile 显示日志文件路径
func (h *ShowHandler) ShowLogFile() {
	fmt.Println("=== GYscan-Lynis日志文件 ===")
	fmt.Println()

	logFiles := []string{
		"/var/log/lynis.log",
		"/var/log/lynis/lynis.log",
		"~/.lynis/lynis.log",
		"/tmp/lynis.log",
	}

	for _, file := range logFiles {
		if expandedFile, err := expandHomeDir(file); err == nil {
			if _, err := os.Stat(expandedFile); err == nil {
				fmt.Printf("✓ %s\n", expandedFile)
			} else {
				fmt.Printf("✗ %s (不存在)\n", expandedFile)
			}
		}
	}
	fmt.Println()
}

// ShowMan 显示手册页信息
func (h *ShowHandler) ShowMan() {
	fmt.Println("=== GYscan-Lynis手册页信息 ===")
	fmt.Println()
	fmt.Println("名称:")
	fmt.Println("    lynis - Linux系统安全审计工具")
	fmt.Println()
	fmt.Println("简介:")
	fmt.Println("    lynis [命令] [选项]")
	fmt.Println()
	fmt.Println("描述:")
	fmt.Println("    Lynis是一个安全审计工具，用于评估Linux系统的安全配置。")
	fmt.Println("    它可以检测安全漏洞、错误配置和合规性问题。")
	fmt.Println()
	fmt.Println("更多信息请参考在线文档或使用 'lynis --help' 命令。")
	fmt.Println()
}

// ShowOptions 显示配置选项
func (h *ShowHandler) ShowOptions() {
	fmt.Println("=== GYscan-Lynis配置选项 ===")
	fmt.Println()

	options := []struct {
		Option      string
		Default     string
		Description string
	}{
		{"quick_scan", "false", "启用快速扫描模式"},
		{"full_scan", "false", "启用完整扫描模式"},
		{"report_format", "text", "报告格式 (text/html/json)"},
		{"output_file", "", "输出文件路径"},
		{"verbose", "false", "详细输出模式"},
		{"color", "true", "启用彩色输出"},
	}

	for _, opt := range options {
		fmt.Printf("%-20s %-15s %s\n", opt.Option, opt.Default, opt.Description)
	}
	fmt.Println()
}

// ShowOS 显示操作系统信息
func (h *ShowHandler) ShowOS() {
	fmt.Println("=== 操作系统信息 ===")
	fmt.Println()

	fmt.Printf("操作系统: %s\n", runtime.GOOS)
	fmt.Printf("架构: %s\n", runtime.GOARCH)
	fmt.Printf("Go版本: %s\n", runtime.Version())

	// 尝试获取更详细的系统信息
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					osName := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
					fmt.Printf("发行版: %s\n", osName)
					break
				}
			}
		}

		if data, err := os.ReadFile("/proc/version"); err == nil {
			fmt.Printf("内核版本: %s", strings.TrimSpace(string(data)))
		}
	}
	fmt.Println()
}

// ShowPIDFile 显示PID文件路径
func (h *ShowHandler) ShowPIDFile() {
	fmt.Println("=== GYscan-Lynis PID文件 ===")
	fmt.Println()

	pidFiles := []string{
		"/var/run/lynis.pid",
		"/var/run/lynis/lynis.pid",
		"/tmp/lynis.pid",
	}

	for _, file := range pidFiles {
		if _, err := os.Stat(file); err == nil {
			fmt.Printf("✓ %s\n", file)
		} else {
			fmt.Printf("✗ %s (不存在)\n", file)
		}
	}
	fmt.Println()
}

// ShowPluginDir 显示插件目录
func (h *ShowHandler) ShowPluginDir() {
	fmt.Println("=== GYscan-Lynis插件目录 ===")
	fmt.Println()

	pluginDirs := []string{
		"/usr/local/lib/lynis/plugins",
		"/usr/lib/lynis/plugins",
		"/opt/lynis/plugins",
		"~/.lynis/plugins",
	}

	for _, dir := range pluginDirs {
		if expandedDir, err := expandHomeDir(dir); err == nil {
			if _, err := os.Stat(expandedDir); err == nil {
				fmt.Printf("✓ %s\n", expandedDir)
			} else {
				fmt.Printf("✗ %s (不存在)\n", expandedDir)
			}
		}
	}
	fmt.Println()
}

// ShowProfiles 显示安全配置文件
func (h *ShowHandler) ShowProfiles() {
	fmt.Println("=== GYscan-Lynis安全配置文件 ===")
	fmt.Println()

	profiles := []struct {
		Profile     string
		Description string
	}{
		{"default", "默认安全配置文件"},
		{"webserver", "Web服务器安全配置"},
		{"database", "数据库服务器安全配置"},
		{"mailserver", "邮件服务器安全配置"},
		{"containers", "容器环境安全配置"},
		{"cis", "CIS基准安全配置"},
		{"pci-dss", "PCI DSS合规配置"},
		{"hipaa", "HIPAA合规配置"},
	}

	for _, profile := range profiles {
		fmt.Printf("%-15s %s\n", profile.Profile, profile.Description)
	}
	fmt.Println()
}

// ShowRelease 显示版本信息
func (h *ShowHandler) ShowRelease() {
	fmt.Println("=== GYscan-Lynis版本信息 ===")
	fmt.Println()
	fmt.Printf("版本: 1.5.0\n")
	fmt.Printf("发布日期: 2024-04-01\n")
	fmt.Printf("构建时间: %s\n", getBuildTime())
	fmt.Printf("Git提交: %s\n", getGitCommit())
	fmt.Println()
}

// ShowReleaseDate 显示发布日期
func (h *ShowHandler) ShowReleaseDate() {
	fmt.Println("=== GYscan-Lynis发布日期 ===")
	fmt.Println()
	fmt.Printf("当前版本发布日期: 2024-04-01\n")
	fmt.Println()
}

// ShowReport 显示报告信息
func (h *ShowHandler) ShowReport() {
	fmt.Println("=== GYscan-Lynis报告信息 ===")
	fmt.Println()

	reportFiles := []string{
		"/var/log/lynis-report.dat",
		"~/.lynis/report.dat",
		"/tmp/lynis-report.dat",
	}

	for _, file := range reportFiles {
		if expandedFile, err := expandHomeDir(file); err == nil {
			if _, err := os.Stat(expandedFile); err == nil {
				fmt.Printf("✓ %s\n", expandedFile)
			} else {
				fmt.Printf("✗ %s (不存在)\n", expandedFile)
			}
		}
	}
	fmt.Println()
}

// ShowSettings 显示设置信息
func (h *ShowHandler) ShowSettings() {
	fmt.Println("=== GYscan-Lynis设置信息 ===")
	fmt.Println()

	settings := []struct {
		Setting     string
		Value       string
		Description string
	}{
		{"audit_mode", "standard", "审计模式 (standard/quick/full)"},
		{"color_output", "true", "彩色输出"},
		{"log_level", "info", "日志级别"},
		{"max_runtime", "3600", "最大运行时间(秒)"},
		{"parallel_tests", "true", "并行测试"},
		{"profile", "default", "安全配置文件"},
		{"report_format", "text", "报告格式"},
		{"skip_tests", "", "跳过的测试"},
		{"verbose", "false", "详细模式"},
	}

	for _, setting := range settings {
		fmt.Printf("%-20s %-15s %s\n", setting.Setting, setting.Value, setting.Description)
	}
	fmt.Println()
}

// ShowTests 显示测试列表
func (h *ShowHandler) ShowTests() {
	fmt.Println("=== GYscan-Lynis安全测试列表 ===")
	fmt.Println()

	tests := []struct {
		ID          string
		Category    string
		Description string
		Severity    string
	}{
		{"AUTH-001", CategoryAuthentication, "检查用户账户和权限配置", "medium"},
		{"BOOT-001", CategoryBootServices, "检查系统启动服务和配置", "medium"},
		{"FILE-001", CategoryFilePermissions, "检查文件系统权限", "high"},
		{"FIRE-001", CategoryFirewalls, "检查防火墙配置", "high"},
		{"KERN-001", CategoryKernel, "检查内核安全配置", "critical"},
		{"NETW-001", CategoryNetworking, "检查网络配置", "medium"},
		{"PROC-001", CategoryProcesses, "检查进程安全", "medium"},
		{"SOFT-001", CategorySoftware, "检查软件包安全", "medium"},
		{"SYSI-001", CategorySystemIntegrity, "检查系统完整性", "high"},
	}

	for _, test := range tests {
		fmt.Printf("%-10s %-20s %-40s %s\n", test.ID, test.Category, test.Description, test.Severity)
	}
	fmt.Println()
}

// ShowVersion 显示版本信息
func (h *ShowHandler) ShowVersion() {
	fmt.Println("=== GYscan-Lynis版本信息 ===")
	fmt.Println()
	fmt.Printf("Lynis安全审计工具 v1.5.0\n")
	fmt.Printf("构建时间: %s\n", getBuildTime())
	fmt.Printf("Go版本: %s\n", runtime.Version())
	fmt.Printf("平台: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
}

// ShowWorkDir 显示工作目录
func (h *ShowHandler) ShowWorkDir() {
	fmt.Println("=== GYscan-Lynis工作目录 ===")
	fmt.Println()

	workDirs := []string{
		"/var/tmp/lynis",
		"/tmp/lynis",
		"~/.lynis",
	}

	for _, dir := range workDirs {
		if expandedDir, err := expandHomeDir(dir); err == nil {
			if _, err := os.Stat(expandedDir); err == nil {
				fmt.Printf("✓ %s\n", expandedDir)
			} else {
				fmt.Printf("✗ %s (不存在)\n", expandedDir)
			}
		}
	}
	fmt.Println()
}

// 辅助函数
func expandHomeDir(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func generateSimpleHash() string {
	hostname, _ := os.Hostname()
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%d", hostname, timestamp)
}

func getMachineID() string {
	// 尝试读取机器ID文件
	machineIDFiles := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}

	for _, file := range machineIDFiles {
		if data, err := os.ReadFile(file); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	return "unknown"
}

func getBuildTime() string {
	// 返回固定的构建时间（实际项目中应该从构建信息获取）
	return "2024-04-01 12:00:00"
}

func getGitCommit() string {
	// 返回固定的Git提交（实际项目中应该从构建信息获取）
	return "a1b2c3d4e5f6"
}
