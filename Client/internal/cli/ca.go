package cli

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"GYscan/internal/configaudit"
	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	auditTarget        string
	auditCategory      string
	auditOutput        string
	auditFormat        string
	auditVerbose       bool
	auditBaseline      string
	auditParallelism   int
	auditTimeout       int
	auditSkipPrivCheck bool

	sshUser     string
	sshPassword string
	sshPort     int
	sshKeyPath  string
	sshKeyData  string

	wmiUser     string
	wmiPassword string
	wmiDomain   string
	wmiPort     int

	osType         string
	connectionMode string
	detectOS       bool
)

var caCmd = &cobra.Command{
	Use:   "ca [target]",
	Short: "配置审计功能 - 检查系统、Web、SSH和中间件配置安全性",
	Long: `配置审计(CA)功能 - 系统性检查并评估各类系统配置的安全性

支持审计的范围:
  - 操作系统: Windows/Linux账户权限、密码策略、服务端口、文件系统权限
  - Web服务: 安全Headers、CORS策略、SSL/TLS配置、会话管理
  - SSH服务: 认证方式、密钥管理、会话超时、访问控制
  - 中间件: 数据库、应用服务器、缓存服务器、消息队列

审计类型:
  - 合规性审计: 依据行业安全标准验证配置合规性
  - 安全性审计: 排查高危配置缺陷
  - 操作性审计: 检查配置的可维护性与可审计性

连接方式:
  - SSH连接: 用于Linux/macOS系统，需要用户名和密码或私钥
  - WMI连接: 用于Windows系统，通过135端口RPC服务

使用规则:
  - Linux系统使用SSH参数(--ssh-user, --ssh-password或--ssh-key)
  - Windows系统使用WMI参数(--wmi-user, --wmi-password)
  - 不能同时指定SSH和WMI连接参数

远程审计使用示例:

  # Linux系统 - 使用SSH密码连接
  GYscan ca 192.168.1.100 --ssh-user root --ssh-password yourpassword
  GYscan ca 192.168.1.100 --ssh-user root --ssh-key ~/.ssh/id_rsa

  # Linux系统 - 指定SSH端口
  GYscan ca 192.168.1.100 --ssh-user admin --ssh-password pass --ssh-port 2222

  # Windows系统 - 使用WMI连接
  GYscan ca 192.168.1.50 --wmi-user administrator --wmi-password yourpassword
  GYscan ca 192.168.1.50 --wmi-user domain\\admin --wmi-password pass --wmi-domain CORP

本地审计使用示例:

  # 审计本地Windows系统（需要管理员权限）
  GYscan ca localhost --category os

  # 审计本地Linux系统（需要sudo/root权限）
  GYscan ca localhost --category os

  # 全面审计本地系统
  GYscan ca localhost --category all

  # 生成HTML报告
  GYscan ca localhost --output report.html --format html

Windows 135端口问题处理:

  # 如果目标Windows系统未开启135端口，会显示详细操作指引
  GYscan ca 192.168.1.50 --wmi-user admin --wmi-password pass

  提示信息将包含:
    - 图形界面开启135端口的步骤
    - 命令行开启135端口的方法
    - 防火墙配置说明
    - RPC服务启动与检查方法
    - 操作完成后的验证步骤`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && auditTarget == "" {
			utils.ErrorPrint("请指定审计目标 (IP地址、主机名或URL)")
			cmd.Help()
			return
		}

		if len(args) > 0 {
			auditTarget = args[0]
		}

		runConfigAudit()
	},
}

func init() {
	caCmd.Flags().StringVarP(&auditCategory, "category", "c", "all",
		"审计类别 (os, web, ssh, middleware, all)")
	caCmd.Flags().StringVarP(&auditOutput, "output", "o", "",
		"输出文件路径")
	caCmd.Flags().StringVarP(&auditFormat, "format", "f", "text",
		"输出格式 (text, json, html)")
	caCmd.Flags().BoolVarP(&auditVerbose, "verbose", "v", false,
		"显示详细信息")
	caCmd.Flags().StringVar(&auditBaseline, "baseline", "enterprise",
		"安全基线配置 (enterprise, high_security, pci_dss, hipaa)")
	caCmd.Flags().IntVarP(&auditParallelism, "parallel", "p", 4,
		"并行审计数量")
	caCmd.Flags().IntVar(&auditTimeout, "timeout", 300,
		"超时时间 (秒)")
	caCmd.Flags().BoolVar(&auditSkipPrivCheck, "skip-priv-check", false,
		"跳过权限检查（谨慎使用，仅当确认已有所需权限时）")

	caCmd.Flags().StringVar(&osType, "os-type", "auto",
		"目标系统类型 (windows, linux, auto)")
	caCmd.Flags().StringVar(&connectionMode, "connection-mode", "auto",
		"连接模式 (ssh, wmi, auto)")
	caCmd.Flags().BoolVar(&detectOS, "detect-os", true,
		"自动检测目标系统类型")

	caCmd.Flags().StringVar(&sshUser, "ssh-user", "",
		"SSH用户名")
	caCmd.Flags().StringVar(&sshPassword, "ssh-password", "",
		"SSH密码")
	caCmd.Flags().StringVar(&sshKeyPath, "ssh-key", "",
		"SSH私钥文件路径")
	caCmd.Flags().StringVar(&sshKeyData, "ssh-key-data", "",
		"SSH私钥内容（直接提供）")
	caCmd.Flags().IntVar(&sshPort, "ssh-port", 22,
		"SSH端口")

	caCmd.Flags().StringVar(&wmiUser, "wmi-user", "",
		"WMI用户名 (Windows审计)")
	caCmd.Flags().StringVar(&wmiPassword, "wmi-password", "",
		"WMI密码 (Windows审计)")
	caCmd.Flags().StringVar(&wmiDomain, "wmi-domain", "",
		"WMI域名 (Windows审计，可选)")
	caCmd.Flags().IntVar(&wmiPort, "wmi-port", 135,
		"WMI/RPC端口 (默认135)")

	rootCmd.AddCommand(caCmd)
}

func runConfigAudit() {
	startTime := time.Now()

	utils.BoldInfo("==============================================")
	utils.BoldInfo("              GYscan 配置审计模块")
	utils.BoldInfo("==============================================")
	fmt.Println()

	utils.LogInfo("审计目标: %s", auditTarget)
	utils.LogInfo("审计类别: %s", auditCategory)
	utils.LogInfo("输出格式: %s", auditFormat)

	osTypeEnum := parseOSType(osType)
	connectionModeEnum := configaudit.ConnectionModeAuto

	var connectionManager *configaudit.ConnectionManager
	var targetOSType configaudit.OSType
	var err error

	needRemote := (sshUser != "" || wmiUser != "")

	if needRemote {
		utils.LogInfo("准备建立远程连接...")

		if sshUser != "" && wmiUser != "" {
			utils.ErrorPrint("不能同时指定SSH和WMI连接参数，请只使用一种连接方式")
			os.Exit(1)
		}

		if sshUser != "" {
			connectionModeEnum = configaudit.ConnectionModeSSH
			if osTypeEnum == configaudit.OSUnknown || osTypeEnum == configaudit.OSAuto {
				osTypeEnum = configaudit.OSLinux
				utils.LogInfo("未指定系统类型，默认为Linux，使用SSH连接")
			} else if osTypeEnum != configaudit.OSLinux && osTypeEnum != configaudit.OSMacOS {
				utils.Warning("警告: SSH连接通常用于Linux/macOS系统，但指定了 %s", osTypeEnum)
			}

			sshConfig := &configaudit.SSHConfig{
				Host:           auditTarget,
				Port:           sshPort,
				Username:       sshUser,
				Password:       sshPassword,
				PrivateKeyPath: sshKeyPath,
				PrivateKey:     sshKeyData,
				Timeout:        time.Duration(auditTimeout) * time.Second,
				MaxRetries:     3,
			}

			connConfig := &configaudit.ConnectionConfig{
				Target:        auditTarget,
				OSType:        osTypeEnum,
				SSHConfig:     sshConfig,
				PreferredMode: connectionModeEnum,
				Timeout:       time.Duration(auditTimeout) * time.Second,
				AutoDetect:    false,
				ForceMode:     true,
			}

			connectionManager = configaudit.NewConnectionManager(connConfig)
			connectionStatus, err := connectionManager.Connect()

			if err != nil {
				utils.ErrorPrint("SSH连接失败: %v", err)
				utils.LogInfo("请检查:")
				utils.LogInfo("  1. SSH服务是否在目标系统上运行 (默认端口: %d)", sshPort)
				utils.LogInfo("  2. 用户名和密码是否正确")
				utils.LogInfo("  3. 防火墙是否允许SSH连接")
				os.Exit(1)
			}

			targetOSType = connectionStatus.OSType
			utils.LogInfo("SSH连接成功 (用户: %s)", sshUser)
			utils.LogInfo("检测到目标系统类型: %s", targetOSType)

		} else if wmiUser != "" {
			connectionModeEnum = configaudit.ConnectionModeWMI
			if osTypeEnum == configaudit.OSUnknown || osTypeEnum == configaudit.OSAuto {
				osTypeEnum = configaudit.OSWindows
				utils.LogInfo("未指定系统类型，默认为Windows，使用WMI连接")
			} else if osTypeEnum != configaudit.OSWindows {
				utils.Warning("警告: WMI连接通常用于Windows系统，但指定了 %s", osTypeEnum)
			}

			username := wmiUser
			if wmiDomain != "" {
				username = wmiDomain + "\\" + wmiUser
			}

			wmiConfig := &configaudit.WMIConfig{
				Host:       auditTarget,
				Port:       wmiPort,
				Username:   username,
				Password:   wmiPassword,
				Timeout:    time.Duration(auditTimeout) * time.Second,
				MaxRetries: 3,
			}

			connConfig := &configaudit.ConnectionConfig{
				Target:        auditTarget,
				OSType:        osTypeEnum,
				WMIConfig:     wmiConfig,
				PreferredMode: connectionModeEnum,
				Timeout:       time.Duration(auditTimeout) * time.Second,
				AutoDetect:    false,
				ForceMode:     true,
			}

			connectionManager = configaudit.NewConnectionManager(connConfig)
			connectionStatus, err := connectionManager.Connect()

			if err != nil {
				utils.ErrorPrint("WMI连接失败: %v", err)

				if osTypeEnum == configaudit.OSWindows || targetOSType == configaudit.OSWindows {
					utils.LogInfo("\n正在检查Windows系统135端口状态...")
					portResult := configaudit.DetectAndGuide135Port(auditTarget, 10*time.Second)
					if !portResult.IsOpen {
						color.Yellow("\n" + portResult.Message)
					}
				}

				utils.LogInfo("\n故障排除建议:")
				utils.LogInfo("  1. 确认目标Windows系统135端口(RPC)已开启")
				utils.LogInfo("  2. 检查用户名、密码或域配置是否正确")
				utils.LogInfo("  3. 确认网络连接正常，防火墙已放行135端口")
				utils.LogInfo("  4. 确认RPC服务和DCOM服务已在目标系统启动")
				os.Exit(1)
			}

			targetOSType = connectionStatus.OSType
			utils.LogInfo("WMI连接成功 (用户: %s)", username)
			utils.LogInfo("检测到目标系统类型: %s", targetOSType)
		}

		defer func() {
			if connectionManager != nil {
				connectionManager.Disconnect()
			}
		}()
	} else {
		if !auditSkipPrivCheck {
			if !checkAuditPrivileges() {
				printPrivilegeInstructions()
				os.Exit(1)
			}
			utils.LogInfo("权限检查通过")

			if runtime.GOOS == "windows" {
				targetOSType = configaudit.OSWindows
			} else {
				targetOSType = configaudit.OSLinux
			}
		} else {
			utils.LogWarning("警告: 已跳过权限检查，某些审计项目可能无法正常执行")
			targetOSType = configaudit.OSUnknown
		}
	}

	categories := parseCategoriesForOS(auditCategory, targetOSType)

	utils.LogInfo("审计类别: %s", categories)
	utils.LogInfo("目标系统类型: %s", targetOSType)

	engineConfig := &configaudit.EngineConfig{
		Parallelism:     auditParallelism,
		Timeout:         time.Duration(auditTimeout) * time.Second,
		RetryCount:      2,
		OutputFormat:    auditFormat,
		IncludeDetails:  auditVerbose,
		SkipPassed:      false,
		BaselineProfile: auditBaseline,
	}

	engine := configaudit.NewAuditEngine(engineConfig)

	configaudit.RegisterEnhancedCollectors(engine)
	configaudit.LoadEnhancedAuditChecks(engine)

	if connectionManager != nil {
		utils.LogInfo("正在收集远程%s系统配置信息...", targetOSType)
		configData := connectionManager.CollectConfig()
		if len(configData) > 0 {
			engine.SetRemoteConfig(configData)
		}
	}

	report, err := engine.RunAudit(auditTarget, categories)
	if err != nil {
		utils.ErrorPrint("审计执行失败: %v", err)
		os.Exit(1)
	}

	report.Category = configaudit.AuditCategory(auditCategory)

	generator := configaudit.NewReportGenerator(auditFormat, auditVerbose)

	if auditOutput != "" {
		if err := generator.Generate(report, auditOutput); err != nil {
			utils.ErrorPrint("报告生成失败: %v", err)
		} else {
			utils.BoldInfo("报告已保存到: %s", auditOutput)
		}
	} else {
		generator.Generate(report, "")
	}

	duration := time.Since(startTime)
	utils.LogInfo("审计完成，耗时: %.2f秒", duration.Seconds())

	if report.Summary.RiskLevel == configaudit.RiskLevelCritical ||
		report.Summary.RiskLevel == configaudit.RiskLevelHigh {
		color.Yellow("\n警告: 发现高风险配置问题，请立即处理!")
	}
}

func handleConnectionError(err error, osType configaudit.OSType, mode configaudit.ConnectionMode) {
	utils.ErrorPrint("连接失败: %v", err)

	if osType == configaudit.OSWindows && mode == configaudit.ConnectionModeWMI {
		utils.LogInfo("\n正在检查Windows系统135端口状态...")

		portResult := configaudit.DetectAndGuide135Port(
			auditTarget,
			10*time.Second,
		)

		if !portResult.IsOpen {
			color.Yellow("\n" + portResult.Message)
		}
	}

	utils.LogInfo("\n故障排除建议:")
	utils.LogInfo("1. 确认目标系统已开启相应的服务 (SSH:22, WMI:135)")
	utils.LogInfo("2. 检查用户名、密码或私钥是否正确")
	utils.LogInfo("3. 确认网络连接正常，防火墙已放行相应端口")
	utils.LogInfo("4. 对于Windows系统，确认RPC服务和DCOM服务已启动")
}

func parseOSType(osTypeStr string) configaudit.OSType {
	switch strings.ToLower(osTypeStr) {
	case "windows":
		return configaudit.OSWindows
	case "linux":
		return configaudit.OSLinux
	case "macos", "darwin":
		return configaudit.OSMacOS
	case "auto", "":
		return configaudit.OSUnknown
	default:
		return configaudit.OSUnknown
	}
}

func hasCategory(categories []configaudit.AuditCategory, target configaudit.AuditCategory) bool {
	for _, cat := range categories {
		if cat == target {
			return true
		}
	}
	return false
}

func checkAuditPrivileges() bool {
	osType := runtime.GOOS

	switch osType {
	case "windows":
		return checkWindowsAdminPrivileges()
	case "linux":
		return checkLinuxRootPrivileges()
	case "darwin":
		return checkLinuxRootPrivileges()
	default:
		utils.LogWarning("不支持的操作系统: %s，将跳过权限检查", osType)
		return true
	}
}

func checkWindowsAdminPrivileges() bool {
	utils.LogInfo("检查Windows管理员权限...")

	currentUser, err := user.Current()
	if err != nil {
		utils.ErrorPrint("无法获取当前用户信息: %v", err)
		return false
	}

	if strings.EqualFold(currentUser.Username, "Administrator") {
		utils.LogInfo("当前用户为 Administrator")
		return true
	}

	isAdmin, err := isRunningAsAdmin()
	if err != nil {
		utils.ErrorPrint("无法检查管理员权限: %v", err)
		return false
	}

	if isAdmin {
		utils.LogInfo("已检测到管理员权限")
		return true
	}

	return false
}

func isRunningAsAdmin() (bool, error) {
	return isAdminGroupMember(), nil
}

func isAdminGroupMember() bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	groups, err := currentUser.GroupIds()
	if err != nil {
		return false
	}

	for _, gid := range groups {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}

		groupName := strings.ToLower(group.Name)
		if groupName == "administrators" || groupName == "admin" {
			return true
		}
	}

	return false
}

func checkLinuxRootPrivileges() bool {
	utils.LogInfo("检查Linux root权限...")

	currentUser, err := user.Current()
	if err != nil {
		utils.ErrorPrint("无法获取当前用户信息: %v", err)
		return false
	}

	if currentUser.Uid == "0" {
		utils.LogInfo("当前用户为 root (UID: 0)")
		return true
	}

	utils.LogWarning("当前用户 '%s' 不是 root用户 (UID: %s)", currentUser.Username, currentUser.Uid)
	utils.LogInfo("当前有效用户: %s, UID: %s, GID: %s", currentUser.Username, currentUser.Uid, currentUser.Gid)

	groups, err := currentUser.GroupIds()
	if err == nil {
		for _, gid := range groups {
			group, err := user.LookupGroupId(gid)
			if err != nil {
				continue
			}
			groupName := strings.ToLower(group.Name)
			if groupName == "sudo" || groupName == "wheel" {
				utils.LogInfo("用户属于 %s 组，可能通过sudo获取权限", group.Name)
				return true
			}
		}
	}

	return false
}

func printPrivilegeInstructions() {
	osType := runtime.GOOS

	fmt.Println()
	color.Yellow("==============================================")
	color.Yellow("                   权限不足")
	color.Yellow("==============================================")
	fmt.Println()

	switch osType {
	case "windows":
		color.Yellow("Windows系统配置审计需要管理员权限")
		fmt.Println()
		fmt.Println("请使用以下方式之一重新运行:")
		fmt.Println()
		color.Cyan("方法1: 以管理员身份运行命令提示符/PowerShell")
		fmt.Println("   1. 右键点击 '命令提示符' 或 'PowerShell'")
		fmt.Println("   2. 选择 '以管理员身份运行'")
		fmt.Println("   3. 运行: GYscan ca <target>")
		fmt.Println()
		color.Cyan("方法2: 使用runas命令")
		fmt.Println("   runas /user:Administrator \"GYscan ca <target>\"")
		fmt.Println()
		color.Cyan("方法3: 通过开始菜单搜索")
		fmt.Println("   1. 按 Win + S 搜索 'cmd' 或 'PowerShell'")
		fmt.Println("   2. 右键点击 '命令提示符' 或 'Windows PowerShell'")
		fmt.Println("   3. 选择 '以管理员身份运行'")
		fmt.Println()

	case "linux":
		color.Yellow("Linux系统配置审计需要root权限")
		fmt.Println()
		fmt.Println("请使用以下方式之一重新运行:")
		fmt.Println()
		color.Cyan("方法1: 使用sudo运行")
		fmt.Println("   sudo GYscan ca <target>")
		fmt.Println()
		color.Cyan("方法2: 切换到root用户")
		fmt.Println("   sudo -i")
		fmt.Println("   GYscan ca <target>")
		fmt.Println()
		color.Cyan("方法3: 直接以root身份运行")
		fmt.Println("   sudo su -")
		fmt.Println("   ./GYscan ca <target>")
		fmt.Println()
		color.Cyan("方法4: 设置执行权限后运行")
		fmt.Println("   chmod +x GYscan")
		fmt.Println("   sudo ./GYscan ca <target>")
		fmt.Println()

	case "darwin":
		color.Yellow("macOS系统配置审计需要root权限")
		fmt.Println()
		fmt.Println("请使用以下方式运行:")
		fmt.Println()
		color.Cyan("使用sudo运行")
		fmt.Println("   sudo GYscan ca <target>")
		fmt.Println()

	default:
		color.Yellow("当前系统权限检查失败，请确保以管理员/root权限运行")
	}

	color.Yellow("==============================================")
	fmt.Println()
	utils.LogInfo("提示: 使用 --skip-priv-check 参数可以强制跳过权限检查（谨慎使用）")
	fmt.Println()
}

func parseCategories(category string) []configaudit.AuditCategory {
	category = strings.ToLower(category)

	if category == "all" {
		return []configaudit.AuditCategory{
			configaudit.CATEGORY_OS,
			configaudit.CATEGORY_WEB,
			configaudit.CATEGORY_SSH,
			configaudit.CATEGORY_MIDDLEWARE,
		}
	}

	categories := []configaudit.AuditCategory{}
	for _, c := range strings.Split(category, ",") {
		c = strings.TrimSpace(c)
		switch c {
		case "os", "windows", "linux":
			categories = append(categories, configaudit.CATEGORY_OS)
		case "web":
			categories = append(categories, configaudit.CATEGORY_WEB)
		case "ssh":
			categories = append(categories, configaudit.CATEGORY_SSH)
		case "middleware", "mw", "db", "database":
			categories = append(categories, configaudit.CATEGORY_MIDDLEWARE)
		}
	}

	if len(categories) == 0 {
		return []configaudit.AuditCategory{
			configaudit.CATEGORY_OS,
			configaudit.CATEGORY_WEB,
			configaudit.CATEGORY_SSH,
			configaudit.CATEGORY_MIDDLEWARE,
		}
	}

	return categories
}

func parseCategoriesForOS(category string, osType configaudit.OSType) []configaudit.AuditCategory {
	category = strings.ToLower(category)

	if category == "all" {
		if osType == configaudit.OSWindows {
			return []configaudit.AuditCategory{
				configaudit.CATEGORY_OS,
				configaudit.CATEGORY_WEB,
				configaudit.CATEGORY_MIDDLEWARE,
			}
		}
		return []configaudit.AuditCategory{
			configaudit.CATEGORY_OS,
			configaudit.CATEGORY_WEB,
			configaudit.CATEGORY_SSH,
			configaudit.CATEGORY_MIDDLEWARE,
		}
	}

	categories := []configaudit.AuditCategory{}
	for _, c := range strings.Split(category, ",") {
		c = strings.TrimSpace(c)
		switch c {
		case "os", "windows", "linux":
			categories = append(categories, configaudit.CATEGORY_OS)
		case "web":
			categories = append(categories, configaudit.CATEGORY_WEB)
		case "ssh":
			if osType == configaudit.OSWindows {
				utils.LogWarning("SSH审计不适用于Windows系统，已跳过")
				continue
			}
			categories = append(categories, configaudit.CATEGORY_SSH)
		case "middleware", "mw", "db", "database":
			categories = append(categories, configaudit.CATEGORY_MIDDLEWARE)
		}
	}

	if len(categories) == 0 {
		if osType == configaudit.OSWindows {
			return []configaudit.AuditCategory{
				configaudit.CATEGORY_OS,
				configaudit.CATEGORY_WEB,
				configaudit.CATEGORY_MIDDLEWARE,
			}
		}
		return []configaudit.AuditCategory{
			configaudit.CATEGORY_OS,
			configaudit.CATEGORY_WEB,
			configaudit.CATEGORY_SSH,
			configaudit.CATEGORY_MIDDLEWARE,
		}
	}

	return categories
}

func loadAuditChecks(engine *configaudit.AuditEngine) {
	configaudit.LoadWindowsChecks(engine)
	configaudit.LoadLinuxChecks(engine)
	configaudit.LoadWebChecks(engine)
	configaudit.LoadSSHChecks(engine)
	configaudit.LoadMiddlewareChecks(engine)

	utils.LogInfo("已加载 %d 个审计检查项", engine.GetCheckCount())
}

func runQuickAudit(target string, category string) *configaudit.AuditReport {
	categories := parseCategories(category)

	engine := configaudit.NewAuditEngine(&configaudit.EngineConfig{
		Parallelism:  2,
		Timeout:      60 * time.Second,
		OutputFormat: "text",
	})

	loadAuditChecks(engine)

	report, _ := engine.RunAudit(target, categories)
	return report
}
