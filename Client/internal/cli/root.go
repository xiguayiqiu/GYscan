package cli

import (
	"fmt"
	"os"
	"strings"

	"GYscan/internal/csrf"
	"GYscan/internal/nmap"
	"GYscan/internal/scapy"
	"GYscan/internal/utils"
	"GYscan/internal/xss"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// 版本号
const (
	Version = "v2.6.0"
)

// rootCmd 表示基础命令
var rootCmd = &cobra.Command{
	Use:   "GYscan [help]",
	Short: "Go语言内网横向边界安全测试工具",
	Long: `GYscan - 作者：BiliBili-弈秋啊 | 基于Go语言开发，专注内网横向边界安全测试
警告：仅用于授权测试，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 直接运行程序时显示艺术字
		printBanner()
	},
	// 禁用completion命令
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	// 禁用mousetrap，允许双击直接进入交互式模式
	SilenceErrors: true,
	SilenceUsage:  true,
}

// printBanner 输出工具标识横幅
func printBanner() {
	fmt.Println()

	// 显示GYscan艺术字 - 使用醒目的蓝色加粗
	figColor := color.New(color.FgHiBlue, color.Bold)
	figColor.Println(`    ____  __   __                             `)
	figColor.Println(`   / ___| \ \ / /  ___    ___    __ _   _ __  `)
	figColor.Println(`  | |  _   \ V /  / __|  / __|  / _` + "`" + ` | | '_ \ `)
	figColor.Println(`  | |_| |   | |   \__ \ | (__  | (_| | | | | | `)
	figColor.Println(`   \____|   |_|   |___/  \___|  \__,_| |_| |_|`)
	figColor.Println(`                                              `)
	fmt.Println()

	// 使用不同颜色显示信息
	utils.BoldInfo("==============================================")
	utils.BoldInfo("GYscan - Go语言内网横向边界安全测试工具")
	utils.BoldInfo("作者: BiliBili-弈秋啊")
	utils.BoldInfo("工具版本: " + Version)
	utils.BoldInfo("描述: 综合测试工具，着重内网资产探测、横向移动、安全验证")

	// 使用红色显示警告信息
	redBold := color.New(color.FgHiRed, color.Bold)
	redBold.Println("警告: 仅用于授权测试，严禁未授权使用！")

	utils.BoldInfo("==============================================")
	utils.BoldInfo("使用 \"./GYscan help\" 获取帮助信息")
}

// Execute 执行根命令
func Execute() {
	// 先显示ASCII艺术字，所有命令执行前都显示
	printBanner()

	// 记录程序启动信息
	utils.LogInfo("GYscan 程序启动，版本: %s", Version)

	// 检查是否需要显示版本信息（仅在根命令下使用-v或--version）
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") && len(os.Args) == 2 {
		utils.LogInfo("显示版本信息")
		return
	}

	// 检查是否是主帮助请求（根命令的帮助）
	if (len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help")) || len(os.Args) == 1 {
		utils.LogInfo("显示帮助信息")
		printCustomHelp()
		return
	}

	// 使用完全自定义的简洁模板，移除所有多余空行并将--help替换为help
	rootCmd.SetUsageTemplate(`Usage:
  {{if .Runnable}}{{.UseLine}}{{end}}
  {{if .HasAvailableSubCommands}}{{.CommandPath}} [command]{{end}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

使用 "{{.CommandPath}} help [command]" 获取命令帮助信息
`)

	// 正常执行命令
	utils.LogInfo("开始执行命令")
	if err := rootCmd.Execute(); err != nil {
		utils.LogError("命令执行失败: %v", err)
		utils.ErrorPrint("%v", err)
		os.Exit(1)
	}
	utils.LogInfo("命令执行完成")
}

// printCustomHelp 自定义帮助信息，将命令按类别分组显示
func printCustomHelp() {
	fmt.Println("Usage:")
	fmt.Println("  GYscan [help] [flags]")
	fmt.Println("  GYscan [command]")
	fmt.Println()

	// 定义命令分组
	commandGroups := make(map[string][]*cobra.Command)

	// 初始化命令分组
	commandGroups["综合工具"] = []*cobra.Command{}
	commandGroups["密码学工具"] = []*cobra.Command{}
	commandGroups["网络扫描工具"] = []*cobra.Command{}
	commandGroups["远程管理工具"] = []*cobra.Command{}
	commandGroups["信息收集工具"] = []*cobra.Command{}
	commandGroups["Web安全工具"] = []*cobra.Command{}
	commandGroups["测试阶段命令"] = []*cobra.Command{}

	// 将命令分组
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "help" {
			continue
		}

		// 检查是否为测试阶段命令
		if strings.Contains(cmd.Short, "测试阶段") || strings.Contains(cmd.Long, "测试阶段") {
			commandGroups["测试阶段命令"] = append(commandGroups["测试阶段命令"], cmd)
			continue
		}

		// 根据命令名称进行分类
		switch cmd.Name() {
		case "about":
			commandGroups["综合工具"] = append(commandGroups["综合工具"], cmd)
		case "crunch", "database", "ftp", "ssh":
			commandGroups["密码学工具"] = append(commandGroups["密码学工具"], cmd)
		case "scan", "dirscan", "route", "whois", "scapy":
			commandGroups["网络扫描工具"] = append(commandGroups["网络扫描工具"], cmd)
		case "powershell", "rdp", "smb", "wmi":
			commandGroups["远程管理工具"] = append(commandGroups["远程管理工具"], cmd)
		case "process", "userinfo", "winlog":
			commandGroups["信息收集工具"] = append(commandGroups["信息收集工具"], cmd)
		case "webshell", "waf", "xss":
			commandGroups["Web安全工具"] = append(commandGroups["Web安全工具"], cmd)
		default:
			// 未分类的命令添加到综合工具
			commandGroups["综合工具"] = append(commandGroups["综合工具"], cmd)
		}
	}

	// 显示命令分组
	fmt.Println("Available Commands:")
	fmt.Println()

	// 定义分组显示顺序
	groupOrder := []string{"综合工具", "密码学工具", "网络扫描工具", "远程管理工具", "信息收集工具", "Web安全工具", "测试阶段命令"}

	for _, group := range groupOrder {
		commands := commandGroups[group]
		if len(commands) == 0 {
			continue
		}

		// 显示分组名称
		fmt.Printf("  ==== %s ====\n", group)
		for _, cmd := range commands {
			fmt.Printf("  %-15s %s\n", cmd.Name(), cmd.Short)
		}
		fmt.Println()
	}

	// 显示全局参数
	fmt.Println("Flags:")
	fmt.Println("      --key string     流量加密密钥 (AES-256)")
	fmt.Println("      --proxy string   代理服务器 (支持 HTTP/SOCKS5)")
	fmt.Println("  -q, --silent         静默模式，仅输出关键结果")
	fmt.Println("  -V, --version        显示版本信息")
	fmt.Println()
	fmt.Println("使用 \"GYscan help [command]\" 获取命令帮助信息")
}

// GetRootCommand 获取根命令（用于插件系统集成）
func GetRootCommand() *cobra.Command {
	return rootCmd
}

// RegisterCommands 注册所有命令
func RegisterCommands(cmd *cobra.Command) {
	// 添加全局参数
	cmd.PersistentFlags().BoolP("silent", "q", false, "静默模式，仅输出关键结果")
	cmd.PersistentFlags().String("proxy", "", "代理服务器 (支持 HTTP/SOCKS5)")
	cmd.PersistentFlags().String("key", "", "流量加密密钥 (AES-256)")
	cmd.PersistentFlags().BoolP("version", "V", false, "显示版本信息")

	// ===== 非测试阶段命令 =====
	cmd.AddCommand(aboutCmd)       // 查看工具信息
	cmd.AddCommand(crunchCmd)      // 密码字典生成工具
	cmd.AddCommand(databaseCmd)    // 数据库密码破解工具
	cmd.AddCommand(dirscanCmd)     // 网站目录扫描工具
	cmd.AddCommand(ftpCmd)         // FTP密码破解
	cmd.AddCommand(linenumCmd)     // Linux本地信息枚举和权限提升工具
	cmd.AddCommand(linuxKernelCmd) // Linux内核漏洞检测工具
	cmd.AddCommand(powershellCmd)  // PowerShell远程执行工具 [WinRM服务利用]
	cmd.AddCommand(processCmd)     // 进程与服务信息收集工具
	cmd.AddCommand(rdpCmd)         // RDP远程桌面工具
	cmd.AddCommand(routeCmd)       // 路由跳数检测
	cmd.AddCommand(nmap.ScanCmd)   // 网络扫描工具
	cmd.AddCommand(scapy.ScapyCmd) // 高级网络包操作工具（类似Scapy）
	cmd.AddCommand(smbCmd)         // SMB协议操作工具
	cmd.AddCommand(sshCmd)         // SSH密码爆破工具（Hydra风格）
	cmd.AddCommand(userinfoCmd)    // 本地用户和组分析
	cmd.AddCommand(webshellCmd)    // WebShell生成工具
	cmd.AddCommand(wmiCmd)         // WMI远程管理工具
	cmd.AddCommand(winlogCmd)      // 远程Windows日志查看工具
	cmd.AddCommand(xss.XssCmd)     // XSS漏洞检测工具
	cmd.AddCommand(wafCmd)         // WAF识别工具
	cmd.AddCommand(whoisCmd)       // Whois查询工具

	// ===== 测试阶段命令 =====
	cmd.AddCommand(csrf.Cmd) // CSRF漏洞检测 [测试阶段]
	cmd.AddCommand(dcomCmd)  // DCOM远程执行模块 [测试阶段]
	cmd.AddCommand(ldapCmd)  // LDAP枚举模块 [测试阶段]
}

// init 初始化命令
func init() {
	RegisterCommands(rootCmd)
}
