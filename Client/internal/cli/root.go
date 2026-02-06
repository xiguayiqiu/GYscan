package cli

import (
	"fmt"
	"os"

	"GYscan/internal/csrf"
	"GYscan/internal/exp"
	"GYscan/internal/nmap"
	"GYscan/internal/scapy"
	"GYscan/internal/subdomain"
	"GYscan/internal/utils"
	"GYscan/internal/webfp"
	"GYscan/internal/xss"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// 版本号
const (
	Version = "v2.8.1"
)

// rootCmd 表示基础命令
var rootCmd = &cobra.Command{
	Use:   "GYscan [help]",
	Short: "Go语言综合渗透测试工具",
	Long: `GYscan - 作者：BiliBili-弈秋啊 | 基于Go语言开发，专注综合渗透测试
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
	utils.BoldInfo("GYscan - Go语言综合渗透测试工具")
	utils.BoldInfo("作者: BiliBili-弈秋啊")
	utils.BoldInfo("工具版本: " + Version)
	utils.BoldInfo("描述: 综合渗透测试工具，着重资产探测、漏洞检测、安全验证")

	// 使用红色显示警告信息
	redBold := color.New(color.FgHiRed, color.Bold)
	redBold.Println("警告: 仅用于授权测试，严禁未授权使用！")

	utils.BoldInfo("==============================================")
	utils.BoldInfo("使用 \"./GYscan help\" 获取帮助信息")
}

// Execute 执行根命令
func Execute() {
	// 解析全局参数
	noBanner := hasFlag("no-banner")
	noColor := hasFlag("no-color")
	verbose := hasFlag("verbose")
	silent := hasFlag("silent")

	// 设置全局状态
	if noColor {
		utils.UseColor = false
	}
	if verbose {
		utils.IsVerbose = true
	}
	if silent {
		utils.IsSilent = true
	}

	// 显示版本信息
	if showVersion() {
		printVersion()
		return
	}

	// 显示帮助信息
	if showHelp() {
		if !noBanner {
			printBanner()
		}
		printCustomHelp()
		return
	}

	// 无参数或只请求横幅时
	if len(os.Args) == 1 || (len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help")) {
		if !noBanner {
			printBanner()
		}
		printCustomHelp()
		return
	}

	// 使用完全自定义的简洁模板
	rootCmd.SetUsageTemplate(`Usage:
  {{if .Runnable}}{{.UseLine}}{{end}}
  {{if .HasAvailableSubCommands}}{{.CommandPath}} [command]{{end}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

Use "{{.CommandPath}} help [command]" 获取命令帮助信息
`)

	// 正常执行命令
	if err := rootCmd.Execute(); err != nil {
		utils.LogError("命令执行失败: %v", err)
		utils.ErrorPrint("%v", err)
		os.Exit(1)
	}
}

// 检查参数是否存在
func hasFlag(name string) bool {
	for _, arg := range os.Args[1:] {
		if arg == "--"+name || arg == "-"+name[0:1] {
			return true
		}
	}
	return false
}

// 检查是否只显示版本
func showVersion() bool {
	return len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") && len(os.Args) == 2
}

// 检查是否只显示帮助
func showHelp() bool {
	return len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help")
}

// printVersion 输出版本信息
func printVersion() {
	fmt.Printf("GYscan version %s\n", Version)
}

// printCustomHelp 自定义帮助信息，将命令按类别分组显示
func printCustomHelp() {
	fmt.Println("Usage:")
	fmt.Println("  GYscan [help] [flags]")
	fmt.Println("  GYscan [command]")
	fmt.Println()

	// 使用CommandRegistry获取分组信息
	r := BuildRegistry()
	commandGroups := make(map[CommandGroup][]*cobra.Command)

	// 将所有命令按组分类
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "help" {
			continue
		}
		registeredCmd := r.GetCommand(cmd.Name())
		if registeredCmd != nil {
			// 找到该命令所属的组
			for group, commands := range r.groups {
				for _, c := range commands {
					if c.Name() == cmd.Name() {
						commandGroups[group] = append(commandGroups[group], cmd)
						break
					}
				}
			}
		}
	}

	// 显示命令分组
	fmt.Println("Available Commands:")
	fmt.Println()

	// 按照预定义的顺序显示分组
	for _, group := range r.GetGroupsInOrder() {
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
	fmt.Println("      --no-banner      不显示启动横幅")
	fmt.Println("      --no-color       禁用颜色输出")
	fmt.Println("  -v, --verbose        显示详细输出")
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
	cmd.PersistentFlags().Bool("no-banner", false, "不显示启动横幅")
	cmd.PersistentFlags().Bool("no-color", false, "禁用颜色输出")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "显示详细输出")

	// ===== 非测试阶段命令 =====
	cmd.AddCommand(aboutCmd)         // 查看工具信息
	cmd.AddCommand(crunchCmd)        // 密码字典生成工具
	cmd.AddCommand(databaseCmd)      // 数据库密码破解工具
	cmd.AddCommand(dirscanCmd)       // 网站目录扫描工具
	cmd.AddCommand(ftpCmd)           // FTP密码破解
	cmd.AddCommand(fuCmd)            // 文件上传漏洞检查工具
	cmd.AddCommand(linenumCmd)       // Linux本地信息枚举和权限提升工具
	cmd.AddCommand(linuxKernelCmd)   // Linux内核漏洞检测工具
	cmd.AddCommand(powershellCmd)    // PowerShell远程执行工具 [WinRM服务利用]
	cmd.AddCommand(processCmd)       // 进程与服务信息收集工具
	cmd.AddCommand(rdpCmd)           // RDP远程桌面工具
	cmd.AddCommand(routeCmd)         // 路由跳数检测
	cmd.AddCommand(nmap.ScanCmd)     // 网络扫描工具
	cmd.AddCommand(scapy.ScapyCmd)   // 高级网络包操作工具（类似Scapy）
	cmd.AddCommand(smbCmd)           // SMB协议操作工具
	cmd.AddCommand(sshCmd)           // SSH密码爆破工具（Hydra风格）
	cmd.AddCommand(subdomain.SubCmd) // 子域名挖掘工具
	cmd.AddCommand(userinfoCmd)      // 本地用户和组分析
	cmd.AddCommand(webshellCmd)      // WebShell生成工具
	cmd.AddCommand(wmiCmd)           // WMI远程管理工具
	cmd.AddCommand(winlogCmd)        // 远程Windows日志查看工具
	cmd.AddCommand(xss.XssCmd)       // XSS漏洞检测工具
	cmd.AddCommand(wafCmd)           // WAF识别工具
	cmd.AddCommand(webfp.WebfpCmd)   // 网站技术指纹识别工具
	cmd.AddCommand(whoisCmd)         // Whois查询工具
	cmd.AddCommand(wwifiCmd)         // Windows系统WiFi破解工具
	cmd.AddCommand(pcCmd)            // 远程补丁探测工具
	cmd.AddCommand(wsCmd)            // WebSocket测试工具

	// ===== 测试阶段命令 =====
	cmd.AddCommand(csrf.Cmd)   // CSRF漏洞检测 [测试阶段]
	cmd.AddCommand(dcomCmd)    // DCOM远程执行模块 [测试阶段]
	cmd.AddCommand(ldapCmd)    // LDAP枚举模块 [测试阶段]
	cmd.AddCommand(mgCmd)      // 蜜罐识别工具 [测试阶段]
	cmd.AddCommand(adcsCmd)    // AD CS 漏洞检测工具 [测试阶段]
	cmd.AddCommand(exp.ExpCmd) // Exploit-DB 漏洞利用搜索和PoC生成 [测试阶段]
}

// init 初始化命令
func init() {
	RegisterCommands(rootCmd)
}
