package cli

import (
	"os"

	"GYscan/internal/nmap"
	"GYscan/internal/utils"

	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// 版本号
const (
	Version = "v2.0.1"
)

// rootCmd 表示基础命令
var rootCmd = &cobra.Command{
	Use:   "GYscan [help]",
	Short: "Go语言内网横向边界安全测试工具",
	Long: `GYscan - 作者：BiliBili-弈秋啊 | 基于Go语言开发，专注内网横向边界安全测试
警告：仅用于授权测试，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}
		// 直接运行程序时显示艺术字
		printBanner()
	},
	// 禁用completion命令
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// printBanner 输出工具标识横幅
func printBanner() {
	// 显示GYscan艺术字
	fig := figure.NewFigure("GYscan", "slant", true)
	fig.Print()
	utils.InfoPrint("")

	utils.InfoPrint("==============================================")
	utils.InfoPrint("GYscan - Go语言内网横向边界安全测试工具")
	utils.InfoPrint("作者: BiliBili-弈秋啊")
	utils.InfoPrint("工具版本: " + Version)
	utils.InfoPrint("描述: 专注内网资产探测、横向移动、安全验证")
	utils.InfoPrint("")

	// 使用color包实现跨平台红色警告显示
	red := color.New(color.FgRed)
	red.Println("警告: 仅用于授权测试，严禁未授权使用！")

	utils.InfoPrint("==============================================")
	utils.InfoPrint("使用 \"./GYscan -h\" 获取帮助信息")
}

// Execute 执行根命令
func Execute() {
	// 设置帮助函数，确保显示帮助信息时也显示艺术字
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printBanner()
		cmd.Usage()
	})

	// 为所有子命令也设置帮助函数
	setHelpFuncForCommands(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		utils.ErrorPrint("%v", err)
		os.Exit(1)
	}
}

// setHelpFuncForCommands 递归为所有命令设置帮助函数和PersistentPreRun
func setHelpFuncForCommands(cmd *cobra.Command) {
	for _, subCmd := range cmd.Commands() {
		subCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
			printBanner()
			cmd.Usage()
		})
		// 为子命令设置PersistentPreRun，确保执行时显示艺术字
		originalPreRun := subCmd.PersistentPreRun
		subCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
			printBanner()
			if originalPreRun != nil {
				originalPreRun(cmd, args)
			}
		}
		// 递归设置子命令的帮助函数
		setHelpFuncForCommands(subCmd)
	}
}

// init 初始化命令
func init() {
	// 添加全局参数
	rootCmd.PersistentFlags().BoolP("silent", "s", false, "静默模式，仅输出关键结果")
	rootCmd.PersistentFlags().String("proxy", "", "代理服务器 (支持 HTTP/SOCKS5)")
	rootCmd.PersistentFlags().String("key", "", "流量加密密钥 (AES-256)")
	rootCmd.PersistentFlags().BoolP("version", "v", false, "显示版本信息")

	// 添加子命令
	rootCmd.AddCommand(aboutCmd)
	rootCmd.AddCommand(webshellCmd)
	rootCmd.AddCommand(crunchCmd)
	rootCmd.AddCommand(samCmd)
	// 添加nmap命令
	rootCmd.AddCommand(nmap.ScanCmd)
	// 添加ssh命令
	rootCmd.AddCommand(sshCmd)
	// 添加database命令
	rootCmd.AddCommand(databaseCmd)
	// 添加userinfo命令
	rootCmd.AddCommand(userinfoCmd)
	// 添加dirscan命令
	rootCmd.AddCommand(dirscanCmd)
	// 添加process命令
	rootCmd.AddCommand(processCmd)
	// 添加route命令
	rootCmd.AddCommand(routeCmd)
}
