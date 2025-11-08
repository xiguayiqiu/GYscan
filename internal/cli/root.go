package cli

import (
	"os"

	"GYscan/internal/nmap"
	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
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

		printBanner()
	},
	// 禁用completion命令
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// printBanner 输出工具标识横幅
func printBanner() {
	utils.InfoPrint("==============================================")
	utils.InfoPrint("GYscan - Go语言内网横向边界安全测试工具")
	utils.InfoPrint("作者: BiliBili-弈秋啊")
	utils.InfoPrint("工具版本: v1.0.0")
	utils.InfoPrint("描述: 专注内网资产探测、横向移动、安全验证")
	utils.InfoPrint("")

	// 使用color包实现跨平台红色警告显示
	red := color.New(color.FgRed)
	red.Println("警告: 仅用于授权测试，严禁未授权使用！")

	utils.InfoPrint("==============================================")
	utils.InfoPrint("Use \"./GYscan -h\" for help")
}

// Execute 执行根命令
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		utils.ErrorPrint("%v", err)
		os.Exit(1)
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
}
