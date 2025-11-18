package cli

import (
	"os"

	"GYscan/internal/csrf"
	"GYscan/internal/nmap"
	"GYscan/internal/utils"
	"GYscan/internal/xss"

	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// 版本号
const (
	Version = "v2.5.0"
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
	// 设置自定义帮助函数，在显示帮助时也显示艺术字
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printBanner()
		cmd.Usage()
	})

	// 检查是否需要显示版本信息（仅在根命令下使用-v或--version）
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") && len(os.Args) == 2 {
		printBanner()
		return
	}

	if err := rootCmd.Execute(); err != nil {
		utils.ErrorPrint("%v", err)
		os.Exit(1)
	}
}

// GetRootCommand 获取根命令（用于插件系统集成）
func GetRootCommand() *cobra.Command {
	return rootCmd
}

// RegisterCommands 注册所有命令
func RegisterCommands(cmd *cobra.Command) {
	// 添加全局参数
	cmd.PersistentFlags().BoolP("silent", "s", false, "静默模式，仅输出关键结果")
	cmd.PersistentFlags().String("proxy", "", "代理服务器 (支持 HTTP/SOCKS5)")
	cmd.PersistentFlags().String("key", "", "流量加密密钥 (AES-256)")
	cmd.PersistentFlags().BoolP("version", "v", false, "显示版本信息")

	// 添加子命令
	cmd.AddCommand(aboutCmd)
	cmd.AddCommand(webshellCmd)
	cmd.AddCommand(crunchCmd)
	cmd.AddCommand(samCmd)
	// 添加nmap命令
	cmd.AddCommand(nmap.ScanCmd)
	// 添加ssh命令
	cmd.AddCommand(sshCmd)
	// 添加database命令
	cmd.AddCommand(databaseCmd)
	// 添加userinfo命令
	cmd.AddCommand(userinfoCmd)
	// 添加dirscan命令
	cmd.AddCommand(dirscanCmd)
	// 添加process命令
	cmd.AddCommand(processCmd)
	// 添加route命令
	cmd.AddCommand(routeCmd)
	// 添加xss命令
	cmd.AddCommand(xss.XssCmd)
	// 添加csrf命令
	cmd.AddCommand(csrf.Cmd)
}

// init 初始化命令
func init() {
	RegisterCommands(rootCmd)
}
