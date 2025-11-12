package cli

import (
	"GYscan/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)
// aboutCmd 表示关于命令
var aboutCmd = &cobra.Command{
	Use:   "about",
	Short: "查看工具信息",
	Long:  "查看工具的作者、版本、寓意等信息",
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}
		printAboutInfo()
	},
}

// printAboutInfo 输出关于信息
func printAboutInfo() {
	utils.InfoPrint("")
	utils.InfoPrint("详细功能说明：")
	utils.InfoPrint("")
	utils.InfoPrint("核心功能模块：")
	utils.InfoPrint("• 资产探测：存活主机、端口、服务识别")
	utils.InfoPrint("• 凭证处理：本地抓取、批量验证")
	utils.InfoPrint("• 横向执行：远程命令、文件上传、漏洞利用")
	utils.InfoPrint("• 权限提升：提权漏洞扫描与执行")
	utils.InfoPrint("• 痕迹清理：日志清理、文件删除")
	utils.InfoPrint("")
	utils.InfoPrint("技术特点：")
	utils.InfoPrint("• 基于Go语言开发，跨平台兼容")
	utils.InfoPrint("• 模块化架构设计，易于扩展")
	utils.InfoPrint("• 多线程并发处理，高效扫描")
	utils.InfoPrint("• 支持多种输出格式和报告生成")
	utils.InfoPrint("")
	utils.InfoPrint("适用场景：")
	utils.InfoPrint("• 内网安全测试与评估")
	utils.InfoPrint("• 红队攻防演练")
	utils.InfoPrint("• 安全运维与监控")
	utils.InfoPrint("")
	
	// 使用color包实现跨平台红色警告显示
	red := color.New(color.FgRed)
	red.Println("重要声明：本工具仅用于已授权的安全测试，严禁未授权使用！")
	
	utils.InfoPrint("==============================================")
}

func init() {
	// about命令不需要额外参数
}