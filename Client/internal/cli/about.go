package cli

import (
	"GYscan/internal/utils"
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
	info := `==============================================
GYscan - Go语言内网横向边界安全测试工具

作者: BiliBili-弈秋啊
版本: 2.0.0
寓意: Go + 内网横向(Y) + 边界安全扫描(scan)

核心功能：
- 资产探测：存活主机、端口、服务识别
- 凭证处理：本地抓取、批量验证
- 横向执行：远程命令、文件上传、漏洞利用
- 权限提升：提权漏洞扫描与执行
- 痕迹清理：日志清理、文件删除

警告：仅用于已授权的内网安全测试，严禁未授权使用！
==============================================`
	utils.InfoPrint(info)
}

func init() {
	// about命令不需要额外参数
}