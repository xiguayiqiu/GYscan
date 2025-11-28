package cli

import (
	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// aboutCmd 表示关于命令
var aboutCmd = &cobra.Command{
	Use:   "about",
	Short: "综合测试工具，着重内网测试",
	Long:  "GYscan是一款专注于内网横向移动和边界安全测试的综合工具，基于Go语言开发，提供高效、可靠的内网安全评估解决方案。",
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
	utils.InfoPrint("• 作为综合测试工具，着重内网安全测试与评估")
	utils.InfoPrint("• 红队攻防演练中的内网横向移动测试")
	utils.InfoPrint("• 安全运维与监控中的内网边界安全检查")
	utils.InfoPrint("")
	utils.InfoPrint("常规横向测试步骤如下")
	utils.InfoPrint("1. 资产探测: 使用各种手段发现目标网络中的存活主机、端口、服务等信息。")
	utils.InfoPrint("1.1 端口扫描: 识别目标主机上开放的端口, 确定服务类型。")
	utils.InfoPrint("1.2 服务识别: 基于端口号, 识别目标主机上运行的具体服务。")
	utils.InfoPrint("1.3 漏洞扫描: 利用工具或经验识别目标主机上存在的安全漏洞。")
	utils.InfoPrint("1.4 漏洞利用: 基于识别到的漏洞, 利用各种手段执行攻击操作。")
	utils.InfoPrint("")
	utils.InfoPrint("2. 凭证处理: 利用工具或经验抓取本地系统凭证、域账号密码等敏感信息。")
	utils.InfoPrint("2.1 本地凭证抓取: 利用工具或经验在目标主机上抓取本地系统账号密码等敏感信息。")
	utils.InfoPrint("2.2 域账号密码抓取: 利用工具或经验在域环境中抓取域账号密码等敏感信息。")
	utils.InfoPrint("2.3 批量验证: 利用工具或经验批量验证抓取到的凭证是否有效, 减少手动验证工作量。")
	utils.InfoPrint("2.4 凭证利用: 利用工具或经验将抓取到的有效凭证用于横向攻击, 执行远程命令、上传文件等操作。")
	utils.InfoPrint("")
	utils.InfoPrint("3. 横向执行: 通过工具或经验在目标主机上执行远程命令、上传文件等操作。")
	utils.InfoPrint("3.1 远程命令执行: 利用工具或经验在目标主机上执行任意命令, 包括系统命令、shell命令等。")
	utils.InfoPrint("3.2 文件上传: 利用工具或经验将本地文件上传到目标主机上, 实现文件传输。")
	utils.InfoPrint("3.3 漏洞利用: 利用工具或经验识别目标主机上存在的提权漏洞, 并执行提权操作。")
	utils.InfoPrint("3.4 服务利用: 利用工具或经验识别目标主机上存在的服务漏洞, 并执行攻击操作。")
	utils.InfoPrint("3.5 权限提升: 利用工具或经验识别并利用提权漏洞, 获取系统管理员权限。")
	utils.InfoPrint("3.6 服务利用: 利用工具或经验识别目标主机上存在的服务漏洞, 并执行攻击操作。")
	utils.InfoPrint("")
	utils.InfoPrint("4. 痕迹清理: 使用工具或经验清理目标主机上的系统日志、文件等痕迹, 防止被发现。")
	utils.InfoPrint("4.1 系统日志清理: 利用工具或经验清理目标主机上的系统日志, 包括系统日志、应用日志等。")
	utils.InfoPrint("4.2 文件删除: 利用工具或经验删除目标主机上的敏感文件, 防止被发现。")
	utils.InfoPrint("4.3 注册表清理: 利用工具或经验清理目标主机上的注册表, 防止被发现。")
	utils.InfoPrint("4.4 服务清理: 利用工具或经验清理目标主机上的服务, 防止被发现。")
	utils.InfoPrint("4.5 进程清理: 利用工具或经验清理目标主机上的进程, 防止被发现。")
	utils.InfoPrint("4.6 系统配置清理: 利用工具或经验清理目标主机上的系统配置, 防止被发现。")
	utils.InfoPrint("4.7 系统服务清理: 利用工具或经验清理目标主机上的系统服务, 防止被发现。")
	utils.InfoPrint("")

	// 使用color包实现跨平台红色警告显示
	red := color.New(color.FgRed)
	red.Println("重要声明：本工具仅用于已授权的安全测试，严禁未授权使用！")

	utils.InfoPrint("==============================================")
}

func init() {
	// about命令不需要额外参数
}
