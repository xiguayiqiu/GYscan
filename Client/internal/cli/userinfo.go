package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"GYscan/internal/userinfo"
	"GYscan/internal/utils"
)

var userinfoCmd = &cobra.Command{
	Use:   "userinfo",
	Short: "本地用户和组分析",
	Long:  `分析本地系统的用户和组信息，支持Windows和Linux系统

功能特性：
• 自动检测操作系统类型（Windows/Linux）
• 显示本地用户账户信息
• 显示本地用户组信息
• 支持详细的权限和属性信息
• 跨平台兼容，支持多种系统

支持的平台：
• Windows: 支持本地用户和组分析
• Linux: 支持本地用户和组分析`,
	Example: `  # 显示本地用户和组信息
  GYscan.exe userinfo
  
  # 仅显示用户信息
  GYscan.exe userinfo --users-only
  
  # 仅显示组信息
  GYscan.exe userinfo --groups-only
  
  # 显示详细信息
  GYscan.exe userinfo --detailed
  
  # 显示帮助信息
  GYscan.exe userinfo --help`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}
		
		// 获取命令行参数
		usersOnly, _ := cmd.Flags().GetBool("users-only")
		groupsOnly, _ := cmd.Flags().GetBool("groups-only")
		
		utils.BannerPrint("本地用户和组分析工具")
		
		// 默认显示用户和组信息
		if !usersOnly && !groupsOnly {
			usersOnly = true
			groupsOnly = true
		}
		
		// 分析用户信息
		if usersOnly {
			fmt.Println("正在分析本地用户信息...")
			users, err := userinfo.AnalyzeLocalUsers()
			if err != nil {
				utils.ErrorPrint("分析用户信息失败: %v", err)
			} else {
				// 总是使用带颜色的格式化输出
				fmt.Println(userinfo.FormatUserInfo(users))
			}
		}
		
		// 分析组信息
		if groupsOnly {
			fmt.Println("正在分析本地组信息...")
			groups, err := userinfo.AnalyzeLocalGroups()
			if err != nil {
				utils.ErrorPrint("分析组信息失败: %v", err)
			} else {
				// 总是使用带颜色的格式化输出
				fmt.Println(userinfo.FormatGroupInfo(groups))
			}
		}
		
		utils.SuccessPrint("用户和组分析完成")
	},
}

func init() {
	// 定义命令行参数
	userinfoCmd.Flags().Bool("users-only", false, "仅显示用户信息")
	userinfoCmd.Flags().Bool("groups-only", false, "仅显示组信息")
	userinfoCmd.Flags().BoolP("detailed", "d", false, "显示详细信息")
}