package cli

import (
	"os"

	"GYscan/internal/smb"
	"GYscan/internal/utils"
	"github.com/spf13/cobra"
)

// smbCmd represents the smb command
var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "SMB协议操作工具",
	Long: `SMB协议操作工具 - 用于SMB协议的安全测试和横向移动

支持功能:
- SMB共享列表查看
- SMB版本检测
- 远程命令执行
- 文件上传下载

示例用法:
  # 列出SMB共享
  ./GYscan smb shares --target 192.168.1.100 --user admin --password password
  
  # 检测SMB版本
  ./GYscan smb version --target 192.168.1.100
  
  # 执行远程命令
  ./GYscan smb exec --target 192.168.1.100 --user admin --password password --command "whoami"
  
  # 使用域名
  ./GYscan smb exec --target 192.168.1.100 --user domain\admin --password password --command "systeminfo"`,
	Run: func(cmd *cobra.Command, args []string) {
		// 直接运行smb命令时显示帮助
		cmd.Help()
	},
}

// smbSharesCmd 列出SMB共享
var smbSharesCmd = &cobra.Command{
	Use:   "shares",
	Short: "列出SMB共享",
	Long:  `列出目标系统上的SMB共享资源`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")

		// 验证参数
		if target == "" {
			utils.ErrorPrint("错误: 必须指定目标主机(--target)")
			os.Exit(1)
		}

		// 创建SMB配置
		config := &smb.SMBConfig{
			Target:     target,
			Port:       port,
			Username:   username,
			Password:   password,
			Domain:     domain,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建SMB客户端
		client, err := smb.NewSMBClient(config)
		if err != nil {
			utils.ErrorPrint("SMB客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 列出共享
		shares, err := client.ListShares()
		if err != nil {
			utils.ErrorPrint("列出共享失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		utils.SuccessPrint("[+] 找到以下SMB共享:")
		for _, share := range shares {
			utils.InfoPrint("  - %s", share)
		}
	},
}

// smbVersionCmd 检测SMB版本
var smbVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "检测SMB版本",
	Long:  `检测目标系统的SMB协议版本`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")

		// 验证参数
		if target == "" {
			utils.ErrorPrint("错误: 必须指定目标主机(--target)")
			os.Exit(1)
		}

		// 创建SMB配置
		config := &smb.SMBConfig{
			Target:     target,
			Port:       port,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建SMB客户端
		client, err := smb.NewSMBClient(config)
		if err != nil {
			utils.ErrorPrint("SMB客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 检测版本
		version, err := client.CheckSMBVersion()
		if err != nil {
			utils.ErrorPrint("版本检测失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		utils.SuccessPrint("[+] SMB版本检测结果: %s", version)
	},
}

// smbExecCmd 执行远程命令
var smbExecCmd = &cobra.Command{
	Use:   "exec",
	Short: "执行远程命令",
	Long:  `通过SMB协议执行远程命令`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		command, _ := cmd.Flags().GetString("command")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")

		// 验证参数
		if target == "" {
			utils.ErrorPrint("错误: 必须指定目标主机(--target)")
			os.Exit(1)
		}

		if command == "" {
			utils.ErrorPrint("错误: 必须指定要执行的命令(--command)")
			os.Exit(1)
		}

		// 创建SMB配置
		config := &smb.SMBConfig{
			Target:     target,
			Port:       port,
			Username:   username,
			Password:   password,
			Domain:     domain,
			Command:    command,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建SMB客户端
		client, err := smb.NewSMBClient(config)
		if err != nil {
			utils.ErrorPrint("SMB客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 执行命令
		result, err := client.ExecuteCommand()
		if err != nil {
			utils.ErrorPrint("命令执行失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

func init() {
	// SMB主命令参数
	smbCmd.PersistentFlags().String("target", "", "目标主机IP或域名")
	smbCmd.PersistentFlags().Int("port", 445, "SMB端口")
	smbCmd.PersistentFlags().String("user", "", "用户名")
	smbCmd.PersistentFlags().String("password", "", "密码")
	smbCmd.PersistentFlags().String("domain", "", "域名")
	smbCmd.PersistentFlags().Int("timeout", 10, "连接超时时间(秒)")
	smbCmd.PersistentFlags().Bool("verbose", false, "详细输出模式")
	smbCmd.PersistentFlags().BoolP("very-verbose", "V", false, "更详细的输出模式")

	// 执行命令参数
	smbExecCmd.Flags().StringP("command", "c", "", "要执行的命令")

	// 添加子命令
	smbCmd.AddCommand(smbSharesCmd)
	smbCmd.AddCommand(smbVersionCmd)
	smbCmd.AddCommand(smbExecCmd)

	// 在根命令中注册smb命令
	// rootCmd.AddCommand(smbCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
}