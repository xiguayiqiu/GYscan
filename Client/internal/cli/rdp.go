package cli

import (
	"fmt"
	"os"

	"GYscan/internal/rdp"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// rdpCmd 表示RDP主命令
var rdpCmd = &cobra.Command{
	Use:   "rdp",
	Short: "RDP远程桌面工具",
	Long: `RDP远程桌面工具

用于检查RDP服务可用性、连接RDP服务、列出RDP会话和远程进程。

示例:
  ./GYscan rdp check --target 192.168.1.100
  ./GYscan rdp connect --target 192.168.1.100 --user admin --password password
  ./GYscan rdp sessions --target 192.168.1.100 --user admin --password password
  ./GYscan rdp processes --target 192.168.1.100 --user admin --password password
`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// rdpCheckCmd 表示RDP检查命令
var rdpCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "检查RDP服务可用性",
	Long: `检查RDP服务是否可用。

示例:
  ./GYscan rdp check --target 192.168.1.100
  ./GYscan rdp check --target 192.168.1.100 --port 3389 --timeout 5
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// 参数验证
		if target == "" {
			fmt.Println(utils.Error("[错误] 必须指定目标主机 (--target)"))
			os.Exit(1)
		}

		// 设置详细模式
		isVerbose := verbose

		// 创建配置
		config := &rdp.RDPConfig{
			Target:  target,
			Port:    port,
			Timeout: timeout,
			Verbose: isVerbose,
		}

		// 创建RDP客户端
		client := rdp.NewClient(config)

		// 检查RDP服务
		if isVerbose {
			fmt.Printf("[信息] 正在检查 %s:%d 的RDP服务...\n", target, port)
		}

		result, err := client.CheckRDP()
		if err != nil {
			fmt.Println(utils.Error("[错误]"), err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

// rdpConnectCmd 表示RDP连接命令
var rdpConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "连接到RDP服务",
	Long: `连接到RDP服务。

示例:
  ./GYscan rdp connect --target 192.168.1.100 --user admin --password password
  ./GYscan rdp connect --target 192.168.1.100 --user admin --password password --domain WORKGROUP
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// 参数验证
		if target == "" {
			fmt.Println(utils.Error("[错误] 必须指定目标主机 (--target)"))
			os.Exit(1)
		}
		if user == "" {
			fmt.Println(utils.Error("[错误] 必须指定用户名 (--user)"))
			os.Exit(1)
		}
		if password == "" {
			fmt.Println(utils.Error("[错误] 必须指定密码 (--password)"))
			os.Exit(1)
		}

		// 设置详细模式
		isVerbose := verbose

		// 创建配置
		config := &rdp.RDPConfig{
			Target:   target,
			Port:     port,
			User:     user,
			Password: password,
			Domain:   domain,
			Timeout:  timeout,
			Verbose:  isVerbose,
		}

		// 创建RDP客户端
		client := rdp.NewClient(config)

		// 连接到RDP服务
		if isVerbose {
			fmt.Printf("[信息] 正在连接到 %s:%d 的RDP服务...\n", target, port)
		}

		result, err := client.Connect()
		if err != nil {
			fmt.Println(utils.Error("[错误]"), err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

// rdpSessionsCmd 表示RDP会话命令
var rdpSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "列出RDP会话",
	Long: `列出远程主机上的RDP会话。

示例:
  ./GYscan rdp sessions --target 192.168.1.100 --user admin --password password
  ./GYscan rdp sessions --target 192.168.1.100 --user admin --password password --verbose
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// 参数验证
		if target == "" {
			fmt.Println(utils.Error("[错误] 必须指定目标主机 (--target)"))
			os.Exit(1)
		}
		if user == "" {
			fmt.Println(utils.Error("[错误] 必须指定用户名 (--user)"))
			os.Exit(1)
		}
		if password == "" {
			fmt.Println(utils.Error("[错误] 必须指定密码 (--password)"))
			os.Exit(1)
		}

		// 设置详细模式
		isVerbose := verbose

		// 创建配置
		config := &rdp.RDPConfig{
			Target:   target,
			Port:     port,
			User:     user,
			Password: password,
			Domain:   domain,
			Timeout:  timeout,
			Verbose:  isVerbose,
		}

		// 创建RDP客户端
		client := rdp.NewClient(config)

		// 获取RDP会话列表
		if isVerbose {
			fmt.Printf("[信息] 正在获取 %s:%d 的RDP会话列表...\n", target, port)
		}

		result, err := client.ListSessions()
		if err != nil {
			fmt.Println(utils.Error("[错误]"), err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

// rdpProcessesCmd 表示RDP进程命令
var rdpProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "列出远程进程",
	Long: `列出远程主机上的进程。

示例:
  ./GYscan rdp processes --target 192.168.1.100 --user admin --password password
  ./GYscan rdp processes --target 192.168.1.100 --user admin --password password --verbose
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// 参数验证
		if target == "" {
			fmt.Println(utils.Error("[错误] 必须指定目标主机 (--target)"))
			os.Exit(1)
		}
		if user == "" {
			fmt.Println(utils.Error("[错误] 必须指定用户名 (--user)"))
			os.Exit(1)
		}
		if password == "" {
			fmt.Println(utils.Error("[错误] 必须指定密码 (--password)"))
			os.Exit(1)
		}

		// 设置详细模式
		isVerbose := verbose

		// 创建配置
		config := &rdp.RDPConfig{
			Target:   target,
			Port:     port,
			User:     user,
			Password: password,
			Domain:   domain,
			Timeout:  timeout,
			Verbose:  isVerbose,
		}

		// 创建RDP客户端
		client := rdp.NewClient(config)

		// 获取远程进程列表
		if isVerbose {
			fmt.Printf("[信息] 正在获取 %s:%d 的远程进程列表...\n", target, port)
		}

		result, err := client.ListProcesses()
		if err != nil {
			fmt.Println(utils.Error("[错误]"), err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

func init() {
	// RDP主命令参数
	rdpCmd.PersistentFlags().String("target", "", "目标主机IP或域名")
	rdpCmd.PersistentFlags().Int("port", 3389, "RDP端口")
	rdpCmd.PersistentFlags().String("user", "", "用户名")
	rdpCmd.PersistentFlags().String("password", "", "密码")
	rdpCmd.PersistentFlags().String("domain", "", "域名")
	rdpCmd.PersistentFlags().Int("timeout", 10, "连接超时时间(秒)")
	rdpCmd.PersistentFlags().Bool("verbose", false, "详细输出模式")

	// 添加子命令
	rdpCmd.AddCommand(rdpCheckCmd)
	rdpCmd.AddCommand(rdpConnectCmd)
	rdpCmd.AddCommand(rdpSessionsCmd)
	rdpCmd.AddCommand(rdpProcessesCmd)

	// 设置必填参数
	_ = rdpCheckCmd.MarkFlagRequired("target")
	_ = rdpConnectCmd.MarkFlagRequired("target")
	_ = rdpConnectCmd.MarkFlagRequired("user")
	_ = rdpConnectCmd.MarkFlagRequired("password")
	_ = rdpSessionsCmd.MarkFlagRequired("target")
	_ = rdpSessionsCmd.MarkFlagRequired("user")
	_ = rdpSessionsCmd.MarkFlagRequired("password")
	_ = rdpProcessesCmd.MarkFlagRequired("target")
	_ = rdpProcessesCmd.MarkFlagRequired("user")
	_ = rdpProcessesCmd.MarkFlagRequired("password")

	// 在根命令中注册rdp命令
	rootCmd.AddCommand(rdpCmd)
}