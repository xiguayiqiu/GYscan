package cli

import (
	"fmt"
	"net"
	"os"
	"time"

	"GYscan/internal/powershell"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// powershellCmd represents the powershell command
var powershellCmd = &cobra.Command{
	Use:   "powershell",
	Short: "PowerShell远程执行工具 [WinRM服务利用]",
	Long: `PowerShell远程执行工具 - 通过WinRM协议执行PowerShell命令

支持功能:
- 执行单条PowerShell命令
- 执行PowerShell脚本
- 测试WinRM连接
- 详细的输出信息

参数:
  --target: 目标主机IP或域名
  --port: WinRM端口 (默认 5985)
  --user: 用户名
  --password: 密码
  --domain: 域名（可选）
  --timeout: 连接超时时间(秒) (默认 10)
  --verbose: 详细输出模式
  --https: 使用HTTPS连接
  -V, --very-verbose: 更详细的输出模式

示例用法:
  ./GYscan powershell exec --target 192.168.1.100 --user administrator --password "P@ssw0rd" --command "whoami"
  ./GYscan powershell script --target 192.168.1.100 --user administrator --password "P@ssw0rd" --script "Get-Process"
  ./GYscan powershell test --target 192.168.1.100 --port 5985
  ./GYscan powershell exec --target 192.168.1.100 --user administrator --password "P@ssw0rd" --command "whoami" --https
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否是help请求
		if len(args) < 1 || args[0] == "help" {
			cmd.Help()
			os.Exit(0)
		}
	},
}

// powershellExecCmd 执行PowerShell命令
var powershellExecCmd = &cobra.Command{
	Use:   "exec",
	Short: "执行PowerShell命令",
	Long: `执行PowerShell命令 - 通过WinRM执行单条PowerShell命令

示例:
  ./GYscan powershell exec --target 192.168.1.100 --user administrator --password "P@ssw0rd" --command "whoami"
  ./GYscan powershell exec --target 192.168.1.100 --user administrator --password "P@ssw0rd" --command "Get-Process | Select-Object -First 5"
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		timeout, _ := cmd.Flags().GetInt("timeout")
		command, _ := cmd.Flags().GetString("command")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")
		https, _ := cmd.Flags().GetBool("https")

		// 参数验证
		if target == "" {
			fmt.Println("[错误] 必须指定目标主机 (--target)")
			os.Exit(1)
		}
		if user == "" {
			fmt.Println("[错误] 必须指定用户名 (--user)")
			os.Exit(1)
		}
		if password == "" {
			fmt.Println("[错误] 必须指定密码 (--password)")
			os.Exit(1)
		}
		if command == "" {
			fmt.Println("[错误] 必须指定要执行的命令 (--command)")
			os.Exit(1)
		}

		// 设置详细模式（使用本地变量）
		isVerbose := verbose || veryVerbose

		// 创建配置
		config := &powershell.PowerShellConfig{
			Target:   target,
			Port:     port,
			User:     user,
			Password: password,
			Domain:   domain,
			Timeout:  timeout,
			Verbose:  verbose || veryVerbose,
			HTTPS:    https,
		}

		// 创建客户端
		client, err := powershell.NewClient(config)
		if err != nil {
			fmt.Printf("[错误] 创建PowerShell客户端失败: %v\n", err)
			os.Exit(1)
		}

		// 连接目标
		if isVerbose {
			fmt.Printf("[信息] 正在连接到 %s:%d\n", target, port)
		}

		err = client.Connect()
		if err != nil {
			fmt.Printf("[错误] 连接失败: %v\n", err)
			os.Exit(1)
		}

		if isVerbose {
			fmt.Printf("[信息] 连接成功，正在执行命令...\n")
		}

		// 执行命令
		result, err := client.ExecuteCommand(command)
		if err != nil {
			fmt.Printf("[错误] 执行命令失败: %v\n", err)
			if result != nil && result.Output != "" {
				fmt.Printf("[输出] %s\n", result.Output)
			}
			os.Exit(1)
		}

		// 输出结果
		fmt.Println("\n[PowerShell命令执行结果]")
		fmt.Println("========================================")
		fmt.Printf("命令: %s\n", command)
		fmt.Printf("状态: %s\n", utils.ColorText("成功", "green"))
		fmt.Printf("执行时间: %v\n", result.ExecutionTime)
		fmt.Println("输出:")
		fmt.Println(result.Output)
	},
}

// powershellScriptCmd 执行PowerShell脚本
var powershellScriptCmd = &cobra.Command{
	Use:   "script",
	Short: "执行PowerShell脚本",
	Long: `执行PowerShell脚本 - 通过WinRM执行PowerShell脚本

示例:
  ./GYscan powershell script --target 192.168.1.100 --user administrator --password "P@ssw0rd" --script "Get-Process"
  ./GYscan powershell script --target 192.168.1.100 --user administrator --password "P@ssw0rd" --script "Get-WmiObject -Class Win32_OperatingSystem"
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		timeout, _ := cmd.Flags().GetInt("timeout")
		script, _ := cmd.Flags().GetString("script")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")
		https, _ := cmd.Flags().GetBool("https")

		// 参数验证
		if target == "" {
			fmt.Println("[错误] 必须指定目标主机 (--target)")
			os.Exit(1)
		}
		if user == "" {
			fmt.Println("[错误] 必须指定用户名 (--user)")
			os.Exit(1)
		}
		if password == "" {
			fmt.Println("[错误] 必须指定密码 (--password)")
			os.Exit(1)
		}
		if script == "" {
			fmt.Println("[错误] 必须指定脚本内容 (--script)")
			os.Exit(1)
		}

		// 设置详细模式（使用本地变量）
		isVerbose := verbose || veryVerbose

		// 创建配置
		config := &powershell.PowerShellConfig{
			Target:   target,
			Port:     port,
			User:     user,
			Password: password,
			Domain:   domain,
			Timeout:  timeout,
			Verbose:  verbose || veryVerbose,
			HTTPS:    https,
		}

		// 创建客户端
		client, err := powershell.NewClient(config)
		if err != nil {
			fmt.Printf("[错误] 创建PowerShell客户端失败: %v\n", err)
			os.Exit(1)
		}

		// 连接目标
		if isVerbose {
			fmt.Printf("[信息] 正在连接到 %s:%d\n", target, port)
		}

		err = client.Connect()
		if err != nil {
			fmt.Printf("[错误] 连接失败: %v\n", err)
			os.Exit(1)
		}

		if isVerbose {
			fmt.Printf("[信息] 连接成功，正在执行脚本...\n")
		}

		// 执行脚本
		result, err := client.ExecuteScript(script)
		if err != nil {
			fmt.Printf("[错误] 执行脚本失败: %v\n", err)
			if result != nil && result.Output != "" {
				fmt.Printf("[输出] %s\n", result.Output)
			}
			os.Exit(1)
		}

		// 输出结果
		fmt.Println("\n[PowerShell脚本执行结果]")
		fmt.Println("========================================")
		fmt.Printf("脚本内容: %s\n", script)
		fmt.Printf("状态: %s\n", utils.ColorText("成功", "green"))
		fmt.Printf("执行时间: %v\n", result.ExecutionTime)
		fmt.Println("输出:")
		fmt.Println(result.Output)
	},
}

// powershellTestCmd 测试WinRM连接
var powershellTestCmd = &cobra.Command{
	Use:   "test",
	Short: "测试WinRM连接",
	Long: `测试WinRM连接 - 检查目标主机是否支持WinRM协议

示例:
  ./GYscan powershell test --target 192.168.1.100
  ./GYscan powershell test --target 192.168.1.100 --port 5986 --timeout 5 --https
`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")

		// 参数验证
		if target == "" {
			fmt.Println("[错误] 必须指定目标主机 (--target)")
			os.Exit(1)
		}

		// 设置详细模式（使用本地变量）
		isVerbose := verbose || veryVerbose

		// 这里我们只是检查端口是否开放，不进行认证
		if isVerbose {
			fmt.Printf("[信息] 正在测试 %s:%d 的WinRM连接...\n", target, port)
		}

		// 真正测试端口是否开放
		address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
		isOpen := err == nil
		if isOpen {
			conn.Close()
			fmt.Printf("[信息] %s:%d WinRM端口开放\n", target, port)
		} else {
			fmt.Printf("[信息] %s:%d WinRM端口未开放: %v\n", target, port, err)
			os.Exit(1)
		}

		fmt.Printf("[信息] WinRM连接测试完成\n")
	},
}

func init() {
	// PowerShell主命令参数
	powershellCmd.PersistentFlags().String("target", "", "目标主机IP或域名")
	powershellCmd.PersistentFlags().Int("port", 5985, "WinRM端口")
	powershellCmd.PersistentFlags().String("user", "", "用户名")
	powershellCmd.PersistentFlags().String("password", "", "密码")
	powershellCmd.PersistentFlags().String("domain", "", "域名")
	powershellCmd.PersistentFlags().Int("timeout", 10, "连接超时时间(秒)")
	powershellCmd.PersistentFlags().Bool("verbose", false, "详细输出模式")
	powershellCmd.PersistentFlags().Bool("https", false, "使用HTTPS连接")
	powershellCmd.PersistentFlags().BoolP("very-verbose", "V", false, "更详细的输出模式")

	// 子命令参数
	powershellExecCmd.Flags().StringP("command", "c", "", "要执行的PowerShell命令")
	powershellScriptCmd.Flags().StringP("script", "x", "", "PowerShell脚本内容")

	// 添加子命令
	powershellCmd.AddCommand(powershellExecCmd)
	powershellCmd.AddCommand(powershellScriptCmd)
	powershellCmd.AddCommand(powershellTestCmd)

	// 设置必填参数
	_ = powershellExecCmd.MarkFlagRequired("target")
	_ = powershellExecCmd.MarkFlagRequired("user")
	_ = powershellExecCmd.MarkFlagRequired("password")
	_ = powershellExecCmd.MarkFlagRequired("command")

	_ = powershellScriptCmd.MarkFlagRequired("target")
	_ = powershellScriptCmd.MarkFlagRequired("user")
	_ = powershellScriptCmd.MarkFlagRequired("password")
	_ = powershellScriptCmd.MarkFlagRequired("script")

	_ = powershellTestCmd.MarkFlagRequired("target")

	// 在根命令中注册powershell命令
	rootCmd.AddCommand(powershellCmd)
}
