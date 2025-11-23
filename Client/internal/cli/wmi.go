package cli

import (
	"fmt"
	"os"

	"GYscan/internal/utils"
	"GYscan/internal/wmi"
	"github.com/spf13/cobra"
)

// wmiCmd represents the wmi command
var wmiCmd = &cobra.Command{
	Use:   "wmi",
	Short: "WMI远程管理工具",
	Long: `WMI(Windows Management Instrumentation)远程管理工具

支持功能:
- 远程命令执行
- WMI查询执行
- 进程列表查看
- 服务列表查看
- 操作系统信息获取

示例用法:
  # 执行WMI查询
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT * FROM Win32_Process"
  
  # 执行远程命令
  ./GYscan wmi exec --target 192.168.1.100 --user admin --password password --command "whoami"
  
  # 列出进程
  ./GYscan wmi processes --target 192.168.1.100 --user admin --password password
  
  # 列出服务
  ./GYscan wmi services --target 192.168.1.100 --user admin --password password
  
  # 获取系统信息
  ./GYscan wmi osinfo --target 192.168.1.100 --user admin --password password`,
	Run: func(cmd *cobra.Command, args []string) {
		// 直接运行wmi命令时显示帮助
		cmd.Help()
	},
}

// wmiExecCmd 通过WMI执行命令
var wmiExecCmd = &cobra.Command{
	Use:   "exec",
	Short: "通过WMI执行命令",
	Long: `使用WMI远程执行命令

使用示例:
  # 执行简单命令
  ./GYscan wmi exec --target 192.168.1.100 --user admin --password password --command "whoami"
  
  # 执行多条命令
  ./GYscan wmi exec --target 192.168.1.100 --user admin --password password --command "ipconfig /all && systeminfo"
  
  # 执行PowerShell命令
  ./GYscan wmi exec --target 192.168.1.100 --user admin --password password --command "powershell.exe -command \"Get-Process\""
  
  # 使用域账号
  ./GYscan wmi exec --target 192.168.1.100 --domain example.com --user admin --password password --command "hostname"
  
  # 设置超时时间
  ./GYscan wmi exec --target 192.168.1.100 --user admin --password password --command "dir C:\\" --timeout 20`,
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

		// 创建WMI配置
		config := &wmi.WMIConfig{
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

		// 创建WMI客户端
		client, err := wmi.NewWMIClient(config)
		if err != nil {
			utils.ErrorPrint("WMI客户端创建失败: %v", err)
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

// wmiQueryCmd 执行WMI查询
var wmiQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "执行WMI查询",
	Long: `执行WQL(Windows Management Instrumentation Query Language)查询

使用示例:
  # 查询所有进程
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT * FROM Win32_Process"
  
  # 查询操作系统信息
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem"
  
  # 查询所有服务
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT Name, DisplayName, State FROM Win32_Service"
  
  # 查询已安装的软件
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT Name, Version FROM Win32_Product"
  
  # 查询网络适配器
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		query, _ := cmd.Flags().GetString("query")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")

		// 验证参数
		if target == "" {
			utils.ErrorPrint("错误: 必须指定目标主机(--target)")
			os.Exit(1)
		}

		if query == "" {
			utils.ErrorPrint("错误: 必须指定WQL查询语句(--query)")
			os.Exit(1)
		}

		// 创建WMI配置
		config := &wmi.WMIConfig{
			Target:     target,
			Port:       port,
			Username:   username,
			Password:   password,
			Domain:     domain,
			Query:      query,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建WMI客户端
		client, err := wmi.NewWMIClient(config)
		if err != nil {
			utils.ErrorPrint("WMI客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 执行查询
		result, err := client.ExecuteQuery()
		if err != nil {
			utils.ErrorPrint("查询执行失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

// wmiProcessesCmd 列出进程
var wmiProcessesCmd = &cobra.Command{
	Use:   "processes",
	Short: "列出远程系统进程",
	Long: `通过WMI获取远程系统的进程列表

使用示例:
  # 列出所有进程
  ./GYscan wmi processes --target 192.168.1.100 --user admin --password password
  
  # 使用域账号列出进程
  ./GYscan wmi processes --target 192.168.1.100 --domain example.com --user admin --password password
  
  # 设置超时时间
  ./GYscan wmi processes --target 192.168.1.100 --user admin --password password --timeout 15`,
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

		// 创建WMI配置
		config := &wmi.WMIConfig{
			Target:     target,
			Port:       port,
			Username:   username,
			Password:   password,
			Domain:     domain,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建WMI客户端
		client, err := wmi.NewWMIClient(config)
		if err != nil {
			utils.ErrorPrint("WMI客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 列出进程
		result, err := client.ListProcesses()
		if err != nil {
			utils.ErrorPrint("进程列表获取失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

// wmiServicesCmd 列出服务
var wmiServicesCmd = &cobra.Command{
	Use:   "services",
	Short: "列出远程系统服务",
	Long: `通过WMI获取远程系统的服务列表

使用示例:
  # 列出所有服务
  ./GYscan wmi services --target 192.168.1.100 --user admin --password password
  
  # 列出特定状态的服务(如Running状态)
  ./GYscan wmi query --target 192.168.1.100 --user admin --password password --query "SELECT Name, DisplayName, State FROM Win32_Service WHERE State='Running'"
  
  # 设置详细输出
  ./GYscan wmi services --target 192.168.1.100 --user admin --password password --verbose`,
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

		// 创建WMI配置
		config := &wmi.WMIConfig{
			Target:     target,
			Port:       port,
			Username:   username,
			Password:   password,
			Domain:     domain,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建WMI客户端
		client, err := wmi.NewWMIClient(config)
		if err != nil {
			utils.ErrorPrint("WMI客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 列出服务
		result, err := client.ListServices()
		if err != nil {
			utils.ErrorPrint("服务列表获取失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

// wmiOSInfoCmd 获取操作系统信息
var wmiOSInfoCmd = &cobra.Command{
	Use:   "osinfo",
	Short: "获取操作系统信息",
	Long: `通过WMI获取远程系统的操作系统信息

使用示例:
  # 获取操作系统基本信息
  ./GYscan wmi osinfo --target 192.168.1.100 --user admin --password password
  
  # 使用更详细的输出模式
  ./GYscan wmi osinfo --target 192.168.1.100 --user admin --password password --verbose
  
  # 使用IP地址作为目标
  ./GYscan wmi osinfo --target 10.0.0.5 --user admin --password password`,
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

		// 创建WMI配置
		config := &wmi.WMIConfig{
			Target:     target,
			Port:       port,
			Username:   username,
			Password:   password,
			Domain:     domain,
			Timeout:    timeout,
			Verbose:    verbose,
			VeryVerbose: veryVerbose,
		}

		// 创建WMI客户端
		client, err := wmi.NewWMIClient(config)
		if err != nil {
			utils.ErrorPrint("WMI客户端创建失败: %v", err)
			os.Exit(1)
		}

		// 获取系统信息
		result, err := client.GetOSInfo()
		if err != nil {
			utils.ErrorPrint("系统信息获取失败: %v", err)
			os.Exit(1)
		}

		// 打印结果
		client.PrintResult(result)
	},
}

func init() {
	// WMI主命令参数
	wmiCmd.PersistentFlags().String("target", "", "目标主机IP或域名")
	wmiCmd.PersistentFlags().Int("port", 135, "WMI端口(WBEM)")
	wmiCmd.PersistentFlags().String("user", "", "用户名")
	wmiCmd.PersistentFlags().String("password", "", "密码")
	wmiCmd.PersistentFlags().String("domain", "", "域名")
	wmiCmd.PersistentFlags().Int("timeout", 10, "连接超时时间(秒)")
	wmiCmd.PersistentFlags().Bool("verbose", false, "详细输出模式")
	wmiCmd.PersistentFlags().BoolP("very-verbose", "", false, "更详细的输出模式")

	// 子命令参数
	wmiExecCmd.Flags().StringP("command", "c", "", "要执行的命令")
	wmiQueryCmd.Flags().StringP("query", "q", "", "WQL查询语句")

	

	// 添加子命令
	wmiCmd.AddCommand(wmiExecCmd)
	wmiCmd.AddCommand(wmiQueryCmd)
	wmiCmd.AddCommand(wmiProcessesCmd)
	wmiCmd.AddCommand(wmiServicesCmd)
	wmiCmd.AddCommand(wmiOSInfoCmd)

	// 为每个子命令设置自定义帮助函数，确保显示完整的帮助信息
	wmiExecCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// 显示艺术字
		printBanner()
		// 手动打印完整帮助信息
		fmt.Printf("%s\n\n", cmd.Short)
		fmt.Printf("%s\n\n", cmd.Long)
		fmt.Println("Usage:")
		cmd.Usage()
		fmt.Println("\nFlags:")
		cmd.LocalFlags().PrintDefaults()
		fmt.Println("\nGlobal Flags:")
		cmd.InheritedFlags().PrintDefaults()
	})
	wmiQueryCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// 显示艺术字
		printBanner()
		fmt.Printf("%s\n\n", cmd.Short)
		fmt.Printf("%s\n\n", cmd.Long)
		fmt.Println("Usage:")
		cmd.Usage()
		fmt.Println("\nFlags:")
		cmd.LocalFlags().PrintDefaults()
		fmt.Println("\nGlobal Flags:")
		cmd.InheritedFlags().PrintDefaults()
	})
	wmiProcessesCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// 显示艺术字
		printBanner()
		fmt.Printf("%s\n\n", cmd.Short)
		fmt.Printf("%s\n\n", cmd.Long)
		fmt.Println("Usage:")
		cmd.Usage()
		fmt.Println("\nFlags:")
		cmd.LocalFlags().PrintDefaults()
		fmt.Println("\nGlobal Flags:")
		cmd.InheritedFlags().PrintDefaults()
	})
	wmiServicesCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// 显示艺术字
		printBanner()
		fmt.Printf("%s\n\n", cmd.Short)
		fmt.Printf("%s\n\n", cmd.Long)
		fmt.Println("Usage:")
		cmd.Usage()
		fmt.Println("\nFlags:")
		cmd.LocalFlags().PrintDefaults()
		fmt.Println("\nGlobal Flags:")
		cmd.InheritedFlags().PrintDefaults()
	})
	wmiOSInfoCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// 显示艺术字
		printBanner()
		fmt.Printf("%s\n\n", cmd.Short)
		fmt.Printf("%s\n\n", cmd.Long)
		fmt.Println("Usage:")
		cmd.Usage()
		fmt.Println("\nFlags:")
		cmd.LocalFlags().PrintDefaults()
		fmt.Println("\nGlobal Flags:")
		cmd.InheritedFlags().PrintDefaults()
	})

	// 在根命令中注册wmi命令
	// rootCmd.AddCommand(wmiCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
}