package cli

import (
	"fmt"
	"time"

	"GYscan/internal/dcom"
	"github.com/spf13/cobra"
)

// dcomCmd 定义DCOM命令
var dcomCmd = &cobra.Command{
	Use:   "dcom",
	Short: "DCOM远程执行模块 [测试阶段]",
	Long: `DCOM远程执行模块用于通过DCOM协议在目标主机上执行远程命令。
支持多种DCOM执行方法，包括MMC20.Application、ShellWindows等。
[测试阶段]`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// dcomExecCmd 定义DCOM执行命令
var dcomExecCmd = &cobra.Command{
	Use:   "execute",
	Short: "通过DCOM执行远程命令",
	Long:  `通过DCOM协议在目标主机上执行指定命令，支持多种执行方法。`,
	Run: func(cmd *cobra.Command, args []string) {
		executeDCOMCommand()
	},
}

// dcomListCmd 定义DCOM对象列表命令
var dcomListCmd = &cobra.Command{
	Use:   "list",
	Short: "列出远程主机上的DCOM对象",
	Long:  `枚举远程主机上可用的DCOM对象，用于识别潜在的攻击目标。`,
	Run: func(cmd *cobra.Command, args []string) {
		listDCOMObjects()
	},
}

// dcomConnectCmd 定义DCOM连接测试命令
var dcomConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "测试DCOM连接",
	Long:  `测试与目标主机的DCOM连接可达性。`,
	Run: func(cmd *cobra.Command, args []string) {
		testDCOMConnection()
	},
}

// DCOM命令行参数
var (
	dcomTarget   string
	dcomUsername string
	dcomPassword string
	dcomDomain   string
	dcomCommand  string
	dcomMethod   string
	dcomTimeout  int
	dcomVerbose  bool
	dcomUseSSL   bool
)

// 初始化DCOM命令
func init() {
	// 添加子命令
	// 命令注册已移至root.go的RegisterCommands函数中统一管理
	dcomCmd.AddCommand(dcomExecCmd)
	dcomCmd.AddCommand(dcomListCmd)
	dcomCmd.AddCommand(dcomConnectCmd)
	
	// 通用参数
	dcomCmd.PersistentFlags().StringVarP(&dcomTarget, "target", "t", "", "目标主机IP地址或主机名 (必填)")
	dcomCmd.PersistentFlags().StringVarP(&dcomUsername, "username", "u", "", "用户名 (必填)")
	dcomCmd.PersistentFlags().StringVarP(&dcomPassword, "password", "p", "", "密码 (必填)")
	dcomCmd.PersistentFlags().StringVarP(&dcomDomain, "domain", "d", "", "域名")
	dcomCmd.PersistentFlags().IntVarP(&dcomTimeout, "timeout", "o", 30, "连接超时时间（秒）")
	dcomCmd.PersistentFlags().BoolVarP(&dcomVerbose, "verbose", "v", false, "显示详细输出")
	dcomCmd.PersistentFlags().BoolVarP(&dcomUseSSL, "ssl", "S", false, "使用SSL加密连接")
	
	// 执行命令参数
	dcomExecCmd.Flags().StringVarP(&dcomCommand, "command", "c", "", "要执行的命令 (必填)")
	dcomExecCmd.Flags().StringVarP(&dcomMethod, "method", "m", "mmc20", "DCOM执行方法 (mmc20, shellwindows, wmiexecute)")
	
	// 注意：不再使用MarkFlagRequired，而是在命令执行时手动验证
}

// 执行DCOM远程命令
func executeDCOMCommand() {
	// 手动验证必填参数
	if dcomTarget == "" {
		fmt.Println("[ERROR] 必须指定目标主机 (--target)")
		return
	}
	if dcomUsername == "" {
		fmt.Println("[ERROR] 必须指定用户名 (--username)")
		return
	}
	if dcomPassword == "" {
		fmt.Println("[ERROR] 必须指定密码 (--password)")
		return
	}
	if dcomCommand == "" {
		fmt.Println("[ERROR] 必须指定要执行的命令 (--command)")
		return
	}
	
	// 创建配置
	config := &dcom.DCOMConfig{
		Target:      dcomTarget,
		Username:    dcomUsername,
		Password:    dcomPassword,
		Domain:      dcomDomain,
		Command:     dcomCommand,
		UseSSL:      dcomUseSSL,
		Timeout:     time.Duration(dcomTimeout) * time.Second,
		Verbose:     dcomVerbose,
		Method:      dcomMethod,
	}
	
	// 创建DCOM客户端
	client := dcom.NewDCOMClient(config)
	
	// 先测试连接
	if !client.Connect() {
		fmt.Println("[ERROR] DCOM连接失败，请检查目标主机是否可达及135端口是否开放")
		return
	}
	
	fmt.Println("[+] 正在通过DCOM执行远程命令...")
	
	// 执行命令
	result := client.ExecuteCommand()
	
	if result.Success {
		fmt.Println("[SUCCESS] 命令执行成功")
		if result.Output != "" {
			fmt.Println("[+] 输出结果:")
			fmt.Println(result.Output)
		}
	} else {
		fmt.Printf("[ERROR] 命令执行失败: %v\n", result.Error)
		if result.Output != "" {
			fmt.Println("[+] 错误输出:")
			fmt.Println(result.Output)
		}
	}
}

// 列出DCOM对象
func listDCOMObjects() {
	// 手动验证必填参数
	if dcomTarget == "" {
		fmt.Println("[ERROR] 必须指定目标主机 (--target)")
		return
	}
	if dcomUsername == "" {
		fmt.Println("[ERROR] 必须指定用户名 (--username)")
		return
	}
	if dcomPassword == "" {
		fmt.Println("[ERROR] 必须指定密码 (--password)")
		return
	}
	
	// 创建配置
	config := &dcom.DCOMConfig{
		Target:      dcomTarget,
		Username:    dcomUsername,
		Password:    dcomPassword,
		Domain:      dcomDomain,
		Timeout:     time.Duration(dcomTimeout) * time.Second,
		Verbose:     dcomVerbose,
	}
	
	// 创建DCOM客户端
	client := dcom.NewDCOMClient(config)
	
	// 先测试连接
	if !client.Connect() {
		fmt.Println("[ERROR] DCOM连接失败，请检查目标主机是否可达及135端口是否开放")
		return
	}
	
	fmt.Println("[+] 正在列出远程主机上的DCOM对象...")
	
	// 列出DCOM对象
	result := client.ListDCOMObjects()
	
	if result.Success {
		fmt.Println("[SUCCESS] DCOM对象枚举成功")
		fmt.Println("[+] 可用的DCOM对象:")
		fmt.Println(result.Output)
	} else {
		fmt.Printf("[ERROR] DCOM对象枚举失败: %v\n", result.Error)
		if result.Output != "" {
			fmt.Println("[+] 错误输出:")
			fmt.Println(result.Output)
		}
	}
}

// 测试DCOM连接
func testDCOMConnection() {
	// 手动验证必填参数
	if dcomTarget == "" {
		fmt.Println("[ERROR] 必须指定目标主机 (--target)")
		return
	}
	if dcomUsername == "" {
		fmt.Println("[ERROR] 必须指定用户名 (--username)")
		return
	}
	if dcomPassword == "" {
		fmt.Println("[ERROR] 必须指定密码 (--password)")
		return
	}
	
	// 创建配置
	config := &dcom.DCOMConfig{
		Target:      dcomTarget,
		Username:    dcomUsername,
		Password:    dcomPassword,
		Domain:      dcomDomain,
		Timeout:     time.Duration(dcomTimeout) * time.Second,
		Verbose:     dcomVerbose,
	}
	
	// 创建DCOM客户端
	client := dcom.NewDCOMClient(config)
	
	fmt.Printf("[+] 正在测试与 %s 的DCOM连接...\n", dcomTarget)
	
	// 测试连接
	connected := client.Connect()
	
	if connected {
		fmt.Println("[SUCCESS] DCOM连接测试成功")
	} else {
		fmt.Println("[ERROR] DCOM连接测试失败")
	}
}