package cli

import (
	"fmt"
	"time"

	"GYscan/internal/kerberos"
	"github.com/spf13/cobra"
)

// kerberosCmd 定义Kerberos命令
var kerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Kerberos攻击模块 [测试阶段]",
	Long: `Kerberos攻击模块提供多种Kerberos相关的攻击技术，包括：
- Kerberoasting：从Kerberos票据中提取服务账户哈希
- AS-REP Roasting：对不需要预认证的账户进行攻击
- Golden Ticket：伪造Kerberos票据（开发中）
- Silver Ticket：伪造服务票据（开发中）
[测试阶段]`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// kerberoastCmd 定义Kerberoasting攻击命令
var kerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "执行Kerberoasting攻击",
	Long:  `枚举域中的服务账户并尝试获取其Kerberos票据，用于离线破解密码哈希。`,
	Run: func(cmd *cobra.Command, args []string) {
		executeKerberoasting()
	},
}

// asreproastCmd 定义AS-REP Roasting攻击命令
var asreproastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "执行AS-REP Roasting攻击",
	Long:  `枚举域中不需要预认证的用户账户，并尝试获取AS-REP响应进行离线破解。`,
	Run: func(cmd *cobra.Command, args []string) {
		executeASREPRoasting()
	},
}

// kerberosConnectCmd 定义Kerberos连接测试命令
var kerberosConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "测试Kerberos连接",
	Long:  `测试与域控制器的Kerberos连接可达性。`,
	Run: func(cmd *cobra.Command, args []string) {
		testKerberosConnection()
	},
}

// Kerberos命令行参数
var (
	kerbTarget        string
	kerbUsername      string
	kerbPassword      string
	kerbHash          string
	kerbDomain        string
	kerbDomainCtrl    string
	kerbTimeout       int
	kerbVerbose       bool
	kerbOutputFile    string
	kerbAttackType    string
	kerbSPN           string
)

// 初始化Kerberos命令
func init() {
	// 添加子命令
	// rootCmd.AddCommand(kerberosCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
	kerberosCmd.AddCommand(kerberoastCmd)
	kerberosCmd.AddCommand(asreproastCmd)
	kerberosCmd.AddCommand(kerberosConnectCmd)
	
	// 通用参数
	kerberosCmd.PersistentFlags().StringVarP(&kerbDomain, "domain", "d", "", "域名称 (必填)")
	kerberosCmd.PersistentFlags().StringVarP(&kerbDomainCtrl, "dc", "k", "", "域控制器地址 (必填)")
	kerberosCmd.PersistentFlags().StringVarP(&kerbUsername, "username", "u", "", "用户名")
	kerberosCmd.PersistentFlags().StringVarP(&kerbPassword, "password", "p", "", "密码")
	kerberosCmd.PersistentFlags().StringVarP(&kerbHash, "hash", "H", "", "NTLM哈希")
	kerberosCmd.PersistentFlags().IntVarP(&kerbTimeout, "timeout", "t", 30, "连接超时时间（秒）")
	kerberosCmd.PersistentFlags().BoolVarP(&kerbVerbose, "verbose", "v", false, "显示详细输出")
	kerberosCmd.PersistentFlags().StringVarP(&kerbOutputFile, "output", "o", "", "结果输出文件路径")
	
	// 特定参数
	kerberoastCmd.Flags().StringVarP(&kerbSPN, "spn", "s", "", "特定的服务主体名称（可选）")
	
	// 必填参数验证已移至命令执行函数中，以确保帮助功能正常工作
}

// 执行Kerberoasting攻击
func executeKerberoasting() {
	// 手动验证必填参数
	if kerbDomain == "" {
		fmt.Println("[ERROR] 必须指定域名称 (--domain)")
		return
	}
	if kerbDomainCtrl == "" {
		fmt.Println("[ERROR] 必须指定域控制器地址 (--dc)")
		return
	}
	// 创建配置
	config := &kerberos.KerberosConfig{
		Target:         kerbTarget,
		Username:       kerbUsername,
		Password:       kerbPassword,
		Hash:           kerbHash,
		Domain:         kerbDomain,
		DomainController: kerbDomainCtrl,
		Timeout:        time.Duration(kerbTimeout) * time.Second,
		Verbose:        kerbVerbose,
		OutputFile:     kerbOutputFile,
		AttackType:     "kerberoasting",
		SPN:            kerbSPN,
	}
	
	// 创建Kerberos客户端
	client := kerberos.NewKerberosClient(config)
	
	// 先测试连接
	if !client.Connect() {
		fmt.Println("[ERROR] Kerberos连接失败，请检查域控制器是否可达及88端口是否开放")
		return
	}
	
	fmt.Println("[+] 正在执行Kerberoasting攻击...")
	
	// 执行攻击
	result := client.ExecuteAttack()
	
	if result.Success {
		fmt.Println("[SUCCESS] Kerberoasting攻击执行完成")
		if result.Output != "" {
			fmt.Println(result.Output)
		}
		if result.Hash != "" {
			fmt.Println("[+] 获取到的哈希值:")
			fmt.Println(result.Hash)
		}
	} else {
		fmt.Printf("[ERROR] Kerberoasting攻击执行失败: %v\n", result.Error)
		if result.Output != "" {
			fmt.Println("[+] 错误输出:")
			fmt.Println(result.Output)
		}
	}
}

// 执行AS-REP Roasting攻击
func executeASREPRoasting() {
	// 手动验证必填参数
	if kerbDomain == "" {
		fmt.Println("[ERROR] 必须指定域名称 (--domain)")
		return
	}
	if kerbDomainCtrl == "" {
		fmt.Println("[ERROR] 必须指定域控制器地址 (--dc)")
		return
	}
	// 创建配置
	config := &kerberos.KerberosConfig{
		Target:         kerbTarget,
		Username:       kerbUsername,
		Password:       kerbPassword,
		Hash:           kerbHash,
		Domain:         kerbDomain,
		DomainController: kerbDomainCtrl,
		Timeout:        time.Duration(kerbTimeout) * time.Second,
		Verbose:        kerbVerbose,
		OutputFile:     kerbOutputFile,
		AttackType:     "asreproasting",
	}
	
	// 创建Kerberos客户端
	client := kerberos.NewKerberosClient(config)
	
	// 先测试连接
	if !client.Connect() {
		fmt.Println("[ERROR] Kerberos连接失败，请检查域控制器是否可达及88端口是否开放")
		return
	}
	
	fmt.Println("[+] 正在执行AS-REP Roasting攻击...")
	
	// 执行攻击
	result := client.ExecuteAttack()
	
	if result.Success {
		fmt.Println("[SUCCESS] AS-REP Roasting攻击执行完成")
		if result.Output != "" {
			fmt.Println(result.Output)
		}
	} else {
		fmt.Printf("[ERROR] AS-REP Roasting攻击执行失败: %v\n", result.Error)
		if result.Output != "" {
			fmt.Println("[+] 错误输出:")
			fmt.Println(result.Output)
		}
	}
}

// 测试Kerberos连接
func testKerberosConnection() {
	// 手动验证必填参数
	if kerbDomain == "" {
		fmt.Println("[ERROR] 必须指定域名称 (--domain)")
		return
	}
	if kerbDomainCtrl == "" {
		fmt.Println("[ERROR] 必须指定域控制器地址 (--dc)")
		return
	}
	// 创建配置
	config := &kerberos.KerberosConfig{
		Domain:         kerbDomain,
		DomainController: kerbDomainCtrl,
		Timeout:        time.Duration(kerbTimeout) * time.Second,
		Verbose:        kerbVerbose,
	}
	
	// 创建Kerberos客户端
	client := kerberos.NewKerberosClient(config)
	
	fmt.Printf("[+] 正在测试与域控制器 %s 的Kerberos连接...\n", kerbDomainCtrl)
	
	// 测试连接
	connected := client.Connect()
	
	if connected {
		fmt.Println("[SUCCESS] Kerberos连接测试成功")
	} else {
		fmt.Println("[ERROR] Kerberos连接测试失败")
	}
}