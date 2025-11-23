package cli

import (
	"os"

	"GYscan/internal/ssh"
	"GYscan/internal/utils"
	"github.com/spf13/cobra"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH密码爆破工具（Hydra风格）",
	Long: `SSH密码爆破工具 - 完全按照Hydra工具风格实现

支持功能:
- SSH用户名/密码认证爆破
- 字典攻击和暴力破解
- 多线程并发爆破
- 支持自定义端口和超时设置
- 智能服务器安全机制处理
- 结果输出和进度显示

Hydra风格参数:
  -l: 指定用户名或用户名字典文件
  -L: 指定用户名字典文件
  -p: 指定密码或密码字典文件  
  -P: 指定密码字典文件
  -t: 并发线程数
  -s: 指定SSH端口
  -d: 尝试间隔(毫秒)，避免触发服务器安全机制
  -D: 尝试间隔(秒)，避免触发服务器安全机制（优先级高于-d）
  -v: 详细输出模式
  -V: 更详细的输出模式
  -f: 找到第一个匹配后停止
  -e: 额外检查（n:空密码, s:用户名作为密码）

示例用法:
  ./GYscan ssh 192.168.1.1 -l root -P pass.txt
  ./GYscan ssh 192.168.1.1 -L users.txt -P pass.txt -t 4
  ./GYscan ssh 192.168.1.1 -l admin -p password -s 2222
  ./GYscan ssh 192.168.1.1 -L users.txt -P pass.txt -v -f
  ./GYscan ssh 192.168.1.1 -l root -P pass.txt -e ns
  ./GYscan ssh 192.168.1.1 -l root -P pass.txt -d 500 (添加500ms间隔避免触发安全机制)
  ./GYscan ssh 192.168.1.1 -l root -P pass.txt -D 2 (添加2秒间隔避免触发安全机制)`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 验证目标参数
	if len(args) == 0 {
		utils.ErrorPrint("错误: 必须指定SSH服务器地址")
		utils.InfoPrint("用法: GYscan ssh <目标> [选项]")
		os.Exit(1)
	}

		target := args[0]

		// 获取命令行参数
		username, _ := cmd.Flags().GetString("username")
		usernameFile, _ := cmd.Flags().GetString("username-file")
		password, _ := cmd.Flags().GetString("password")
		passwordFile, _ := cmd.Flags().GetString("password-file")
		threads, _ := cmd.Flags().GetInt("threads")
		port, _ := cmd.Flags().GetInt("port")
		attemptDelay, _ := cmd.Flags().GetInt("attempt-delay")
		attemptDelaySeconds, _ := cmd.Flags().GetInt("attempt-delay-seconds")
		verbose, _ := cmd.Flags().GetBool("verbose")
		veryVerbose, _ := cmd.Flags().GetBool("very-verbose")
		stopOnFirst, _ := cmd.Flags().GetBool("stop-on-first")
		extraChecks, _ := cmd.Flags().GetString("extra-checks")
		timeout, _ := cmd.Flags().GetInt("timeout")

		// 验证参数
	if username == "" && usernameFile == "" {
		utils.ErrorPrint("错误: 必须指定用户名(-l)或用户名字典文件(-L)")
		os.Exit(1)
	}

	if password == "" && passwordFile == "" {
		utils.ErrorPrint("错误: 必须指定密码(-p)或密码字典文件(-P)")
		os.Exit(1)
	}

		// 创建SSH爆破配置
		// 处理尝试间隔参数优先级：秒参数优先于毫秒参数
		if attemptDelaySeconds > 0 {
			// 用户指定了秒间隔，转换为毫秒
			attemptDelay = attemptDelaySeconds * 1000
			if verbose || veryVerbose {
				utils.InfoPrint("[+] 使用用户指定的尝试间隔: %d秒 (%d毫秒)", attemptDelaySeconds, attemptDelay)
			}
		} else if usernameFile != "" || passwordFile != "" {
			// 如果使用字典文件且未设置尝试间隔，自动设置默认间隔避免触发服务器安全机制
			if attemptDelay == 0 {
				attemptDelay = 1000 // 默认1000毫秒间隔，更保守的设置
				// 同时限制线程数为1，避免并发过高
				if threads > 1 {
					threads = 1
				}
				if verbose || veryVerbose {
					utils.WarningPrint("[!] 检测到字典文件，自动设置: 尝试间隔=%d毫秒, 线程数=%d", attemptDelay, threads)
				}
			} else {
				// 用户已经指定了尝试间隔，使用用户指定的值
				if verbose || veryVerbose {
					utils.InfoPrint("[+] 使用用户指定的尝试间隔: %d毫秒", attemptDelay)
				}
			}
		}
		
		config := &ssh.SSHConfig{
			Target:        target,
			Port:          port,
			Username:      username,
			UsernameFile:  usernameFile,
			Password:      password,
			PasswordFile:  passwordFile,
			Threads:       threads,
			Timeout:       timeout,
			AttemptDelay:  attemptDelay,
			Verbose:       verbose,
			VeryVerbose:   veryVerbose,
			StopOnFirst:   stopOnFirst,
			ExtraChecks:   extraChecks,
		}

		// 创建SSH爆破器
		bruteforcer := ssh.NewSSHBruteforcer(config)

		// 执行爆破
	result, err := bruteforcer.Bruteforce()
	if err != nil {
		utils.ErrorPrint("SSH爆破失败: %v", err)
		os.Exit(1)
	}

		// 打印结果
		bruteforcer.PrintResults(result)
	},
}

func init() {
	// Hydra风格参数
	sshCmd.Flags().StringP("username", "l", "", "指定用户名")
	sshCmd.Flags().StringP("username-file", "L", "", "指定用户名字典文件")
	sshCmd.Flags().StringP("password", "p", "", "指定密码")
	sshCmd.Flags().StringP("password-file", "P", "", "指定密码字典文件")
	sshCmd.Flags().IntP("threads", "t", 1, "并发线程数")
	sshCmd.Flags().IntP("port", "S", 22, "SSH端口")
	sshCmd.Flags().IntP("attempt-delay", "d", 0, "尝试间隔(毫秒)，避免触发服务器安全机制")
	sshCmd.Flags().IntP("attempt-delay-seconds", "D", 0, "尝试间隔(秒)，避免触发服务器安全机制（优先级高于-d）")
	sshCmd.Flags().Bool("verbose", false, "详细输出模式")
	sshCmd.Flags().BoolP("very-verbose", "", false, "更详细的输出模式")
	sshCmd.Flags().BoolP("stop-on-first", "f", false, "找到第一个匹配后停止")
	sshCmd.Flags().StringP("extra-checks", "e", "", "额外检查 (n:空密码, s:用户名作为密码)")
	sshCmd.Flags().Int("timeout", 30, "连接超时时间(秒)")

}