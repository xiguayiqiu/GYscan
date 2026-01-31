package cli

import (
	"GYscan/internal/ssh"
	"GYscan/internal/utils"
	"time"

	"github.com/spf13/cobra"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH密码爆破工具（Hydra风格）",
	Long: `ssh命令 - SSH密码爆破工具（Hydra风格）

功能包括：
• 支持单目标和批量目标SSH密码爆破
• 支持用户名列表和密码列表文件
• 支持自定义端口和超时时间
• 支持详细输出模式
• 支持并发线程设置
• 支持结果输出到文件

示例用法：
  # 单目标爆破
  ./GYscan ssh --target 192.168.1.100 --user root --passwords password.txt
  
  # 批量目标爆破
  ./GYscan ssh --file targets.txt --user root --passwords password.txt
  
  # 自定义端口和线程
  ./GYscan ssh --target 192.168.1.100 --port 2222 --user root --passwords password.txt --threads 10
  
  # 输出结果到文件
  ./GYscan ssh --target 192.168.1.100 --user root --passwords password.txt --output ssh-results.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取命令行参数
		target, _ := cmd.Flags().GetString("target")
		file, _ := cmd.Flags().GetString("file")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		usernames, _ := cmd.Flags().GetString("users")
		passwords, _ := cmd.Flags().GetString("passwords")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		delay, _ := cmd.Flags().GetInt("delay")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// 验证参数
		if target == "" && file == "" {
			utils.ErrorPrint("错误: 必须指定目标(--target)或目标文件(--file)")
			cmd.Help()
			return
		}

		if username == "" && usernames == "" {
			utils.ErrorPrint("错误: 必须指定用户名(--user)或用户名列表(--users)")
			cmd.Help()
			return
		}

		if passwords == "" {
			utils.ErrorPrint("错误: 必须指定密码列表(--passwords)")
			cmd.Help()
			return
		}

		// 打印开始信息
		utils.SuccessPrint("[+] SSH密码爆破工具启动")
		utils.InfoPrint("[*] 开始时间: %s", time.Now().Format("2006-01-02 15:04:05"))
		if target != "" {
			utils.InfoPrint("[*] 目标: %s:%d", target, port)
		} else {
			utils.InfoPrint("[*] 目标文件: %s", file)
		}
		if username != "" {
			utils.InfoPrint("[*] 用户名: %s", username)
		} else {
			utils.InfoPrint("[*] 用户名列表: %s", usernames)
		}
		utils.InfoPrint("[*] 密码列表: %s", passwords)
		utils.InfoPrint("[*] 线程数: %d", threads)
		utils.InfoPrint("[*] 超时时间: %d秒", timeout)
		if output != "" {
			utils.InfoPrint("[*] 结果输出: %s", output)
		}
		utils.InfoPrint("")

		// 准备SSH配置
		config := &ssh.SSHConfig{
			Target:       target,
			TargetFile:   file,
			Port:         port,
			Username:     username,
			UsernameFile: usernames,
			Password:     "",
			PasswordFile: passwords,
			Threads:      threads,
			Timeout:      timeout,
			AttemptDelay: delay,
			Verbose:      verbose,
			VeryVerbose:  false,
			StopOnFirst:  false,
			ExtraChecks:  "",
		}

		// 创建SSH爆破器
		bruteforcer := ssh.NewSSHBruteforcer(config)

		// 执行爆破
		results, err := bruteforcer.Bruteforce()
		if err != nil {
			utils.ErrorPrint("[!] 爆破失败: %v", err)
			return
		}

		// 打印结果
		bruteforcer.PrintResults(results)

		// 统计结果
		successCount := 0
		for _, result := range results {
			if result.Success {
				successCount++
			}
		}

		// 打印最终结果
		utils.InfoPrint("[*] 结束时间: %s", time.Now().Format("2006-01-02 15:04:05"))
		if successCount > 0 {
			utils.SuccessPrint("[+] 爆破完成，发现 %d 个有效凭据", successCount)
		} else {
			utils.ErrorPrint("[-] 爆破完成，未发现有效凭据")
		}

		// 关闭爆破器资源
		bruteforcer.Close()
	},
}

func init() {
	// SSH命令参数
	sshCmd.Flags().String("target", "", "目标主机IP或域名")
	sshCmd.Flags().String("file", "", "包含目标列表的文件")
	sshCmd.Flags().Int("port", 22, "SSH端口")
	sshCmd.Flags().String("user", "", "单个用户名")
	sshCmd.Flags().String("users", "", "包含用户名列表的文件")
	sshCmd.Flags().String("passwords", "", "包含密码列表的文件")
	sshCmd.Flags().Int("threads", 1, "并发线程数")
	sshCmd.Flags().Int("timeout", 15, "连接超时时间(秒)")
	sshCmd.Flags().Int("delay", 2000, "尝试间隔(毫秒)")
	sshCmd.Flags().String("output", "", "结果输出文件")
	sshCmd.Flags().Bool("verbose", false, "详细输出模式")

	// 在根命令中注册ssh命令
	// rootCmd.AddCommand(sshCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
}
