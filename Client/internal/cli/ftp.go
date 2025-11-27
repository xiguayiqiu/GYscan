package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"GYscan/internal/ftp"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var ftpCmd = &cobra.Command{
	Use:   "ftp [target]",
	Short: "FTP密码破解工具",
	Long: `使用字典攻击或指定用户名密码组合破解FTP服务器密码，支持多线程并发破解，实时显示破解进度和结果。

该工具采用高效的并发设计，能够快速尝试大量用户名和密码组合，适用于授权的渗透测试和安全评估。

支持的目标格式：
  - 直接IP地址：192.168.1.1
  - IP地址+端口：192.168.1.1:2121
  - FTP URL格式：ftp://192.168.1.1:21

支持的用户名/密码输入方式：
  - 直接指定：-u admin,root -p password123,admin123
  - 字典文件：--username-file users.txt --password-file passwords.txt`,
	Example: `  # 使用直接指定的用户名和密码破解
  GYscan.exe ftp 192.168.1.1 -u admin,root -p password123,admin123
  
  # 使用字典文件破解
  GYscan.exe ftp 192.168.1.1 --username-file users.txt --password-file passwords.txt
  
  # 指定端口和线程数
  GYscan.exe ftp 192.168.1.1:2121 -u admin -p pass.txt -t 20
  
  # 使用FTP URL格式
  GYscan.exe ftp ftp://192.168.1.1 -u admin -p password123
  
  # 调整超时时间
  GYscan.exe ftp 192.168.1.1 -u admin -p pass.txt --timeout 5`,
	Args: func(cmd *cobra.Command, args []string) error {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			return nil
		}
		// 正常参数验证
		return cobra.ExactArgs(1)(cmd, args)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		target := args[0]

		// 获取用户名参数
		usernameStr, _ := cmd.Flags().GetString("username")
		usernameFile, _ := cmd.Flags().GetString("username-file")

		// 验证必需参数
		if usernameStr == "" && usernameFile == "" {
			fmt.Println("错误: 必须指定用户名(-u)或用户名字典文件(--username-file)")
			cmd.Help()
			return
		}

		// 获取密码参数
		passwordStr, _ := cmd.Flags().GetString("password")
		passwordFile, _ := cmd.Flags().GetString("password-file")

		// 获取其他参数
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")

		// 解析用户名列表
		usernames, err := parseCredentials(usernameStr, usernameFile)
		if err != nil {
			fmt.Printf("错误: 解析用户名失败 - %v\n", err)
			return
		}

		// 解析密码列表
		passwords, err := parseCredentials(passwordStr, passwordFile)
		if err != nil {
			fmt.Printf("错误: 解析密码失败 - %v\n", err)
			return
		}

		if len(usernames) == 0 {
			fmt.Println("错误: 未指定用户名")
			return
		}

		if len(passwords) == 0 {
			fmt.Println("错误: 未指定密码")
			return
		}

		// 显示破解信息
		utils.BannerPrint("FTP密码破解工具")
		fmt.Printf("目标: %s\n", target)
		fmt.Printf("用户数: %d, 密码数: %d\n", len(usernames), len(passwords))
		fmt.Printf("线程数: %d, 超时: %d秒\n", threads, timeout)
		fmt.Printf("总尝试次数: %d\n", len(usernames)*len(passwords))
		fmt.Println()

		// 执行FTP破解
		results, err := ftp.CrackFTP(target, usernames, passwords, threads, timeout)
		if err != nil {
			fmt.Printf("错误: FTP破解失败 - %v\n", err)
			return
		}

		// 显示结果
		successCount := 0
		for _, result := range results {
			if result.Success {
				successCount++
			}
		}

		fmt.Printf("\n破解完成！\n")
		fmt.Printf("总尝试次数: %d\n", len(results))
		fmt.Printf("成功破解: %d\n", successCount)

		if len(results) > 0 {
			successRate := float64(successCount) / float64(len(results)) * 100
			fmt.Printf("成功率: %.2f%%\n", successRate)
		}

		if successCount > 0 {
			fmt.Printf("\n成功账户:\n")
			// 去重显示成功结果
			uniqueResults := make(map[string]bool)
			for _, result := range results {
				if result.Success {
					key := result.Username + "|" + result.Password
					if !uniqueResults[key] {
						uniqueResults[key] = true
						utils.SuccessPrint("用户名: %s, 密码: %s, 耗时: %v",
							result.Username, result.Password, result.Duration)
					}
				}
			}
		}
	},
}

// parseCredentials 解析凭据（字符串或文件）
func parseCredentials(credStr, credFile string) ([]string, error) {
	var credentials []string

	// 从字符串解析
	if credStr != "" {
		creds := strings.Split(credStr, ",")
		for _, cred := range creds {
			cred = strings.TrimSpace(cred)
			if cred != "" {
				// 直接检查文件是否存在，不依赖扩展名
				if _, err := os.Stat(cred); err == nil {
					// 是文件路径，读取文件内容
					file, err := os.Open(cred)
					if err != nil {
						// 如果无法打开文件，将其作为密码处理
						credentials = append(credentials, cred)
						continue
					}
					defer file.Close()

					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line != "" && !strings.HasPrefix(line, "#") {
							credentials = append(credentials, line)
						}
					}

					if err := scanner.Err(); err != nil {
						return nil, fmt.Errorf("读取文件 %s 失败: %v", cred, err)
					}
				} else {
					// 不是文件路径，直接作为密码
					credentials = append(credentials, cred)
				}
			}
		}
	}

	// 从文件解析
	if credFile != "" {
		file, err := os.Open(credFile)
		if err != nil {
			return nil, fmt.Errorf("无法打开文件 %s: %v", credFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				credentials = append(credentials, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("读取文件 %s 失败: %v", credFile, err)
		}
	}

	return credentials, nil
}

func init() {
	// 添加FTP命令到根命令
	// rootCmd.AddCommand(ftpCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理

	// 定义命令行参数
	ftpCmd.Flags().StringP("username", "u", "", "用户名列表，用逗号分隔")
	ftpCmd.Flags().String("username-file", "", "用户名文件路径")
	ftpCmd.Flags().StringP("password", "p", "", "密码列表，用逗号分隔")
	ftpCmd.Flags().String("password-file", "", "密码文件路径")
	ftpCmd.Flags().IntP("threads", "t", 5, "并发线程数")
	ftpCmd.Flags().Int("timeout", 10, "连接超时时间（秒）")

	// 不设置MarkFlagRequired，改为在Run函数内部验证必需参数
}
