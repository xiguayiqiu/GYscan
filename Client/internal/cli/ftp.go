package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

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
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助或无参数
		if len(args) == 0 || args[0] == "help" {
			cmd.Help()
			return
		}

		// 获取目标文件参数
		targetsFile, _ := cmd.Flags().GetString("targets-file")
		concurrentTargets, _ := cmd.Flags().GetInt("concurrent-targets")

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

		// 解析目标列表
		var targets []string
		if targetsFile != "" {
			// 从文件读取目标
			file, err := os.Open(targetsFile)
			if err != nil {
				fmt.Printf("错误: 打开目标文件失败 - %v\n", err)
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				target := strings.TrimSpace(scanner.Text())
				if target != "" && !strings.HasPrefix(target, "#") {
					targets = append(targets, target)
				}
			}

			if err := scanner.Err(); err != nil {
				fmt.Printf("错误: 读取目标文件失败 - %v\n", err)
				return
			}

			if len(targets) == 0 {
				fmt.Println("错误: 目标文件中未找到有效目标")
				return
			}
		} else {
			// 从命令行参数获取单个目标
			if len(args) == 0 {
				fmt.Println("请指定扫描目标 (直接传递目标参数或使用 -L 标志指定目标文件)")
				fmt.Println("用法: GYscan ftp 目标 [选项] 或 GYscan ftp -L 目标文件 [选项]")
				return
			}
			targets = []string{args[0]}
		}

		// 显示破解信息
		utils.BannerPrint("FTP密码破解工具")
		fmt.Printf("目标数: %d\n", len(targets))
		fmt.Printf("用户数: %d, 密码数: %d\n", len(usernames), len(passwords))
		fmt.Printf("每个目标线程数: %d, 超时: %d秒\n", threads, timeout)
		fmt.Printf("同时破解目标数: %d\n", concurrentTargets)
		fmt.Printf("总尝试次数: %d\n", len(targets)*len(usernames)*len(passwords))
		fmt.Println()

		// 执行FTP破解
		var allResults []ftp.CrackResult

		// 创建并发控制通道
		semaphore := make(chan struct{}, concurrentTargets)
		var wg sync.WaitGroup
		var mu sync.Mutex

		// 遍历所有目标
		for _, target := range targets {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(t string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				fmt.Printf("开始破解目标: %s\n", t)

				// 执行FTP破解
				results, err := ftp.CrackFTP(t, usernames, passwords, threads, timeout)
				if err != nil {
					fmt.Printf("错误: 目标 %s 破解失败 - %v\n", t, err)
					return
				}

				// 保存结果
				mu.Lock()
				allResults = append(allResults, results...)
				mu.Unlock()
			}(target)
		}

		// 等待所有目标破解完成
		wg.Wait()

		// 显示结果
		successCount := 0
		for _, result := range allResults {
			if result.Success {
				successCount++
			}
		}

		fmt.Printf("\n破解完成！\n")
		fmt.Printf("总尝试次数: %d\n", len(allResults))
		fmt.Printf("成功破解: %d\n", successCount)

		if len(allResults) > 0 {
			successRate := float64(successCount) / float64(len(allResults)) * 100
			fmt.Printf("成功率: %.2f%%\n", successRate)
		}

		if successCount > 0 {
			// 去重显示成功结果
			uniqueResults := make(map[string]bool)
			var resultsList []ftp.CrackResult
			for _, result := range allResults {
				if result.Success {
					key := result.Target + "|" + result.Username + "|" + result.Password
					if !uniqueResults[key] {
						uniqueResults[key] = true
						resultsList = append(resultsList, result)
					}
				}
			}

			// 确保结果输出前有换行
			fmt.Println()

			// 按照用户要求的格式输出结果
			for i, result := range resultsList {
				if i > 0 {
					fmt.Println("============")
					fmt.Println()
				}
				utils.SuccessPrint("FTP目标：%s\n", result.Target)
				utils.SuccessPrint("FTP用户：%s\n", result.Username)
				utils.SuccessPrint("FTP密码：%s\n", result.Password)
				fmt.Println()
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
	ftpCmd.Flags().StringP("username-file", "U", "", "用户名文件路径")
	ftpCmd.Flags().StringP("password", "p", "", "密码列表，用逗号分隔")
	ftpCmd.Flags().String("password-file", "", "密码文件路径")
	ftpCmd.Flags().StringP("targets-file", "L", "", "多个目标文件路径，每行一个目标")
	ftpCmd.Flags().IntP("concurrent-targets", "k", 3, "同时破解的目标个数，默认3个")
	ftpCmd.Flags().IntP("threads", "t", 20, "每个目标的并发线程数，默认20个")
	ftpCmd.Flags().Int("timeout", 5, "连接超时时间（秒），建议2-5秒")

	// 不设置MarkFlagRequired，改为在Run函数内部验证必需参数
}
