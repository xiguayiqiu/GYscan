package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"GYscan/internal/ftp"
	"GYscan/internal/utils"
)

var ftpCmd = &cobra.Command{
	Use:   "ftp [target]",
	Short: "FTP密码破解",
	Long:  `使用字典攻击破解FTP服务器密码，支持多线程并发破解`,
	Example: `  # 破解FTP服务器
  GYscan.exe ftp ftp://192.168.1.1 -u admin,root -p pass.txt
  
  # 指定端口和线程数
  GYscan.exe ftp 192.168.1.1:2121 -u user.txt -p pass.txt -t 10`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		
		// 获取用户名参数
		usernameStr, _ := cmd.Flags().GetString("username")
		usernameFile, _ := cmd.Flags().GetString("username-file")
		
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
				credentials = append(credentials, cred)
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
	rootCmd.AddCommand(ftpCmd)
	
	// 定义命令行参数
	ftpCmd.Flags().StringP("username", "u", "", "用户名列表，用逗号分隔")
	ftpCmd.Flags().String("username-file", "", "用户名文件路径")
	ftpCmd.Flags().StringP("password", "p", "", "密码列表，用逗号分隔")
	ftpCmd.Flags().String("password-file", "", "密码文件路径")
	ftpCmd.Flags().IntP("threads", "t", 5, "并发线程数")
	ftpCmd.Flags().Int("timeout", 10, "连接超时时间（秒）")
	
	// 设置必需参数
	ftpCmd.MarkFlagRequired("username")
	// 密码参数可以通过-p或--password-file指定，不强制要求-p
}