package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/dirscan"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// dirscanCmd 网站目录扫描命令
var dirscanCmd = &cobra.Command{
	Use:   "dirscan [options] -u URL",
	Short: "网站目录扫描工具",
	Long: `网站目录扫描工具 - 基于dirsearch的目录爆破功能

支持功能:
- 多线程目录扫描
- 自定义字典文件
- 扩展名扫描
- 状态码过滤
- 代理支持
- 结果导出

使用示例:
  ./GYscan dirscan -u http://example.com                    # 基本扫描
  ./GYscan dirscan -u https://example.com -w wordlist.txt    # 自定义字典
  ./GYscan dirscan -u http://example.com -t 50 -e php,html   # 多线程+扩展名
  ./GYscan dirscan -u http://example.com --proxy http://127.0.0.1:8080  # 代理扫描
  ./GYscan dirscan -u http://example.com -o results.txt      # 保存结果

警告: 仅用于授权测试和安全评估，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 解析参数
		targetURL, _ := cmd.Flags().GetString("url")
		wordlist, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		extensions, _ := cmd.Flags().GetString("extensions")
		outputFile, _ := cmd.Flags().GetString("output")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		proxy, _ := cmd.Flags().GetString("proxy")
		showAll, _ := cmd.Flags().GetBool("show-all")
		statusCodes, _ := cmd.Flags().GetString("status-codes")

		// 验证必需参数
		if targetURL == "" {
			utils.ErrorPrint("必须指定目标URL (-u/--url)")
			cmd.Help()
			return
		}

		// 处理字典选择
	var wordlistPath string
	if wordlist == "" {
		// 显示内置字典选择菜单
		utils.InfoPrint("请选择内置字典:")
		utils.InfoPrint("1. 大型字典 (dirmap/dicc.txt) - 9756个条目")
		utils.InfoPrint("2. 中型字典 (dirmap/medium.txt) - 2762个条目")
		utils.InfoPrint("输入选择 (1或2): ")
		
		var choice string
		_, err := fmt.Scanln(&choice)
		if err != nil {
			// 处理输入错误，使用默认值
			utils.WarningPrint("输入错误，使用默认中型字典")
			choice = "2"
		}
		
		// 清理输入，移除换行符和空格
		choice = strings.TrimSpace(choice)
		
		if choice != "1" && choice != "2" {
			utils.WarningPrint("无效选择，使用默认中型字典")
			choice = "2"
		}
		
		wordlist = choice
		
		// 验证内置字典文件存在
		wordlistPath = dirscan.BuiltinWordlists[choice]
		if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
			utils.ErrorPrint("内置字典文件不存在: %s", wordlistPath)
			utils.InfoPrint("请确保dirmap目录下的字典文件存在")
			return
		}
		
		utils.InfoPrint("使用内置字典: %s", wordlistPath)
	} else {
		// 验证外部字典文件存在
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			utils.ErrorPrint("字典文件不存在: %s", wordlist)
			utils.InfoPrint("请使用 -w/--wordlist 参数指定有效的字典文件")
			return
		}
	}

		// 解析扩展名
		var extList []string
		if extensions != "" {
			extList = parseExtensions(extensions)
		}

		// 解析状态码过滤
		statusCodeList := parseStatusCodes(statusCodes)

		// 创建扫描配置
	// 如果使用内置字典，使用实际的字典路径而不是选择数字
	configWordlist := wordlist
	if wordlistPath != "" {
		configWordlist = wordlistPath
	}
	
	config := &dirscan.ScanConfig{
		URL:              targetURL,
		Wordlist:         configWordlist,
		Threads:          threads,
		Timeout:          time.Duration(timeout) * time.Second,
		UserAgent:        userAgent,
		Extensions:       extList,
		OutputFile:       outputFile,
		ShowAll:          showAll,
		StatusCodeFilter: statusCodeList,
		Proxy:            proxy,
		FollowRedirects:  true,
	}

		// 创建扫描器
		scanner, err := dirscan.NewScanner(config)
		if err != nil {
			utils.ErrorPrint("创建扫描器失败: %v", err)
			return
		}

		// 执行扫描
		err = scanner.Start()
		if err != nil {
			utils.ErrorPrint("扫描失败: %v", err)
			return
		}
	},
}

// parseExtensions 解析扩展名字符串
func parseExtensions(extStr string) []string {
	if extStr == "" {
		return nil
	}
	
	exts := strings.Split(extStr, ",")
	var result []string
	
	for _, ext := range exts {
		ext = strings.TrimSpace(ext)
		if ext != "" {
			result = append(result, ext)
		}
	}
	
	return result
}

// parseStatusCodes 解析状态码字符串
func parseStatusCodes(statusStr string) []int {
	if statusStr == "" {
		return nil
	}
	
	codes := strings.Split(statusStr, ",")
	var result []int
	
	for _, codeStr := range codes {
		codeStr = strings.TrimSpace(codeStr)
		if codeStr == "" {
			continue
		}
		
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			utils.WarningPrint("无效的状态码: %s", codeStr)
			continue
		}
		
		result = append(result, code)
	}
	
	return result
}

// init 初始化dirscan命令
func init() {
	// 必需参数
	dirscanCmd.Flags().StringP("url", "u", "", "目标URL (必需)")
	
	// 字典相关
	dirscanCmd.Flags().StringP("wordlist", "w", "", "字典文件路径 (默认使用内置字典)")
	
	// 扫描配置
	dirscanCmd.Flags().IntP("threads", "t", 20, "并发线程数")
	dirscanCmd.Flags().Int("timeout", 10, "请求超时时间(秒)")
	dirscanCmd.Flags().StringP("extensions", "e", "", "扩展名扫描 (逗号分隔，如: php,html,txt)")
	dirscanCmd.Flags().String("user-agent", "", "自定义User-Agent")
	dirscanCmd.Flags().String("proxy", "", "代理服务器 (支持HTTP/SOCKS)")
	
	// 输出配置
	dirscanCmd.Flags().StringP("output", "o", "", "结果输出文件")
	dirscanCmd.Flags().Bool("show-all", false, "显示所有响应 (包括错误)")
	dirscanCmd.Flags().String("status-codes", "", "过滤状态码 (逗号分隔，如: 200,301,403)")
	
	// 不设置MarkFlagRequired，改为在Run函数内部验证必需参数
}