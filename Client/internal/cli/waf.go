package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"GYscan/internal/waf"

	"github.com/spf13/cobra"
)

var (
	wafTarget      string
	wafFile        string
	wafConcurrency int
	wafRulesPath   string
	wafOutputFile  string
	wafOutputFormat string
)

// wafCmd WAF识别命令
var wafCmd = &cobra.Command{
	Use:   "waf [options]",
	Short: "WAF识别工具",
	Long: `WAF识别工具 - 用于识别网站使用的Web应用防火墙类型
支持通过被动特征（响应头、证书、响应内容）和主动轻量探测识别常见WAF`,
	Run: func(cmd *cobra.Command, args []string) {
		if wafTarget == "" && wafFile == "" {
			fmt.Println("\033[31m[ERROR] 请指定目标 (-u) 或目标文件 (-f)\033[0m")
			cmd.Usage()
			return
		}

		executeWAFDetection()
	},
}

// executeWAFDetection 执行WAF检测
func executeWAFDetection() {
	// 创建WAF检测器
	detector := waf.NewWAFDetector()

	// 加载规则文件
	rulesPath := wafRulesPath
	if rulesPath == "" {
		// 使用嵌入规则文件，无需指定路径
		rulesPath = ""
	}

	fmt.Println("\033[34m[INFO] 正在加载WAF规则...\033[0m")
	err := detector.LoadRules(rulesPath)
	if err != nil {
		fmt.Printf("\033[31m[ERROR] 加载规则失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m[INFO] 规则加载成功\033[0m")

	var targets []string
	if wafTarget != "" {
		targets = []string{wafTarget}
	} else if wafFile != "" {
		fmt.Printf("\033[34m[INFO] 正在读取目标文件: %s\033[0m\n", wafFile)
		content, err := os.ReadFile(wafFile)
		if err != nil {
			fmt.Printf("\033[31m[ERROR] 读取目标文件失败: %v\033[0m\n", err)
			return
		}
		// 读取每行作为一个目标
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		fmt.Printf("\033[32m[INFO] 共读取到 %d 个目标\033[0m\n", len(targets))
	}

	// 设置并发数
	if wafConcurrency <= 0 {
		wafConcurrency = 20 // 默认并发数
	} else if wafConcurrency > 100 {
		wafConcurrency = 100 // 最大并发数限制
	}

	fmt.Println("\033[34m[INFO] 开始进行WAF识别检测...\033[0m")
	fmt.Printf("\033[34m[INFO] 并发数: %d\033[0m\n", wafConcurrency)

	// 使用DetectTargets进行并发检测
		results := detector.DetectTargets(targets, wafConcurrency)
		
		// 打印所有结果
		for _, result := range results {
			printWAFResult(result)
		}
		
		// 统计结果
		totalDetected := 0
		for _, result := range results {
			if result.Detected {
				totalDetected++
			}
		}
		
		fmt.Printf("\033[32m[INFO] 检测完成: 共检测 %d 个目标，发现 %d 个存在WAF的站点\033[0m\n", len(targets), totalDetected)
		
		// 保存结果到文件
		if wafOutputFile != "" {
			fmt.Printf("\033[34m[INFO] 正在保存结果到文件: %s\033[0m\n", wafOutputFile)
			err := saveResultsToFile(results, wafOutputFile, wafOutputFormat)
			if err != nil {
				fmt.Printf("\033[31m[ERROR] 保存结果失败: %v\033[0m\n", err)
			} else {
				fmt.Println("\033[32m[SUCCESS] 结果保存成功\033[0m")
			}
		}

	fmt.Println("\033[32m[INFO] WAF识别检测完成\033[0m")
}

// printWAFResult 打印WAF检测结果
func printWAFResult(result *waf.WAFResult) {
	if result.Detected {
		fmt.Printf("\033[32m[+] %s -> 检测到WAF: %s (厂商: %s) 置信度: %d%%\033[0m\n", 
			result.Target, result.WAFName, result.Vendor, result.Confidence)
	} else {
		fmt.Printf("\033[34m[-] %s -> %s\033[0m\n", result.Target, result.Description)
	}
}

// init 初始化waf命令参数
func init() {
	wafCmd.Flags().StringVarP(&wafTarget, "url", "u", "", "指定目标URL (例如: https://example.com)")
	wafCmd.Flags().StringVarP(&wafFile, "file", "f", "", "指定包含多个目标的文件路径")
	wafCmd.Flags().IntVar(&wafConcurrency, "concurrency", 20, "并发数量 (1-100)")
	wafCmd.Flags().StringVar(&wafRulesPath, "rules", "", "自定义WAF规则文件路径")
	wafCmd.Flags().StringVarP(&wafOutputFile, "output", "o", "", "结果输出文件路径")
	wafCmd.Flags().StringVar(&wafOutputFormat, "format", "txt", "输出格式: txt (文本) 或 json (JSON格式)")
}

// GetWAFCmd 获取WAF命令（用于外部调用）
func GetWAFCmd() *cobra.Command {
	return wafCmd
}

// saveResultsToFile 保存检测结果到文件
func saveResultsToFile(results []*waf.WAFResult, filePath string, format string) error {
	var content string
	var err error
	
	// 根据指定格式生成内容
	switch strings.ToLower(format) {
	case "json":
		// 转换为JSON格式
		jsonData, err2 := json.MarshalIndent(results, "", "  ")
		if err2 != nil {
			return fmt.Errorf("JSON序列化失败: %v", err2)
		}
		content = string(jsonData)
	
	case "txt", "":
		// 文本格式
		var builder strings.Builder
		builder.WriteString("=== WAF识别结果报告 ===\n")
		builder.WriteString(fmt.Sprintf("生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
		builder.WriteString(fmt.Sprintf("目标数量: %d\n\n", len(results)))
		
		for _, result := range results {
			builder.WriteString(fmt.Sprintf("目标: %s\n", result.Target))
			if result.Detected {
				builder.WriteString("状态: 检测到WAF\n")
				builder.WriteString(fmt.Sprintf("类型: %s (厂商: %s)\n", result.WAFName, result.Vendor))
				builder.WriteString(fmt.Sprintf("置信度: %d%%\n", result.Confidence))
			} else {
				builder.WriteString(fmt.Sprintf("状态: %s\n", result.Description))
				if result.ErrorMessage != "" {
					builder.WriteString(fmt.Sprintf("错误: %s\n", result.ErrorMessage))
				}
			}
			builder.WriteString("--------------------\n")
		}
		
		content = builder.String()
	
	default:
		return fmt.Errorf("不支持的输出格式: %s", format)
	}
	
	// 写入文件
	err = os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}
	
	return nil
}