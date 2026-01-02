package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"GYscan/internal/honeypot"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var mgCmd = &cobra.Command{
	Use:   "mg",
	Short: "蜜罐识别工具 - 检测目标是否为蜜罐系统 [测试阶段]",
	Long: `mg命令 - 蜜罐识别工具 [测试阶段]

功能包括：
• 自动化检测目标是否为蜜罐（支持Kippo、ConPot、Dionaea、HFish等常见蜜罐）
• 输出可量化的识别结果（置信度 + 特征匹配明细）
• 支持自定义特征库，适配新类型蜜罐
• 支持单IP/IP段扫描、多协议验证
• 轻量化设计，无复杂依赖

示例用法：
  # 单目标快速检测
  ./GYscan mg --target 192.168.1.100

  # 单目标深度检测（包含行为分析）
  ./GYscan mg --target 192.168.1.100 --mode deep

  # 指定端口检测
  ./GYscan mg --target 192.168.1.100 --ports 22,80,443

  # JSON格式输出
  ./GYscan mg --target 192.168.1.100 --output json

  # 批量检测
  ./GYscan mg --file targets.txt --threads 5

  # 自定义特征库
  ./GYscan mg --target 192.168.1.100 --config ./custom_signatures.json`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		file, _ := cmd.Flags().GetString("file")
		ports, _ := cmd.Flags().GetString("ports")
		mode, _ := cmd.Flags().GetString("mode")
		output, _ := cmd.Flags().GetString("output")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		configPath, _ := cmd.Flags().GetString("config")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if target == "" && file == "" {
			utils.ErrorPrint("错误: 必须指定目标(--target)或目标文件(--file)")
			cmd.Help()
			return
		}

		scanMode := honeypot.QuickScan
		if mode == "deep" {
			scanMode = honeypot.DeepScan
		}

		outputFormat := honeypot.FormatText
		if output == "json" {
			outputFormat = honeypot.FormatJSON
		}

		utils.SuccessPrint("[+] 蜜罐识别工具启动")
		utils.InfoPrint("[*] 开始时间: %s", time.Now().Format("2006-01-02 15:04:05"))
		utils.InfoPrint("[*] 检测模式: %s", scanMode)
		utils.InfoPrint("[*] 输出格式: %s", outputFormat)
		if target != "" {
			utils.InfoPrint("[*] 目标: %s", target)
		} else {
			utils.InfoPrint("[*] 目标文件: %s", file)
			utils.InfoPrint("[*] 线程数: %d", threads)
		}
		if ports != "" {
			utils.InfoPrint("[*] 扫描端口: %s", ports)
		}
		if configPath != "" {
			utils.InfoPrint("[*] 特征库: %s", configPath)
		}
		utils.InfoPrint("[*] 超时时间: %d秒", timeout)
		utils.InfoPrint("")

		config := &honeypot.Config{
			Target:       target,
			Ports:        ports,
			Mode:         scanMode,
			OutputFormat: outputFormat,
			Threads:      threads,
			Timeout:      timeout,
			ConfigPath:   configPath,
			Verbose:      verbose,
		}

		detector := honeypot.NewDetector(config)
		if err := detector.LoadCustomSignatures(); err != nil {
			utils.ErrorPrint("[!] 加载自定义特征库失败: %v", err)
		}

		var allResults []*honeypot.DetectionResult

		if target != "" {
			if err := detector.ValidateTarget(target); err != nil {
				utils.ErrorPrint("[!] 目标验证失败: %v", err)
				return
			}
			allResults = detector.Detect(target)
		} else {
			targets, err := readTargetsFromFile(file)
			if err != nil {
				utils.ErrorPrint("[!] 读取目标文件失败: %v", err)
				return
			}
			allResults = detector.DetectBatch(targets)
		}

		utils.InfoPrint("[*] 结束时间: %s", time.Now().Format("2006-01-02 15:04:05"))
		utils.InfoPrint("")

		if outputFormat == honeypot.FormatJSON {
			printResultsJSON(allResults)
		} else {
			printResultsText(allResults)
		}

		stats := detector.GetStatistics(allResults)
		printStatistics(stats)
	},
}

func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

func printResultsText(results []*honeypot.DetectionResult) {
	honeypotCount := 0
	for _, r := range results {
		if r.IsHoneypot {
			honeypotCount++
		}
	}

	if honeypotCount > 0 {
		utils.WarningPrint("[!] 检测完成，发现 %d 个可能的蜜罐目标", honeypotCount)
	} else {
		utils.SuccessPrint("[+] 检测完成，未发现明显蜜罐特征")
	}
	utils.InfoPrint("")

	for i, result := range results {
		fmt.Println(strings.Repeat("=", 60))

		utils.BoldInfo("[目标 %d] %s:%d", i+1, result.Target, result.Port)

		if result.ServiceInfo != nil {
			utils.InfoPrint("服务: %s", result.Service)
			utils.InfoPrint("Banner: %s", truncateToLength(result.ServiceInfo.Banner, 80))
		}

		confidence := result.Confidence
		riskLevel := result.RiskLevel

		switch riskLevel {
		case honeypot.RiskCritical:
			utils.ErrorPrint("风险等级: %s (置信度: %d%%)", riskLevel, confidence)
		case honeypot.RiskHigh:
			utils.ErrorPrint("风险等级: %s (置信度: %d%%)", riskLevel, confidence)
		case honeypot.RiskMedium:
			utils.WarningPrint("风险等级: %s (置信度: %d%%)", riskLevel, confidence)
		default:
			utils.SuccessPrint("风险等级: %s (置信度: %d%%)", riskLevel, confidence)
		}

		if result.IsHoneypot {
			utils.ErrorPrint("识别结果: 可能是蜜罐 (%s)", result.HoneypotType)
		} else {
			utils.SuccessPrint("识别结果: 未检测到蜜罐特征")
		}

		if len(result.MatchedFeatures) > 0 {
			utils.InfoPrint("")
			utils.BoldInfo("匹配特征:")
			sortedFeatures := honeypot.NewMatcher().SortFeaturesByWeight(result.MatchedFeatures)
			for _, feature := range sortedFeatures {
				utils.InfoPrint("  [+] %s (权重: %d)", feature.Name, feature.Weight)
				utils.InfoPrint("      %s", feature.Description)
			}
		}

		utils.InfoPrint("")
		utils.InfoPrint("建议: %s", result.Suggestion)

		if result.BehaviorAnalysis != nil {
			utils.InfoPrint("")
			utils.BoldInfo("行为分析:")
			if result.BehaviorAnalysis.ResponseTimeFixed {
				utils.WarningPrint("  [!] 响应时间过于规律")
			}
			if result.BehaviorAnalysis.ProtocolInconsistent {
				utils.WarningPrint("  [!] 协议响应异常")
			}
			utils.InfoPrint("  %s", result.BehaviorAnalysis.Details)
		}

		utils.InfoPrint("")
		utils.InfoPrint("检测耗时: %v", result.ScanDuration)
		fmt.Println()
	}
}

func printResultsJSON(results []*honeypot.DetectionResult) {
	for _, result := range results {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			utils.ErrorPrint("[!] JSON序列化失败: %v", err)
			continue
		}
		fmt.Println(string(data))
		fmt.Println()
	}
}

func printStatistics(stats map[string]int) {
	utils.InfoPrint("")
	utils.BoldInfo("统计信息:")
	utils.InfoPrint("  总检测数: %d", stats["total"])
	utils.InfoPrint("  蜜罐目标: %d", stats["honeypot"])
	utils.InfoPrint("  高风险: %d", stats["high"])
	utils.InfoPrint("  中风险: %d", stats["medium"])
	utils.InfoPrint("  低风险: %d", stats["low"])
	utils.InfoPrint("  平均置信度: %d%%", stats["confidence"])
}

func truncateToLength(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func init() {
	mgCmd.Flags().String("target", "", "目标IP或域名（支持单个目标）")
	mgCmd.Flags().String("file", "", "包含目标列表的文件（每行一个目标）")
	mgCmd.Flags().String("ports", "", "指定扫描端口（默认：常见服务端口）")
	mgCmd.Flags().String("mode", "quick", "扫描模式：quick（快速）/deep（深度）")
	mgCmd.Flags().String("output", "text", "输出格式：text/json")
	mgCmd.Flags().Int("threads", 5, "并发线程数")
	mgCmd.Flags().Int("timeout", 30, "连接超时时间(秒)")
	mgCmd.Flags().String("config", "", "自定义特征库文件路径")
	mgCmd.Flags().Bool("verbose", false, "详细输出模式")
}
