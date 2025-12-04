package cli

import (
	"GYscan/internal/utils"
	"GYscan/internal/whois"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var whoisCmd = &cobra.Command{
	Use:   "whois [target]",
	Short: "Whois查询工具",
	Long:  `Whois查询工具，用于查询域名或IP地址的注册信息，支持单个查询和批量查询。`,
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		// 获取命令行参数
		file, _ := cmd.Flags().GetString("file")
		output, _ := cmd.Flags().GetString("output")
		silent, _ := cmd.Flags().GetBool("silent")

		var targets []string

		// 从文件读取目标列表
		if file != "" {
			content, err := os.ReadFile(file)
			if err != nil {
				utils.ErrorPrint("读取文件失败: %v", err)
				return
			}
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		} else if len(args) > 0 {
			// 从命令行参数获取目标
			targets = args
		} else {
			utils.ErrorPrint("请提供查询目标或使用 -f 参数指定目标文件")
			cmd.Help()
			return
		}

		if len(targets) == 0 {
			utils.ErrorPrint("没有有效的查询目标")
			return
		}

		// 执行Whois查询
		fmt.Printf("[GYscan-Whois] 开始查询，共 %d 个目标\n", len(targets))

		results := whois.BatchWhois(targets)

		// 格式化输出结果
	var allOutput strings.Builder

	for _, result := range results {
		fmt.Printf("[GYscan-Whois] 查询完成: %s\n", result.Query)
		formatted := whois.FormatResult(result)
		allOutput.WriteString(formatted)
		allOutput.WriteString(strings.Repeat("=", 50))
		allOutput.WriteString("\n\n")
		if !silent {
			fmt.Println(formatted)
		}
	}

		// 保存结果到文件
		if output != "" {
			err := os.WriteFile(output, []byte(allOutput.String()), 0644)
			if err != nil {
				utils.ErrorPrint("保存结果到文件失败: %v", err)
			} else {
				utils.SuccessPrint("结果已保存到文件: %s", output)
			}
		}

		fmt.Printf("[GYscan-Whois] 查询完成，共查询 %d 个目标\n", len(results))
	},
}

func init() {
	// 添加命令参数
	whoisCmd.Flags().StringP("file", "f", "", "从文件中读取目标列表进行批量查询")
	whoisCmd.Flags().StringP("output", "o", "", "将结果输出到指定文件")
	whoisCmd.Flags().BoolP("silent", "q", false, "静默模式，仅输出关键结果")
}
