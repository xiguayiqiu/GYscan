package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/fatih/color"
)

// GenerateAuditReport 生成审计报告
func GenerateAuditReport(report *AuditReport, outputPath string) error {
	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 根据文件扩展名确定报告格式
	ext := strings.ToLower(filepath.Ext(outputPath))
	switch ext {
	case ".html":
		return generateHTMLReport(report, outputPath)
	case ".json":
		return generateJSONReport(report, outputPath)
	default:
		return generateTextReport(report, outputPath)
	}
}

// generateJSONReport 生成JSON格式报告
func generateJSONReport(report *AuditReport, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建JSON文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("编码JSON失败: %v", err)
	}

	return nil
}

// generateTextReport 生成文本格式报告
func generateTextReport(report *AuditReport, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建文本文件失败: %v", err)
	}
	defer file.Close()

	// 报告头部
	fmt.Fprintf(file, "Windows安全审计报告\n")
	fmt.Fprintf(file, "====================\n\n")
	
	// 系统信息
	fmt.Fprintf(file, "系统信息:\n")
	fmt.Fprintf(file, "- 主机名: %s\n", report.SystemInfo.Hostname)
	fmt.Fprintf(file, "- 操作系统: %s %s\n", report.SystemInfo.OS, report.SystemInfo.Version)
	fmt.Fprintf(file, "- 架构: %s\n", report.SystemInfo.Architecture)
	fmt.Fprintf(file, "- 域: %s\n", report.SystemInfo.Domain)
	fmt.Fprintf(file, "- 当前用户: %s (管理员: %v)\n", report.SystemInfo.CurrentUser, report.SystemInfo.IsAdmin)
	fmt.Fprintf(file, "\n")

	// 审计摘要
	fmt.Fprintf(file, "审计摘要:\n")
	fmt.Fprintf(file, "- 总检查项: %d\n", report.Summary.TotalChecks)
	fmt.Fprintf(file, "- 通过: %d\n", report.Summary.Passed)
	fmt.Fprintf(file, "- 失败: %d\n", report.Summary.Failed)
	fmt.Fprintf(file, "- 警告: %d\n", report.Summary.Warnings)
	fmt.Fprintf(file, "- 错误: %d\n", report.Summary.Errors)
	fmt.Fprintf(file, "- 风险评分: %d\n", report.Summary.RiskScore)
	fmt.Fprintf(file, "\n")

	// 审计时间
	fmt.Fprintf(file, "审计时间:\n")
	fmt.Fprintf(file, "- 开始时间: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "- 耗时: %v\n", report.Duration)
	fmt.Fprintf(file, "\n")

	// 详细结果
	if len(report.Results) > 0 {
		fmt.Fprintf(file, "详细审计结果:\n")
		fmt.Fprintf(file, "==============\n\n")

		// 按模块分组
		modules := make(map[string][]AuditResult)
		for _, result := range report.Results {
			modules[result.ModuleName] = append(modules[result.ModuleName], result)
		}

		for moduleName, results := range modules {
			fmt.Fprintf(file, "模块: %s\n", moduleName)
			fmt.Fprintf(file, "%s\n", strings.Repeat("-", len(moduleName)+7))

			for i, result := range results {
				fmt.Fprintf(file, "%d. [%s] %s\n", i+1, result.Status, result.Description)
				
				// 显示风险级别
				switch result.Level {
				case AuditLevelHigh:
					fmt.Fprintf(file, "   风险级别: 高 (评分: %d)\n", result.RiskScore)
				case AuditLevelMedium:
					fmt.Fprintf(file, "   风险级别: 中 (评分: %d)\n", result.RiskScore)
				case AuditLevelLow:
					fmt.Fprintf(file, "   风险级别: 低 (评分: %d)\n", result.RiskScore)
				}

				// 显示建议
				if result.Recommendation != "" {
					fmt.Fprintf(file, "   建议: %s\n", result.Recommendation)
				}

				// 显示详细信息（如果可用）
				if result.Details != nil {
					if details, ok := result.Details.(string); ok && details != "" {
						fmt.Fprintf(file, "   详情: %s\n", details)
					}
				}

				fmt.Fprintf(file, "\n")
			}
		}
	}

	return nil
}

// generateHTMLReport 生成HTML格式报告
func generateHTMLReport(report *AuditReport, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	htmlTemplate := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows安全审计报告</title>
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            line-height: 1.6; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); 
            color: white; 
            padding: 30px; 
            text-align: center;
        }
        .header h1 { 
            margin: 0; 
            font-size: 2.5em; 
            font-weight: 300;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header p { 
            margin: 10px 0 0; 
            font-size: 1.1em; 
            opacity: 0.9;
        }
        .content { padding: 30px; }
        .section { 
            margin-bottom: 30px; 
            background: #f8f9fa; 
            border-radius: 10px; 
            padding: 25px;
            border-left: 5px solid #3498db;
        }
        .section h2 { 
            color: #2c3e50; 
            margin-top: 0; 
            border-bottom: 2px solid #e9ecef; 
            padding-bottom: 10px;
            font-size: 1.5em;
        }
        .info-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 15px; 
            margin-top: 15px;
        }
        .info-item { 
            background: white; 
            padding: 15px; 
            border-radius: 8px; 
            border-left: 4px solid #3498db;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin-top: 15px;
        }
        .summary-item { 
            text-align: center; 
            padding: 20px; 
            border-radius: 10px; 
            color: white;
            font-weight: bold;
            font-size: 1.1em;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .total { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); }
        .passed { background: linear-gradient(135deg, #27ae60 0%, #229954 100%); }
        .failed { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .warnings { background: linear-gradient(135deg, #f39c12 0%, #d35400 100%); }
        .errors { background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); }
        .risk { background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); }
        .result-item { 
            background: white; 
            margin: 15px 0; 
            padding: 20px; 
            border-radius: 10px; 
            border-left: 5px solid;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .result-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .high-risk { border-left-color: #e74c3c; }
        .medium-risk { border-left-color: #f39c12; }
        .low-risk { border-left-color: #27ae60; }
        .error-risk { border-left-color: #95a5a6; }
        .status-badge { 
            padding: 5px 12px; 
            border-radius: 20px; 
            font-size: 0.9em; 
            color: white; 
            font-weight: bold;
            display: inline-block;
            margin-right: 10px;
        }
        .pass { background: #27ae60; }
        .fail { background: #e74c3c; }
        .warning { background: #f39c12; }
        .error-badge { background: #95a5a6; }
        .risk-badge { 
            padding: 4px 10px; 
            border-radius: 15px; 
            font-size: 0.8em; 
            color: white; 
            font-weight: bold;
            display: inline-block;
        }
        .high { background: #e74c3c; }
        .medium { background: #f39c12; }
        .low { background: #27ae60; }
        .result-details { 
            margin-top: 15px; 
            padding: 15px; 
            background: #f8f9fa; 
            border-radius: 8px;
            border-left: 3px solid #3498db;
        }
        .timestamp { 
            font-size: 0.9em; 
            color: #6c757d; 
            margin-top: 10px;
            text-align: right;
        }
        .module-section {
            margin-bottom: 30px;
            background: #ffffff;
            border-radius: 10px;
            border: 1px solid #e9ecef;
            overflow: hidden;
        }
        .module-title {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            color: #2c3e50;
            margin: 0;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
            font-size: 1.3em;
            font-weight: 600;
        }
        .module-stats {
            font-size: 0.8em;
            color: #6c757d;
            font-weight: normal;
            margin-left: 10px;
        }
        .module-results {
            padding: 20px;
        }
        .module-results .result-item {
            margin: 10px 0;
            padding: 15px;
        }
        .module-results .result-item h4 {
            margin: 0 0 10px 0;
            font-size: 1.1em;
        }
        @media (max-width: 768px) {
            .container { margin: 10px; border-radius: 10px; }
            .header { padding: 20px; }
            .header h1 { font-size: 2em; }
            .content { padding: 20px; }
            .info-grid, .summary-grid { grid-template-columns: 1fr; }
            .module-title { padding: 15px; font-size: 1.1em; }
            .module-results { padding: 15px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Windows安全审计报告</h1>
            <p>生成时间: TIMESTAMP</p>
        </div>

        <div class="content">
            <div class="section">
                <h2>系统信息</h2>
                <div class="info-grid">
                    <div class="info-item"><strong>主机名:</strong> HOSTNAME</div>
                    <div class="info-item"><strong>操作系统:</strong> OS_VERSION</div>
                    <div class="info-item"><strong>架构:</strong> ARCHITECTURE</div>
                    <div class="info-item"><strong>域:</strong> DOMAIN</div>
                    <div class="info-item"><strong>当前用户:</strong> CURRENT_USER</div>
                    <div class="info-item"><strong>管理员权限:</strong> IS_ADMIN</div>
                </div>
            </div>

            <div class="section">
                <h2>审计摘要</h2>
                <div class="summary-grid">
                    <div class="summary-item total">总检查项: TOTAL_CHECKS</div>
                    <div class="summary-item passed">通过: PASSED</div>
                    <div class="summary-item failed">失败: FAILED</div>
                    <div class="summary-item warnings">警告: WARNINGS</div>
                    <div class="summary-item errors">错误: ERRORS</div>
                    <div class="summary-item risk">风险评分: RISK_SCORE</div>
                </div>
                <p style="margin-top: 15px;"><strong>审计耗时:</strong> DURATION</p>
            </div>

            <div class="section">
                <h2>详细审计结果</h2>
                RESULTS_CONTENT
            </div>
        </div>
    </div>
</body>
</html>`

	// 替换模板中的占位符
	htmlContent := strings.ReplaceAll(htmlTemplate, "TIMESTAMP", report.Timestamp.Format("2006-01-02 15:04:05"))
	htmlContent = strings.ReplaceAll(htmlContent, "HOSTNAME", report.SystemInfo.Hostname)
	htmlContent = strings.ReplaceAll(htmlContent, "OS_VERSION", fmt.Sprintf("%s %s", report.SystemInfo.OS, report.SystemInfo.Version))
	htmlContent = strings.ReplaceAll(htmlContent, "ARCHITECTURE", report.SystemInfo.Architecture)
	htmlContent = strings.ReplaceAll(htmlContent, "DOMAIN", report.SystemInfo.Domain)
	htmlContent = strings.ReplaceAll(htmlContent, "CURRENT_USER", report.SystemInfo.CurrentUser)
	htmlContent = strings.ReplaceAll(htmlContent, "IS_ADMIN", fmt.Sprintf("%v", report.SystemInfo.IsAdmin))
	htmlContent = strings.ReplaceAll(htmlContent, "TOTAL_CHECKS", fmt.Sprintf("%d", report.Summary.TotalChecks))
	htmlContent = strings.ReplaceAll(htmlContent, "PASSED", fmt.Sprintf("%d", report.Summary.Passed))
	htmlContent = strings.ReplaceAll(htmlContent, "FAILED", fmt.Sprintf("%d", report.Summary.Failed))
	htmlContent = strings.ReplaceAll(htmlContent, "WARNINGS", fmt.Sprintf("%d", report.Summary.Warnings))
	htmlContent = strings.ReplaceAll(htmlContent, "ERRORS", fmt.Sprintf("%d", report.Summary.Errors))
	htmlContent = strings.ReplaceAll(htmlContent, "RISK_SCORE", fmt.Sprintf("%d", report.Summary.RiskScore))
	htmlContent = strings.ReplaceAll(htmlContent, "DURATION", report.Duration.String())

	// 处理结果部分 - 按模块分组显示
	var resultsHTML strings.Builder
	
	// 按模块分组结果
	resultsByModule := make(map[string][]AuditResult)
	for _, result := range report.Results {
		resultsByModule[result.ModuleName] = append(resultsByModule[result.ModuleName], result)
	}
	
	// 定义模块显示顺序
	moduleOrder := []string{"account", "eventlog", "filesystem", "network", "process", "registry"}
	
	// 统计各模块结果
	for _, moduleName := range moduleOrder {
		if results, exists := resultsByModule[moduleName]; exists && len(results) > 0 {
			// 计算模块统计
			var moduleFailed, moduleWarnings, modulePassed int
			for _, result := range results {
				switch result.Status {
				case "fail":
					moduleFailed++
				case "warning":
					moduleWarnings++
				case "pass":
					modulePassed++
				}
			}
			
			// 模块标题
			moduleTitle := getModuleDisplayName(moduleName)
			resultsHTML.WriteString(fmt.Sprintf(`
                <div class="module-section">
                    <h3 class="module-title">%s <span class="module-stats">(失败: %d, 警告: %d, 通过: %d)</span></h3>
                    <div class="module-results">`, moduleTitle, moduleFailed, moduleWarnings, modulePassed))
			
			// 模块内结果
			for _, result := range results {
				// 确定风险级别对应的CSS类
				riskClass := "low-risk"
				switch result.Level {
				case AuditLevelHigh:
					riskClass = "high-risk"
				case AuditLevelMedium:
					riskClass = "medium-risk"
				case AuditLevelLow:
					riskClass = "low-risk"
				default:
					riskClass = "error-risk"
				}

				// 状态显示文本
				statusText := getStatusDisplayText(result.Status)
				
				resultHTML := fmt.Sprintf(`
                        <div class="result-item %s">
                            <h4><span class="status-badge %s">%s</span>%s</h4>
                            <p><strong>风险级别:</strong> <span class="risk-badge %s">%s</span> (评分: %d)</p>`, 
					riskClass, result.Status, statusText, result.Description,
					string(result.Level), getLevelDisplayText(result.Level), result.RiskScore)

				// 添加建议和详情
				if result.Recommendation != "" || result.Details != nil {
					resultHTML += `
                            <div class="result-details">`
					
					if result.Recommendation != "" {
						resultHTML += fmt.Sprintf(`
                                <p><strong>建议:</strong> %s</p>`, result.Recommendation)
					}

					if result.Details != nil {
						if details, ok := result.Details.(string); ok && details != "" {
							resultHTML += fmt.Sprintf(`
                                <p><strong>详情:</strong> %s</p>`, details)
						}
					}
					
					resultHTML += `
                            </div>`
				}

				resultHTML += fmt.Sprintf(`
                            <div class="timestamp">检查时间: %s</div>
                        </div>`, result.Timestamp.Format("2006-01-02 15:04:05"))

				resultsHTML.WriteString(resultHTML)
			}
			
			resultsHTML.WriteString(`
                    </div>
                </div>`)
		}
	}

	htmlContent = strings.ReplaceAll(htmlContent, "RESULTS_CONTENT", resultsHTML.String())

	// 写入文件
	_, err = file.WriteString(htmlContent)
	if err != nil {
		return fmt.Errorf("写入HTML文件失败: %v", err)
	}

	return nil
}

// getModuleDisplayName 获取模块显示名称
func getModuleDisplayName(moduleName string) string {
	switch moduleName {
	case "account":
		return "账户安全审计"
	case "eventlog":
		return "事件日志审计"
	case "filesystem":
		return "文件系统审计"
	case "network":
		return "网络配置审计"
	case "process":
		return "进程安全审计"
	case "registry":
		return "注册表审计"
	default:
		return moduleName
	}
}

// getStatusDisplayText 获取状态显示文本
func getStatusDisplayText(status string) string {
	switch status {
	case "pass":
		return "通过"
	case "fail":
		return "失败"
	case "warning":
		return "警告"
	default:
		return status
	}
}

// getLevelDisplayText 获取风险级别显示文本
func getLevelDisplayText(level AuditLevel) string {
	switch level {
	case AuditLevelHigh:
		return "高风险"
	case AuditLevelMedium:
		return "中等风险"
	case AuditLevelLow:
		return "低风险"
	default:
		return string(level)
	}
}

// PrintAuditSummary 打印审计摘要
func PrintAuditSummary(report *AuditReport) {
	// 使用颜色输出
	fmt.Println("\n" + strings.Repeat("═", 70))
	color.Cyan("Windows安全审计完成")
	fmt.Println(strings.Repeat("═", 70))
	
	// 系统信息
	fmt.Printf("系统: %s %s (%s)\n", 
		report.SystemInfo.OS, 
		report.SystemInfo.Version, 
		report.SystemInfo.Architecture)
	fmt.Printf("主机: %s (%s)\n", 
		report.SystemInfo.Hostname, 
		report.SystemInfo.Domain)
	fmt.Printf("用户: %s (管理员: %v)\n", 
		report.SystemInfo.CurrentUser, 
		report.SystemInfo.IsAdmin)
	
	// 审计结果统计
	fmt.Println("\n审计结果统计:")
	fmt.Printf("总检查项: %d\n", report.Summary.TotalChecks)
	
	// 使用颜色显示不同状态的结果
	if report.Summary.Passed > 0 {
		color.Green("通过: %d", report.Summary.Passed)
	} else {
		fmt.Printf("通过: %d\n", report.Summary.Passed)
	}
	
	if report.Summary.Failed > 0 {
		color.Red("失败: %d", report.Summary.Failed)
	} else {
		fmt.Printf("失败: %d\n", report.Summary.Failed)
	}
	
	if report.Summary.Warnings > 0 {
		color.Yellow("警告: %d", report.Summary.Warnings)
	} else {
		fmt.Printf("警告: %d\n", report.Summary.Warnings)
	}
	
	if report.Summary.Errors > 0 {
		color.Magenta("错误: %d", report.Summary.Errors)
	} else {
		fmt.Printf("错误: %d\n", report.Summary.Errors)
	}
	
	// 风险评分和等级
	riskLevel := "低"
	if report.Summary.RiskScore >= 70 {
		riskLevel = "高"
		color.Red("风险评分: %d (%s)", report.Summary.RiskScore, riskLevel)
	} else if report.Summary.RiskScore >= 40 {
		riskLevel = "中"
		color.Yellow("风险评分: %d (%s)", report.Summary.RiskScore, riskLevel)
	} else {
		color.Green("风险评分: %d (%s)", report.Summary.RiskScore, riskLevel)
	}
	
	// 按模块统计
	fmt.Println("\n模块结果分布:")
	resultsByModule := make(map[string]int)
	for _, result := range report.Results {
		resultsByModule[result.ModuleName]++
	}
	
	// 定义模块显示顺序
	moduleOrder := []string{"account", "eventlog", "filesystem", "network", "process", "registry"}
	for _, moduleName := range moduleOrder {
		if count, exists := resultsByModule[moduleName]; exists {
			fmt.Printf("- %s: %d项\n", getModuleDisplayName(moduleName), count)
		}
	}
	
	// 时间信息
	fmt.Printf("\n审计耗时: %v\n", report.Duration)
	fmt.Printf("完成时间: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
	
	// 最终建议
	fmt.Println("\n" + strings.Repeat("─", 70))
	if report.Summary.RiskScore >= 70 {
		color.Red("⚠️  系统存在高风险安全问题，建议立即处理！")
	} else if report.Summary.RiskScore >= 40 {
		color.Yellow("⚠️  系统存在中等风险问题，建议尽快处理！")
	} else {
		color.Green("✅  系统安全状况良好，继续保持！")
	}
	fmt.Println(strings.Repeat("─", 70))
}