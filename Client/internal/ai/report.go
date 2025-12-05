package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// ReportData 和 Finding 类型已移至types包，直接使用types.ReportData和types.Finding

// ReportFormat 报告格式类型
type ReportFormat string

const (
	// FormatMarkdown Markdown格式
	FormatMarkdown ReportFormat = "markdown"
	// FormatHTML HTML格式
	FormatHTML ReportFormat = "html"
	// FormatPDF PDF格式
	FormatPDF ReportFormat = "pdf"
)

// GenerateReport 生成指定格式的安全报告
// resourceDir 资源目录，用于存储报告和其他生成的文件
func GenerateReport(data types.ReportData, resourceDir string, formats ...ReportFormat) error {
	utils.InfoPrint("正在生成安全报告...")

	// 生成报告文件名
	reportDir := filepath.Join(resourceDir, "reports")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return fmt.Errorf("创建报告目录失败: %v", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	target := data.Metadata["target"]
	scanType := data.Metadata["scan_type"]

	// 清理目标字符串，替换特殊字符
	safeTarget := strings.ReplaceAll(target, ":", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "/", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "\\", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "?", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "*", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "<", "_")
	safeTarget = strings.ReplaceAll(safeTarget, ">", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "|", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "\"", "_")

	baseName := fmt.Sprintf("%s_%s_%s", scanType, safeTarget, timestamp)

	// 如果未指定格式，默认生成HTML格式
	if len(formats) == 0 {
		formats = append(formats, FormatHTML)
	}

	// 生成指定格式的报告
	for _, format := range formats {
		// 首先生成Markdown内容作为基础
		mdContent := generateMarkdownReport(data)

		switch format {
		case FormatMarkdown:
			// 生成Markdown报告
			reportPath := filepath.Join(reportDir, baseName+"_"+string(format)+".md")
			if err := os.WriteFile(reportPath, []byte(mdContent), 0644); err != nil {
				return fmt.Errorf("写入Markdown报告失败: %v", err)
			}
			utils.SuccessPrint("Markdown报告已生成: %s", reportPath)

		case FormatHTML:
			// 生成HTML报告
			reportPath := filepath.Join(reportDir, baseName+"_"+string(format)+"_report.html")
			htmlContent := generateHTMLReport(mdContent)
			if err := os.WriteFile(reportPath, []byte(htmlContent), 0644); err != nil {
				return fmt.Errorf("写入HTML报告失败: %v", err)
			}
			utils.SuccessPrint("HTML报告已生成: %s", reportPath)

		case FormatPDF:
			// 生成PDF报告
			reportPath := filepath.Join(reportDir, baseName+"_"+string(format)+"_report.pdf")

			// 改进的PDF生成逻辑 - 生成可读的文本PDF
			// 使用简单的文本格式避免乱码问题
			pdfContent := generateTextPDFReport(mdContent)

			if err := os.WriteFile(reportPath, []byte(pdfContent), 0644); err != nil {
				return fmt.Errorf("写入PDF报告失败: %v", err)
			}
			utils.SuccessPrint("PDF报告已生成: %s", reportPath)

		default:
			return fmt.Errorf("不支持的报告格式: %s", format)
		}
	}

	return nil
}

// generateHTMLReport 生成HTML格式报告
func generateHTMLReport(markdown string) string {
	// 使用更完善的HTML模板
	htmlTemplate := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2, h3, h4, h5, h6 {
            color: #2c3e50;
            margin-top: 1.5em;
            margin-bottom: 0.5em;
        }
        h1 {
            font-size: 2em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 0.3em;
        }
        h2 {
            font-size: 1.5em;
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 0.2em;
        }
        h3 {
            font-size: 1.2em;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        code {
            background-color: #f0f0f0;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', Courier, monospace;
        }
        pre {
            background-color: #f0f0f0;
            padding: 1em;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
        }
        ul, ol {
            margin: 1em 0;
            padding-left: 2em;
        }
        li {
            margin: 0.5em 0;
        }
        .report-header {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .report-section {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 2em;
            padding-top: 1em;
            border-top: 1px solid #e0e0e0;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .severity-critical {
            color: #e74c3c;
            font-weight: bold;
        }
        .severity-high {
            color: #e67e22;
            font-weight: bold;
        }
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .severity-low {
            color: #3498db;
            font-weight: bold;
        }
        .severity-info {
            color: #2ecc71;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>安全扫描报告</h1>
    </div>
    
    <div class="report-section">
        <!--REPORT_CONTENT-->
    </div>
    
    <div class="footer">
        <p>报告生成时间: <!--REPORT_TIME--></p>
        <p>生成工具: GYscan AI 模块</p>
    </div>
</body>
</html>`

	// 使用现有的markdownToHTML函数转换内容
	htmlContent := markdownToHTML(markdown)
	reportTime := time.Now().Format("2006-01-02 15:04:05")

	// 使用更安全的字符串替换方式，避免%字符导致的问题
	fullHTML := strings.Replace(htmlTemplate, "<!--REPORT_CONTENT-->", htmlContent, 1)
	fullHTML = strings.Replace(fullHTML, "<!--REPORT_TIME-->", reportTime, 1)
	return fullHTML
}

// GenerateReportFromTask 从任务生成报告
func GenerateReportFromTask(task *types.Task, resourceDir string, formats ...ReportFormat) error {
	// 解析任务结果中的AI分析数据
	var findings []types.Finding
	var recommendations []string
	var riskAssessment types.RiskAssessment

	// 如果任务结果包含AI分析数据，尝试解析它
	if task.Results != "" {
		// 尝试解析JSON格式的AI分析结果
		var aiResults struct {
			Findings        []types.Finding      `json:"findings"`
			Recommendations []string             `json:"recommendations"`
			RiskAssessment  types.RiskAssessment `json:"risk_assessment"`
			Summary         string               `json:"summary"`
		}

		if err := json.Unmarshal([]byte(task.Results), &aiResults); err == nil {
			// 成功解析JSON格式
			findings = aiResults.Findings
			recommendations = aiResults.Recommendations
			riskAssessment = aiResults.RiskAssessment
		} else {
			// 如果不是JSON格式，将整个结果作为摘要
			// 并创建基本的发现结果
			if strings.Contains(strings.ToLower(task.Results), "critical") || strings.Contains(strings.ToLower(task.Results), "high") {
				findings = []types.Finding{
					{
						ID:             "auto-generated-1",
						TaskID:         task.ID,
						Type:           "Security",
						Severity:       "High",
						Title:          "AI分析发现安全问题",
						Description:    task.Results,
						Location:       task.Target,
						Evidence:       "AI分析结果",
						Recommendation: "请查看详细分析结果",
						Impact:         "需要进一步调查",
						Confidence:     0.7, // 置信度设为0.7（中等）
						CreatedAt:      time.Now(),
						References:     []string{},
					},
				}
				recommendations = []string{"根据AI分析结果进行进一步调查", "实施相应的安全措施"}
				riskAssessment = types.RiskAssessment{
					OverallRisk:      "Medium",
					RiskScore:        6.0,
					CriticalFindings: 0,
					HighFindings:     1,
					MediumFindings:   0,
					LowFindings:      0,
					Recommendations:  []string{"AI分析发现潜在安全问题"},
				}
			}
		}
	}

	// 将任务数据转换为报告数据
	data := types.ReportData{
		ID:              task.ID,
		TaskID:          task.ID,
		Title:           fmt.Sprintf("安全扫描报告 - %s", task.Target),
		Summary:         task.Results,
		Findings:        findings,
		RiskAssessment:  riskAssessment,
		Recommendations: recommendations,
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     task.Target,
			"scan_type":  task.Type,
			"start_time": task.StartTime.Format("2006-01-02 15:04:05"),
			"end_time":   task.EndTime.Format("2006-01-02 15:04:05"),
			"duration":   task.Duration,
			"logs":       task.Results, // 使用Results作为日志内容
		},
	}

	return GenerateReport(data, resourceDir, formats...)
}

// generateMarkdownReport 生成Markdown报告内容
func generateMarkdownReport(data types.ReportData) string {
	// 改进的Markdown模板，更美观，更完整
	md := `# %s

## 目标信息
| 项目 | 值 |
|------|-----|
| 目标 | %s |
| 扫描类型 | %s |
| 开始时间 | %s |
| 结束时间 | %s |
| 持续时间 | %s |

## 摘要
%s

## 发现结果
%s

## 建议措施
%s

## 执行日志
%s

---

**报告生成时间**: %s  
**生成工具**: GYscan AI 模块
`

	// 替换发现结果
	findingsMD := ""
	for i, finding := range data.Findings {
		findingsMD += fmt.Sprintf("### 发现结果 %d\n", i+1)
		findingsMD += fmt.Sprintf("**类型**: %s\n", cleanString(finding.Type))
		findingsMD += fmt.Sprintf("**严重程度**: %s\n", cleanString(finding.Severity))
		findingsMD += fmt.Sprintf("**标题**: %s\n", cleanString(finding.Title))
		findingsMD += fmt.Sprintf("**位置**: %s\n", cleanString(finding.Location))
		findingsMD += "**描述**:\n"

		// 处理嵌套的Markdown内容，确保正确的格式
		description := cleanString(finding.Description)
		// 移除可能的顶层标题，避免嵌套冲突
		description = strings.ReplaceAll(description, "# ", "")
		description = strings.ReplaceAll(description, "## ", "")
		description = strings.ReplaceAll(description, "### ", "")
		findingsMD += fmt.Sprintf("%s\n", description)

		findingsMD += "**建议**:\n"
		recommendation := cleanString(finding.Recommendation)
		recommendation = strings.ReplaceAll(recommendation, "# ", "")
		recommendation = strings.ReplaceAll(recommendation, "## ", "")
		recommendation = strings.ReplaceAll(recommendation, "### ", "")
		findingsMD += fmt.Sprintf("%s\n", recommendation)
		findingsMD += "\n"
	}

	if findingsMD == "" {
		findingsMD = "未发现任何问题。\n"
	}

	// 替换建议措施
	recommendationsMD := ""
	for i, rec := range data.Recommendations {
		cleanedRec := cleanString(rec)
		cleanedRec = strings.ReplaceAll(cleanedRec, "# ", "")
		cleanedRec = strings.ReplaceAll(cleanedRec, "## ", "")
		if cleanedRec != "" {
			recommendationsMD += fmt.Sprintf("%d. %s\n", i+1, cleanedRec)
		}
	}

	if recommendationsMD == "" {
		recommendationsMD = "1. 无特殊建议。\n"
	}

	// 替换日志
	logMD := "```\n"
	// 从Metadata中获取日志信息，如果存在的话
	if logs, exists := data.Metadata["logs"]; exists && logs != "" {
		cleanedLog := cleanString(logs)
		if cleanedLog != "" {
			logMD += cleanedLog + "\n\n"
		}
	}
	logMD += "```\n"

	if logMD == "```\n```\n" {
		logMD = "```\n无日志记录。\n```\n"
	}

	// 清理摘要中的无效格式
	cleanedSummary := cleanString(data.Summary)
	cleanedSummary = strings.ReplaceAll(cleanedSummary, "# ", "")
	cleanedSummary = strings.ReplaceAll(cleanedSummary, "## ", "")

	// 使用fmt.Sprintf直接替换所有变量，避免复杂的字符串替换
	target := data.Metadata["target"]
	scanType := data.Metadata["scan_type"]
	startTime := data.Metadata["start_time"]
	endTime := data.Metadata["end_time"]
	duration := data.Metadata["duration"]

	reportContent := fmt.Sprintf(md,
		data.Title,                               // 报告标题
		target,                                   // 目标
		scanType,                                 // 扫描类型
		startTime,                                // 开始时间
		endTime,                                  // 结束时间
		duration,                                 // 持续时间
		cleanedSummary,                           // 摘要
		findingsMD,                               // 发现结果
		recommendationsMD,                        // 建议措施
		logMD,                                    // 执行日志
		time.Now().Format("2006-01-02 15:04:05"), // 报告生成时间
	)

	return reportContent
}

// toLower 转换为小写
func toLower(s string) string {
	return strings.ToLower(s)
}

// cleanString 清理字符串中的乱码字符和无效Markdown格式
func cleanString(s string) string {
	// 移除不可打印字符，只保留ASCII可打印字符
	var result strings.Builder
	for _, r := range s {
		// 只保留ASCII可打印字符 (32-126) 和换行符、制表符
		if (r >= 32 && r <= 126) || r == '\n' || r == '\t' {
			result.WriteRune(r)
		}
	}

	cleaned := result.String()

	// 修复URL格式
	cleaned = strings.ReplaceAll(cleaned, "https//", "https://")
	cleaned = strings.ReplaceAll(cleaned, "http//", "http://")

	// 修复表格格式
	cleaned = strings.ReplaceAll(cleaned, "MAC Address::", "MAC Address:")
	cleaned = strings.ReplaceAll(cleaned, "Service Info OS", "Service Info: OS")

	// 移除无效的Markdown格式
	cleaned = strings.ReplaceAll(cleaned, "===  ===", "")
	cleaned = strings.ReplaceAll(cleaned, "---  ", "")
	cleaned = strings.ReplaceAll(cleaned, "?D1???", "")
	cleaned = strings.ReplaceAll(cleaned, "****", "")
	cleaned = strings.ReplaceAll(cleaned, ":  ", ": ")
	cleaned = strings.ReplaceAll(cleaned, "::", ":")
	cleaned = strings.ReplaceAll(cleaned, "---\n ", "")
	cleaned = strings.ReplaceAll(cleaned, "\n ", "\n")

	// 修复标题格式
	cleaned = strings.ReplaceAll(cleaned, "#1) ", "## 1) ")
	cleaned = strings.ReplaceAll(cleaned, "#2) ", "## 2) ")
	cleaned = strings.ReplaceAll(cleaned, "#3) ", "## 3) ")
	cleaned = strings.ReplaceAll(cleaned, "#4) ", "## 4) ")
	cleaned = strings.ReplaceAll(cleaned, "#FTP", "## FTP")
	cleaned = strings.ReplaceAll(cleaned, "#SSH", "## SSH")
	cleaned = strings.ReplaceAll(cleaned, "#MySQL", "## MySQL")
	cleaned = strings.ReplaceAll(cleaned, "### ", "### ")
	cleaned = strings.ReplaceAll(cleaned, "## ", "## ")

	// 添加标题后的空行
	cleaned = strings.ReplaceAll(cleaned, "## 1) ", "## 1)\n\n")
	cleaned = strings.ReplaceAll(cleaned, "## 2) ", "## 2)\n\n")
	cleaned = strings.ReplaceAll(cleaned, "## 3) ", "## 3)\n\n")
	cleaned = strings.ReplaceAll(cleaned, "## 4) ", "## 4)\n\n")
	cleaned = strings.ReplaceAll(cleaned, "## FTP", "## FTP\n")
	cleaned = strings.ReplaceAll(cleaned, "## SSH", "## SSH\n")
	cleaned = strings.ReplaceAll(cleaned, "## MySQL", "## MySQL\n")

	// 修复列表格式
	cleaned = strings.ReplaceAll(cleaned, "- \n", "- ")
	cleaned = strings.ReplaceAll(cleaned, "1. \n", "1. ")

	// 修复代码块格式
	cleaned = strings.ReplaceAll(cleaned, "\n\t```", "\n```")
	cleaned = strings.ReplaceAll(cleaned, "```\t", "```")

	// 修复重复的换行
	for strings.Contains(cleaned, "\n\n\n") {
		cleaned = strings.ReplaceAll(cleaned, "\n\n\n", "\n\n")
	}

	// 移除空行开头
	cleaned = strings.TrimLeft(cleaned, "\n")

	return cleaned
}

// generateTextPDFReport 生成可读的文本PDF报告
func generateTextPDFReport(markdown string) string {
	// 将Markdown转换为纯文本，避免PDF乱码问题
	textContent := markdownToPlainText(markdown)

	// 生成简单的文本格式PDF，使用纯ASCII字符避免编码问题
	pdfContent := `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length ` + fmt.Sprintf("%d", len(textContent)+200) + ` >> stream
BT
/F1 12 Tf
50 800 Td
(Security Scan Report) Tj
0 -20 Td
/F1 10 Tf
` + textContent + `
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000052 00000 n 
0000000095 00000 n 
0000000182 00000 n 
0000000338 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
475
%%EOF`

	return pdfContent
}

// markdownToPlainText 将Markdown转换为纯文本
func markdownToPlainText(markdown string) string {
	// 移除Markdown格式标记
	text := strings.ReplaceAll(markdown, "#", "")
	text = strings.ReplaceAll(text, "**", "")
	text = strings.ReplaceAll(text, "*", "")
	text = strings.ReplaceAll(text, "`", "")
	text = strings.ReplaceAll(text, "```", "")
	text = strings.ReplaceAll(text, "-", "• ")
	text = strings.ReplaceAll(text, "|", " ")

	// 移除多余的空行
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}

	// 确保文本编码正确
	text = cleanString(text)

	return text
}

// markdownToHTML 简单的Markdown到HTML转换
// 注意：此函数在enhanced_reporter.go中实现，此处直接使用
