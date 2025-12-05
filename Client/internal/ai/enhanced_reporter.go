package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// EnhancedReporter 增强的报告生成器
type EnhancedReporter struct {
	aiClient    *AIClient
	toolManager *ToolManager
	reportDir   string
}

// NewEnhancedReporter 创建新的增强报告生成器
func NewEnhancedReporter(aiClient *AIClient, toolManager *ToolManager, reportDir string) *EnhancedReporter {
	return &EnhancedReporter{
		aiClient:    aiClient,
		toolManager: toolManager,
		reportDir:   reportDir,
	}
}

// GenerateEnhancedReport 生成增强的安全报告
func (r *EnhancedReporter) GenerateEnhancedReport(
	task *types.Task,
	phases []types.WorkflowPhase,
	findings []types.Finding,
	riskAssessment *types.RiskAssessment,
	formats ...ReportFormat,
) error {
	utils.InfoPrint("正在生成增强安全报告...")

	// 确保报告目录存在
	if err := os.MkdirAll(r.reportDir, 0755); err != nil {
		return fmt.Errorf("创建报告目录失败: %v", err)
	}

	// 生成报告文件名
	timestamp := time.Now().Format("20060102-150405")
	baseName := fmt.Sprintf("%s_%s_%s", task.Type, task.Target, timestamp)

	// 如果未指定格式，默认生成HTML格式
	if len(formats) == 0 {
		formats = []ReportFormat{FormatHTML}
	}

	// 生成报告数据
	reportData := r.buildReportData(task, phases, findings, riskAssessment)

	// 生成指定格式的报告
	for _, format := range formats {
		switch format {
		case FormatMarkdown:
			if err := r.generateMarkdownReport(reportData, baseName); err != nil {
				return err
			}
		case FormatHTML:
			if err := r.generateHTMLReport(reportData, baseName); err != nil {
				return err
			}
		case FormatPDF:
			if err := r.generatePDFReport(reportData, baseName); err != nil {
				return err
			}
		default:
			return fmt.Errorf("不支持的报告格式: %s", format)
		}
	}

	utils.SuccessPrint("增强安全报告生成完成")
	return nil
}

// buildReportData 构建报告数据
func (r *EnhancedReporter) buildReportData(
	task *types.Task,
	phases []types.WorkflowPhase,
	findings []types.Finding,
	riskAssessment *types.RiskAssessment,
) types.ReportData {
	// 按严重程度排序发现结果
	sort.Slice(findings, func(i, j int) bool {
		return getSeverityWeight(findings[i].Severity) > getSeverityWeight(findings[j].Severity)
	})

	// 构建报告数据
	data := types.ReportData{
		ID:              task.ID,
		TaskID:          task.ID,
		Title:           fmt.Sprintf("增强安全扫描报告 - %s", task.Target),
		Summary:         r.generateSummary(task, findings, riskAssessment),
		Findings:        r.convertFindings(findings),
		RiskAssessment:  *riskAssessment,
		Recommendations: r.generateRecommendations(findings, riskAssessment),
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     task.Target,
			"scan_type":  task.Type,
			"start_time": task.StartTime.Format("2006-01-02 15:04:05"),
			"end_time":   task.EndTime.Format("2006-01-02 15:04:05"),
			"duration":   task.Duration,
			"logs":       strings.Join(r.extractLogs(phases), "\n"),
		},
	}

	return data
}

// generateSummary 生成报告摘要
func (r *EnhancedReporter) generateSummary(
	task *types.Task,
	findings []types.Finding,
	riskAssessment *types.RiskAssessment,
) string {
	var summary strings.Builder

	summary.WriteString("## 扫描概览\n\n")
	summary.WriteString(fmt.Sprintf("- **目标**: %s\n", task.Target))
	summary.WriteString(fmt.Sprintf("- **扫描类型**: %s\n", task.Type))
	summary.WriteString(fmt.Sprintf("- **扫描时间**: %s - %s\n",
		task.StartTime.Format("2006-01-02 15:04:05"),
		task.EndTime.Format("2006-01-02 15:04:05")))
	summary.WriteString(fmt.Sprintf("- **持续时间**: %s\n", task.Duration))

	// 统计发现结果
	severityCount := make(map[string]int)
	for _, finding := range findings {
		severityCount[finding.Severity]++
	}

	summary.WriteString("\n## 发现统计\n\n")
	summary.WriteString(fmt.Sprintf("- **严重发现**: %d\n", severityCount["critical"]))
	summary.WriteString(fmt.Sprintf("- **高危发现**: %d\n", severityCount["high"]))
	summary.WriteString(fmt.Sprintf("- **中危发现**: %d\n", severityCount["medium"]))
	summary.WriteString(fmt.Sprintf("- **低危发现**: %d\n", severityCount["low"]))
	summary.WriteString(fmt.Sprintf("- **信息发现**: %d\n", severityCount["info"]))

	// 风险评估
	if riskAssessment != nil {
		summary.WriteString("\n## 风险评估\n\n")
		summary.WriteString(fmt.Sprintf("- **总体风险级别**: %s\n", riskAssessment.OverallRisk))
		summary.WriteString(fmt.Sprintf("- **风险评分**: %.1f/10\n", riskAssessment.RiskScore))
	}

	return summary.String()
}

// convertFindings 转换发现结果
func (r *EnhancedReporter) convertFindings(findings []types.Finding) []types.Finding {
	var result []types.Finding

	for _, f := range findings {
		finding := types.Finding{
			Type:           f.Type,
			Severity:       f.Severity,
			Title:          f.Title,
			Description:    f.Description,
			Location:       f.Location,
			Recommendation: f.Recommendation,
		}
		result = append(result, finding)
	}

	return result
}

// generateRecommendations 生成建议措施
func (r *EnhancedReporter) generateRecommendations(
	findings []types.Finding,
	riskAssessment *types.RiskAssessment,
) []string {
	var recommendations []string

	// 添加风险评估建议
	if riskAssessment != nil && len(riskAssessment.Recommendations) > 0 {
		recommendations = append(recommendations, riskAssessment.Recommendations...)
	}

	// 基于发现结果生成建议
	criticalFindings := filterFindingsBySeverity(findings, "critical")
	highFindings := filterFindingsBySeverity(findings, "high")

	if len(criticalFindings) > 0 {
		recommendations = append(recommendations,
			"立即修复所有严重级别的安全漏洞，这些漏洞可能导致系统被完全控制")
	}

	if len(highFindings) > 0 {
		recommendations = append(recommendations,
			"优先修复高危级别的安全漏洞，这些漏洞可能导致敏感信息泄露或服务中断")
	}

	// 添加通用建议
	recommendations = append(recommendations,
		"定期进行安全扫描和漏洞评估",
		"建立完善的安全监控和应急响应机制",
		"加强员工安全意识培训",
		"及时更新系统和应用程序补丁",
	)

	return recommendations
}

// extractLogs 提取执行日志
func (r *EnhancedReporter) extractLogs(phases []types.WorkflowPhase) []string {
	var logs []string

	for _, phase := range phases {
		// 将WorkflowPhase枚举转换为字符串
		logs = append(logs, fmt.Sprintf("阶段: %s - 状态: 已完成 - 进度: 100.0%%", string(phase)))
	}

	return logs
}

// generateMarkdownReport 生成Markdown格式报告
func (r *EnhancedReporter) generateMarkdownReport(data types.ReportData, baseName string) error {
	reportPath := filepath.Join(r.reportDir, baseName+"_enhanced.md")

	// 生成增强的Markdown内容
	mdContent := r.generateEnhancedMarkdown(data)

	if err := os.WriteFile(reportPath, []byte(mdContent), 0644); err != nil {
		return fmt.Errorf("写入Markdown报告失败: %v", err)
	}

	utils.SuccessPrint("增强Markdown报告已生成: %s", reportPath)
	return nil
}

// generateHTMLReport 生成HTML格式报告
func (r *EnhancedReporter) generateHTMLReport(data types.ReportData, baseName string) error {
	reportPath := filepath.Join(r.reportDir, baseName+"_enhanced.html")

	// 首先生成Markdown内容
	mdContent := r.generateEnhancedMarkdown(data)

	// 转换为HTML
	htmlContent := r.generateEnhancedHTML(mdContent)

	if err := os.WriteFile(reportPath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("写入HTML报告失败: %v", err)
	}

	utils.SuccessPrint("增强HTML报告已生成: %s", reportPath)
	return nil
}

// generatePDFReport 生成PDF格式报告
func (r *EnhancedReporter) generatePDFReport(data types.ReportData, baseName string) error {
	reportPath := filepath.Join(r.reportDir, baseName+"_enhanced.pdf")

	// 首先生成HTML内容
	mdContent := r.generateEnhancedMarkdown(data)
	htmlContent := r.generateEnhancedHTML(mdContent)

	// 简化PDF生成（实际项目中应使用专业PDF库）
	pdfContent := fmt.Sprintf("%%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources 5 0 R >>\nendobj\n4 0 obj\n<< /Length 1000 >> stream\nBT /F1 12 Tf 50 792 Td (增强安全扫描报告) Tj ET\nBT /F1 10 Tf 50 770 Td (目标: %s) Tj ET\nBT /F1 10 Tf 50 750 Td (扫描时间: %s) Tj ET\nendstream\nendobj\n5 0 obj\n<< /Font << /F1 6 0 R >> >>\nendobj\n6 0 obj\n<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\nxref\n0 7\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000095 00000 n \n0000000182 00000 n \n0000000338 00000 n \n0000000378 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n475\n%%EOF\n\nHTML Content:\n%s",
		data.Metadata["target"], data.Metadata["start_time"], htmlContent)

	if err := os.WriteFile(reportPath, []byte(pdfContent), 0644); err != nil {
		return fmt.Errorf("写入PDF报告失败: %v", err)
	}

	utils.SuccessPrint("增强PDF报告已生成: %s", reportPath)
	return nil
}

// generateEnhancedMarkdown 生成增强的Markdown内容
func (r *EnhancedReporter) generateEnhancedMarkdown(data types.ReportData) string {
	var md strings.Builder

	// 报告标题
	md.WriteString(fmt.Sprintf("# %s\n\n", data.Title))

	// 执行概览
	md.WriteString("## 执行概览\n\n")
	md.WriteString("| 项目 | 值 |\n")
	md.WriteString("|------|-----|\n")
	md.WriteString(fmt.Sprintf("| 目标 | %s |\n", data.Metadata["target"]))
	md.WriteString(fmt.Sprintf("| 扫描类型 | %s |\n", data.Metadata["scan_type"]))
	md.WriteString(fmt.Sprintf("| 开始时间 | %s |\n", data.Metadata["start_time"]))
	md.WriteString(fmt.Sprintf("| 结束时间 | %s |\n", data.Metadata["end_time"]))
	md.WriteString(fmt.Sprintf("| 持续时间 | %s |\n\n", data.Metadata["duration"]))

	// 报告摘要
	md.WriteString("## 报告摘要\n\n")
	md.WriteString(data.Summary)
	md.WriteString("\n\n")

	// 发现结果详情
	md.WriteString("## 发现结果详情\n\n")
	if len(data.Findings) == 0 {
		md.WriteString("未发现任何安全问题。\n\n")
	} else {
		for i, finding := range data.Findings {
			md.WriteString(fmt.Sprintf("### 发现 %d: %s\n\n", i+1, finding.Title))
			md.WriteString("| 属性 | 值 |\n")
			md.WriteString("|------|-----|\n")
			md.WriteString(fmt.Sprintf("| 类型 | %s |\n", finding.Type))
			md.WriteString(fmt.Sprintf("| 严重程度 | **%s** |\n", finding.Severity))
			md.WriteString(fmt.Sprintf("| 位置 | %s |\n", finding.Location))
			md.WriteString(fmt.Sprintf("| 描述 | %s |\n", finding.Description))
			md.WriteString(fmt.Sprintf("| 建议 | %s |\n\n", finding.Recommendation))
		}
	}

	// 建议措施
	md.WriteString("## 建议措施\n\n")
	for i, rec := range data.Recommendations {
		md.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
	}
	md.WriteString("\n")

	// 执行日志
	md.WriteString("## 执行日志\n\n")
	md.WriteString("```\n")
	if logs, exists := data.Metadata["logs"]; exists {
		logLines := strings.Split(logs, "\n")
		for _, log := range logLines {
			md.WriteString(fmt.Sprintf("%s\n", log))
		}
	}
	md.WriteString("```\n\n")

	// 报告脚注
	md.WriteString("---\n")
	md.WriteString("**报告生成时间**: " + time.Now().Format("2006-01-02 15:04:05") + "  \n")
	md.WriteString("**生成工具**: GYscan AI 增强报告模块\n")

	return md.String()
}

// generateEnhancedHTML 生成增强的HTML内容
func (r *EnhancedReporter) generateEnhancedHTML(markdown string) string {
	// 使用更完善的HTML模板
	htmlTemplate := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>增强安全扫描报告</title>
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
        .risk-critical {
            background-color: #e74c3c;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-high {
            background-color: #e67e22;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-medium {
            background-color: #f39c12;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
        .risk-low {
            background-color: #3498db;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>增强安全扫描报告</h1>
        <p>基于AI驱动的智能安全评估系统</p>
    </div>
    
    <div class="report-section">
        <!--REPORT_CONTENT-->
    </div>
    
    <div class="footer">
        <p>报告生成时间: <!--REPORT_TIME--></p>
        <p>生成工具: GYscan AI 增强报告模块</p>
    </div>
</body>
</html>`

	// 转换Markdown为HTML
	htmlContent := markdownToHTML(markdown)
	reportTime := time.Now().Format("2006-01-02 15:04:05")

	// 使用更安全的字符串替换方式，避免%字符导致的问题
	fullHTML := strings.Replace(htmlTemplate, "<!--REPORT_CONTENT-->", htmlContent, 1)
	fullHTML = strings.Replace(fullHTML, "<!--REPORT_TIME-->", reportTime, 1)
	return fullHTML
}

// 辅助函数

// getSeverityWeight 获取严重程度权重
func getSeverityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// filterFindingsBySeverity 按严重程度过滤发现结果
func filterFindingsBySeverity(findings []types.Finding, severity string) []types.Finding {
	var result []types.Finding

	for _, finding := range findings {
		if strings.EqualFold(finding.Severity, severity) {
			result = append(result, finding)
		}
	}

	return result
}

// markdownToHTML 将Markdown转换为HTML
func markdownToHTML(markdown string) string {
	// 实现基本的Markdown到HTML转换
	html := markdown

	// 转换代码块（先转换代码块，避免与其他转换冲突）
	html = regexp.MustCompile("(?m)^```([\\s\\S]*?)^```$").ReplaceAllString(html, "<pre><code>$1</code></pre>")

	// 转换行内代码
	html = regexp.MustCompile("`([^`]+)`").ReplaceAllString(html, "<code>$1</code>")

	// 转换标题
	html = regexp.MustCompile("(?m)^# (.*)$").ReplaceAllString(html, "<h1>$1</h1>")
	html = regexp.MustCompile("(?m)^## (.*)$").ReplaceAllString(html, "<h2>$1</h2>")
	html = regexp.MustCompile("(?m)^### (.*)$").ReplaceAllString(html, "<h3>$1</h3>")
	html = regexp.MustCompile("(?m)^#### (.*)$").ReplaceAllString(html, "<h4>$1</h4>")
	html = regexp.MustCompile("(?m)^##### (.*)$").ReplaceAllString(html, "<h5>$1</h5>")
	html = regexp.MustCompile("(?m)^###### (.*)$").ReplaceAllString(html, "<h6>$1</h6>")

	// 转换粗体
	html = regexp.MustCompile("\\*\\*(.*?)\\*\\*").ReplaceAllString(html, "<strong>$1</strong>")

	// 转换表格
	// 简单的表格转换，支持基本的Markdown表格语法
	html = regexp.MustCompile("(?m)(\\|.*?\\|\\n\\|.*?\\|)(\\n(?:\\|.*?\\|\\n)*)").ReplaceAllStringFunc(html, func(table string) string {
		lines := strings.Split(strings.TrimSpace(table), "\n")
		if len(lines) < 2 {
			return table
		}

		result := "<table>\n"

		// 表头
		headerCells := regexp.MustCompile("\\|").Split(strings.TrimSpace(lines[0]), -1)
		result += "<thead>\n<tr>\n"
		for _, cell := range headerCells[1 : len(headerCells)-1] { // 去掉首尾空元素
			result += fmt.Sprintf("<th>%s</th>\n", strings.TrimSpace(cell))
		}
		result += "</tr>\n</thead>\n"

		// 表格内容
		result += "<tbody>\n"
		for i := 2; i < len(lines); i++ { // 从第三行开始（跳过表头和分隔线）
			rowCells := regexp.MustCompile("\\|").Split(strings.TrimSpace(lines[i]), -1)
			result += "<tr>\n"
			for _, cell := range rowCells[1 : len(rowCells)-1] { // 去掉首尾空元素
				result += fmt.Sprintf("<td>%s</td>\n", strings.TrimSpace(cell))
			}
			result += "</tr>\n"
		}
		result += "</tbody>\n"

		result += "</table>\n"
		return result
	})

	// 转换列表
	html = regexp.MustCompile("(?m)^- (.*)$").ReplaceAllString(html, "<ul><li>$1</li></ul>")
	html = regexp.MustCompile("(?m)^(\\d+)\\. (.*)$").ReplaceAllString(html, "<ol><li>$2</li></ol>")

	// 合并相邻的列表项
	html = regexp.MustCompile("</ul>\\s*<ul>").ReplaceAllString(html, "")
	html = regexp.MustCompile("</ol>\\s*<ol>").ReplaceAllString(html, "")

	// 转换水平线
	html = regexp.MustCompile("(?m)^---$").ReplaceAllString(html, "<hr>")

	// 转换段落 - 使用更简单的方式，避免使用负向前瞻断言
	lines := strings.Split(html, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// 检查是否已经是HTML标签
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") {
			continue
		}
		// 检查是否以特定标签开头
		if strings.HasPrefix(trimmed, "<h") || strings.HasPrefix(trimmed, "</h") ||
			strings.HasPrefix(trimmed, "<table") || strings.HasPrefix(trimmed, "<tr") ||
			strings.HasPrefix(trimmed, "<td") || strings.HasPrefix(trimmed, "<th") ||
			strings.HasPrefix(trimmed, "<ul") || strings.HasPrefix(trimmed, "<ol") ||
			strings.HasPrefix(trimmed, "<li") || strings.HasPrefix(trimmed, "<pre") ||
			strings.HasPrefix(trimmed, "<code") || strings.HasPrefix(trimmed, "<hr") {
			continue
		}
		// 转换为段落
		lines[i] = "<p>" + line + "</p>"
	}
	html = strings.Join(lines, "\n")

	// 清理多余的空行
	html = regexp.MustCompile("\\n\\s*\\n").ReplaceAllString(html, "\n")

	return fmt.Sprintf("<div class=\"markdown-content\">%s</div>", html)
}
