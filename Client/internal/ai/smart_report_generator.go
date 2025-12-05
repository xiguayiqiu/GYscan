package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// SmartReportGenerator 智能报告生成器
type SmartReportGenerator struct {
	aiClient  *AIClient
	logger    *PenetrationLogger
	reportDir string
	maxTokens int
	chunkSize int
}

// NewSmartReportGenerator 创建新的智能报告生成器
func NewSmartReportGenerator(aiClient *AIClient, logger *PenetrationLogger, reportDir string) *SmartReportGenerator {
	return &SmartReportGenerator{
		aiClient:  aiClient,
		logger:    logger,
		reportDir: reportDir,
		maxTokens: 8000, // 默认最大token数
		chunkSize: 2000, // 分块大小
	}
}

// GenerateSmartReport 生成智能报告
func (g *SmartReportGenerator) GenerateSmartReport(target string, formats ...ReportFormat) error {
	utils.InfoPrint("开始生成智能渗透测试报告...")

	// 确保报告目录存在
	if err := os.MkdirAll(g.reportDir, 0755); err != nil {
		return fmt.Errorf("创建报告目录失败: %v", err)
	}

	// 生成报告文件名
	timestamp := time.Now().Format("20060102-150405")
	safeTarget := sanitizeFilename(target)
	baseName := fmt.Sprintf("smart_report_%s_%s", safeTarget, timestamp)

	// 如果未指定格式，默认生成HTML格式
	if len(formats) == 0 {
		formats = []ReportFormat{FormatHTML}
	}

	// 生成AI总结的报告内容
	aiReport, err := g.generateAIReport()
	if err != nil {
		utils.WarningPrint("AI报告生成失败: %v，将使用基础报告", err)
		aiReport = g.generateBasicReport()
	}

	// 构建报告数据
	reportData := g.buildReportData(target, aiReport)

	// 生成指定格式的报告
	for _, format := range formats {
		switch format {
		case FormatMarkdown:
			if err := g.generateMarkdownReport(reportData, baseName); err != nil {
				return err
			}
		case FormatHTML:
			if err := g.generateHTMLReport(reportData, baseName); err != nil {
				return err
			}
		case FormatPDF:
			if err := g.generatePDFReport(reportData, baseName); err != nil {
				return err
			}
		default:
			return fmt.Errorf("不支持的报告格式: %s", format)
		}
	}

	utils.SuccessPrint("智能渗透测试报告生成完成")
	return nil
}

// generateAIReport 使用AI生成报告内容
func (g *SmartReportGenerator) generateAIReport() (string, error) {
	if g.aiClient == nil {
		return "", fmt.Errorf("AI客户端未初始化")
	}

	// 获取日志内容（智能处理大token内容）
	logContent := g.logger.GetLogContentForAI(g.maxTokens)

	// 如果日志内容太大，使用分块处理
	if len(logContent) > g.chunkSize {
		return g.generateChunkedAIReport(logContent)
	}

	// 直接生成报告
	return g.generateSingleAIReport(logContent)
}

// generateChunkedAIReport 分块处理大日志内容
func (g *SmartReportGenerator) generateChunkedAIReport(logContent string) (string, error) {
	utils.InfoPrint("检测到大日志内容，使用分块处理...")

	// 分块处理日志内容
	chunks := g.splitLogContent(logContent)
	utils.InfoPrint("日志内容已分为 %d 个块", len(chunks))

	// 生成摘要和关键信息
	summary, err := g.generateSummaryAnalysis(chunks)
	if err != nil {
		return "", fmt.Errorf("生成摘要分析失败: %v", err)
	}

	// 分析每个块并生成详细报告
	detailedAnalysis, err := g.analyzeChunks(chunks)
	if err != nil {
		return "", fmt.Errorf("分析日志块失败: %v", err)
	}

	// 合并分析结果
	finalReport := g.mergeAnalysisResults(summary, detailedAnalysis)

	return finalReport, nil
}

// generateSingleAIReport 生成单个AI报告
func (g *SmartReportGenerator) generateSingleAIReport(logContent string) (string, error) {
	systemPrompt := `你是一名专业的渗透测试工程师。请根据提供的渗透测试日志生成专业的渗透测试报告。

报告必须严格按照以下格式和内容要求生成：

## 渗透测试报告

### 执行摘要
- 测试目标：{目标URL}
- 测试时间：{具体时间}
- 测试范围：简要描述测试范围
- 总体风险评估：{风险等级}
- 主要发现：简要列出关键安全问题

### 测试过程概述
- 信息收集阶段：描述信息收集方法和结果
- 漏洞扫描阶段：描述漏洞扫描过程
- 渗透测试执行：描述具体的测试步骤
- 结果验证：验证发现的问题

### 发现的安全问题
按以下格式列出每个安全问题：
1. **问题标题**
   - **问题描述**：详细描述问题
   - **风险等级**：高/中/低
   - **影响范围**：描述影响范围
   - **修复建议**：提供具体的修复建议

### 风险评估
- 总体风险等级评估
- 各风险点的详细评估
- 风险优先级排序

### 修复建议
- 按优先级列出修复建议
- 提供具体的实施步骤
- 建议的时间框架

### 技术细节
- 使用的工具和技术
- 测试环境信息
- 其他技术相关信息

重要要求：
1. 不要包含任何示例内容或占位符
2. 所有内容必须基于实际日志信息
3. 使用专业的技术语言
4. 确保报告结构清晰、逻辑严谨`

	userContent := fmt.Sprintf(`目标: %s

渗透测试日志内容:
%s

请生成专业的渗透测试报告。`, g.logger.target, logContent)

	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: userContent,
		},
	}

	report, err := g.aiClient.Chat(messages)
	if err != nil {
		return "", fmt.Errorf("AI生成报告失败: %v", err)
	}

	return report, nil
}

// generateSummaryAnalysis 生成摘要分析
func (g *SmartReportGenerator) generateSummaryAnalysis(chunks []string) (string, error) {
	systemPrompt := `你是一名渗透测试分析师。请根据提供的日志摘要生成执行摘要。

重点关注：
- 测试的整体过程
- 主要发现的问题
- 关键的成功和失败
- 总体风险评估`

	// 使用第一个和最后一个块生成摘要
	summaryContent := fmt.Sprintf("日志摘要（共%d个块）:\n\n第一个块内容:\n%s\n\n最后一个块内容:\n%s",
		len(chunks), chunks[0], chunks[len(chunks)-1])

	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: summaryContent,
		},
	}

	summary, err := g.aiClient.Chat(messages)
	if err != nil {
		return "", fmt.Errorf("生成摘要分析失败: %v", err)
	}

	return summary, nil
}

// analyzeChunks 分析日志块
func (g *SmartReportGenerator) analyzeChunks(chunks []string) (string, error) {
	var analysisResults []string

	for i, chunk := range chunks {
		utils.InfoPrint("分析日志块 %d/%d", i+1, len(chunks))

		systemPrompt := `你正在分析渗透测试日志的一个片段。请专注于：
- 这个片段中的关键活动
- 发现的潜在安全问题
- 工具执行的结果
- 任何错误或异常`

		userContent := fmt.Sprintf(`日志片段 %d/%d:
%s

请分析这个日志片段。`, i+1, len(chunks), chunk)

		messages := []Message{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: userContent,
			},
		}

		analysis, err := g.aiClient.Chat(messages)
		if err != nil {
			utils.WarningPrint("分析块 %d 失败: %v", i+1, err)
			continue
		}

		analysisResults = append(analysisResults, fmt.Sprintf("=== 块 %d 分析结果 ===\n%s\n", i+1, analysis))
	}

	return strings.Join(analysisResults, "\n"), nil
}

// mergeAnalysisResults 合并分析结果
func (g *SmartReportGenerator) mergeAnalysisResults(summary, detailedAnalysis string) string {
	systemPrompt := `你是一名专业的报告编写者。请将摘要和详细分析合并成一个完整的渗透测试报告。

报告必须严格按照以下格式和内容要求生成：

## 渗透测试报告

### 执行摘要
- 测试目标：{目标URL}
- 测试时间：{具体时间}
- 测试范围：简要描述测试范围
- 总体风险评估：{风险等级}
- 主要发现：简要列出关键安全问题

### 测试过程概述
- 信息收集阶段：描述信息收集方法和结果
- 漏洞扫描阶段：描述漏洞扫描过程
- 渗透测试执行：描述具体的测试步骤
- 结果验证：验证发现的问题

### 发现的安全问题
按以下格式列出每个安全问题：
1. **问题标题**
   - **问题描述**：详细描述问题
   - **风险等级**：高/中/低
   - **影响范围**：描述影响范围
   - **修复建议**：提供具体的修复建议

### 风险评估
- 总体风险等级评估
- 各风险点的详细评估
- 风险优先级排序

### 修复建议
- 按优先级列出修复建议
- 提供具体的实施步骤
- 建议的时间框架

### 技术细节
- 使用的工具和技术
- 测试环境信息
- 其他技术相关信息

重要要求：
1. 不要包含任何示例内容或占位符
2. 所有内容必须基于实际摘要和分析信息
3. 使用专业的技术语言
4. 确保报告结构清晰、逻辑严谨`

	userContent := fmt.Sprintf(`执行摘要:
%s

详细分析:
%s

请合并这些内容，生成完整的渗透测试报告。`, summary, detailedAnalysis)

	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: userContent,
		},
	}

	finalReport, err := g.aiClient.Chat(messages)
	if err != nil {
		utils.WarningPrint("合并分析结果失败: %v", err)
		return fmt.Sprintf("执行摘要:\n%s\n\n详细分析:\n%s", summary, detailedAnalysis)
	}

	return finalReport
}

// splitLogContent 分割日志内容
func (g *SmartReportGenerator) splitLogContent(content string) []string {
	lines := strings.Split(content, "\n")
	var chunks []string
	var currentChunk strings.Builder

	for _, line := range lines {
		// 如果当前块加上新行会超过分块大小，保存当前块
		if currentChunk.Len()+len(line) > g.chunkSize && currentChunk.Len() > 0 {
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
		}

		currentChunk.WriteString(line)
		currentChunk.WriteString("\n")
	}

	// 添加最后一个块
	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	return chunks
}

// generateBasicReport 生成基础报告
func (g *SmartReportGenerator) generateBasicReport() string {
	logSummary := g.logger.GetLogSummary()

	report := fmt.Sprintf(`智能渗透测试报告
目标: %s
生成时间: %s

%s

=== 报告摘要 ===
此报告基于渗透测试日志自动生成。由于日志内容较大，使用了智能摘要技术。

=== 建议 ===
1. 查看完整的日志文件获取详细信息
2. 根据日志中的发现进行进一步调查
3. 实施相应的安全措施`,
		g.logger.target,
		time.Now().Format("2006-01-02 15:04:05"),
		logSummary)

	return report
}

// buildReportData 构建报告数据
func (g *SmartReportGenerator) buildReportData(target, aiReport string) types.ReportData {
	// 从日志中提取发现的问题
	findings := g.extractFindingsFromLogs()

	return types.ReportData{
		ID:              fmt.Sprintf("smart_report_%s", time.Now().Format("20060102150405")),
		TaskID:          "smart_penetration_test",
		Title:           "智能渗透测试报告",
		Summary:         aiReport,
		Findings:        findings,
		RiskAssessment:  types.RiskAssessment{},
		Recommendations: g.generateRecommendations(findings),
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     target,
			"scan_type":  "smart_exp",
			"start_time": time.Now().Format("2006-01-02 15:04:05"),
			"end_time":   time.Now().Format("2006-01-02 15:04:05"),
			"duration":   "智能分析完成",
			"logs":       aiReport,
		},
	}
}

// extractFindingsFromLogs 从日志中提取发现的问题
func (g *SmartReportGenerator) extractFindingsFromLogs() []types.Finding {
	var findings []types.Finding
	entries := g.logger.GetLogEntries()

	// 从日志条目中提取关键信息
	for _, entry := range entries {
		if entry.Error != "" {
			// 错误信息可能表示安全问题
			finding := types.Finding{
				Type:           "执行错误",
				Severity:       "Medium",
				Title:          fmt.Sprintf("工具执行错误: %s", entry.Tool),
				Description:    entry.Error,
				Location:       g.logger.target,
				Recommendation: "检查工具配置和网络连接",
			}
			findings = append(findings, finding)
		}

		// 检测到潜在的安全问题关键词
		if containsSecurityKeywords(entry.Description + entry.Output) {
			finding := types.Finding{
				Type:           "潜在安全问题",
				Severity:       "High",
				Title:          "检测到潜在安全问题",
				Description:    entry.Description,
				Location:       g.logger.target,
				Recommendation: "需要进一步调查确认",
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// generateRecommendations 生成建议措施
func (g *SmartReportGenerator) generateRecommendations(findings []types.Finding) []string {
	recommendations := []string{
		"定期进行安全扫描和渗透测试",
		"及时更新系统和应用程序补丁",
		"加强访问控制和认证机制",
		"建立完善的安全监控体系",
	}

	// 基于发现的问题添加具体建议
	if len(findings) > 0 {
		recommendations = append(recommendations,
			"根据本次测试发现的问题，制定具体的修复计划")
	}

	return recommendations
}

// 报告生成方法（与现有报告系统兼容）
func (g *SmartReportGenerator) generateMarkdownReport(data types.ReportData, baseName string) error {
	reportPath := filepath.Join(g.reportDir, baseName+"_smart.md")

	// 生成增强的Markdown内容
	mdContent := g.generateEnhancedMarkdown(data)

	if err := os.WriteFile(reportPath, []byte(mdContent), 0644); err != nil {
		return fmt.Errorf("写入Markdown报告失败: %v", err)
	}

	utils.SuccessPrint("智能Markdown报告已生成: %s", reportPath)
	return nil
}

func (g *SmartReportGenerator) generateHTMLReport(data types.ReportData, baseName string) error {
	reportPath := filepath.Join(g.reportDir, baseName+"_smart.html")

	// 生成增强的HTML报告，包含详细日志展示
	htmlContent := g.generateEnhancedHTMLReport(data)

	if err := os.WriteFile(reportPath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("写入HTML报告失败: %v", err)
	}

	utils.SuccessPrint("智能HTML报告已生成: %s", reportPath)
	return nil
}

// generateEnhancedHTMLReport 生成增强的HTML报告，包含详细过程展示
func (g *SmartReportGenerator) generateEnhancedHTMLReport(data types.ReportData) string {
	var html strings.Builder

	// HTML头部
	html.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>智能渗透测试报告 - ` + data.Title + `</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007acc; margin: 0; }
        .header .meta { color: #666; font-size: 14px; margin-top: 10px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #007acc; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; line-height: 1.6; }
        .findings-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .findings-table th, .findings-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .findings-table th { background-color: #007acc; color: white; }
        .severity-high { background-color: #ffebee; color: #c62828; }
        .severity-medium { background-color: #fff3e0; color: #ef6c00; }
        .severity-low { background-color: #e8f5e8; color: #2e7d32; }
        .log-section { margin-top: 20px; }
        .log-toggle { background: #007acc; color: white; border: none; padding: 10px 15px; border-radius: 5px; cursor: pointer; margin-bottom: 10px; }
        .log-content { display: none; background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
        .log-entry { margin-bottom: 10px; padding: 8px; border-left: 3px solid #007acc; background: #f0f8ff; }
        .log-time { color: #666; font-size: 12px; }
        .log-tool { font-weight: bold; color: #007acc; }
        .log-error { border-left-color: #ff4444; background: #ffeaea; }
        .recommendations { background: #e8f5e8; padding: 15px; border-radius: 5px; }
        .recommendations li { margin-bottom: 5px; }
        .footer { text-align: center; margin-top: 40px; color: #666; font-size: 12px; }
        .phase-section { margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .phase-title { font-weight: bold; color: #007acc; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>` + data.Title + `</h1>
            <div class="meta">
                目标: ` + data.Metadata["target"] + ` | 生成时间: ` + data.CreatedAt.Format("2006-01-02 15:04:05") + ` | 报告ID: ` + data.ID + `
            </div>
        </div>`)

	// 执行摘要
	html.WriteString(`
        <div class="section">
            <h2>执行摘要</h2>
            <div class="summary">` + data.Summary + `</div>
        </div>`)

	// 渗透阶段概述
	html.WriteString(`
        <div class="section">
            <h2>渗透测试阶段</h2>`)

	// 获取日志条目并按阶段分组
	entries := g.logger.GetLogEntries()
	phaseEntries := make(map[string][]LogEntry)
	for _, entry := range entries {
		phaseEntries[string(entry.Phase)] = append(phaseEntries[string(entry.Phase)], entry)
	}

	// 显示每个阶段
	for phase, phaseEntries := range phaseEntries {
		html.WriteString(`
            <div class="phase-section">
                <div class="phase-title">` + phase + `</div>`)

		// 显示该阶段的前3个条目，其余可展开查看
		for i, entry := range phaseEntries {
			if i < 3 {
				entryClass := "log-entry"
				if entry.Error != "" {
					entryClass += " log-error"
				}

				html.WriteString(`
                <div class="` + entryClass + `">
                    <div class="log-time">` + entry.Timestamp.Format("15:04:05") + `</div>
                    <div class="log-tool">` + entry.Tool + `</div>
                    <div>` + entry.Description + `</div>`)

				if entry.Error != "" {
					html.WriteString(`
                    <div style="color: #ff4444;">错误: ` + entry.Error + `</div>`)
				}

				if entry.Output != "" && len(entry.Output) < 200 {
					html.WriteString(`
                    <div style="font-size: 12px; color: #666;">输出: ` + entry.Output + `</div>`)
				}

				html.WriteString(`
                </div>`)
			}
		}

		// 如果还有更多条目，添加展开按钮
		if len(phaseEntries) > 3 {
			html.WriteString(`
                <button class="log-toggle" onclick="toggleLogs('` + phase + `')">显示全部 ` + strconv.Itoa(len(phaseEntries)-3) + ` 个条目</button>
                <div id="` + phase + `" class="log-content">`)

			for i, entry := range phaseEntries {
				if i >= 3 {
					entryClass := "log-entry"
					if entry.Error != "" {
						entryClass += " log-error"
					}

					html.WriteString(`
                    <div class="` + entryClass + `">
                        <div class="log-time">` + entry.Timestamp.Format("15:04:05") + `</div>
                        <div class="log-tool">` + entry.Tool + `</div>
                        <div>` + entry.Description + `</div>`)

					if entry.Error != "" {
						html.WriteString(`
                        <div style="color: #ff4444;">错误: ` + entry.Error + `</div>`)
					}

					if entry.Output != "" {
						html.WriteString(`
                        <div style="font-size: 12px; color: #666;">输出: ` + entry.Output + `</div>`)
					}

					html.WriteString(`
                    </div>`)
				}
			}

			html.WriteString(`
                </div>`)
		}

		html.WriteString(`
            </div>`)
	}

	// 发现的安全问题
	html.WriteString(`
        <div class="section">
            <h2>发现的安全问题</h2>`)

	if len(data.Findings) == 0 {
		html.WriteString(`
            <p>未发现明确的安全问题。</p>`)
	} else {
		html.WriteString(`
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>问题</th>
                        <th>类型</th>
                        <th>严重程度</th>
                        <th>描述</th>
                        <th>建议</th>
                    </tr>
                </thead>
                <tbody>`)

		for _, finding := range data.Findings {
			severityClass := ""
			switch finding.Severity {
			case "High":
				severityClass = "severity-high"
			case "Medium":
				severityClass = "severity-medium"
			case "Low":
				severityClass = "severity-low"
			}

			html.WriteString(`
                    <tr>
                        <td>` + finding.Title + `</td>
                        <td>` + finding.Type + `</td>
                        <td class="` + severityClass + `">` + finding.Severity + `</td>
                        <td>` + finding.Description + `</td>
                        <td>` + finding.Recommendation + `</td>
                    </tr>`)
		}

		html.WriteString(`
                </tbody>
            </table>`)
	}

	html.WriteString(`
        </div>`)

	// 修复建议
	html.WriteString(`
        <div class="section">
            <h2>修复建议</h2>
            <div class="recommendations">
                <ol>`)

	for _, recommendation := range data.Recommendations {
		html.WriteString(`
                    <li>` + recommendation + `</li>`)
	}

	html.WriteString(`
                </ol>
            </div>
        </div>`)

	// 完整日志展示（可展开）
	html.WriteString(`
        <div class="section">
            <h2>完整渗透过程日志</h2>
            <button class="log-toggle" onclick="toggleLogs('fullLogs')">展开查看完整日志</button>
            <div id="fullLogs" class="log-content">`)

	for _, entry := range entries {
		entryClass := "log-entry"
		if entry.Error != "" {
			entryClass += " log-error"
		}

		html.WriteString(`
                <div class="` + entryClass + `">
                    <div class="log-time">` + entry.Timestamp.Format("2006-01-02 15:04:05") + `</div>
                    <div class="log-tool">` + entry.Tool + `</div>
                    <div>` + entry.Description + `</div>`)

		if entry.Error != "" {
			html.WriteString(`
                    <div style="color: #ff4444;">错误: ` + entry.Error + `</div>`)
		}

		if entry.Output != "" {
			html.WriteString(`
                    <div style="font-size: 12px; color: #666;">输出: ` + entry.Output + `</div>`)
		}

		html.WriteString(`
                </div>`)
	}

	html.WriteString(`
            </div>
        </div>`)

	// 技术细节和脚注
	html.WriteString(`
        <div class="section">
            <h2>技术细节</h2>
            <p>此报告基于智能渗透测试系统生成，结合了AI分析和传统安全工具的结果。系统记录了从开始到结束的所有渗透过程，并通过AI进行智能总结。</p>
        </div>
        
        <div class="footer">
            报告生成系统: GYscan 智能渗透测试平台 | 生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `
        </div>
    </div>
    
    <script>
        function toggleLogs(id) {
            var element = document.getElementById(id);
            var button = element.previousElementSibling;
            if (element.style.display === "block") {
                element.style.display = "none";
                button.textContent = button.textContent.replace("收起", "展开");
            } else {
                element.style.display = "block";
                button.textContent = button.textContent.replace("展开", "收起");
            }
        }
    </script>
</body>
</html>`)

	return html.String()
}

func (g *SmartReportGenerator) generatePDFReport(data types.ReportData, baseName string) error {
	// PDF生成逻辑（简化实现）
	utils.InfoPrint("PDF报告生成功能待实现，将生成HTML报告替代")
	return g.generateHTMLReport(data, baseName)
}

// generateEnhancedMarkdown 生成增强的Markdown内容
func (g *SmartReportGenerator) generateEnhancedMarkdown(data types.ReportData) string {
	var md strings.Builder

	md.WriteString(fmt.Sprintf("# %s\n\n", data.Title))
	md.WriteString(fmt.Sprintf("**目标**: %s\n", data.Metadata["target"]))
	md.WriteString(fmt.Sprintf("**生成时间**: %s\n", data.CreatedAt.Format("2006-01-02 15:04:05")))
	md.WriteString(fmt.Sprintf("**报告ID**: %s\n\n", data.ID))

	md.WriteString("## 执行摘要\n\n")
	md.WriteString(data.Summary)
	md.WriteString("\n\n")

	md.WriteString("## 发现的安全问题\n\n")
	if len(data.Findings) == 0 {
		md.WriteString("未发现明确的安全问题。\n\n")
	} else {
		for i, finding := range data.Findings {
			md.WriteString(fmt.Sprintf("### 问题 %d: %s\n", i+1, finding.Title))
			md.WriteString(fmt.Sprintf("- **类型**: %s\n", finding.Type))
			md.WriteString(fmt.Sprintf("- **严重程度**: %s\n", finding.Severity))
			md.WriteString(fmt.Sprintf("- **描述**: %s\n", finding.Description))
			md.WriteString(fmt.Sprintf("- **建议**: %s\n\n", finding.Recommendation))
		}
	}

	md.WriteString("## 修复建议\n\n")
	for i, recommendation := range data.Recommendations {
		md.WriteString(fmt.Sprintf("%d. %s\n", i+1, recommendation))
	}

	md.WriteString("\n## 技术细节\n\n")
	md.WriteString("此报告基于智能渗透测试系统生成，结合了AI分析和传统安全工具的结果。")

	return md.String()
}

// 辅助函数
func containsSecurityKeywords(text string) bool {
	keywords := []string{
		"漏洞", "vulnerability", "安全", "security",
		"攻击", "attack", "注入", "injection",
		"跨站", "xss", "sql", "命令注入",
		"权限提升", "privilege escalation",
		"敏感信息", "sensitive information",
		"配置错误", "misconfiguration",
	}

	lowerText := strings.ToLower(text)
	for _, keyword := range keywords {
		if strings.Contains(lowerText, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}
