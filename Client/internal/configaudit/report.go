package configaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

type ReportGenerator struct {
	outputFormat string
	verbose      bool
	colors       bool
	showDetails  bool
}

func NewReportGenerator(format string, verbose bool) *ReportGenerator {
	return &ReportGenerator{
		outputFormat: format,
		verbose:      verbose,
		colors:       true,
		showDetails:  true,
	}
}

func (rg *ReportGenerator) SetColorsEnabled(enabled bool) {
	rg.colors = enabled
}

func (rg *ReportGenerator) SetShowDetails(show bool) {
	rg.showDetails = show
}

func (rg *ReportGenerator) Generate(report *AuditReport, outputFile string) error {
	switch strings.ToLower(rg.outputFormat) {
	case "json":
		return rg.generateJSON(report, outputFile)
	case "html":
		return rg.generateHTML(report, outputFile)
	default:
		return rg.generateText(report, outputFile)
	}
}

func (rg *ReportGenerator) generateJSON(report *AuditReport, outputFile string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}

	fmt.Println(string(data))
	return nil
}

func (rg *ReportGenerator) generateHTML(report *AuditReport, outputFile string) error {
	html := rg.buildHTMLReport(report)

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(html), 0644)
	}

	fmt.Println(html)
	return nil
}

func (rg *ReportGenerator) buildHTMLReport(report *AuditReport) string {
	riskClass := "risk-low"
	if report.Summary.RiskLevel == RiskLevelCritical {
		riskClass = "risk-critical"
	} else if report.Summary.RiskLevel == RiskLevelHigh {
		riskClass = "risk-high"
	} else if report.Summary.RiskLevel == RiskLevelMedium {
		riskClass = "risk-medium"
	}

	passedPercent := float64(report.Summary.PassedChecks) / float64(report.Summary.TotalChecks) * 100
	failedPercent := float64(report.Summary.FailedChecks) / float64(report.Summary.TotalChecks) * 100

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>配置审计报告 - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card.pass { background: #e8f5e9; border: 2px solid #4CAF50; }
        .summary-card.fail { background: #ffebee; border: 2px solid #f44336; }
        .summary-card.warning { background: #fff3e0; border: 2px solid #ff9800; }
        .summary-card.info { background: #e3f2fd; border: 2px solid #2196f3; }
        .score { font-size: 48px; font-weight: bold; color: %s; }
        .risk-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; color: white; }
        .risk-critical { background: #d32f2f; }
        .risk-high { background: #f57c00; }
        .risk-medium { background: #fbc02d; color: #333; }
        .risk-low { background: #388e3c; }
        .check-item { margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #ddd; }
        .check-item.pass { background: #e8f5e9; border-left-color: #4CAF50; }
        .check-item.fail { background: #ffebee; border-left-color: #f44336; }
        .check-item.warning { background: #fff3e0; border-left-color: #ff9800; }
        .check-title { font-weight: bold; margin-bottom: 5px; }
        .check-details { color: #666; font-size: 14px; }
        .config-info { background: #f5f5f5; padding: 10px; border-radius: 5px; margin: 10px 0; font-family: monospace; font-size: 13px; }
        .config-info strong { color: #2196f3; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; font-weight: bold; }
        tr:hover { background: #f9f9f9; }
        .evidence-section { background: #fff8e1; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #ffc107; }
        .evidence-section pre { white-space: pre-wrap; margin: 0; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>配置审计报告</h1>
        <p><strong>目标:</strong> %s</p>
        <p><strong>生成时间:</strong> %s</p>
        <p><strong>审计类别:</strong> %s</p>
        <p><strong>执行时间:</strong> %.2f 秒</p>
        
        <h2>审计摘要</h2>
        <div class="summary">
            <div class="summary-card pass">
                <h3>通过</h3>
                <div class="score" style="color: #4CAF50;">%d</div>
                <p>%.1f%%</p>
            </div>
            <div class="summary-card fail">
                <h3>失败</h3>
                <div class="score" style="color: #f44336;">%d</div>
                <p>%.1f%%</p>
            </div>
            <div class="summary-card warning">
                <h3>警告</h3>
                <div class="score" style="color: #ff9800;">%d</div>
            </div>
        </div>
        
        <p><strong>整体评分:</strong> %.1f/100 <span class="risk-badge %s">%s</span></p>
        <p><strong>合规率:</strong> %.1f%%</p>
        
        <h2>详细审计结果</h2>
        <table>
            <tr>
                <th>检查ID</th>
                <th>检查名称</th>
                <th>状态</th>
                <th>风险等级</th>
                <th>详情</th>
                <th>配置信息</th>
                <th>实际值</th>
                <th>期望值</th>
            </tr>
`, report.Target, rg.getRiskColor(report.Summary.RiskLevel),
		report.Target, report.Timestamp, report.Category,
		report.Duration, report.Summary.PassedChecks, passedPercent,
		report.Summary.FailedChecks, failedPercent, report.Summary.WarningChecks,
		report.Summary.OverallScore, riskClass, report.Summary.RiskLevel,
		report.Summary.ComplianceRate)

	for _, result := range report.Results {
		statusClass := "pass"
		if result.Status == CheckStatusFail {
			statusClass = "fail"
		} else if result.Status == CheckStatusWarning {
			statusClass = "warning"
		}

		actualValue := ""
		if result.ActualValue != nil {
			actualValue = fmt.Sprintf("%v", result.ActualValue)
		}
		expectedValue := ""
		if result.ExpectedValue != nil {
			expectedValue = fmt.Sprintf("%v", result.ExpectedValue)
		}

		configInfo := ""
		if result.ConfigFile != "" || result.ConfigKey != "" || result.RawValue != "" {
			configInfo = fmt.Sprintf("<div class='config-info'><strong>配置文件:</strong> %s<br><strong>配置项:</strong> %s<br><strong>当前值:</strong> %s</div>",
				result.ConfigFile, result.ConfigKey, result.RawValue)
		}

		html += fmt.Sprintf(`            <tr class="%s">
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="risk-badge %s">%s</span></td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
            </tr>
`, statusClass, result.CheckID, result.CheckID, result.Status,
			rg.getRiskClass(result.RiskLevel), result.RiskLevel,
			result.Details, configInfo, actualValue, expectedValue)
	}

	html += `        </table>
        
        <h2>配置证据详情</h2>
`
	for _, result := range report.Results {
		if result.Evidence != "" {
			html += fmt.Sprintf(`
        <div class="check-item %s">
            <div class="check-title">[%s] %s</div>
            <div class="evidence-section">
                <pre>%s</pre>
            </div>
        </div>
`, rg.getResultClass(result.Status), result.CheckID, result.Details, result.Evidence)
		}
	}

	html += `
        <h2>整改建议</h2>
        <ul>
`
	for _, remediation := range report.RemediationPlan {
		html += fmt.Sprintf(`            <li><strong>%s</strong> (优先级: %d)
                <p>%s</p>
                <p><strong>建议操作:</strong> %s</p>
                <p><strong>预估时间:</strong> %s</p>
            </li>
`, remediation.Title, remediation.Priority, remediation.Description,
			strings.Join(remediation.Steps, ", "), remediation.EstimatedTime)
	}

	html += `        </ul>
    </div>
</body>
</html>`
	return html
}

func (rg *ReportGenerator) getResultClass(status CheckStatus) string {
	switch status {
	case CheckStatusPass:
		return "pass"
	case CheckStatusFail:
		return "fail"
	case CheckStatusWarning:
		return "warning"
	default:
		return ""
	}
}

func (rg *ReportGenerator) getRiskColor(level RiskLevel) string {
	switch level {
	case RiskLevelCritical:
		return "#d32f2f"
	case RiskLevelHigh:
		return "#f57c00"
	case RiskLevelMedium:
		return "#fbc02d"
	default:
		return "#388e3c"
	}
}

func (rg *ReportGenerator) getRiskClass(level RiskLevel) string {
	switch level {
	case RiskLevelCritical:
		return "risk-critical"
	case RiskLevelHigh:
		return "risk-high"
	case RiskLevelMedium:
		return "risk-medium"
	default:
		return "risk-low"
	}
}

func (rg *ReportGenerator) generateText(report *AuditReport, outputFile string) error {
	var output strings.Builder

	rg.printTextReport(&output, report)

	content := output.String()

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(content), 0644)
	}

	fmt.Println(content)
	return nil
}

func (rg *ReportGenerator) printTextReport(output *strings.Builder, report *AuditReport) {
	border := strings.Repeat("=", 70)
	border2 := strings.Repeat("-", 70)

	output.WriteString("\n")
	output.WriteString(border + "\n")
	output.WriteString("                    配置审计报告\n")
	output.WriteString(border + "\n\n")

	output.WriteString(fmt.Sprintf("审计目标: %s\n", report.Target))
	output.WriteString(fmt.Sprintf("审计时间: %s\n", report.Timestamp))
	output.WriteString(fmt.Sprintf("审计类别: %s\n", report.Category))
	output.WriteString(fmt.Sprintf("执行耗时: %.2f 秒\n\n", report.Duration))

	output.WriteString(border2 + "\n")
	output.WriteString("                         审计摘要\n")
	output.WriteString(border2 + "\n")
	output.WriteString(fmt.Sprintf("  总检查项:    %d\n", report.Summary.TotalChecks))
	output.WriteString(fmt.Sprintf("  通过:        %d\n", report.Summary.PassedChecks))
	output.WriteString(fmt.Sprintf("  失败:        %d\n", report.Summary.FailedChecks))
	output.WriteString(fmt.Sprintf("  警告:        %d\n", report.Summary.WarningChecks))
	output.WriteString(fmt.Sprintf("  错误:        %d\n", report.Summary.ErrorChecks))
	output.WriteString("\n")
	output.WriteString(fmt.Sprintf("  整体评分:    %.1f/100\n", report.Summary.OverallScore))
	output.WriteString(fmt.Sprintf("  风险等级:    %s\n", report.Summary.RiskLevel))
	output.WriteString(fmt.Sprintf("  合规率:      %.1f%%\n", report.Summary.ComplianceRate))
	output.WriteString("\n")

	if rg.colors {
		rg.printColoredResults(output, report)
	} else {
		rg.printResults(output, report)
	}

	if len(report.RemediationPlan) > 0 {
		output.WriteString(border2 + "\n")
		output.WriteString("                       整改建议\n")
		output.WriteString(border2 + "\n\n")

		for i, remediation := range report.RemediationPlan {
			output.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, remediation.Title))
			output.WriteString(fmt.Sprintf("      优先级: %d\n", remediation.Priority))
			output.WriteString(fmt.Sprintf("      描述:   %s\n", remediation.Description))
			if len(remediation.Steps) > 0 {
				output.WriteString(fmt.Sprintf("      操作:   %s\n", strings.Join(remediation.Steps, ", ")))
			}
			output.WriteString(fmt.Sprintf("      预估时间: %s\n", remediation.EstimatedTime))
			output.WriteString(fmt.Sprintf("      风险:    %s\n", remediation.Risk))
			output.WriteString("\n")
		}
	}

	output.WriteString(border + "\n")
	output.WriteString("                      报告结束\n")
	output.WriteString(border + "\n")
}

func (rg *ReportGenerator) printColoredResults(output *strings.Builder, report *AuditReport) {
	border2 := strings.Repeat("-", 70)
	output.WriteString(border2 + "\n")
	output.WriteString("                       详细审计结果\n")
	output.WriteString(border2 + "\n")

	allResults := append(append(report.FailedChecks, report.Warnings...), report.PassedChecks...)

	if len(allResults) == 0 {
		output.WriteString("\n  未发现任何审计结果\n\n")
		return
	}

	for _, result := range allResults {
		statusIcon := "✓"
		if result.Status == CheckStatusFail {
			statusIcon = "✗"
		} else if result.Status == CheckStatusWarning {
			statusIcon = "⚠"
		} else if result.Status == CheckStatusError {
			statusIcon = "!"
		}

		output.WriteString("\n")
		output.WriteString(fmt.Sprintf("  %s [%s]\n", statusIcon, result.CheckID))
		output.WriteString(strings.Repeat("  ", 2) + border2 + "\n")

		output.WriteString(fmt.Sprintf("  %-15s %s\n", "状态:", result.Status))
		output.WriteString(fmt.Sprintf("  %-15s %s\n", "风险等级:", result.RiskLevel))
		output.WriteString(fmt.Sprintf("  %-15s %s\n", "描述:", result.Details))

		if result.ConfigFile != "" || result.ConfigKey != "" || result.RawValue != "" {
			output.WriteString("\n")
			output.WriteString("  [配置证据]\n")
			output.WriteString(strings.Repeat("  ", 2) + border2 + "\n")
			if result.ConfigFile != "" {
				output.WriteString(fmt.Sprintf("  %-15s %s\n", "配置文件:", result.ConfigFile))
			}
			if result.ConfigKey != "" {
				output.WriteString(fmt.Sprintf("  %-15s %s\n", "配置项:", result.ConfigKey))
			}
			if result.RawValue != "" {
				output.WriteString(fmt.Sprintf("  %-15s %s\n", "当前值:", result.RawValue))
			}
		}

		if result.ActualValue != nil {
			actualStr := fmt.Sprintf("%v", result.ActualValue)
			if len(actualStr) > 60 {
				actualStr = actualStr[:60] + "..."
			}
			output.WriteString(fmt.Sprintf("  %-15s %s\n", "实际值:", actualStr))
		}

		if result.ExpectedValue != nil {
			expectedStr := fmt.Sprintf("%v", result.ExpectedValue)
			if len(expectedStr) > 60 {
				expectedStr = expectedStr[:60] + "..."
			}
			output.WriteString(fmt.Sprintf("  %-15s %s\n", "期望值:", expectedStr))
		}

		if result.Evidence != "" {
			evidence := result.Evidence
			lines := strings.Split(evidence, "\n")
			output.WriteString("\n")
			output.WriteString("  [详细证据]\n")
			output.WriteString(strings.Repeat("  ", 2) + border2 + "\n")
			for _, line := range lines {
				output.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}

		output.WriteString("\n")
	}

	output.WriteString("\n")
}

func (rg *ReportGenerator) printResults(output *strings.Builder, report *AuditReport) {
	border2 := strings.Repeat("-", 70)
	output.WriteString(border2 + "\n")
	output.WriteString("                       详细审计结果\n")
	output.WriteString(border2 + "\n")

	allResults := report.Results
	if len(allResults) == 0 {
		output.WriteString("\n  未发现任何审计结果\n\n")
		return
	}

	for _, result := range allResults {
		statusIcon := "[PASS]"
		if result.Status == CheckStatusFail {
			statusIcon = "[FAIL]"
		} else if result.Status == CheckStatusWarning {
			statusIcon = "[WARN]"
		} else if result.Status == CheckStatusError {
			statusIcon = "[ERROR]"
		}

		output.WriteString("\n")
		output.WriteString(fmt.Sprintf("  %s [%s]\n", statusIcon, result.CheckID))
		output.WriteString(strings.Repeat("  ", 2) + border2 + "\n")

		output.WriteString(fmt.Sprintf("  状态:     %s\n", result.Status))
		output.WriteString(fmt.Sprintf("  风险等级: %s\n", result.RiskLevel))
		output.WriteString(fmt.Sprintf("  描述:     %s\n", result.Details))

		if result.ConfigFile != "" || result.ConfigKey != "" || result.RawValue != "" {
			output.WriteString("\n")
			output.WriteString("  [配置证据]\n")
			output.WriteString(strings.Repeat("  ", 2) + border2 + "\n")
			if result.ConfigFile != "" {
				output.WriteString(fmt.Sprintf("  配置文件: %s\n", result.ConfigFile))
			}
			if result.ConfigKey != "" {
				output.WriteString(fmt.Sprintf("  配置项:   %s\n", result.ConfigKey))
			}
			if result.RawValue != "" {
				output.WriteString(fmt.Sprintf("  当前值:   %s\n", result.RawValue))
			}
		}

		if result.ActualValue != nil {
			output.WriteString(fmt.Sprintf("  实际值:   %v\n", result.ActualValue))
		}
		if result.ExpectedValue != nil {
			output.WriteString(fmt.Sprintf("  期望值:   %v\n", result.ExpectedValue))
		}
		if result.Evidence != "" {
			lines := strings.Split(result.Evidence, "\n")
			output.WriteString("\n")
			output.WriteString("  [详细证据]\n")
			output.WriteString(strings.Repeat("  ", 2) + border2 + "\n")
			for _, line := range lines {
				output.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}

		output.WriteString("\n")
	}

	output.WriteString("\n")
}

type ReportExporter struct {
	baseDir string
}

func NewReportExporter(baseDir string) *ReportExporter {
	if baseDir == "" {
		baseDir = "./audit_reports"
	}
	return &ReportExporter{baseDir: baseDir}
}

func (re *ReportExporter) Export(report *AuditReport, format string) ([]string, error) {
	os.MkdirAll(re.baseDir, 0755)

	timestamp := time.Now().Format("20060102_150405")
	targetSafe := strings.ReplaceAll(report.Target, ":", "_")
	targetSafe = strings.ReplaceAll(targetSafe, "/", "_")

	var files []string

	for _, f := range strings.Split(format, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			f = "text"
		}

		filename := fmt.Sprintf("%s/%s_%s_%s", re.baseDir, targetSafe, timestamp, f)
		generator := NewReportGenerator(f, false)

		if err := generator.Generate(report, filename); err != nil {
			return files, err
		}

		files = append(files, filename)
	}

	return files, nil
}

func (rg *ReportGenerator) PrintSummary(report *AuditReport) {
	border := strings.Repeat("=", 60)

	fmt.Println("\n" + border)
	color.Cyan("                    配置审计完成")
	fmt.Println(border)

	fmt.Printf("  目标:      %s\n", report.Target)
	fmt.Printf("  类别:      %s\n", report.Category)
	fmt.Printf("  耗时:      %.2f秒\n", report.Duration)

	fmt.Println("\n  检查结果:")
	fmt.Printf("    总计:    %d\n", report.Summary.TotalChecks)
	color.Green("    通过:    %d", report.Summary.PassedChecks)
	color.Red("    失败:    %d", report.Summary.FailedChecks)
	color.Yellow("    警告:    %d", report.Summary.WarningChecks)

	fmt.Println("\n  风险评估:")
	fmt.Printf("    评分:    %.1f/100\n", report.Summary.OverallScore)
	fmt.Printf("    风险:    %s\n", report.Summary.RiskLevel)
	fmt.Printf("    合规率:  %.1f%%\n", report.Summary.ComplianceRate)
	fmt.Println(border)
}

func ExtractCheckID(checkID string) (category string, number string) {
	re := regexp.MustCompile(`^([A-Z]+)-[A-Z]+-(\d+)$`)
	matches := re.FindStringSubmatch(checkID)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}
	return "", ""
}
