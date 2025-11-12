package lynis

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
)

// ReportGenerator 报告生成器
type ReportGenerator struct {
	result *AuditResult
}

// NewReportGenerator 创建新的报告生成器
func NewReportGenerator(result *AuditResult) *ReportGenerator {
	return &ReportGenerator{
		result: result,
	}
}

// GenerateReport 生成安全审计报告
func (rg *ReportGenerator) GenerateReport(format string, outputPath string) error {
	switch strings.ToLower(format) {
	case "html":
		return rg.generateHTMLReport(outputPath)
	case "json":
		return rg.generateJSONReport(outputPath)
	case "text":
		fallthrough
	default:
		return rg.generateTextReport(outputPath)
	}
}

// generateHTMLReport 生成HTML格式报告
func (rg *ReportGenerator) generateHTMLReport(outputPath string) error {
	const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>系统安全审计报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background: #e8f4fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .test-item { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .passed { border-left: 5px solid #28a745; }
        .failed { border-left: 5px solid #dc3545; }
        .warning { border-left: 5px solid #ffc107; }
        .skipped { border-left: 5px solid #6c757d; }
        .critical { background-color: #f8d7da; }
        .high { background-color: #fff3cd; }
        .medium { background-color: #d1ecf1; }
        .low { background-color: #d4edda; }
        .info { background-color: #e2e3e5; }
        .severity-badge { padding: 2px 6px; border-radius: 3px; font-size: 12px; color: white; }
        .critical-badge { background-color: #dc3545; }
        .high-badge { background-color: #fd7e14; }
        .medium-badge { background-color: #ffc107; color: black; }
        .low-badge { background-color: #28a745; }
        .info-badge { background-color: #6c757d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>系统安全审计报告</h1>
        <p><strong>生成时间:</strong> {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
        <p><strong>扫描目标:</strong> {{.SystemInfo.Hostname}}</p>
        <p><strong>扫描耗时:</strong> {{.ScanDuration}}</p>
    </div>

    <div class="summary">
        <h2>审计摘要</h2>
        <p><strong>总测试数:</strong> {{.Summary.TotalTests}}</p>
        <p><strong>通过:</strong> {{.Summary.PassedTests}} | 
           <strong>失败:</strong> {{.Summary.FailedTests}} | 
           <strong>警告:</strong> {{.Summary.WarningTests}} | 
           <strong>跳过:</strong> {{.Summary.SkippedTests}}</p>
        <p><strong>严重级别分布:</strong>
            <span class="severity-badge critical-badge">严重: {{.Summary.CriticalFindings}}</span>
            <span class="severity-badge high-badge">高危: {{.Summary.HighFindings}}</span>
            <span class="severity-badge medium-badge">中危: {{.Summary.MediumFindings}}</span>
            <span class="severity-badge low-badge">低危: {{.Summary.LowFindings}}</span>
            <span class="severity-badge info-badge">信息: {{.Summary.InfoFindings}}</span>
        </p>
    </div>

    <div class="system-info">
        <h2>系统信息</h2>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr><td><strong>主机名</strong></td><td>{{.SystemInfo.Hostname}}</td></tr>
            <tr><td><strong>操作系统</strong></td><td>{{.SystemInfo.OS}}</td></tr>
            <tr><td><strong>内核版本</strong></td><td>{{.SystemInfo.KernelVersion}}</td></tr>
            <tr><td><strong>架构</strong></td><td>{{.SystemInfo.Architecture}}</td></tr>
            <tr><td><strong>运行时间</strong></td><td>{{.SystemInfo.Uptime}}</td></tr>
            <tr><td><strong>CPU核心数</strong></td><td>{{.SystemInfo.CPUCount}}</td></tr>
            <tr><td><strong>内存总量</strong></td><td>{{.SystemInfo.MemoryTotal}}</td></tr>
            <tr><td><strong>磁盘使用</strong></td><td>{{.SystemInfo.DiskUsage}}</td></tr>
        </table>
    </div>

    <div class="test-results">
        <h2>安全测试结果</h2>
        {{range .Tests}}
        <div class="test-item {{.Status}}">
            <h3>{{.ID}} - {{.Description}}</h3>
            <p><strong>分类:</strong> {{.Category}} | 
               <strong>状态:</strong> <span class="severity-badge {{.Severity}}-badge">{{.Status}}</span> |
               <strong>严重级别:</strong> <span class="severity-badge {{.Severity}}-badge">{{.Severity}}</span>
            </p>
            {{if .Details}}
            <div class="details">
                <h4>详细信息:</h4>
                <ul>
                {{range $key, $value := .Details}}
                    <li><strong>{{$key}}:</strong> {{$value}}</li>
                {{end}}
                </ul>
            </div>
            {{end}}
        </div>
        {{end}}
    </div>

    {{if .Findings}}
    <div class="security-findings">
        <h2>安全发现</h2>
        {{range .Findings}}
        <div class="finding {{.Severity}}">
            <h3>{{.ID}} - {{.Description}}</h3>
            <p><strong>严重级别:</strong> <span class="severity-badge {{.Severity}}-badge">{{.Severity}}</span></p>
            <p><strong>建议:</strong> {{.Recommendation}}</p>
            {{if .Evidence}}<p><strong>证据:</strong> {{.Evidence}}</p>{{end}}
        </div>
        {{end}}
    </div>
    {{end}}
</body>
</html>`

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %v", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建HTML报告文件失败: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, rg.result); err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	return nil
}

// generateJSONReport 生成JSON格式报告
func (rg *ReportGenerator) generateJSONReport(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建JSON报告文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(rg.result); err != nil {
		return fmt.Errorf("生成JSON报告失败: %v", err)
	}

	return nil
}

// generateTextReport 生成文本格式报告
func (rg *ReportGenerator) generateTextReport(outputPath string) error {
	var report strings.Builder
	
	// 报告头部
	report.WriteString("系统安全审计报告\n")
	report.WriteString("==================\n\n")
	report.WriteString(fmt.Sprintf("生成时间: %s\n", rg.result.Timestamp.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("扫描目标: %s\n", rg.result.SystemInfo.Hostname))
	report.WriteString(fmt.Sprintf("扫描耗时: %s\n\n", rg.result.ScanDuration))

	// 审计摘要
	report.WriteString("审计摘要\n")
	report.WriteString("--------\n")
	report.WriteString(fmt.Sprintf("总测试数: %d\n", rg.result.Summary.TotalTests))
	report.WriteString(fmt.Sprintf("通过: %d | 失败: %d | 警告: %d | 跳过: %d\n", 
		rg.result.Summary.PassedTests, rg.result.Summary.FailedTests, 
		rg.result.Summary.WarningTests, rg.result.Summary.SkippedTests))
	report.WriteString(fmt.Sprintf("严重级别分布: 严重:%d 高危:%d 中危:%d 低危:%d 信息:%d\n\n",
		rg.result.Summary.CriticalFindings, rg.result.Summary.HighFindings,
		rg.result.Summary.MediumFindings, rg.result.Summary.LowFindings,
		rg.result.Summary.InfoFindings))

	// 系统信息
	report.WriteString("系统信息\n")
	report.WriteString("--------\n")
	report.WriteString(fmt.Sprintf("主机名: %s\n", rg.result.SystemInfo.Hostname))
	report.WriteString(fmt.Sprintf("操作系统: %s\n", rg.result.SystemInfo.OS))
	report.WriteString(fmt.Sprintf("内核版本: %s\n", rg.result.SystemInfo.KernelVersion))
	report.WriteString(fmt.Sprintf("架构: %s\n", rg.result.SystemInfo.Architecture))
	report.WriteString(fmt.Sprintf("运行时间: %s\n", rg.result.SystemInfo.Uptime))
	report.WriteString(fmt.Sprintf("CPU核心数: %d\n", rg.result.SystemInfo.CPUCount))
	report.WriteString(fmt.Sprintf("内存总量: %s\n", rg.result.SystemInfo.MemoryTotal))
	report.WriteString(fmt.Sprintf("磁盘使用: %s\n\n", rg.result.SystemInfo.DiskUsage))

	// 安全测试结果
	report.WriteString("安全测试结果\n")
	report.WriteString("------------\n")
	for _, test := range rg.result.Tests {
		report.WriteString(fmt.Sprintf("测试ID: %s\n", test.ID))
		report.WriteString(fmt.Sprintf("描述: %s\n", test.Description))
		report.WriteString(fmt.Sprintf("分类: %s | 状态: %s | 严重级别: %s\n", 
			test.Category, test.Status, test.Severity))
		
		if len(test.Details) > 0 {
			report.WriteString("详细信息:\n")
			for key, value := range test.Details {
				report.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
			}
		}
		report.WriteString("\n")
	}

	// 安全发现
	if len(rg.result.Findings) > 0 {
		report.WriteString("安全发现\n")
		report.WriteString("--------\n")
		for _, finding := range rg.result.Findings {
			report.WriteString(fmt.Sprintf("发现ID: %s\n", finding.ID))
			report.WriteString(fmt.Sprintf("描述: %s\n", finding.Description))
			report.WriteString(fmt.Sprintf("严重级别: %s\n", finding.Severity))
			report.WriteString(fmt.Sprintf("建议: %s\n", finding.Recommendation))
			if finding.Evidence != "" {
				report.WriteString(fmt.Sprintf("证据: %s\n", finding.Evidence))
			}
			report.WriteString("\n")
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建文本报告文件失败: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(report.String())
	if err != nil {
		return fmt.Errorf("写入文本报告失败: %v", err)
	}

	return nil
}

// PrintSummary 打印审计摘要
func (rg *ReportGenerator) PrintSummary() {
	summary := rg.result.Summary
	
	fmt.Println("=== 安全审计摘要 ===")
	fmt.Printf("总测试数: %d\n", summary.TotalTests)
	fmt.Printf("通过: %d | 失败: %d | 警告: %d | 跳过: %d\n", 
		summary.PassedTests, summary.FailedTests, summary.WarningTests, summary.SkippedTests)
	fmt.Printf("严重级别分布: 严重:%d 高危:%d 中危:%d 低危:%d 信息:%d\n",
		summary.CriticalFindings, summary.HighFindings,
		summary.MediumFindings, summary.LowFindings, summary.InfoFindings)
	fmt.Printf("扫描耗时: %s\n", rg.result.ScanDuration)
}