package ai

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// ProfessionalReportGenerator 专业报告生成器
type ProfessionalReportGenerator struct {
	Target          string
	ReconResults    string
	VulnResults     string
	LateralResults  string
	ReportOutputDir string
	Logger          *PenetrationLogger
}

// ReportData 报告数据结构体（已移至types包）
type ReportData = types.ReportData

// Vulnerability 漏洞信息结构体（已移至types包）
type Vulnerability = types.Finding

// GenerateProfessionalReport 生成专业渗透测试报告
func (prg *ProfessionalReportGenerator) GenerateProfessionalReport() (string, error) {
	utils.InfoPrint("开始生成专业渗透测试报告...")

	// 创建报告目录
	if err := os.MkdirAll(prg.ReportOutputDir, 0755); err != nil {
		return "", fmt.Errorf("创建报告目录失败: %v", err)
	}

	// 生成HTML报告
	htmlReportPath, err := prg.generateHTMLReport()
	if err != nil {
		utils.ErrorPrint("生成HTML报告失败: %v", err)
	} else {
		utils.SuccessPrint("HTML报告已生成: %s", htmlReportPath)
	}

	// 生成JSON报告
	jsonReportPath, err := prg.generateJSONReport()
	if err != nil {
		utils.ErrorPrint("生成JSON报告失败: %v", err)
	} else {
		utils.SuccessPrint("JSON报告已生成: %s", jsonReportPath)
	}

	// 生成Markdown报告
	mdReportPath, err := prg.generateMarkdownReport()
	if err != nil {
		utils.ErrorPrint("生成Markdown报告失败: %v", err)
	} else {
		utils.SuccessPrint("Markdown报告已生成: %s", mdReportPath)
	}

	// 生成执行摘要
	execSummaryPath, err := prg.generateExecutiveSummary()
	if err != nil {
		utils.ErrorPrint("生成执行摘要失败: %v", err)
	} else {
		utils.SuccessPrint("执行摘要已生成: %s", execSummaryPath)
	}

	return fmt.Sprintf("报告生成完成:\n- HTML报告: %s\n- JSON报告: %s\n- Markdown报告: %s\n- 执行摘要: %s",
		htmlReportPath, jsonReportPath, mdReportPath, execSummaryPath), nil
}

// generateHTMLReport 生成HTML格式报告
func (prg *ProfessionalReportGenerator) generateHTMLReport() (string, error) {
	reportPath := filepath.Join(prg.ReportOutputDir, "professional_penetration_report.html")

	// 准备报告数据
	reportData := prg.prepareReportData()

	// HTML模板
	htmlTemplate := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .vulnerability { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #e74c3c; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #f39c12; }
        .medium { border-left-color: #f1c40f; }
        .low { border-left-color: #27ae60; }
        .info { border-left-color: #3498db; }
        .risk-level { font-size: 24px; font-weight: bold; margin: 20px 0; }
        .recommendation { background: #e8f4fd; padding: 10px; margin: 5px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <h2>目标: {{index .Metadata "target"}}</h2>
            <p>扫描时间: {{index .Metadata "scan_date"}} | 持续时间: {{index .Metadata "scan_duration"}}</p>
        </div>

        <div class="section">
            <h2>执行摘要</h2>
            <p>{{.Summary}}</p>
            <div class="risk-level">风险等级: {{.RiskAssessment.OverallRisk}} (评分: {{.RiskAssessment.RiskScore}})</div>
        </div>

        {{if .Findings}}
        <div class="section">
            <h2>发现结果 ({{len .Findings}} 个)</h2>
            {{range .Findings}}
            <div class="vulnerability {{.Severity}}">
                <h3>{{.Title}} (严重程度: {{.Severity}})</h3>
                <p><strong>类型:</strong> {{.Type}}</p>
                <p><strong>位置:</strong> {{.Location}}</p>
                <p><strong>描述:</strong> {{.Description}}</p>
                <p><strong>影响:</strong> {{.Impact}}</p>
                <p><strong>修复建议:</strong> {{.Recommendation}}</p>
                <p><strong>证据:</strong> {{.Evidence}}</p>
                <p><strong>置信度:</strong> {{.Confidence}}</p>
            </div>
            {{end}}
        </div>
        {{end}}

        <div class="section">
            <h2>风险评估</h2>
            <p><strong>总体风险:</strong> {{.RiskAssessment.OverallRisk}}</p>
            <p><strong>风险评分:</strong> {{.RiskAssessment.RiskScore}}</p>
            <p><strong>严重发现:</strong> {{.RiskAssessment.CriticalFindings}} 个</p>
            <p><strong>高危发现:</strong> {{.RiskAssessment.HighFindings}} 个</p>
            <p><strong>中危发现:</strong> {{.RiskAssessment.MediumFindings}} 个</p>
            <p><strong>低危发现:</strong> {{.RiskAssessment.LowFindings}} 个</p>
        </div>

        <div class="section">
            <h2>修复建议</h2>
            {{range .Recommendations}}
            <div class="recommendation">{{.}}</div>
            {{end}}
        </div>

        <div class="section">
            <h2>技术细节</h2>
            <pre>{{index .Metadata "technical_details"}}</pre>
        </div>
    </div>
</body>
</html>`

	// 解析并执行模板
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("解析HTML模板失败: %v", err)
	}

	file, err := os.Create(reportPath)
	if err != nil {
		return "", fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, reportData); err != nil {
		return "", fmt.Errorf("执行HTML模板失败: %v", err)
	}

	return reportPath, nil
}

// generateJSONReport 生成JSON格式报告
func (prg *ProfessionalReportGenerator) generateJSONReport() (string, error) {
	reportPath := filepath.Join(prg.ReportOutputDir, "professional_penetration_report.json")

	reportData := prg.prepareReportData()

	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化JSON失败: %v", err)
	}

	if err := os.WriteFile(reportPath, jsonData, 0644); err != nil {
		return "", fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return reportPath, nil
}

// generateMarkdownReport 生成Markdown格式报告
func (prg *ProfessionalReportGenerator) generateMarkdownReport() (string, error) {
	reportPath := filepath.Join(prg.ReportOutputDir, "professional_penetration_report.md")

	reportData := prg.prepareReportData()

	var mdBuilder strings.Builder
	mdBuilder.WriteString(fmt.Sprintf("# %s\n\n", reportData.Title))
	mdBuilder.WriteString(fmt.Sprintf("**目标:** %s\n\n", reportData.Metadata["target"]))
	mdBuilder.WriteString(fmt.Sprintf("**扫描时间:** %s\n\n", reportData.Metadata["scan_date"]))
	mdBuilder.WriteString(fmt.Sprintf("**持续时间:** %s\n\n", reportData.Metadata["scan_duration"]))
	mdBuilder.WriteString(fmt.Sprintf("**风险等级:** %s (评分: %.1f)\n\n", reportData.RiskAssessment.OverallRisk, reportData.RiskAssessment.RiskScore))

	mdBuilder.WriteString("## 执行摘要\n\n")
	mdBuilder.WriteString(reportData.Summary + "\n\n")

	mdBuilder.WriteString("## 风险评估\n\n")
	mdBuilder.WriteString(fmt.Sprintf("- **总体风险:** %s\n", reportData.RiskAssessment.OverallRisk))
	mdBuilder.WriteString(fmt.Sprintf("- **风险评分:** %.1f\n", reportData.RiskAssessment.RiskScore))
	mdBuilder.WriteString(fmt.Sprintf("- **严重发现:** %d 个\n", reportData.RiskAssessment.CriticalFindings))
	mdBuilder.WriteString(fmt.Sprintf("- **高危发现:** %d 个\n", reportData.RiskAssessment.HighFindings))
	mdBuilder.WriteString(fmt.Sprintf("- **中危发现:** %d 个\n", reportData.RiskAssessment.MediumFindings))
	mdBuilder.WriteString(fmt.Sprintf("- **低危发现:** %d 个\n\n", reportData.RiskAssessment.LowFindings))

	if len(reportData.Findings) > 0 {
		mdBuilder.WriteString("## 发现结果\n\n")
		for _, finding := range reportData.Findings {
			mdBuilder.WriteString(fmt.Sprintf("### %s (严重程度: %s)\n\n", finding.Title, finding.Severity))
			mdBuilder.WriteString(fmt.Sprintf("**类型:** %s\n\n", finding.Type))
			mdBuilder.WriteString(fmt.Sprintf("**位置:** %s\n\n", finding.Location))
			mdBuilder.WriteString(fmt.Sprintf("**描述:** %s\n\n", finding.Description))
			mdBuilder.WriteString(fmt.Sprintf("**影响:** %s\n\n", finding.Impact))
			mdBuilder.WriteString(fmt.Sprintf("**修复建议:** %s\n\n", finding.Recommendation))
			mdBuilder.WriteString(fmt.Sprintf("**证据:** %s\n\n", finding.Evidence))
			mdBuilder.WriteString(fmt.Sprintf("**置信度:** %.2f\n\n", finding.Confidence))
		}
	}

	mdBuilder.WriteString("## 修复建议\n\n")
	for _, rec := range reportData.Recommendations {
		mdBuilder.WriteString(fmt.Sprintf("- %s\n", rec))
	}
	mdBuilder.WriteString("\n")

	mdBuilder.WriteString("## 技术细节\n\n")
	mdBuilder.WriteString("```\n")
	mdBuilder.WriteString(reportData.Metadata["technical_details"])
	mdBuilder.WriteString("\n```\n")

	if err := os.WriteFile(reportPath, []byte(mdBuilder.String()), 0644); err != nil {
		return "", fmt.Errorf("写入Markdown文件失败: %v", err)
	}

	return reportPath, nil
}

// generateExecutiveSummary 生成执行摘要
func (prg *ProfessionalReportGenerator) generateExecutiveSummary() (string, error) {
	summaryPath := filepath.Join(prg.ReportOutputDir, "executive_summary.txt")

	reportData := prg.prepareReportData()

	var summaryBuilder strings.Builder
	summaryBuilder.WriteString("=== 渗透测试执行摘要 ===\n\n")
	summaryBuilder.WriteString(fmt.Sprintf("目标: %s\n", reportData.Metadata["target"]))
	summaryBuilder.WriteString(fmt.Sprintf("扫描时间: %s\n", reportData.Metadata["scan_date"]))
	summaryBuilder.WriteString(fmt.Sprintf("风险等级: %s (评分: %.1f)\n\n", reportData.RiskAssessment.OverallRisk, reportData.RiskAssessment.RiskScore))
	summaryBuilder.WriteString("主要发现:\n")

	summaryBuilder.WriteString(fmt.Sprintf("- 严重发现: %d 个\n", reportData.RiskAssessment.CriticalFindings))
	summaryBuilder.WriteString(fmt.Sprintf("- 高危发现: %d 个\n", reportData.RiskAssessment.HighFindings))
	summaryBuilder.WriteString(fmt.Sprintf("- 中危发现: %d 个\n", reportData.RiskAssessment.MediumFindings))
	summaryBuilder.WriteString(fmt.Sprintf("- 低危发现: %d 个\n\n", reportData.RiskAssessment.LowFindings))

	summaryBuilder.WriteString("关键建议:\n")
	for i, rec := range reportData.Recommendations {
		if i >= 5 { // 只显示前5条关键建议
			break
		}
		summaryBuilder.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
	}

	if err := os.WriteFile(summaryPath, []byte(summaryBuilder.String()), 0644); err != nil {
		return "", fmt.Errorf("写入执行摘要文件失败: %v", err)
	}

	return summaryPath, nil
}

// generateDetailedReport 生成详细技术报告
func (prg *ProfessionalReportGenerator) generateDetailedReport() (string, error) {
	detailedPath := filepath.Join(prg.ReportOutputDir, "detailed_report.txt")

	reportData := prg.prepareReportData()

	var detailedBuilder strings.Builder
	detailedBuilder.WriteString("=== 详细技术报告 ===\n\n")
	detailedBuilder.WriteString(fmt.Sprintf("目标系统: %s\n", reportData.Metadata["target"]))
	detailedBuilder.WriteString(fmt.Sprintf("扫描时间: %s\n", reportData.Metadata["scan_date"]))
	detailedBuilder.WriteString(fmt.Sprintf("总体风险等级: %s (评分: %.1f)\n\n", reportData.RiskAssessment.OverallRisk, reportData.RiskAssessment.RiskScore))

	detailedBuilder.WriteString("发现详情:\n\n")

	// 按严重程度分组显示
	severityGroups := map[string][]types.Finding{
		"严重": {},
		"高危": {},
		"中危": {},
		"低危": {},
	}

	for _, finding := range reportData.Findings {
		severityGroups[finding.Severity] = append(severityGroups[finding.Severity], finding)
	}

	// 严重发现
	if len(severityGroups["严重"]) > 0 {
		detailedBuilder.WriteString("严重发现:\n")
		for _, finding := range severityGroups["严重"] {
			detailedBuilder.WriteString(fmt.Sprintf("- %s: %s (位置: %s)\n", finding.Type, finding.Description, finding.Location))
		}
		detailedBuilder.WriteString("\n")
	}

	// 高危发现
	if len(severityGroups["高危"]) > 0 {
		detailedBuilder.WriteString("高危发现:\n")
		for _, finding := range severityGroups["高危"] {
			detailedBuilder.WriteString(fmt.Sprintf("- %s: %s (位置: %s)\n", finding.Type, finding.Description, finding.Location))
		}
		detailedBuilder.WriteString("\n")
	}

	// 中危发现
	if len(severityGroups["中危"]) > 0 {
		detailedBuilder.WriteString("中危发现:\n")
		for _, finding := range severityGroups["中危"] {
			detailedBuilder.WriteString(fmt.Sprintf("- %s: %s (位置: %s)\n", finding.Type, finding.Description, finding.Location))
		}
		detailedBuilder.WriteString("\n")
	}

	// 低危发现
	if len(severityGroups["低危"]) > 0 {
		detailedBuilder.WriteString("低危发现:\n")
		for _, finding := range severityGroups["低危"] {
			detailedBuilder.WriteString(fmt.Sprintf("- %s: %s (位置: %s)\n", finding.Type, finding.Description, finding.Location))
		}
		detailedBuilder.WriteString("\n")
	}

	detailedBuilder.WriteString("技术细节:\n")
	if techDetails, ok := reportData.Metadata["technical_details"]; ok {
		detailedBuilder.WriteString(techDetails)
	}

	if err := os.WriteFile(detailedPath, []byte(detailedBuilder.String()), 0644); err != nil {
		return "", fmt.Errorf("写入详细报告文件失败: %v", err)
	}

	return detailedPath, nil
}

// prepareReportData 准备报告数据
func (prg *ProfessionalReportGenerator) prepareReportData() ReportData {
	// 这里应该分析实际的结果数据，这里使用示例数据

	// 创建Finding列表
	var findings []types.Finding

	// 添加严重漏洞
	findings = append(findings, types.Finding{
		ID:             "1",
		TaskID:         "professional_report",
		Type:           "vulnerability",
		Severity:       "critical",
		Title:          "SQL注入漏洞",
		Description:    "在用户登录接口存在SQL注入漏洞",
		Location:       "用户登录接口",
		Evidence:       "成功利用该漏洞获取了数据库信息",
		Recommendation: "使用参数化查询或ORM框架",
		Impact:         "可能导致数据库完全被控制",
		Confidence:     0.95,
		CreatedAt:      time.Now(),
		References:     []string{"CWE-89"},
	})

	// 添加高危漏洞
	findings = append(findings, types.Finding{
		ID:             "2",
		TaskID:         "professional_report",
		Type:           "vulnerability",
		Severity:       "high",
		Title:          "XSS跨站脚本漏洞",
		Description:    "在搜索功能中存在反射型XSS漏洞",
		Location:       "搜索功能",
		Evidence:       "成功执行了恶意脚本",
		Recommendation: "对用户输入进行严格过滤和编码",
		Impact:         "可能窃取用户会话信息",
		Confidence:     0.85,
		CreatedAt:      time.Now(),
		References:     []string{"CWE-79"},
	})

	// 创建风险评估
	riskAssessment := types.RiskAssessment{
		ID:               "1",
		TaskID:           "professional_report",
		OverallRisk:      "high",
		RiskScore:        7.5,
		CriticalFindings: 1,
		HighFindings:     1,
		MediumFindings:   0,
		LowFindings:      0,
		Recommendations: []string{
			"立即修复SQL注入漏洞",
			"加强输入验证和过滤机制",
			"更新所有软件到最新版本",
			"实施Web应用防火墙",
			"加强访问控制和权限管理",
		},
		CreatedAt: time.Now(),
	}

	return ReportData{
		ID:             "professional_report_" + time.Now().Format("20060102150405"),
		TaskID:         "professional_report",
		Title:          "专业渗透测试报告 - " + prg.Target,
		Summary:        "本次渗透测试发现了多个严重安全漏洞，需要立即修复。",
		Findings:       findings,
		RiskAssessment: riskAssessment,
		Recommendations: []string{
			"立即修复SQL注入漏洞",
			"加强输入验证和过滤机制",
			"更新所有软件到最新版本",
			"实施Web应用防火墙",
			"加强访问控制和权限管理",
		},
		CreatedAt: time.Now(),
		Metadata: map[string]string{
			"target":            prg.Target,
			"scan_date":         time.Now().Format("2006-01-02 15:04:05"),
			"scan_duration":     "2小时30分钟",
			"executive_summary": "本次渗透测试发现了多个严重安全漏洞，需要立即修复。",
			"risk_level":        "高",
			"technical_details": prg.ReconResults + "\n\n" + prg.VulnResults + "\n\n" + prg.LateralResults,
		},
	}
}

// AnalyzeResults 分析渗透测试结果
func (prg *ProfessionalReportGenerator) AnalyzeResults() (string, error) {
	utils.InfoPrint("开始分析渗透测试结果...")

	var analysis strings.Builder
	analysis.WriteString("=== 渗透测试结果分析 ===\n\n")

	// 分析信息收集结果
	analysis.WriteString("1. 信息收集阶段分析:\n")
	reconAnalysis := prg.analyzeReconResults()
	analysis.WriteString(reconAnalysis)
	analysis.WriteString("\n")

	// 分析漏洞评估结果
	analysis.WriteString("2. 漏洞评估阶段分析:\n")
	vulnAnalysis := prg.analyzeVulnerabilityResults()
	analysis.WriteString(vulnAnalysis)
	analysis.WriteString("\n")

	// 分析横向移动结果
	analysis.WriteString("3. 横向移动阶段分析:\n")
	lateralAnalysis := prg.analyzeLateralMovementResults()
	analysis.WriteString(lateralAnalysis)
	analysis.WriteString("\n")

	// 总体风险评估
	analysis.WriteString("4. 总体风险评估:\n")
	riskAssessment := prg.performRiskAssessment()
	analysis.WriteString(riskAssessment)

	return analysis.String(), nil
}

// analyzeReconResults 分析信息收集结果
func (prg *ProfessionalReportGenerator) analyzeReconResults() string {
	var analysis strings.Builder

	// 这里应该根据实际的信息收集结果进行分析
	// 目前使用简单的逻辑分析
	if strings.Contains(strings.ToLower(prg.ReconResults), "成功") {
		analysis.WriteString("   ✓ 信息收集阶段完成良好，获取了丰富的目标信息\n")
	} else {
		analysis.WriteString("   ⚠ 信息收集阶段存在部分失败，可能影响后续测试\n")
	}

	return analysis.String()
}

// analyzeVulnerabilityResults 分析漏洞评估结果
func (prg *ProfessionalReportGenerator) analyzeVulnerabilityResults() string {
	var analysis strings.Builder

	// 分析漏洞严重程度分布
	if strings.Contains(prg.VulnResults, "严重") {
		analysis.WriteString("   ⚠ 发现严重漏洞，需要立即修复\n")
	}
	if strings.Contains(prg.VulnResults, "高危") {
		analysis.WriteString("   ⚠ 发现高危漏洞，建议尽快修复\n")
	}
	if strings.Contains(prg.VulnResults, "成功") {
		analysis.WriteString("   ✓ 漏洞验证成功，确认了漏洞的存在性\n")
	}

	return analysis.String()
}

// analyzeLateralMovementResults 分析横向移动结果
func (prg *ProfessionalReportGenerator) analyzeLateralMovementResults() string {
	var analysis strings.Builder

	// 分析横向移动的成功情况
	if strings.Contains(prg.LateralResults, "成功") {
		analysis.WriteString("   ✓ 横向移动阶段成功，证明了内部网络的安全性薄弱\n")
	} else {
		analysis.WriteString("   ⚠ 横向移动阶段存在限制，可能由于网络隔离或安全控制\n")
	}

	return analysis.String()
}

// performRiskAssessment 执行风险评估
func (prg *ProfessionalReportGenerator) performRiskAssessment() string {
	var assessment strings.Builder

	// 基于发现的结果进行风险评估
	hasCritical := strings.Contains(prg.VulnResults, "严重") || strings.Contains(prg.VulnResults, "critical")
	hasHigh := strings.Contains(prg.VulnResults, "高危") || strings.Contains(prg.VulnResults, "high")
	lateralSuccess := strings.Contains(prg.LateralResults, "成功")

	if hasCritical && lateralSuccess {
		assessment.WriteString("   🔴 极高风险: 存在严重漏洞且横向移动成功\n")
		assessment.WriteString("      建议立即采取修复措施并加强安全监控\n")
	} else if hasCritical {
		assessment.WriteString("   🟠 高风险: 存在严重漏洞但横向移动受限\n")
		assessment.WriteString("      建议尽快修复关键漏洞\n")
	} else if hasHigh {
		assessment.WriteString("   🟡 中风险: 存在高危漏洞\n")
		assessment.WriteString("      建议在合理时间内修复高危漏洞\n")
	} else {
		assessment.WriteString("   🟢 低风险: 未发现严重或高危漏洞\n")
		assessment.WriteString("      建议继续保持良好的安全实践\n")
	}

	return assessment.String()
}
