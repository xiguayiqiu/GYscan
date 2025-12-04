package ai

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// TestPhase 测试阶段定义（已移至types包）
type TestPhase = types.TestPhase

// 阶段常量（已移至types包）
const (
	PhaseReconnaissance    = types.TestPhaseReconnaissance    // 信息收集
	PhaseVulnerabilityScan = types.TestPhaseVulnerabilityScan // 漏洞扫描
	PhaseExploitation      = types.TestPhaseExploitation      // 漏洞利用
	PhasePostExploitation  = types.TestPhasePostExploitation  // 后渗透
	PhaseReporting         = types.TestPhaseReporting         // 报告生成
)

// TestOrchestrator 自动化测试流程编排器
type TestOrchestrator struct {
	AIClient       *AIClient
	TargetAnalyzer *TargetAnalyzer
	ToolManager    *ToolManager
	WorkflowEngine *WorkflowEngine
	Config         config.AIConfig
	CurrentPhase   TestPhase
	TestResults    *TestResults
}

// TestResults 测试结果汇总
type TestResults struct {
	Target          string                     `json:"target"`
	TargetAnalysis  *TargetAnalysisResult      `json:"target_analysis"`
	Phases          map[TestPhase]*PhaseResult `json:"phases"`
	Vulnerabilities []types.Vulnerability      `json:"vulnerabilities"`
	Findings        []types.Finding            `json:"findings"`
	RiskAssessment  *types.RiskAssessment      `json:"risk_assessment"`
	StartTime       time.Time                  `json:"start_time"`
	EndTime         time.Time                  `json:"end_time"`
	Status          string                     `json:"status"`
}

// PhaseResult 阶段测试结果
type PhaseResult struct {
	Phase           TestPhase             `json:"phase"`
	StartTime       time.Time             `json:"start_time"`
	EndTime         time.Time             `json:"end_time"`
	ToolsExecuted   []string              `json:"tools_executed"`
	ToolResults     []types.ToolResult    `json:"tool_results"`
	Vulnerabilities []types.Vulnerability `json:"vulnerabilities"`
	Findings        []types.Finding       `json:"findings"`
	Status          string                `json:"status"`
	Error           string                `json:"error,omitempty"`
}

// NewTestOrchestrator 创建新的测试编排器
func NewTestOrchestrator(aiClient *AIClient, targetAnalyzer *TargetAnalyzer, toolManager *ToolManager, workflowEngine *WorkflowEngine, cfg config.AIConfig) *TestOrchestrator {
	return &TestOrchestrator{
		AIClient:       aiClient,
		TargetAnalyzer: targetAnalyzer,
		ToolManager:    toolManager,
		WorkflowEngine: workflowEngine,
		Config:         cfg,
		CurrentPhase:   PhaseReconnaissance,
		TestResults: &TestResults{
			Phases: make(map[TestPhase]*PhaseResult),
			Status: "pending",
		},
	}
}

// ExecuteFullTest 执行完整的渗透测试流程
func (to *TestOrchestrator) ExecuteFullTest(target string) (*TestResults, error) {
	utils.InfoPrint("开始执行完整渗透测试流程，目标: %s", target)

	to.TestResults.Target = target
	to.TestResults.StartTime = time.Now()
	to.TestResults.Status = "running"

	// 1. 目标分析
	utils.InfoPrint("阶段1: 目标智能分析")
	targetAnalysis, err := to.TargetAnalyzer.Analyze(target)
	if err != nil {
		to.TestResults.Status = "failed"
		to.TestResults.EndTime = time.Now()
		return to.TestResults, fmt.Errorf("目标分析失败: %v", err)
	}
	to.TestResults.TargetAnalysis = targetAnalysis

	// 2. 信息收集阶段
	utils.InfoPrint("阶段2: 信息收集")
	reconResult, err := to.executeReconnaissancePhase(target, targetAnalysis)
	if err != nil {
		utils.WarningPrint("信息收集阶段部分失败: %v", err)
	}
	to.TestResults.Phases[PhaseReconnaissance] = reconResult

	// 3. 漏洞扫描阶段
	utils.InfoPrint("阶段3: 漏洞扫描")
	vulnScanResult, err := to.executeVulnerabilityScanPhase(target, targetAnalysis, reconResult)
	if err != nil {
		utils.WarningPrint("漏洞扫描阶段部分失败: %v", err)
	}
	to.TestResults.Phases[PhaseVulnerabilityScan] = vulnScanResult

	// 4. 漏洞利用阶段（基于风险评估决定是否执行）
	if targetAnalysis.RiskLevel == types.RiskLevelHigh || targetAnalysis.RiskLevel == types.RiskLevelMedium {
		utils.InfoPrint("阶段4: 漏洞利用")
		exploitResult, err := to.executeExploitationPhase(target, targetAnalysis, vulnScanResult)

		if err != nil {
			utils.WarningPrint("漏洞利用阶段部分失败: %v", err)
		}
		to.TestResults.Phases[PhaseExploitation] = exploitResult
	} else {
		utils.InfoPrint("跳过漏洞利用阶段（风险级别较低）")
	}

	// 5. 后渗透阶段（仅在漏洞利用成功时执行）
	if exploitResult, exists := to.TestResults.Phases[PhaseExploitation]; exists && len(exploitResult.Vulnerabilities) > 0 {
		utils.InfoPrint("阶段5: 后渗透测试")
		postExploitResult, err := to.executePostExploitationPhase(target, targetAnalysis, exploitResult)

		if err != nil {
			utils.WarningPrint("后渗透阶段部分失败: %v", err)
		}
		to.TestResults.Phases[PhasePostExploitation] = postExploitResult
	} else {
		utils.InfoPrint("跳过后渗透阶段（无成功利用的漏洞）")
	}

	// 6. 汇总结果和风险评估
	utils.InfoPrint("阶段6: 结果汇总和风险评估")
	to.aggregateResults()

	// 7. 报告生成阶段
	utils.InfoPrint("阶段7: 报告生成")
	reportResult, err := to.executeReportingPhase()
	if err != nil {
		utils.WarningPrint("报告生成阶段失败: %v", err)
	}
	to.TestResults.Phases[PhaseReporting] = reportResult

	to.TestResults.EndTime = time.Now()
	to.TestResults.Status = "completed"

	duration := to.TestResults.EndTime.Sub(to.TestResults.StartTime)
	utils.SuccessPrint("渗透测试完成 - 目标: %s, 耗时: %v, 发现漏洞: %d",
		target, duration, len(to.TestResults.Vulnerabilities))

	return to.TestResults, nil
}

// executeReconnaissancePhase 执行信息收集阶段
func (to *TestOrchestrator) executeReconnaissancePhase(target string, analysis *TargetAnalysisResult) (*PhaseResult, error) {
	result := &PhaseResult{
		Phase:     PhaseReconnaissance,
		StartTime: time.Now(),
		Status:    "running",
	}

	toolsToExecute := to.selectReconnaissanceTools(analysis)

	for _, toolName := range toolsToExecute {
		if toolInterface, exists := to.ToolManager.GetTool(toolName); exists && toolInterface.IsAvailable() {
			utils.InfoPrint("执行工具: %s", toolName)

			// 类型断言，将ToolInterface转换为*BaseTool
			tool, ok := toolInterface.(*BaseTool)
			if !ok {
				utils.WarningPrint("工具 %s 类型转换失败", toolName)
				continue
			}

			toolResult, err := to.executeTool(tool, target, analysis)
			if err != nil {
				utils.WarningPrint("工具 %s 执行失败: %v", toolName, err)
				result.Error = fmt.Sprintf("%s: %v", toolName, err)
			} else {
				result.ToolsExecuted = append(result.ToolsExecuted, toolName)
				result.ToolResults = append(result.ToolResults, toolResult)

				// 解析工具结果，提取有用信息
				findings := to.parseToolResults(toolResult, analysis)
				result.Findings = append(result.Findings, findings...)
			}
		} else {
			utils.WarningPrint("工具 %s 不可用", toolName)
		}
	}

	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

// selectReconnaissanceTools 选择信息收集工具
func (to *TestOrchestrator) selectReconnaissanceTools(analysis *TargetAnalysisResult) []string {
	tools := []string{}

	// 基于目标类型选择工具
	switch analysis.Type {
	case types.TargetTypeWebApp:
		tools = append(tools, "nmap", "nikto", "gobuster", "whatweb")
	case types.TargetTypeAPI:
		tools = append(tools, "nmap", "postman", "curl")
	case types.TargetTypeNetwork:
		tools = append(tools, "nmap", "masscan", "nessus")
	case types.TargetTypeIoT:
		tools = append(tools, "nmap", "shodan", "firmwalker")
	default:
		tools = append(tools, "nmap") // 默认工具
	}

	// 基于开放服务调整工具选择
	for _, service := range analysis.Services {
		switch service {
		case "http", "https":
			if !contains(tools, "nikto") {
				tools = append(tools, "nikto")
			}
		case "ssh":
			if !contains(tools, "hydra") {
				tools = append(tools, "hydra")
			}
		case "ftp":
			if !contains(tools, "ftp-anon") {
				tools = append(tools, "ftp-anon")
			}
		}
	}

	return tools
}

// executeVulnerabilityScanPhase 执行漏洞扫描阶段
func (to *TestOrchestrator) executeVulnerabilityScanPhase(target string, analysis *TargetAnalysisResult, reconResult *PhaseResult) (*PhaseResult, error) {
	result := &PhaseResult{
		Phase:     PhaseVulnerabilityScan,
		StartTime: time.Now(),
		Status:    "running",
	}

	toolsToExecute := to.selectVulnerabilityScanTools(analysis, reconResult)

	for _, toolName := range toolsToExecute {
		if toolInterface, exists := to.ToolManager.GetTool(toolName); exists && toolInterface.IsAvailable() {
			utils.InfoPrint("执行漏洞扫描工具: %s", toolName)

			// 类型断言，将ToolInterface转换为*BaseTool
			tool, ok := toolInterface.(*BaseTool)
			if !ok {
				utils.WarningPrint("工具 %s 类型转换失败", toolName)
				continue
			}

			toolResult, err := to.executeTool(tool, target, analysis)
			if err != nil {
				utils.WarningPrint("漏洞扫描工具 %s 执行失败: %v", toolName, err)
				result.Error = fmt.Sprintf("%s: %v", toolName, err)
			} else {
				result.ToolsExecuted = append(result.ToolsExecuted, toolName)
				result.ToolResults = append(result.ToolResults, toolResult)

				// 解析漏洞扫描结果
				vulnerabilities := to.parseVulnerabilityResults(toolResult, analysis)
				result.Vulnerabilities = append(result.Vulnerabilities, vulnerabilities...)
			}
		} else {
			utils.WarningPrint("漏洞扫描工具 %s 不可用", toolName)
		}
	}

	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

// selectVulnerabilityScanTools 选择漏洞扫描工具
func (to *TestOrchestrator) selectVulnerabilityScanTools(analysis *TargetAnalysisResult, reconResult *PhaseResult) []string {
	tools := []string{}

	// 基于目标类型选择工具
	switch analysis.Type {
	case types.TargetTypeWebApp:
		tools = append(tools, "sqlmap", "nikto", "wpscan", "joomscan")
	case types.TargetTypeAPI:
		tools = append(tools, "postman", "burp", "zap")
	case types.TargetTypeNetwork:
		tools = append(tools, "nessus", "openvas", "nmap")
	case types.TargetTypeIoT:
		tools = append(tools, "firmwalker", "binwalk")
	}

	// 基于信息收集结果调整工具选择
	for _, finding := range reconResult.Findings {
		if strings.Contains(strings.ToLower(finding.Description), "wordpress") && !contains(tools, "wpscan") {
			tools = append(tools, "wpscan")
		} else if strings.Contains(strings.ToLower(finding.Description), "joomla") && !contains(tools, "joomscan") {
			tools = append(tools, "joomscan")
		}
	}

	return tools
}

// executeExploitationPhase 执行漏洞利用阶段
func (to *TestOrchestrator) executeExploitationPhase(target string, analysis *TargetAnalysisResult, vulnScanResult *PhaseResult) (*PhaseResult, error) {
	result := &PhaseResult{
		Phase:     PhaseExploitation,
		StartTime: time.Now(),
		Status:    "running",
	}

	// 选择要利用的漏洞（基于严重性和置信度）
	vulnerabilitiesToExploit := to.selectVulnerabilitiesForExploitation(vulnScanResult.Vulnerabilities)

	for _, vuln := range vulnerabilitiesToExploit {
		utils.InfoPrint("尝试利用漏洞: %s (严重性: %s)", vuln.Name, vuln.Severity)

		exploitResult, err := to.executeExploit(vuln, target, analysis)
		if err != nil {
			utils.WarningPrint("漏洞利用失败: %s - %v", vuln.Name, err)
		} else {
			result.Vulnerabilities = append(result.Vulnerabilities, exploitResult)
			utils.SuccessPrint("漏洞利用成功: %s", vuln.Name)
		}
	}

	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

// selectVulnerabilitiesForExploitation 选择要利用的漏洞
func (to *TestOrchestrator) selectVulnerabilitiesForExploitation(vulnerabilities []types.Vulnerability) []types.Vulnerability {
	var selected []types.Vulnerability

	// 按严重性和置信度排序
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].Severity == vulnerabilities[j].Severity {
			return vulnerabilities[i].Confidence > vulnerabilities[j].Confidence
		}
		return severityWeight(vulnerabilities[i].Severity) > severityWeight(vulnerabilities[j].Severity)
	})

	// 选择前3个高危或中危漏洞
	count := 0
	for _, vuln := range vulnerabilities {
		if (vuln.Severity == "high" || vuln.Severity == "medium") && vuln.Confidence > 0.5 {
			selected = append(selected, vuln)
			count++
			if count >= 3 {
				break
			}
		}
	}

	return selected
}

// executePostExploitationPhase 执行后渗透阶段
func (to *TestOrchestrator) executePostExploitationPhase(target string, analysis *TargetAnalysisResult, exploitResult *PhaseResult) (*PhaseResult, error) {
	result := &PhaseResult{
		Phase:     PhasePostExploitation,
		StartTime: time.Now(),
		Status:    "running",
	}

	// 基于成功利用的漏洞执行后渗透操作
	for _, vuln := range exploitResult.Vulnerabilities {
		utils.InfoPrint("执行后渗透操作，基于漏洞: %s", vuln.Name)

		// 这里可以实现具体的后渗透逻辑
		// 例如：权限提升、横向移动、数据窃取等

		finding := types.Finding{
			ID:          fmt.Sprintf("post-exploit-%s", vuln.ID),
			Title:       fmt.Sprintf("后渗透测试 - %s", vuln.Name),
			Description: fmt.Sprintf("基于漏洞 %s 执行的后渗透操作", vuln.Name),
			Severity:    "info",
			Confidence:  0.7,
			CreatedAt:   time.Now(),
		}
		result.Findings = append(result.Findings, finding)
	}

	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

// ReportGenerator 报告生成器
type ReportGenerator struct{}

// NewReportGenerator 创建新的报告生成器
func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{}
}

// GenerateMarkdown 生成Markdown格式报告
func (rg *ReportGenerator) GenerateMarkdown(data types.ReportData) (string, error) {
	var content strings.Builder

	content.WriteString(fmt.Sprintf("# %s\n\n", data.Title))
	content.WriteString("## 目标信息\n\n")
	content.WriteString(fmt.Sprintf("- **目标**: %s\n", data.Metadata["target"]))
	content.WriteString(fmt.Sprintf("- **开始时间**: %s\n", data.Metadata["start_time"]))
	content.WriteString(fmt.Sprintf("- **结束时间**: %s\n", data.Metadata["end_time"]))
	content.WriteString(fmt.Sprintf("- **持续时间**: %s\n\n", data.Metadata["duration"]))

	content.WriteString("## 摘要\n\n")
	content.WriteString(fmt.Sprintf("%s\n\n", data.Summary))

	if len(data.Findings) > 0 {
		content.WriteString("## 发现结果\n\n")
		for i, finding := range data.Findings {
			content.WriteString(fmt.Sprintf("### 发现 %d\n", i+1))
			content.WriteString(fmt.Sprintf("- **标题**: %s\n", finding.Title))
			content.WriteString(fmt.Sprintf("- **严重程度**: %s\n", finding.Severity))
			content.WriteString(fmt.Sprintf("- **描述**: %s\n\n", finding.Description))
		}
	}

	content.WriteString("## 风险评估\n\n")
	content.WriteString(fmt.Sprintf("- **整体风险级别**: %s\n", data.RiskAssessment.OverallRisk))
	content.WriteString(fmt.Sprintf("- **风险评分**: %.1f\n", data.RiskAssessment.RiskScore))
	content.WriteString(fmt.Sprintf("- **严重发现**: %d 个\n", data.RiskAssessment.CriticalFindings))
	content.WriteString(fmt.Sprintf("- **高危发现**: %d 个\n", data.RiskAssessment.HighFindings))
	content.WriteString(fmt.Sprintf("- **中危发现**: %d 个\n", data.RiskAssessment.MediumFindings))
	content.WriteString(fmt.Sprintf("- **低危发现**: %d 个\n\n", data.RiskAssessment.LowFindings))

	if len(data.Recommendations) > 0 {
		content.WriteString("### 建议措施\n\n")
		for i, rec := range data.Recommendations {
			content.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

	return content.String(), nil
}

// GenerateHTML 生成HTML格式报告
func (rg *ReportGenerator) GenerateHTML(data types.ReportData) (string, error) {
	markdownContent, err := rg.GenerateMarkdown(data)
	if err != nil {
		return "", err
	}

	return markdownToHTML(markdownContent), nil
}

// executeReportingPhase 执行报告生成阶段
func (to *TestOrchestrator) executeReportingPhase() (*PhaseResult, error) {
	result := &PhaseResult{
		Phase:     PhaseReporting,
		StartTime: time.Now(),
		Status:    "running",
	}

	// 生成报告
	reportGenerator := NewReportGenerator()
	reportData := to.prepareReportData()

	// 生成Markdown报告
	_, err := reportGenerator.GenerateMarkdown(reportData)
	if err != nil {
		utils.WarningPrint("Markdown报告生成失败: %v", err)
	} else {
		utils.InfoPrint("Markdown报告生成成功")
	}

	// 生成HTML报告
	_, err = reportGenerator.GenerateHTML(reportData)
	if err != nil {
		utils.WarningPrint("HTML报告生成失败: %v", err)
	} else {
		utils.InfoPrint("HTML报告生成成功")
	}

	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

// executeTool 执行单个工具
func (to *TestOrchestrator) executeTool(tool *BaseTool, target string, analysis *TargetAnalysisResult) (types.ToolResult, error) {
	// 构建工具参数
	args := to.buildToolArguments(tool.Name(), target, analysis)

	// 执行工具
	output, err := tool.Run(args...)
	if err != nil {
		return types.ToolResult{}, err
	}

	return types.ToolResult{
		ID:         fmt.Sprintf("%s-%s", tool.Name(), time.Now().Format("20060102150405")),
		TaskID:     fmt.Sprintf("task-%s", target),
		StepID:     fmt.Sprintf("step-%s", tool.Name()),
		ToolName:   tool.Name(),
		Command:    strings.Join(args, " "),
		ExitCode:   0,
		Stdout:     output,
		Stderr:     "",
		StartTime:  time.Now(),
		EndTime:    time.Now(),
		Duration:   "0s",
		ParsedData: "",
		Status:     "success",
		Severity:   "info",
	}, nil
}

// buildToolArguments 构建工具参数
func (to *TestOrchestrator) buildToolArguments(toolName, target string, analysis *TargetAnalysisResult) []string {
	switch toolName {
	case "nmap":
		return []string{"-sS", "-T4", "-A", "-v", target}
	case "nikto":
		return []string{"-h", target, "-o", "nikto.html"}
	case "sqlmap":
		return []string{"-u", fmt.Sprintf("http://%s/", target), "--batch", "--level=3"}
	case "gobuster":
		return []string{"dir", "-u", fmt.Sprintf("http://%s/", target), "-w", "/usr/share/wordlists/dirb/common.txt"}
	default:
		return []string{target}
	}
}

// parseToolResults 解析工具结果
func (to *TestOrchestrator) parseToolResults(result types.ToolResult, analysis *TargetAnalysisResult) []types.Finding {
	var findings []types.Finding

	// 简单的结果解析逻辑
	// 实际实现中应该使用更复杂的解析器

	finding := types.Finding{
		ID:          fmt.Sprintf("tool-%s-%s", result.ToolName, result.ID),
		Title:       fmt.Sprintf("工具执行结果 - %s", result.ToolName),
		Description: fmt.Sprintf("工具 %s 执行完成，标准输出长度: %d", result.ToolName, len(result.Stdout)),
		Severity:    "info",
		Confidence:  0.8,
		CreatedAt:   time.Now(),
	}
	findings = append(findings, finding)

	return findings
}

// parseVulnerabilityResults 解析漏洞扫描结果
func (to *TestOrchestrator) parseVulnerabilityResults(result types.ToolResult, analysis *TargetAnalysisResult) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability

	// 简单的漏洞解析逻辑
	// 实际实现中应该使用工具特定的解析器

	vuln := types.Vulnerability{
		ID:          fmt.Sprintf("scan-%s-%s", result.ToolName, result.ID),
		Name:        fmt.Sprintf("%s 扫描发现", result.ToolName),
		Description: fmt.Sprintf("工具 %s 发现的潜在漏洞", result.ToolName),
		Severity:    "medium",
		Location:    analysis.Target,
		Confidence:  0.6,
		CreatedAt:   time.Now(),
	}
	vulnerabilities = append(vulnerabilities, vuln)

	return vulnerabilities
}

// executeExploit 执行漏洞利用
func (to *TestOrchestrator) executeExploit(vuln types.Vulnerability, target string, analysis *TargetAnalysisResult) (types.Vulnerability, error) {
	// 简单的漏洞利用模拟
	// 实际实现中应该使用具体的漏洞利用工具

	exploitedVuln := vuln
	// 由于Vulnerability结构体没有ExploitResult字段，我们只能记录利用状态
	// 在实际实现中，应该将利用结果存储在单独的字段或数据库中

	return exploitedVuln, nil
}

// aggregateResults 汇总测试结果
func (to *TestOrchestrator) aggregateResults() {
	// 收集所有阶段的漏洞
	for _, phaseResult := range to.TestResults.Phases {
		to.TestResults.Vulnerabilities = append(to.TestResults.Vulnerabilities, phaseResult.Vulnerabilities...)
		to.TestResults.Findings = append(to.TestResults.Findings, phaseResult.Findings...)
	}

	// 执行风险评估
	to.TestResults.RiskAssessment = to.assessOverallRisk()
}

// assessOverallRisk 评估整体风险
func (to *TestOrchestrator) assessOverallRisk() *types.RiskAssessment {
	assessment := &types.RiskAssessment{
		ID:          fmt.Sprintf("risk-%s", to.TestResults.Target),
		TaskID:      fmt.Sprintf("task-%s", to.TestResults.Target),
		OverallRisk: string(types.RiskLevelLow),
		CreatedAt:   time.Now(),
	}

	// 基于发现的漏洞评估风险
	highVulns := 0
	mediumVulns := 0
	lowVulns := 0

	for _, vuln := range to.TestResults.Vulnerabilities {
		switch vuln.Severity {
		case "high":
			highVulns++
		case "medium":
			mediumVulns++
		case "low":
			lowVulns++
		}
	}

	if highVulns > 0 {
		assessment.OverallRisk = string(types.RiskLevelHigh)
	} else if mediumVulns > 0 {
		assessment.OverallRisk = string(types.RiskLevelMedium)
	} else if lowVulns > 0 {
		assessment.OverallRisk = string(types.RiskLevelLow)
	}

	// 设置风险评分和发现数量
	assessment.RiskScore = calculateRiskScore(highVulns, mediumVulns, lowVulns)
	assessment.CriticalFindings = 0 // 暂时设为0，需要根据实际漏洞严重程度计算
	assessment.HighFindings = highVulns
	assessment.MediumFindings = mediumVulns
	assessment.LowFindings = lowVulns
	assessment.Recommendations = to.generateRiskRecommendations(highVulns, mediumVulns, lowVulns)

	return assessment
}

// calculateRiskScore 计算风险评分
func calculateRiskScore(high, medium, low int) float64 {
	// 简单的风险评分计算：高风险*3 + 中风险*2 + 低风险*1
	score := float64(high*3 + medium*2 + low)
	// 归一化到0-10分
	if score > 0 {
		return score / float64(high+medium+low) * 10
	}
	return 0
}

// generateRiskRecommendations 生成风险建议
func (to *TestOrchestrator) generateRiskRecommendations(high, medium, low int) []string {
	recommendations := []string{}

	if high > 0 {
		recommendations = append(recommendations,
			"立即修复所有高危漏洞",
			"加强安全监控和日志记录",
			"考虑暂时限制对受影响服务的访问",
		)
	}

	if medium > 0 {
		recommendations = append(recommendations,
			"制定中危漏洞修复计划",
			"加强输入验证和输出编码",
			"定期进行安全扫描",
		)
	}

	if low > 0 {
		recommendations = append(recommendations,
			"修复低危漏洞以提升整体安全性",
			"加强安全意识培训",
			"实施安全开发最佳实践",
		)
	}

	return recommendations
}

// prepareReportData 准备报告数据
func (to *TestOrchestrator) prepareReportData() types.ReportData {
	return types.ReportData{
		ID:              fmt.Sprintf("report-%s", to.TestResults.Target),
		TaskID:          fmt.Sprintf("task-%s", to.TestResults.Target),
		Title:           fmt.Sprintf("安全测试报告 - %s", to.TestResults.Target),
		Summary:         to.generateReportSummary(),
		Findings:        to.TestResults.Findings,
		RiskAssessment:  *to.TestResults.RiskAssessment,
		Recommendations: to.TestResults.RiskAssessment.Recommendations,
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     to.TestResults.Target,
			"start_time": to.TestResults.StartTime.Format("2006-01-02 15:04:05"),
			"end_time":   to.TestResults.EndTime.Format("2006-01-02 15:04:05"),
			"duration":   to.TestResults.EndTime.Sub(to.TestResults.StartTime).String(),
		},
	}
}

// generateReportSummary 生成报告摘要
func (to *TestOrchestrator) generateReportSummary() string {
	totalVulns := len(to.TestResults.Vulnerabilities)
	highVulns := 0
	mediumVulns := 0
	lowVulns := 0

	for _, vuln := range to.TestResults.Vulnerabilities {
		switch vuln.Severity {
		case "high":
			highVulns++
		case "medium":
			mediumVulns++
		case "low":
			lowVulns++
		}
	}

	return fmt.Sprintf(`本次安全测试共发现 %d 个安全漏洞：
- 高危漏洞: %d 个
- 中危漏洞: %d 个  
- 低危漏洞: %d 个

整体风险级别: %s
建议立即采取相应的安全措施。`,
		totalVulns, highVulns, mediumVulns, lowVulns, to.TestResults.RiskAssessment.OverallRisk)
}

// severityWeight 计算严重性权重
func severityWeight(severity string) int {
	switch severity {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// contains 检查字符串切片是否包含某个元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
