package ai

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// ReportAnalyzer 报告分析器
type ReportAnalyzer struct {
	aiClient    *AIClient
	toolManager *ToolManager
}

// NewReportAnalyzer 创建新的报告分析器
func NewReportAnalyzer(aiClient *AIClient, toolManager *ToolManager) *ReportAnalyzer {
	return &ReportAnalyzer{
		aiClient:    aiClient,
		toolManager: toolManager,
	}
}

// AnalyzeReport 分析安全报告
func (r *ReportAnalyzer) AnalyzeReport(reportData types.ReportData) (*types.AIAnalysis, error) {
	utils.InfoPrint("正在分析安全报告...")

	// 提取关键信息
	analysis := &types.AIAnalysis{
		ID:        generateAnalysisID(),
		TaskID:    extractTaskIDFromReport(reportData),
		Type:      "report_analysis",
		CreatedAt: time.Now(),
		Provider:  r.aiClient.Config.Provider,
	}

	// 分析发现结果
	findingsAnalysis := r.analyzeFindings(reportData.Findings)

	// 分析风险评估
	riskAnalysis := r.analyzeRiskPatterns(reportData)

	// 生成建议优化
	recommendations := r.generateOptimizationRecommendations(reportData)

	// 构建分析内容
	analysis.Content = r.buildAnalysisContent(reportData, findingsAnalysis, riskAnalysis, recommendations)

	utils.SuccessPrint("安全报告分析完成")
	return analysis, nil
}

// AnalyzeTrends 分析趋势数据
func (r *ReportAnalyzer) AnalyzeTrends(reports []types.ReportData) (*types.AIAnalysis, error) {
	utils.InfoPrint("正在分析安全趋势...")

	if len(reports) == 0 {
		return nil, fmt.Errorf("无报告数据可供分析")
	}

	analysis := &types.AIAnalysis{
		ID:        generateAnalysisID(),
		Type:      "trend_analysis",
		CreatedAt: time.Now(),
		Provider:  r.aiClient.Config.Provider,
	}

	// 分析趋势数据
	trendData := r.analyzeSecurityTrends(reports)

	// 生成趋势报告
	analysis.Content = r.buildTrendAnalysisContent(reports, trendData)

	utils.SuccessPrint("安全趋势分析完成")
	return analysis, nil
}

// CompareReports 比较多个报告
func (r *ReportAnalyzer) CompareReports(reports []types.ReportData) (*types.AIAnalysis, error) {
	utils.InfoPrint("正在比较安全报告...")

	if len(reports) < 2 {
		return nil, fmt.Errorf("需要至少两个报告进行比较")
	}

	analysis := &types.AIAnalysis{
		ID:        generateAnalysisID(),
		Type:      "report_comparison",
		CreatedAt: time.Now(),
		Provider:  r.aiClient.Config.Provider,
	}

	// 比较报告数据
	comparisonData := r.compareReportData(reports)

	// 生成比较报告
	analysis.Content = r.buildComparisonContent(reports, comparisonData)

	utils.SuccessPrint("安全报告比较完成")
	return analysis, nil
}

// analyzeFindings 分析发现结果
func (r *ReportAnalyzer) analyzeFindings(findings []types.Finding) *FindingAnalysis {
	analysis := &FindingAnalysis{
		TotalFindings:     len(findings),
		SeverityBreakdown: make(map[string]int),
		TypeBreakdown:     make(map[string]int),
		CommonPatterns:    []string{},
		TopRisks:          []types.Finding{},
	}

	// 统计严重程度分布
	for _, finding := range findings {
		analysis.SeverityBreakdown[finding.Severity]++
		analysis.TypeBreakdown[finding.Type]++
	}

	// 识别常见模式
	analysis.CommonPatterns = r.identifyCommonPatterns(findings)

	// 提取高风险发现
	analysis.TopRisks = r.extractTopRisks(findings, 5)

	return analysis
}

// analyzeRiskPatterns 分析风险模式
func (r *ReportAnalyzer) analyzeRiskPatterns(reportData types.ReportData) *RiskPatternAnalysis {
	analysis := &RiskPatternAnalysis{
		RiskLevel:        "low",
		RiskFactors:      []string{},
		ImprovementAreas: []string{},
		ConfidenceScore:  0.0,
	}

	// 分析风险级别
	analysis.RiskLevel = r.calculateOverallRiskLevel(reportData.Findings)

	// 识别风险因素
	analysis.RiskFactors = r.identifyRiskFactors(reportData)

	// 识别改进领域
	analysis.ImprovementAreas = r.identifyImprovementAreas(reportData)

	// 计算置信度评分
	analysis.ConfidenceScore = r.calculateConfidenceScore(reportData)

	return analysis
}

// generateOptimizationRecommendations 生成优化建议
func (r *ReportAnalyzer) generateOptimizationRecommendations(reportData types.ReportData) []string {
	var recommendations []string

	// 基于发现结果生成建议
	if len(reportData.Findings) > 0 {
		criticalFindings := filterFindingsBySeverity(reportData.Findings, "critical")
		highFindings := filterFindingsBySeverity(reportData.Findings, "high")

		if len(criticalFindings) > 0 {
			recommendations = append(recommendations,
				"建议立即修复所有严重级别的安全漏洞",
				"考虑进行渗透测试验证修复效果",
			)
		}

		if len(highFindings) > 0 {
			recommendations = append(recommendations,
				"优先修复高危级别的安全漏洞",
				"加强安全监控和日志审计",
			)
		}
	}

	// 基于扫描类型生成建议
	if scanType, exists := reportData.Metadata["scan_type"]; exists && scanType == "exp" {
		recommendations = append(recommendations,
			"考虑进行定期安全评估",
			"建立安全开发生命周期(SDLC)",
		)
	}

	// 通用建议
	recommendations = append(recommendations,
		"定期更新安全策略和流程",
		"加强员工安全意识培训",
		"实施持续安全监控",
	)

	return recommendations
}

// analyzeSecurityTrends 分析安全趋势
func (r *ReportAnalyzer) analyzeSecurityTrends(reports []types.ReportData) *types.TrendAnalysis {
	analysis := &types.TrendAnalysis{
		ID:               generateAnalysisID(),
		Type:             "security",
		Period:           "custom",
		StartDate:        time.Now(),
		EndDate:          time.Now(),
		TotalTasks:       len(reports),
		SuccessRate:      0.0,
		AvgDuration:      0.0,
		CriticalFindings: 0,
		HighFindings:     0,
		Trend:            "stable",
		Insights:         []string{},
		Recommendations:  []string{},
		CreatedAt:        time.Now(),
	}

	// 分析趋势指标
	analysis.Insights = r.calculateTrendMetrics(reports)

	// 识别改进领域
	analysis.Recommendations = r.identifyTrendImprovementAreas(reports)

	// 识别新兴风险
	// analysis.EmergingRisks = r.identifyEmergingRisks(reports)

	return analysis
}

// compareReportData 比较报告数据
func (r *ReportAnalyzer) compareReportData(reports []types.ReportData) *ComparisonAnalysis {
	analysis := &ComparisonAnalysis{
		ReportCount:      len(reports),
		CommonFindings:   []types.Finding{},
		UniqueFindings:   make(map[string][]types.Finding),
		RiskComparison:   make(map[string]string),
		ImprovementTrend: "",
	}

	// 比较发现结果
	analysis.CommonFindings = r.findCommonFindings(reports)
	analysis.UniqueFindings = r.findUniqueFindings(reports)

	// 比较风险级别
	analysis.RiskComparison = r.compareRiskLevels(reports)

	// 分析改进趋势
	analysis.ImprovementTrend = r.analyzeImprovementTrend(reports)

	return analysis
}

// 辅助分析函数

// identifyCommonPatterns 识别常见模式
func (r *ReportAnalyzer) identifyCommonPatterns(findings []types.Finding) []string {
	var patterns []string

	// 按类型统计
	typeCount := make(map[string]int)
	for _, finding := range findings {
		typeCount[finding.Type]++
	}

	// 识别常见类型
	for findingType, count := range typeCount {
		if count >= 2 { // 至少出现两次才认为是常见模式
			patterns = append(patterns, fmt.Sprintf("常见%s类型问题: %d次", findingType, count))
		}
	}

	// 识别常见位置模式
	locationPatterns := r.identifyLocationPatterns(findings)
	patterns = append(patterns, locationPatterns...)

	return patterns
}

// identifyLocationPatterns 识别位置模式
func (r *ReportAnalyzer) identifyLocationPatterns(findings []types.Finding) []string {
	var patterns []string
	locationCount := make(map[string]int)

	for _, finding := range findings {
		if finding.Location != "" {
			locationCount[finding.Location]++
		}
	}

	for location, count := range locationCount {
		if count >= 2 {
			patterns = append(patterns, fmt.Sprintf("位置%s发现多个问题: %d次", location, count))
		}
	}

	return patterns
}

// extractTopRisks 提取高风险发现
func (r *ReportAnalyzer) extractTopRisks(findings []types.Finding, limit int) []types.Finding {
	// 按严重程度排序
	sortedFindings := make([]types.Finding, len(findings))
	copy(sortedFindings, findings)

	sort.Slice(sortedFindings, func(i, j int) bool {
		return getSeverityWeight(sortedFindings[i].Severity) > getSeverityWeight(sortedFindings[j].Severity)
	})

	// 返回前limit个发现
	if len(sortedFindings) > limit {
		return sortedFindings[:limit]
	}
	return sortedFindings
}

// calculateOverallRiskLevel 计算总体风险级别
func (r *ReportAnalyzer) calculateOverallRiskLevel(findings []types.Finding) string {
	criticalCount := len(filterFindingsBySeverity(findings, "critical"))
	highCount := len(filterFindingsBySeverity(findings, "high"))
	mediumCount := len(filterFindingsBySeverity(findings, "medium"))

	if criticalCount > 0 {
		return "critical"
	} else if highCount > 0 {
		return "high"
	} else if mediumCount > 0 {
		return "medium"
	} else {
		return "low"
	}
}

// identifyRiskFactors 识别风险因素
func (r *ReportAnalyzer) identifyRiskFactors(reportData types.ReportData) []string {
	var factors []string

	criticalFindings := filterFindingsBySeverity(reportData.Findings, "critical")
	highFindings := filterFindingsBySeverity(reportData.Findings, "high")

	if len(criticalFindings) > 0 {
		factors = append(factors, "存在严重级别的安全漏洞")
	}

	if len(highFindings) > 0 {
		factors = append(factors, "存在多个高危级别的安全漏洞")
	}

	if len(reportData.Findings) > 10 {
		factors = append(factors, "发现的安全问题数量较多")
	}

	// 分析扫描类型
	if scanType, exists := reportData.Metadata["scan_type"]; exists && scanType == "exp" {
		factors = append(factors, "渗透测试发现可利用漏洞")
	}

	return factors
}

// identifyImprovementAreas 识别改进领域
func (r *ReportAnalyzer) identifyImprovementAreas(reportData types.ReportData) []string {
	var areas []string

	if len(reportData.Findings) == 0 {
		areas = append(areas, "当前安全状况良好，继续保持")
		return areas
	}

	// 基于发现结果识别改进领域
	webFindings := filterFindingsByType(reportData.Findings, "web")
	if len(webFindings) > 0 {
		areas = append(areas, "加强Web应用安全防护")
	}

	networkFindings := filterFindingsByType(reportData.Findings, "network")
	if len(networkFindings) > 0 {
		areas = append(areas, "加强网络安全配置")
	}

	configFindings := filterFindingsByType(reportData.Findings, "configuration")
	if len(configFindings) > 0 {
		areas = append(areas, "优化安全配置管理")
	}

	return areas
}

// calculateConfidenceScore 计算置信度评分
func (r *ReportAnalyzer) calculateConfidenceScore(reportData types.ReportData) float64 {
	score := 0.0

	// 基于发现数量
	if len(reportData.Findings) > 0 {
		score += 0.3
	}

	// 基于严重程度
	criticalFindings := filterFindingsBySeverity(reportData.Findings, "critical")
	if len(criticalFindings) > 0 {
		score += 0.4
	}

	// 基于扫描完整性
	if scanType, exists := reportData.Metadata["scan_type"]; exists && scanType == "exp" {
		score += 0.3
	}

	return score
}

// 实现缺失的辅助方法

// calculateTrendMetrics 计算趋势指标
func (r *ReportAnalyzer) calculateTrendMetrics(reports []types.ReportData) []string {
	var insights []string

	if len(reports) == 0 {
		return []string{"无历史数据可用于趋势分析"}
	}

	// 计算总发现数趋势
	totalFindings := 0
	for _, report := range reports {
		totalFindings += len(report.Findings)
	}
	averageFindings := float64(totalFindings) / float64(len(reports))
	insights = append(insights, fmt.Sprintf("平均每次扫描发现%.1f个问题", averageFindings))

	// 计算高风险发现趋势
	highRiskCount := 0
	for _, report := range reports {
		for _, finding := range report.Findings {
			if finding.Severity == "high" || finding.Severity == "critical" {
				highRiskCount++
			}
		}
	}
	if highRiskCount > 0 {
		insights = append(insights, fmt.Sprintf("累计发现%d个高风险问题", highRiskCount))
	}

	return insights
}

// identifyTrendImprovementAreas 识别趋势改进领域
func (r *ReportAnalyzer) identifyTrendImprovementAreas(reports []types.ReportData) []string {
	var recommendations []string

	if len(reports) < 2 {
		return []string{"需要更多历史数据来识别改进趋势"}
	}

	// 分析发现结果类型分布
	typeDistribution := make(map[string]int)
	for _, report := range reports {
		for _, finding := range report.Findings {
			typeDistribution[finding.Type]++
		}
	}

	// 识别最常见的发现类型
	for findingType, count := range typeDistribution {
		if count >= len(reports) {
			recommendations = append(recommendations, fmt.Sprintf("重点关注%s类型问题的持续改进", findingType))
		}
	}

	return recommendations
}

// findCommonFindings 查找共同发现
func (r *ReportAnalyzer) findCommonFindings(reports []types.ReportData) []types.Finding {
	if len(reports) < 2 {
		return []types.Finding{}
	}

	// 使用第一个报告作为基准
	baseReport := reports[0]
	commonFindings := []types.Finding{}

	// 查找在多个报告中都出现的发现
	for _, finding := range baseReport.Findings {
		foundInAll := true
		for _, report := range reports[1:] {
			foundInReport := false
			for _, f := range report.Findings {
				if f.Type == finding.Type && f.Severity == finding.Severity {
					foundInReport = true
					break
				}
			}
			if !foundInReport {
				foundInAll = false
				break
			}
		}
		if foundInAll {
			commonFindings = append(commonFindings, finding)
		}
	}

	return commonFindings
}

// findUniqueFindings 查找独特发现
func (r *ReportAnalyzer) findUniqueFindings(reports []types.ReportData) map[string][]types.Finding {
	uniqueFindings := make(map[string][]types.Finding)

	for i, report := range reports {
		reportKey := fmt.Sprintf("报告%d", i+1)
		uniqueFindings[reportKey] = []types.Finding{}

		// 查找该报告独有的发现
		for _, finding := range report.Findings {
			unique := true
			for j, otherReport := range reports {
				if i == j {
					continue
				}
				for _, otherFinding := range otherReport.Findings {
					if otherFinding.Type == finding.Type && otherFinding.Severity == finding.Severity {
						unique = false
						break
					}
				}
				if !unique {
					break
				}
			}
			if unique {
				uniqueFindings[reportKey] = append(uniqueFindings[reportKey], finding)
			}
		}
	}

	return uniqueFindings
}

// compareRiskLevels 比较风险级别
func (r *ReportAnalyzer) compareRiskLevels(reports []types.ReportData) map[string]string {
	riskComparison := make(map[string]string)

	for i, report := range reports {
		reportKey := fmt.Sprintf("报告%d", i+1)
		riskComparison[reportKey] = report.RiskAssessment.OverallRisk
	}

	return riskComparison
}

// analyzeImprovementTrend 分析改进趋势
func (r *ReportAnalyzer) analyzeImprovementTrend(reports []types.ReportData) string {
	if len(reports) < 2 {
		return "需要更多数据来分析改进趋势"
	}

	// 按时间排序报告
	sortedReports := make([]types.ReportData, len(reports))
	copy(sortedReports, reports)
	sort.Slice(sortedReports, func(i, j int) bool {
		return sortedReports[i].CreatedAt.Before(sortedReports[j].CreatedAt)
	})

	// 分析发现数量趋势
	firstReport := sortedReports[0]
	lastReport := sortedReports[len(sortedReports)-1]

	firstFindings := len(firstReport.Findings)
	lastFindings := len(lastReport.Findings)

	if lastFindings < firstFindings {
		improvementRate := float64(firstFindings-lastFindings) / float64(firstFindings) * 100
		return fmt.Sprintf("安全状况改善，发现问题减少%.1f%%", improvementRate)
	} else if lastFindings > firstFindings {
		return "安全状况需要关注，发现问题数量增加"
	} else {
		return "安全状况保持稳定"
	}
}

// 构建分析内容的函数

func (r *ReportAnalyzer) buildAnalysisContent(
	reportData types.ReportData,
	findingsAnalysis *FindingAnalysis,
	riskAnalysis *RiskPatternAnalysis,
	recommendations []string,
) string {
	var content strings.Builder

	content.WriteString("# 安全报告分析\n\n")
	content.WriteString(fmt.Sprintf("**分析时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// 执行概览
	content.WriteString("## 执行概览\n\n")
	if target, exists := reportData.Metadata["target"]; exists {
		content.WriteString(fmt.Sprintf("- **目标**: %s\n", target))
	}
	if scanType, exists := reportData.Metadata["scan_type"]; exists {
		content.WriteString(fmt.Sprintf("- **扫描类型**: %s\n", scanType))
	}
	content.WriteString(fmt.Sprintf("- **发现总数**: %d\n", findingsAnalysis.TotalFindings))
	content.WriteString(fmt.Sprintf("- **总体风险**: %s\n", riskAnalysis.RiskLevel))

	// 发现结果分析
	content.WriteString("\n## 发现结果分析\n\n")
	for severity, count := range findingsAnalysis.SeverityBreakdown {
		content.WriteString(fmt.Sprintf("- **%s**: %d个\n", severity, count))
	}

	// 常见模式
	if len(findingsAnalysis.CommonPatterns) > 0 {
		content.WriteString("\n## 常见模式\n\n")
		for _, pattern := range findingsAnalysis.CommonPatterns {
			content.WriteString(fmt.Sprintf("- %s\n", pattern))
		}
	}

	// 风险分析
	content.WriteString("\n## 风险分析\n\n")
	for _, factor := range riskAnalysis.RiskFactors {
		content.WriteString(fmt.Sprintf("- %s\n", factor))
	}

	// 优化建议
	content.WriteString("\n## 优化建议\n\n")
	for i, recommendation := range recommendations {
		content.WriteString(fmt.Sprintf("%d. %s\n", i+1, recommendation))
	}

	return content.String()
}

func (r *ReportAnalyzer) buildTrendAnalysisContent(reports []types.ReportData, trendData *types.TrendAnalysis) string {
	var content strings.Builder

	content.WriteString("# 安全趋势分析\n\n")
	content.WriteString(fmt.Sprintf("**分析时间范围**: %s 至 %s\n\n",
		trendData.StartDate.Format("2006-01-02"), trendData.EndDate.Format("2006-01-02")))
	content.WriteString(fmt.Sprintf("**分析报告数量**: %d\n\n", trendData.TotalTasks))

	// 趋势指标
	content.WriteString("## 趋势指标\n\n")
	content.WriteString(fmt.Sprintf("- **总任务数**: %d\n", trendData.TotalTasks))
	content.WriteString(fmt.Sprintf("- **成功率**: %.2f%%\n", trendData.SuccessRate))
	content.WriteString(fmt.Sprintf("- **平均耗时**: %.2f秒\n", trendData.AvgDuration))
	content.WriteString(fmt.Sprintf("- **严重发现数**: %d\n", trendData.CriticalFindings))
	content.WriteString(fmt.Sprintf("- **高危发现数**: %d\n", trendData.HighFindings))
	content.WriteString(fmt.Sprintf("- **趋势**: %s\n", trendData.Trend))

	// 分析洞察
	if len(trendData.Insights) > 0 {
		content.WriteString("\n## 分析洞察\n\n")
		for _, insight := range trendData.Insights {
			content.WriteString(fmt.Sprintf("- %s\n", insight))
		}
	}

	// 改进建议
	if len(trendData.Recommendations) > 0 {
		content.WriteString("\n## 改进建议\n\n")
		for _, recommendation := range trendData.Recommendations {
			content.WriteString(fmt.Sprintf("- %s\n", recommendation))
		}
	}

	return content.String()
}

func (r *ReportAnalyzer) buildComparisonContent(reports []types.ReportData, comparisonData *ComparisonAnalysis) string {
	var content strings.Builder

	content.WriteString("# 安全报告比较分析\n\n")
	content.WriteString(fmt.Sprintf("**比较报告数量**: %d\n\n", comparisonData.ReportCount))

	// 共同发现
	content.WriteString("## 共同发现\n\n")
	if len(comparisonData.CommonFindings) > 0 {
		for i, finding := range comparisonData.CommonFindings {
			content.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, finding.Title, finding.Severity))
		}
	} else {
		content.WriteString("无共同发现\n\n")
	}

	// 风险比较
	content.WriteString("\n## 风险比较\n\n")
	for reportTarget, riskLevel := range comparisonData.RiskComparison {
		content.WriteString(fmt.Sprintf("- **%s**: %s\n", reportTarget, riskLevel))
	}

	// 改进趋势
	content.WriteString("\n## 改进趋势\n\n")
	content.WriteString(fmt.Sprintf("%s\n", comparisonData.ImprovementTrend))

	return content.String()
}

// 辅助数据结构

type FindingAnalysis struct {
	TotalFindings     int
	SeverityBreakdown map[string]int
	TypeBreakdown     map[string]int
	CommonPatterns    []string
	TopRisks          []types.Finding
}

type RiskPatternAnalysis struct {
	RiskLevel        string
	RiskFactors      []string
	ImprovementAreas []string
	ConfidenceScore  float64
}

// TrendAnalysis 趋势分析结构体（已移至types包）
// type TrendAnalysis = types.TrendAnalysis

type TrendMetric struct {
	CurrentValue  string
	PreviousValue string
	Trend         string
}

type ComparisonAnalysis struct {
	ReportCount      int
	CommonFindings   []types.Finding
	UniqueFindings   map[string][]types.Finding
	RiskComparison   map[string]string
	ImprovementTrend string
}

// 工具函数

func generateAnalysisID() string {
	return fmt.Sprintf("analysis-%d", time.Now().Unix())
}

func extractTaskIDFromReport(reportData types.ReportData) string {
	// 从报告标题中提取任务ID
	re := regexp.MustCompile(`任务ID: (\S+)`)
	matches := re.FindStringSubmatch(reportData.Summary)
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}

func calculateTimeRange(reports []types.ReportData) string {
	if len(reports) == 0 {
		return "无数据"
	}

	// 获取最早和最晚的报告时间
	earliest := reports[0].CreatedAt
	latest := reports[0].CreatedAt

	for _, report := range reports {
		if report.CreatedAt.Before(earliest) {
			earliest = report.CreatedAt
		}
		if report.CreatedAt.After(latest) {
			latest = report.CreatedAt
		}
	}

	return fmt.Sprintf("%s 至 %s",
		earliest.Format("2006-01-02"),
		latest.Format("2006-01-02"))
}

func filterFindingsByType(findings []types.Finding, findingType string) []types.Finding {
	var result []types.Finding

	for _, finding := range findings {
		if strings.Contains(strings.ToLower(finding.Type), strings.ToLower(findingType)) {
			result = append(result, finding)
		}
	}

	return result
}
