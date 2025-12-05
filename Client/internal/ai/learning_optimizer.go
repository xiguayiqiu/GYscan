package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// LearningOptimizer 学习优化器
type LearningOptimizer struct {
	dataPath     string
	aiClient     *AIClient
	toolManager  *ToolManager
	learningData *LearningData
}

// LearningData 学习数据
type LearningData struct {
	PerformanceMetrics []PerformanceMetric `json:"performance_metrics"`
	Patterns           []Pattern           `json:"patterns"`
	Optimizations      []Optimization      `json:"optimizations"`
	LastUpdated        time.Time           `json:"last_updated"`
}

// PerformanceMetric 性能指标
type PerformanceMetric struct {
	Timestamp     time.Time `json:"timestamp"`
	MetricType    string    `json:"metric_type"`
	Value         float64   `json:"value"`
	Target        string    `json:"target"`
	ScanType      string    `json:"scan_type"`
	SuccessRate   float64   `json:"success_rate"`
	FalsePositive float64   `json:"false_positive"`
}

// Pattern 模式识别
type Pattern struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Pattern     string    `json:"pattern"`
	Confidence  float64   `json:"confidence"`
	Occurrences int       `json:"occurrences"`
	LastSeen    time.Time `json:"last_seen"`
	Impact      string    `json:"impact"`
}

// Optimization 优化建议
type Optimization struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Description   string    `json:"description"`
	Impact        string    `json:"impact"`
	Priority      string    `json:"priority"`
	Applied       bool      `json:"applied"`
	AppliedAt     time.Time `json:"applied_at"`
	Effectiveness float64   `json:"effectiveness"`
}

// NewLearningOptimizer 创建新的学习优化器
func NewLearningOptimizer(dataPath string, aiClient *AIClient, toolManager *ToolManager) (*LearningOptimizer, error) {
	optimizer := &LearningOptimizer{
		dataPath:    dataPath,
		aiClient:    aiClient,
		toolManager: toolManager,
	}

	// 加载学习数据
	if err := optimizer.loadLearningData(); err != nil {
		utils.WarningPrint("无法加载学习数据，将创建新数据: %v", err)
		optimizer.learningData = &LearningData{
			LastUpdated: time.Now(),
		}
	}

	return optimizer, nil
}

// RecordPerformance 记录性能指标
func (l *LearningOptimizer) RecordPerformance(metric PerformanceMetric) error {
	utils.InfoPrint("记录性能指标: %s", metric.MetricType)

	metric.Timestamp = time.Now()
	l.learningData.PerformanceMetrics = append(l.learningData.PerformanceMetrics, metric)

	// 保持性能指标数量在合理范围内
	if len(l.learningData.PerformanceMetrics) > 1000 {
		l.learningData.PerformanceMetrics = l.learningData.PerformanceMetrics[100:]
	}

	l.learningData.LastUpdated = time.Now()
	return l.saveLearningData()
}

// AnalyzePatterns 分析模式
func (l *LearningOptimizer) AnalyzePatterns(taskData types.Task, findings []types.Finding) error {
	utils.InfoPrint("分析安全模式...")

	// 分析目标类型模式
	targetPatterns := l.analyzeTargetPatterns(taskData, findings)
	l.learningData.Patterns = append(l.learningData.Patterns, targetPatterns...)

	// 分析漏洞模式
	vulnerabilityPatterns := l.analyzeVulnerabilityPatterns(findings)
	l.learningData.Patterns = append(l.learningData.Patterns, vulnerabilityPatterns...)

	// 分析工具效果模式
	toolPatterns := l.analyzeToolPatterns(taskData)
	l.learningData.Patterns = append(l.learningData.Patterns, toolPatterns...)

	l.learningData.LastUpdated = time.Now()
	return l.saveLearningData()
}

// GenerateOptimizations 生成优化建议
func (l *LearningOptimizer) GenerateOptimizations() ([]Optimization, error) {
	utils.InfoPrint("生成优化建议...")

	var optimizations []Optimization

	// 基于性能指标生成优化
	performanceOpts := l.generatePerformanceOptimizations()
	optimizations = append(optimizations, performanceOpts...)

	// 基于模式分析生成优化
	patternOpts := l.generatePatternOptimizations()
	optimizations = append(optimizations, patternOpts...)

	// 基于工具效果生成优化
	toolOpts := l.generateToolOptimizations()
	optimizations = append(optimizations, toolOpts...)

	// 保存优化建议
	l.learningData.Optimizations = append(l.learningData.Optimizations, optimizations...)
	l.learningData.LastUpdated = time.Now()

	if err := l.saveLearningData(); err != nil {
		return nil, err
	}

	utils.SuccessPrint("生成%d个优化建议", len(optimizations))
	return optimizations, nil
}

// ApplyOptimization 应用优化建议
func (l *LearningOptimizer) ApplyOptimization(optimizationID string) error {
	utils.InfoPrint("应用优化建议: %s", optimizationID)

	for i, opt := range l.learningData.Optimizations {
		if opt.ID == optimizationID && !opt.Applied {
			// 应用优化
			if err := l.applySpecificOptimization(opt); err != nil {
				return fmt.Errorf("应用优化失败: %v", err)
			}

			// 更新优化状态
			l.learningData.Optimizations[i].Applied = true
			l.learningData.Optimizations[i].AppliedAt = time.Now()
			l.learningData.LastUpdated = time.Now()

			if err := l.saveLearningData(); err != nil {
				return err
			}

			utils.SuccessPrint("优化建议已应用")
			return nil
		}
	}

	return fmt.Errorf("未找到优化建议或已应用: %s", optimizationID)
}

// GetPerformanceReport 获取性能报告
func (l *LearningOptimizer) GetPerformanceReport() (*PerformanceReport, error) {
	utils.InfoPrint("生成性能报告...")

	report := &PerformanceReport{
		GeneratedAt:     time.Now(),
		Metrics:         make(map[string]PerformanceSummary),
		Trends:          []TrendAnalysis{},
		Recommendations: []string{},
	}

	// 分析性能指标
	if err := l.analyzePerformanceMetrics(report); err != nil {
		return nil, err
	}

	// 分析趋势
	if err := l.analyzeTrends(report); err != nil {
		return nil, err
	}

	// 生成建议
	report.Recommendations = l.generatePerformanceRecommendations(report)

	utils.SuccessPrint("性能报告生成完成")
	return report, nil
}

// 模式分析函数

func (l *LearningOptimizer) analyzeTargetPatterns(taskData types.Task, findings []types.Finding) []Pattern {
	var patterns []Pattern

	// 分析目标类型与漏洞关联
	targetType := taskData.Type // 使用任务类型作为目标类型
	vulnerabilityTypes := make(map[string]int)

	for _, finding := range findings {
		vulnerabilityTypes[finding.Type]++
	}

	for vulnType, count := range vulnerabilityTypes {
		if count >= 2 { // 至少出现两次才认为是模式
			pattern := Pattern{
				ID:          fmt.Sprintf("target-%s-%s", targetType, vulnType),
				Type:        "target_vulnerability",
				Pattern:     fmt.Sprintf("%s目标类型常见%s漏洞", targetType, vulnType),
				Confidence:  float64(count) / float64(len(findings)),
				Occurrences: count,
				LastSeen:    time.Now(),
				Impact:      "高",
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

func (l *LearningOptimizer) analyzeVulnerabilityPatterns(findings []types.Finding) []Pattern {
	var patterns []Pattern

	// 分析漏洞组合模式
	vulnerabilityCombinations := make(map[string]int)

	for i := 0; i < len(findings)-1; i++ {
		for j := i + 1; j < len(findings); j++ {
			combination := fmt.Sprintf("%s+%s", findings[i].Type, findings[j].Type)
			vulnerabilityCombinations[combination]++
		}
	}

	for combination, count := range vulnerabilityCombinations {
		if count >= 2 {
			pattern := Pattern{
				ID:          fmt.Sprintf("vuln-combination-%s", strings.ReplaceAll(combination, "+", "-")),
				Type:        "vulnerability_combination",
				Pattern:     fmt.Sprintf("漏洞组合模式: %s", combination),
				Confidence:  float64(count) / float64(len(findings)*(len(findings)-1)/2),
				Occurrences: count,
				LastSeen:    time.Now(),
				Impact:      "中",
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

func (l *LearningOptimizer) analyzeToolPatterns(taskData types.Task) []Pattern {
	var patterns []Pattern

	// 分析工具使用效果
	toolEffectiveness := make(map[string]int)

	for _, step := range taskData.Steps {
		if step.Status == "completed" && step.Results != "" {
			toolEffectiveness[step.Name]++ // 使用步骤名称作为工具标识
		}
	}

	for tool, effectiveness := range toolEffectiveness {
		pattern := Pattern{
			ID:          fmt.Sprintf("tool-effectiveness-%s", tool),
			Type:        "tool_effectiveness",
			Pattern:     fmt.Sprintf("工具%s在%s类型目标上效果良好", tool, taskData.Type),
			Confidence:  float64(effectiveness) / float64(len(taskData.Steps)),
			Occurrences: effectiveness,
			LastSeen:    time.Now(),
			Impact:      "低",
		}
		patterns = append(patterns, pattern)
	}

	return patterns
}

// 优化生成函数

func (l *LearningOptimizer) generatePerformanceOptimizations() []Optimization {
	var optimizations []Optimization

	// 分析最近性能指标
	recentMetrics := l.getRecentMetrics(30) // 最近30天的指标

	if len(recentMetrics) == 0 {
		return optimizations
	}

	// 分析成功率
	successRate := l.calculateAverageSuccessRate(recentMetrics)
	if successRate < 0.8 {
		optimizations = append(optimizations, Optimization{
			ID:          "opt-success-rate-low",
			Type:        "performance",
			Description: "检测成功率较低，建议优化扫描策略",
			Impact:      "高",
			Priority:    "high",
			Applied:     false,
		})
	}

	// 分析误报率
	falsePositiveRate := l.calculateAverageFalsePositiveRate(recentMetrics)
	if falsePositiveRate > 0.2 {
		optimizations = append(optimizations, Optimization{
			ID:          "opt-false-positive-high",
			Type:        "accuracy",
			Description: "误报率较高，建议优化检测规则",
			Impact:      "中",
			Priority:    "medium",
			Applied:     false,
		})
	}

	return optimizations
}

func (l *LearningOptimizer) generatePatternOptimizations() []Optimization {
	var optimizations []Optimization

	// 基于高频模式生成优化
	recentPatterns := l.getRecentPatterns(30)

	for _, pattern := range recentPatterns {
		if pattern.Confidence > 0.7 && pattern.Occurrences >= 3 {
			optimization := Optimization{
				ID:          fmt.Sprintf("opt-pattern-%s", pattern.ID),
				Type:        "pattern_based",
				Description: fmt.Sprintf("基于模式'%s'优化检测策略", pattern.Pattern),
				Impact:      pattern.Impact,
				Priority:    "medium",
				Applied:     false,
			}
			optimizations = append(optimizations, optimization)
		}
	}

	return optimizations
}

func (l *LearningOptimizer) generateToolOptimizations() []Optimization {
	var optimizations []Optimization

	// 分析工具使用模式
	toolUsage := make(map[string]int)
	for _, metric := range l.learningData.PerformanceMetrics {
		toolUsage[metric.Target]++
	}

	// 识别使用频率低的工具
	for tool, usage := range toolUsage {
		if usage < 5 { // 使用次数少于5次
			optimizations = append(optimizations, Optimization{
				ID:          fmt.Sprintf("opt-tool-usage-%s", tool),
				Type:        "tool_usage",
				Description: fmt.Sprintf("工具%s使用频率较低，考虑优化或替换", tool),
				Impact:      "低",
				Priority:    "low",
				Applied:     false,
			})
		}
	}

	return optimizations
}

// 应用优化函数

func (l *LearningOptimizer) applySpecificOptimization(optimization Optimization) error {
	switch optimization.Type {
	case "performance":
		return l.applyPerformanceOptimization(optimization)
	case "accuracy":
		return l.applyAccuracyOptimization(optimization)
	case "pattern_based":
		return l.applyPatternOptimization(optimization)
	case "tool_usage":
		return l.applyToolUsageOptimization(optimization)
	default:
		return fmt.Errorf("未知的优化类型: %s", optimization.Type)
	}
}

func (l *LearningOptimizer) applyPerformanceOptimization(optimization Optimization) error {
	// 实现性能优化逻辑
	utils.InfoPrint("应用性能优化: %s", optimization.Description)
	return nil
}

func (l *LearningOptimizer) applyAccuracyOptimization(optimization Optimization) error {
	// 实现准确率优化逻辑
	utils.InfoPrint("应用准确率优化: %s", optimization.Description)
	return nil
}

func (l *LearningOptimizer) applyPatternOptimization(optimization Optimization) error {
	// 实现基于模式的优化逻辑
	utils.InfoPrint("应用模式优化: %s", optimization.Description)
	return nil
}

func (l *LearningOptimizer) applyToolUsageOptimization(optimization Optimization) error {
	// 实现工具使用优化逻辑
	utils.InfoPrint("应用工具使用优化: %s", optimization.Description)
	return nil
}

// 性能报告相关函数

func (l *LearningOptimizer) analyzePerformanceMetrics(report *PerformanceReport) error {
	if len(l.learningData.PerformanceMetrics) == 0 {
		return fmt.Errorf("无性能数据可供分析")
	}

	// 按指标类型分组
	metricsByType := make(map[string][]PerformanceMetric)
	for _, metric := range l.learningData.PerformanceMetrics {
		metricsByType[metric.MetricType] = append(metricsByType[metric.MetricType], metric)
	}

	// 计算每个指标类型的统计信息
	for metricType, metrics := range metricsByType {
		summary := PerformanceSummary{
			Count:         len(metrics),
			AverageValue:  l.calculateAverageValue(metrics),
			MinValue:      l.calculateMinValue(metrics),
			MaxValue:      l.calculateMaxValue(metrics),
			SuccessRate:   l.calculateAverageSuccessRate(metrics),
			FalsePositive: l.calculateAverageFalsePositiveRate(metrics),
		}
		report.Metrics[metricType] = summary
	}

	return nil
}

func (l *LearningOptimizer) analyzeTrends(report *PerformanceReport) error {
	// 分析性能趋势
	recentMetrics := l.getRecentMetrics(7) // 最近7天
	if len(recentMetrics) < 2 {
		return nil // 数据不足，无法分析趋势
	}

	// 按时间排序
	sort.Slice(recentMetrics, func(i, j int) bool {
		return recentMetrics[i].Timestamp.Before(recentMetrics[j].Timestamp)
	})

	// 分析趋势
	firstValue := recentMetrics[0].Value
	lastValue := recentMetrics[len(recentMetrics)-1].Value

	trend := "稳定"
	if lastValue > firstValue*1.1 {
		trend = "上升"
	} else if lastValue < firstValue*0.9 {
		trend = "下降"
	}

	trendAnalysis := types.TrendAnalysis{
		ID:          fmt.Sprintf("trend_%s", time.Now().Format("20060102150405")),
		Type:        "performance",
		Period:      "weekly",
		StartDate:   time.Now().AddDate(0, 0, -7),
		EndDate:     time.Now(),
		TotalTasks:  1,
		SuccessRate: 1.0,
		AvgDuration: lastValue,
		Trend:       trend,
		CreatedAt:   time.Now(),
	}

	if trend == "上升" {
		trendAnalysis.Insights = []string{"性能指标呈现上升趋势"}
		trendAnalysis.Recommendations = []string{"继续保持当前优化策略"}
	} else if trend == "下降" {
		trendAnalysis.Insights = []string{"性能指标呈现下降趋势"}
		trendAnalysis.Recommendations = []string{"需要优化检测策略"}
	}

	report.Trends = append(report.Trends, trendAnalysis)

	return nil
}

func (l *LearningOptimizer) generatePerformanceRecommendations(report *PerformanceReport) []string {
	var recommendations []string

	// 基于性能指标生成建议
	for metricType, summary := range report.Metrics {
		if summary.SuccessRate < 0.8 {
			recommendations = append(recommendations,
				fmt.Sprintf("优化%s检测策略以提高成功率", metricType))
		}

		if summary.FalsePositive > 0.2 {
			recommendations = append(recommendations,
				fmt.Sprintf("优化%s检测规则以降低误报率", metricType))
		}
	}

	// 基于趋势生成建议
	for _, trend := range report.Trends {
		if trend.Trend == "下降" {
			recommendations = append(recommendations,
				fmt.Sprintf("注意%s性能下降趋势，需要及时优化", trend.Type))
		}
	}

	return recommendations
}

// 数据管理函数

func (l *LearningOptimizer) loadLearningData() error {
	dataFile := filepath.Join(l.dataPath, "learning_data.json")

	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		return err
	}

	data, err := os.ReadFile(dataFile)
	if err != nil {
		return err
	}

	var learningData LearningData
	if err := json.Unmarshal(data, &learningData); err != nil {
		return err
	}

	l.learningData = &learningData
	return nil
}

func (l *LearningOptimizer) saveLearningData() error {
	if err := os.MkdirAll(l.dataPath, 0755); err != nil {
		return err
	}

	dataFile := filepath.Join(l.dataPath, "learning_data.json")

	data, err := json.MarshalIndent(l.learningData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dataFile, data, 0644)
}

// 工具函数

func (l *LearningOptimizer) getRecentMetrics(days int) []PerformanceMetric {
	var recent []PerformanceMetric
	cutoff := time.Now().AddDate(0, 0, -days)

	for _, metric := range l.learningData.PerformanceMetrics {
		if metric.Timestamp.After(cutoff) {
			recent = append(recent, metric)
		}
	}

	return recent
}

func (l *LearningOptimizer) getRecentPatterns(days int) []Pattern {
	var recent []Pattern
	cutoff := time.Now().AddDate(0, 0, -days)

	for _, pattern := range l.learningData.Patterns {
		if pattern.LastSeen.After(cutoff) {
			recent = append(recent, pattern)
		}
	}

	return recent
}

func (l *LearningOptimizer) calculateAverageValue(metrics []PerformanceMetric) float64 {
	if len(metrics) == 0 {
		return 0
	}

	sum := 0.0
	for _, metric := range metrics {
		sum += metric.Value
	}

	return sum / float64(len(metrics))
}

func (l *LearningOptimizer) calculateMinValue(metrics []PerformanceMetric) float64 {
	if len(metrics) == 0 {
		return 0
	}

	min := metrics[0].Value
	for _, metric := range metrics {
		if metric.Value < min {
			min = metric.Value
		}
	}

	return min
}

func (l *LearningOptimizer) calculateMaxValue(metrics []PerformanceMetric) float64 {
	if len(metrics) == 0 {
		return 0
	}

	max := metrics[0].Value
	for _, metric := range metrics {
		if metric.Value > max {
			max = metric.Value
		}
	}

	return max
}

func (l *LearningOptimizer) calculateAverageSuccessRate(metrics []PerformanceMetric) float64 {
	if len(metrics) == 0 {
		return 0
	}

	sum := 0.0
	count := 0

	for _, metric := range metrics {
		if metric.SuccessRate > 0 {
			sum += metric.SuccessRate
			count++
		}
	}

	if count == 0 {
		return 0
	}

	return sum / float64(count)
}

func (l *LearningOptimizer) calculateAverageFalsePositiveRate(metrics []PerformanceMetric) float64 {
	if len(metrics) == 0 {
		return 0
	}

	sum := 0.0
	count := 0

	for _, metric := range metrics {
		if metric.FalsePositive > 0 {
			sum += metric.FalsePositive
			count++
		}
	}

	if count == 0 {
		return 0
	}

	return sum / float64(count)
}

// 性能报告数据结构

type PerformanceReport struct {
	GeneratedAt     time.Time                     `json:"generated_at"`
	Metrics         map[string]PerformanceSummary `json:"metrics"`
	Trends          []TrendAnalysis               `json:"trends"`
	Recommendations []string                      `json:"recommendations"`
}

type PerformanceSummary struct {
	Count         int     `json:"count"`
	AverageValue  float64 `json:"average_value"`
	MinValue      float64 `json:"min_value"`
	MaxValue      float64 `json:"max_value"`
	SuccessRate   float64 `json:"success_rate"`
	FalsePositive float64 `json:"false_positive"`
}

// TrendAnalysis 趋势分析结构体（已移至types包）
type TrendAnalysis = types.TrendAnalysis
