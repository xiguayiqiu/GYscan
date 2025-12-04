package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"GYscan/internal/utils"
)

// AdaptiveDecisionSystem 自适应决策系统
type AdaptiveDecisionSystem struct {
	decisionRules   []DecisionRule
	learningModels  map[string]LearningModel
	performanceData map[string][]PerformanceRecord
	aiClient        *AIClient
	toolManager     *ToolManager
	dataPath        string
	config          DecisionConfig
}

// DecisionRule 决策规则
type DecisionRule struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"` // "tool_selection", "scan_strategy", "risk_assessment"
	Conditions  []DecisionCondition `json:"conditions"`
	Actions     []DecisionAction    `json:"actions"`
	Priority    int                 `json:"priority"`
	Confidence  float64             `json:"confidence"`
	Enabled     bool                `json:"enabled"`
	LastUsed    time.Time           `json:"last_used"`
	SuccessRate float64             `json:"success_rate"`
}

// DecisionCondition 决策条件
type DecisionCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "==", "!=", ">", "<", ">=", "<=", "contains", "matches"
	Value    interface{} `json:"value"`
	Weight   float64     `json:"weight"`
}

// DecisionAction 决策动作
type DecisionAction struct {
	Type       string                 `json:"type"` // "select_tool", "set_parameter", "change_strategy"
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
	Confidence float64                `json:"confidence"`
}

// LearningModel 学习模型
type LearningModel struct {
	ModelID     string                 `json:"model_id"`
	ModelType   string                 `json:"model_type"` // "classification", "regression", "clustering"
	Features    []string               `json:"features"`
	Parameters  map[string]interface{} `json:"parameters"`
	Accuracy    float64                `json:"accuracy"`
	LastTrained time.Time              `json:"last_trained"`
	Enabled     bool                   `json:"enabled"`
}

// PerformanceRecord 性能记录
type PerformanceRecord struct {
	RecordID  string             `json:"record_id"`
	Context   DecisionContext    `json:"context"`
	Decision  DecisionResult     `json:"decision"`
	Outcome   DecisionOutcome    `json:"outcome"`
	Timestamp time.Time          `json:"timestamp"`
	Metrics   PerformanceMetrics `json:"metrics"`
}

// DecisionContext 决策上下文
type DecisionContext struct {
	Target          string                 `json:"target"`
	ScanType        string                 `json:"scan_type"`
	Environment     map[string]interface{} `json:"environment"`
	Constraints     map[string]interface{} `json:"constraints"`
	PreviousResults []interface{}          `json:"previous_results"`
}

// DecisionResult 决策结果
type DecisionResult struct {
	RuleID     string           `json:"rule_id"`
	Actions    []DecisionAction `json:"actions"`
	Confidence float64          `json:"confidence"`
	Reasoning  string           `json:"reasoning"`
}

// DecisionOutcome 决策结果
type DecisionOutcome struct {
	Success       bool                   `json:"success"`
	Effectiveness float64                `json:"effectiveness"`
	Impact        string                 `json:"impact"` // "positive", "neutral", "negative"
	Details       map[string]interface{} `json:"details"`
	Lessons       []string               `json:"lessons"`
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
	ExecutionTime float64 `json:"execution_time"`
	ResourceUsage float64 `json:"resource_usage"`
	SuccessRate   float64 `json:"success_rate"`
	Accuracy      float64 `json:"accuracy"`
	Efficiency    float64 `json:"efficiency"`
}

// DecisionConfig 决策配置
type DecisionConfig struct {
	LearningEnabled     bool    `json:"learning_enabled"`
	AdaptationRate      float64 `json:"adaptation_rate"`
	ConfidenceThreshold float64 `json:"confidence_threshold"`
	MaxRules            int     `json:"max_rules"`
	RetentionPeriod     int     `json:"retention_period"` // 天数
}

// NewAdaptiveDecisionSystem 创建新的自适应决策系统
func NewAdaptiveDecisionSystem(dataPath string, aiClient *AIClient, toolManager *ToolManager) (*AdaptiveDecisionSystem, error) {
	ads := &AdaptiveDecisionSystem{
		learningModels:  make(map[string]LearningModel),
		performanceData: make(map[string][]PerformanceRecord),
		aiClient:        aiClient,
		toolManager:     toolManager,
		dataPath:        dataPath,
		config: DecisionConfig{
			LearningEnabled:     true,
			AdaptationRate:      0.1,
			ConfidenceThreshold: 0.7,
			MaxRules:            100,
			RetentionPeriod:     30,
		},
	}

	// 加载决策规则
	if err := ads.loadDecisionRules(); err != nil {
		utils.WarningPrint("无法加载决策规则，将使用默认规则: %v", err)
		ads.initializeDefaultRules()
	}

	// 加载学习模型
	if err := ads.loadLearningModels(); err != nil {
		utils.InfoPrint("无法加载学习模型，将初始化新模型")
	}

	// 加载性能数据
	if err := ads.loadPerformanceData(); err != nil {
		utils.InfoPrint("无法加载性能数据，将初始化新数据集")
	}

	utils.SuccessPrint("自适应决策系统初始化完成")
	return ads, nil
}

// MakeDecision 基于上下文做出决策
func (a *AdaptiveDecisionSystem) MakeDecision(context DecisionContext) (*DecisionResult, error) {
	utils.InfoPrint("开始决策过程...")

	// 评估所有适用的规则
	applicableRules := a.evaluateRules(context)

	if len(applicableRules) == 0 {
		// 如果没有适用的规则，使用AI进行决策
		return a.makeAIDecision(context)
	}

	// 选择最佳规则
	bestRule := a.selectBestRule(applicableRules, context)

	// 执行决策动作
	result := &DecisionResult{
		RuleID:     bestRule.ID,
		Actions:    bestRule.Actions,
		Confidence: bestRule.Confidence,
		Reasoning:  a.generateReasoning(bestRule, context),
	}

	// 记录决策
	a.recordDecision(context, result, nil)

	utils.SuccessPrint("决策完成，置信度: %.2f", result.Confidence)
	return result, nil
}

// EvaluateDecision 评估决策效果
func (a *AdaptiveDecisionSystem) EvaluateDecision(context DecisionContext, result DecisionResult, outcome DecisionOutcome) error {
	utils.InfoPrint("评估决策效果...")

	// 更新规则的成功率
	a.updateRulePerformance(result.RuleID, outcome)

	// 记录性能数据
	record := PerformanceRecord{
		RecordID:  generateRecordID(),
		Context:   context,
		Decision:  result,
		Outcome:   outcome,
		Timestamp: time.Now(),
		Metrics:   a.calculatePerformanceMetrics(outcome),
	}

	a.addPerformanceRecord(record)

	// 如果学习功能启用，进行模型训练
	if a.config.LearningEnabled {
		go a.trainLearningModels()
	}

	utils.SuccessPrint("决策评估完成")
	return nil
}

// OptimizeRules 优化决策规则
func (a *AdaptiveDecisionSystem) OptimizeRules() error {
	utils.InfoPrint("开始优化决策规则...")

	// 分析性能数据
	analysis := a.analyzePerformanceData()

	// 基于分析结果优化规则
	a.applyOptimizations(analysis)

	// 清理过时的规则和数据
	a.cleanupOldData()

	utils.SuccessPrint("决策规则优化完成")
	return nil
}

// GetDecisionInsights 获取决策洞察
func (a *AdaptiveDecisionSystem) GetDecisionInsights(days int) (*DecisionInsights, error) {
	utils.InfoPrint("生成决策洞察...")

	insights := &DecisionInsights{
		GeneratedAt:     time.Now(),
		Period:          fmt.Sprintf("最近%d天", days),
		KeyMetrics:      make(map[string]interface{}),
		Trends:          make(map[string]TrendAnalysis),
		Recommendations: []string{},
	}

	// 分析性能趋势
	a.analyzeDecisionTrends(days, insights)

	// 生成洞察和建议
	a.generateInsights(insights)

	utils.SuccessPrint("决策洞察生成完成")
	return insights, nil
}

// 规则评估和选择函数

func (a *AdaptiveDecisionSystem) evaluateRules(context DecisionContext) []DecisionRule {
	var applicableRules []DecisionRule

	for _, rule := range a.decisionRules {
		if !rule.Enabled {
			continue
		}

		if a.ruleMatchesContext(rule, context) {
			applicableRules = append(applicableRules, rule)
		}
	}

	return applicableRules
}

func (a *AdaptiveDecisionSystem) ruleMatchesContext(rule DecisionRule, context DecisionContext) bool {
	matchScore := 0.0
	totalWeight := 0.0

	for _, condition := range rule.Conditions {
		if a.conditionMatches(condition, context) {
			matchScore += condition.Weight
		}
		totalWeight += condition.Weight
	}

	// 计算匹配度
	matchRatio := matchScore / totalWeight

	return matchRatio >= a.config.ConfidenceThreshold
}

func (a *AdaptiveDecisionSystem) conditionMatches(condition DecisionCondition, context DecisionContext) bool {
	// 根据字段类型获取值
	var actualValue interface{}

	switch condition.Field {
	case "target_type":
		actualValue = context.Environment["target_type"]
	case "scan_type":
		actualValue = context.ScanType
	case "risk_level":
		actualValue = context.Environment["risk_level"]
	default:
		actualValue = context.Environment[condition.Field]
	}

	if actualValue == nil {
		return false
	}

	// 根据操作符进行匹配
	return a.compareValues(actualValue, condition.Value, condition.Operator)
}

func (a *AdaptiveDecisionSystem) compareValues(actual, expected interface{}, operator string) bool {
	switch operator {
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	case "contains":
		if actualStr, ok := actual.(string); ok {
			if expectedStr, ok := expected.(string); ok {
				return strings.Contains(actualStr, expectedStr)
			}
		}
		return false
	case "matches":
		if actualStr, ok := actual.(string); ok {
			if expectedStr, ok := expected.(string); ok {
				return strings.Contains(strings.ToLower(actualStr), strings.ToLower(expectedStr))
			}
		}
		return false
	default:
		// 数值比较
		return a.compareNumericValues(actual, expected, operator)
	}
}

func (a *AdaptiveDecisionSystem) compareNumericValues(actual, expected interface{}, operator string) bool {
	actualFloat, ok1 := toFloat64(actual)
	expectedFloat, ok2 := toFloat64(expected)

	if !ok1 || !ok2 {
		return false
	}

	switch operator {
	case ">":
		return actualFloat > expectedFloat
	case "<":
		return actualFloat < expectedFloat
	case ">=":
		return actualFloat >= expectedFloat
	case "<=":
		return actualFloat <= expectedFloat
	default:
		return false
	}
}

func (a *AdaptiveDecisionSystem) selectBestRule(rules []DecisionRule, context DecisionContext) DecisionRule {
	if len(rules) == 1 {
		return rules[0]
	}

	// 根据优先级、置信度和成功率排序
	sort.Slice(rules, func(i, j int) bool {
		scoreI := a.calculateRuleScore(rules[i], context)
		scoreJ := a.calculateRuleScore(rules[j], context)
		return scoreI > scoreJ
	})

	return rules[0]
}

func (a *AdaptiveDecisionSystem) calculateRuleScore(rule DecisionRule, context DecisionContext) float64 {
	// 基础分数：优先级 + 置信度 + 成功率
	baseScore := float64(rule.Priority)*0.3 + rule.Confidence*0.4 + rule.SuccessRate*0.3

	// 上下文适配度
	contextScore := a.calculateContextAdaptation(rule, context)

	return baseScore * contextScore
}

func (a *AdaptiveDecisionSystem) calculateContextAdaptation(rule DecisionRule, context DecisionContext) float64 {
	// 简化实现：基于规则最后使用时间和上下文匹配度
	timeFactor := 1.0
	if !rule.LastUsed.IsZero() {
		daysSinceLastUse := time.Since(rule.LastUsed).Hours() / 24
		timeFactor = math.Max(0.5, 1.0-daysSinceLastUse/30.0) // 30天内线性衰减
	}

	return timeFactor
}

// AI决策函数

func (a *AdaptiveDecisionSystem) makeAIDecision(context DecisionContext) (*DecisionResult, error) {
	utils.InfoPrint("使用AI进行决策...")

	// 准备AI分析数据
	analysisData := map[string]interface{}{
		"context":         context,
		"available_rules": len(a.decisionRules),
		"timestamp":       time.Now(),
	}

	// 调用AI进行分析
	aiResult, err := a.aiClient.Analyze(analysisData)
	if err != nil {
		return nil, fmt.Errorf("AI决策失败: %v", err)
	}

	// 解析AI结果
	result := a.parseAIResult(aiResult, context)

	// 创建新的决策规则
	newRule := a.createRuleFromAIDecision(result, context)
	a.addDecisionRule(newRule)

	return result, nil
}

func (a *AdaptiveDecisionSystem) parseAIResult(aiResult interface{}, context DecisionContext) *DecisionResult {
	// 简化实现：基于AI分析生成决策结果
	return &DecisionResult{
		RuleID:     "ai-generated",
		Actions:    []DecisionAction{},
		Confidence: 0.8,
		Reasoning:  "基于AI分析生成的决策",
	}
}

func (a *AdaptiveDecisionSystem) createRuleFromAIDecision(result *DecisionResult, context DecisionContext) DecisionRule {
	// 基于AI决策创建新的规则
	return DecisionRule{
		ID:          generateRuleID(),
		Name:        "AI生成规则",
		Description: "基于AI分析自动生成的决策规则",
		Type:        "ai_generated",
		Conditions:  a.extractConditionsFromContext(context),
		Actions:     result.Actions,
		Priority:    50,
		Confidence:  result.Confidence,
		Enabled:     true,
		LastUsed:    time.Now(),
		SuccessRate: 0.5, // 初始成功率
	}
}

// 性能管理和优化函数

func (a *AdaptiveDecisionSystem) updateRulePerformance(ruleID string, outcome DecisionOutcome) {
	for i, rule := range a.decisionRules {
		if rule.ID == ruleID {
			// 更新成功率
			if outcome.Success {
				rule.SuccessRate = math.Min(1.0, rule.SuccessRate+a.config.AdaptationRate)
			} else {
				rule.SuccessRate = math.Max(0.0, rule.SuccessRate-a.config.AdaptationRate)
			}

			rule.LastUsed = time.Now()
			a.decisionRules[i] = rule
			break
		}
	}

	// 保存更新后的规则
	a.saveDecisionRules()
}

func (a *AdaptiveDecisionSystem) analyzePerformanceData() *PerformanceAnalysis {
	analysis := &PerformanceAnalysis{
		TotalRecords:      0,
		SuccessRate:       0.0,
		AverageConfidence: 0.0,
		RulePerformance:   make(map[string]RuleStats),
		Trends:            make(map[string]TrendData),
	}

	// 分析性能数据
	for _, records := range a.performanceData {
		analysis.TotalRecords += len(records)

		for _, record := range records {
			if record.Outcome.Success {
				analysis.SuccessRate += 1.0
			}
			analysis.AverageConfidence += record.Decision.Confidence

			// 更新规则统计
			stats := analysis.RulePerformance[record.Decision.RuleID]
			stats.UsageCount++
			if record.Outcome.Success {
				stats.SuccessCount++
			}
			analysis.RulePerformance[record.Decision.RuleID] = stats
		}
	}

	if analysis.TotalRecords > 0 {
		analysis.SuccessRate /= float64(analysis.TotalRecords)
		analysis.AverageConfidence /= float64(analysis.TotalRecords)
	}

	return analysis
}

func (a *AdaptiveDecisionSystem) applyOptimizations(analysis *PerformanceAnalysis) {
	// 基于分析结果优化规则
	for ruleID, stats := range analysis.RulePerformance {
		successRate := float64(stats.SuccessCount) / float64(stats.UsageCount)

		if successRate < 0.3 && stats.UsageCount > 5 {
			// 禁用低成功率规则
			a.disableRule(ruleID)
		} else if successRate > 0.8 {
			// 提高高成功率规则的优先级
			a.increaseRulePriority(ruleID)
		}
	}

	// 如果规则数量超过限制，清理最不常用的规则
	if len(a.decisionRules) > a.config.MaxRules {
		a.cleanupLeastUsedRules()
	}
}

// 数据管理函数

func (a *AdaptiveDecisionSystem) loadDecisionRules() error {
	rulesFile := filepath.Join(a.dataPath, "decision_rules.json")

	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return err
	}

	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return err
	}

	var rules []DecisionRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	// 过滤启用的规则
	for _, rule := range rules {
		if rule.Enabled {
			a.decisionRules = append(a.decisionRules, rule)
		}
	}

	return nil
}

func (a *AdaptiveDecisionSystem) saveDecisionRules() error {
	if err := os.MkdirAll(a.dataPath, 0755); err != nil {
		return err
	}

	rulesFile := filepath.Join(a.dataPath, "decision_rules.json")

	data, err := json.MarshalIndent(a.decisionRules, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(rulesFile, data, 0644)
}

func (a *AdaptiveDecisionSystem) addDecisionRule(rule DecisionRule) {
	a.decisionRules = append(a.decisionRules, rule)
	a.saveDecisionRules()
}

func (a *AdaptiveDecisionSystem) disableRule(ruleID string) {
	for i, rule := range a.decisionRules {
		if rule.ID == ruleID {
			rule.Enabled = false
			a.decisionRules[i] = rule
			break
		}
	}
	a.saveDecisionRules()
}

func (a *AdaptiveDecisionSystem) increaseRulePriority(ruleID string) {
	for i, rule := range a.decisionRules {
		if rule.ID == ruleID && rule.Priority < 100 {
			rule.Priority += 10
			a.decisionRules[i] = rule
			break
		}
	}
	a.saveDecisionRules()
}

// 初始化默认规则
func (a *AdaptiveDecisionSystem) initializeDefaultRules() {
	defaultRules := []DecisionRule{
		{
			ID:          "rule-web-scan",
			Name:        "Web应用扫描规则",
			Description: "针对Web应用的扫描策略选择",
			Type:        "scan_strategy",
			Conditions: []DecisionCondition{
				{Field: "target_type", Operator: "==", Value: "web_application", Weight: 1.0},
			},
			Actions: []DecisionAction{
				{Type: "select_tool", Target: "nmap", Parameters: map[string]interface{}{"scan_type": "web"}},
			},
			Priority:    80,
			Confidence:  0.9,
			Enabled:     true,
			SuccessRate: 0.8,
		},
		{
			ID:          "rule-network-scan",
			Name:        "网络扫描规则",
			Description: "针对网络设备的扫描策略选择",
			Type:        "scan_strategy",
			Conditions: []DecisionCondition{
				{Field: "target_type", Operator: "==", Value: "network_device", Weight: 1.0},
			},
			Actions: []DecisionAction{
				{Type: "select_tool", Target: "nmap", Parameters: map[string]interface{}{"scan_type": "network"}},
			},
			Priority:    70,
			Confidence:  0.85,
			Enabled:     true,
			SuccessRate: 0.75,
		},
	}

	a.decisionRules = defaultRules
	a.saveDecisionRules()
}

// 工具函数

func generateRecordID() string {
	return fmt.Sprintf("rec-%d", time.Now().UnixNano())
}

func generateRuleID() string {
	return fmt.Sprintf("rule-%d", time.Now().UnixNano())
}

func toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

// 简化实现的其他函数

func (a *AdaptiveDecisionSystem) loadLearningModels() error {
	// 简化实现
	return nil
}

func (a *AdaptiveDecisionSystem) loadPerformanceData() error {
	// 简化实现
	return nil
}

func (a *AdaptiveDecisionSystem) recordDecision(context DecisionContext, result *DecisionResult, outcome *DecisionOutcome) {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) addPerformanceRecord(record PerformanceRecord) {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) trainLearningModels() {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) cleanupOldData() {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) cleanupLeastUsedRules() {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) generateReasoning(rule DecisionRule, context DecisionContext) string {
	return fmt.Sprintf("基于规则'%s'进行决策", rule.Name)
}

func (a *AdaptiveDecisionSystem) calculatePerformanceMetrics(outcome DecisionOutcome) PerformanceMetrics {
	return PerformanceMetrics{
		ExecutionTime: 1.0,
		ResourceUsage: 0.5,
		SuccessRate:   outcome.Effectiveness,
		Accuracy:      0.8,
		Efficiency:    0.7,
	}
}

func (a *AdaptiveDecisionSystem) analyzeDecisionTrends(days int, insights *DecisionInsights) {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) generateInsights(insights *DecisionInsights) {
	// 简化实现
}

func (a *AdaptiveDecisionSystem) extractConditionsFromContext(context DecisionContext) []DecisionCondition {
	// 简化实现
	return []DecisionCondition{}
}

// 决策洞察数据结构

type DecisionInsights struct {
	GeneratedAt     time.Time                `json:"generated_at"`
	Period          string                   `json:"period"`
	KeyMetrics      map[string]interface{}   `json:"key_metrics"`
	Trends          map[string]TrendAnalysis `json:"trends"`
	Recommendations []string                 `json:"recommendations"`
}

type PerformanceAnalysis struct {
	TotalRecords      int                  `json:"total_records"`
	SuccessRate       float64              `json:"success_rate"`
	AverageConfidence float64              `json:"average_confidence"`
	RulePerformance   map[string]RuleStats `json:"rule_performance"`
	Trends            map[string]TrendData `json:"trends"`
}

type RuleStats struct {
	UsageCount   int `json:"usage_count"`
	SuccessCount int `json:"success_count"`
}

type TrendData struct {
	Values []float64   `json:"values"`
	Times  []time.Time `json:"times"`
}
