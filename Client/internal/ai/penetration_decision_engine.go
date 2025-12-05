package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"
)

// PenetrationDecisionEngine 渗透决策引擎
type PenetrationDecisionEngine struct {
	AIClient        AIClientInterface
	ToolManager     *ToolManager
	DecisionHistory []*PenetrationDecision
	HistoryMutex    sync.RWMutex
	RiskAssessment  *RiskAssessmentEngine
	StrategyLibrary *StrategyLibrary
}

// PenetrationDecision 渗透决策
type PenetrationDecision struct {
	ID             string
	Target         string
	Phase          string
	DecisionType   string
	Tool           string
	Parameters     []string
	Reasoning      string
	RiskLevel      string
	ExpectedImpact string
	Timestamp      time.Time
	Executed       bool
	Success        bool
	ActualImpact   string
	LessonsLearned string
}

// RiskAssessmentEngine 风险评估引擎
type RiskAssessmentEngine struct {
	RiskFactors map[string]float64
	RiskMatrix  map[string]map[string]string
}

// StrategyLibrary 策略库
type StrategyLibrary struct {
	Strategies map[string]*PenetrationStrategy
}

// PenetrationStrategy 渗透策略
type PenetrationStrategy struct {
	Name         string
	Description  string
	Phases       []*StrategyPhase
	ApplicableTo []string
	SuccessRate  float64
	Complexity   string
}

// StrategyPhase 策略阶段
type StrategyPhase struct {
	Name            string
	Tools           []string
	Objectives      []string
	SuccessCriteria []string
}

// NewPenetrationDecisionEngine 创建新的渗透决策引擎
func NewPenetrationDecisionEngine(aiClient AIClientInterface, toolManager *ToolManager) *PenetrationDecisionEngine {
	engine := &PenetrationDecisionEngine{
		AIClient:        aiClient,
		ToolManager:     toolManager,
		DecisionHistory: make([]*PenetrationDecision, 0),
		RiskAssessment:  NewRiskAssessmentEngine(),
		StrategyLibrary: NewStrategyLibrary(),
	}

	return engine
}

// NewRiskAssessmentEngine 创建风险评估引擎
func NewRiskAssessmentEngine() *RiskAssessmentEngine {
	return &RiskAssessmentEngine{
		RiskFactors: map[string]float64{
			"target_sensitivity":    0.0,
			"attack_surface":        0.0,
			"vulnerability_density": 0.0,
			"business_impact":       0.0,
			"legal_risk":            0.0,
		},
		RiskMatrix: map[string]map[string]string{
			"low": {
				"color":    "green",
				"action":   "proceed",
				"priority": "low",
			},
			"medium": {
				"color":    "yellow",
				"action":   "proceed_with_caution",
				"priority": "medium",
			},
			"high": {
				"color":    "orange",
				"action":   "review_required",
				"priority": "high",
			},
			"critical": {
				"color":    "red",
				"action":   "stop_and_review",
				"priority": "critical",
			},
		},
	}
}

// NewStrategyLibrary 创建策略库
func NewStrategyLibrary() *StrategyLibrary {
	library := &StrategyLibrary{
		Strategies: make(map[string]*PenetrationStrategy),
	}

	// 预定义策略
	library.initializeDefaultStrategies()

	return library
}

// initializeDefaultStrategies 初始化默认策略
func (sl *StrategyLibrary) initializeDefaultStrategies() {
	// Web应用渗透策略
	sl.Strategies["web_app_standard"] = &PenetrationStrategy{
		Name:         "Web应用标准渗透",
		Description:  "针对标准Web应用的全面渗透测试策略",
		ApplicableTo: []string{"web_app", "website", "web_service"},
		SuccessRate:  0.85,
		Complexity:   "medium",
		Phases: []*StrategyPhase{
			{
				Name:  "信息收集",
				Tools: []string{"nmap", "whatweb", "nikto", "dirb"},
				Objectives: []string{
					"识别开放端口和服务",
					"获取Web技术栈信息",
					"发现目录和文件",
					"识别WAF和防护措施",
				},
			},
			{
				Name:  "漏洞扫描",
				Tools: []string{"sqlmap", "nuclei", "wpscan", "joomscan"},
				Objectives: []string{
					"检测SQL注入漏洞",
					"扫描已知Web漏洞",
					"检查CMS特定漏洞",
				},
			},
			{
				Name:  "漏洞利用",
				Tools: []string{"metasploit", "custom_exploits"},
				Objectives: []string{
					"验证漏洞可利用性",
					"获取系统访问权限",
					"提升权限",
				},
			},
		},
	}

	// 网络渗透策略
	sl.Strategies["network_standard"] = &PenetrationStrategy{
		Name:         "网络标准渗透",
		Description:  "针对网络设备和服务的渗透测试策略",
		ApplicableTo: []string{"network", "server", "infrastructure"},
		SuccessRate:  0.78,
		Complexity:   "high",
		Phases: []*StrategyPhase{
			{
				Name:  "网络发现",
				Tools: []string{"nmap", "masscan", "ping"},
				Objectives: []string{
					"发现网络拓扑",
					"识别活动主机",
					"扫描开放端口",
				},
			},
			{
				Name:  "服务枚举",
				Tools: []string{"nmap", "enum4linux", "smbclient"},
				Objectives: []string{
					"识别运行的服务",
					"枚举用户和共享",
					"获取服务版本信息",
				},
			},
			{
				Name:  "漏洞利用",
				Tools: []string{"metasploit", "exploitdb", "custom_exploits"},
				Objectives: []string{
					"利用已知漏洞",
					"获取远程访问",
					"横向移动",
				},
			},
		},
	}

	// API渗透策略
	sl.Strategies["api_standard"] = &PenetrationStrategy{
		Name:         "API标准渗透",
		Description:  "针对RESTful API和Web服务的渗透测试策略",
		ApplicableTo: []string{"api", "rest", "graphql"},
		SuccessRate:  0.82,
		Complexity:   "medium",
		Phases: []*StrategyPhase{
			{
				Name:  "API发现",
				Tools: []string{"curl", "postman", "burp"},
				Objectives: []string{
					"识别API端点",
					"分析API文档",
					"理解认证机制",
				},
			},
			{
				Name:  "安全测试",
				Tools: []string{"sqlmap", "nuclei", "custom_scripts"},
				Objectives: []string{
					"测试认证绕过",
					"检测注入漏洞",
					"验证输入验证",
				},
			},
			{
				Name:  "业务逻辑测试",
				Tools: []string{"custom_scripts", "manual_testing"},
				Objectives: []string{
					"测试业务逻辑漏洞",
					"验证数据完整性",
					"检查权限控制",
				},
			},
		},
	}
}

// MakeDecision 制定渗透决策
func (pde *PenetrationDecisionEngine) MakeDecision(target string, phase string, context string) (*PenetrationDecision, error) {
	// 风险评估
	riskLevel := pde.assessRisk(target, context)

	// 选择策略
	strategy := pde.selectStrategy(target, phase, context)

	// 使用AI生成决策
	decision, err := pde.generateDecisionWithAI(target, phase, context, riskLevel, strategy)
	if err != nil {
		return nil, err
	}

	// 记录决策
	pde.recordDecision(decision)

	return decision, nil
}

// assessRisk 风险评估
func (pde *PenetrationDecisionEngine) assessRisk(target string, context string) string {
	// 基于目标类型和上下文进行风险评估
	riskScore := 0.0

	// 目标敏感性评估
	if strings.Contains(context, "production") || strings.Contains(context, "live") {
		riskScore += 0.8
	} else if strings.Contains(context, "staging") || strings.Contains(context, "test") {
		riskScore += 0.4
	} else {
		riskScore += 0.2
	}

	// 攻击面评估
	if strings.Contains(target, ".gov") || strings.Contains(target, ".edu") {
		riskScore += 0.7
	} else if strings.Contains(target, ".com") || strings.Contains(target, ".org") {
		riskScore += 0.5
	} else {
		riskScore += 0.3
	}

	// 基于风险分数确定风险等级
	if riskScore >= 0.8 {
		return "critical"
	} else if riskScore >= 0.6 {
		return "high"
	} else if riskScore >= 0.4 {
		return "medium"
	} else {
		return "low"
	}
}

// selectStrategy 选择策略
func (pde *PenetrationDecisionEngine) selectStrategy(target string, phase string, context string) *PenetrationStrategy {
	// 基于目标类型选择策略
	var strategyName string

	if strings.Contains(context, "web") || strings.Contains(target, "http") {
		strategyName = "web_app_standard"
	} else if strings.Contains(context, "network") || strings.Contains(context, "server") {
		strategyName = "network_standard"
	} else if strings.Contains(context, "api") || strings.Contains(context, "rest") {
		strategyName = "api_standard"
	} else {
		// 默认使用Web应用策略
		strategyName = "web_app_standard"
	}

	if strategy, exists := pde.StrategyLibrary.Strategies[strategyName]; exists {
		return strategy
	}

	// 返回默认策略
	return pde.StrategyLibrary.Strategies["web_app_standard"]
}

// generateDecisionWithAI 使用AI生成决策
func (pde *PenetrationDecisionEngine) generateDecisionWithAI(target, phase, context, riskLevel string, strategy *PenetrationStrategy) (*PenetrationDecision, error) {
	if pde.AIClient == nil {
		return pde.generateDefaultDecision(target, phase, context, riskLevel, strategy), nil
	}

	// 构建AI提示
	systemPrompt := `你是一名专业的渗透测试工程师。请根据目标信息、当前阶段、上下文和风险评估，制定最佳的渗透测试决策。`

	userContent := fmt.Sprintf(`目标: %s
阶段: %s
上下文: %s
风险等级: %s
策略: %s

历史决策记录:
%s

请生成渗透测试决策，包括：
1. 选择最合适的工具
2. 制定工具参数
3. 说明决策理由
4. 评估预期影响

返回JSON格式:
{
  "tool": "工具名称",
  "parameters": ["参数1", "参数2"],
  "reasoning": "决策理由",
  "expected_impact": "预期影响"
}`,
		target, phase, context, riskLevel, strategy.Name, pde.formatDecisionHistoryForAI())

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

	// 调用AI生成决策
	response, err := pde.AIClient.Chat(messages)
	if err != nil {
		utils.WarningPrint("AI决策生成失败，使用默认决策: %v", err)
		return pde.generateDefaultDecision(target, phase, context, riskLevel, strategy), nil
	}

	// 解析AI返回的决策
	var aiDecision struct {
		Tool           string   `json:"tool"`
		Parameters     []string `json:"parameters"`
		Reasoning      string   `json:"reasoning"`
		ExpectedImpact string   `json:"expected_impact"`
	}

	if err := json.Unmarshal([]byte(response), &aiDecision); err != nil {
		utils.WarningPrint("AI决策解析失败，使用默认决策: %v", err)
		return pde.generateDefaultDecision(target, phase, context, riskLevel, strategy), nil
	}

	// 验证工具可用性
	if _, exists := pde.ToolManager.GetTool(aiDecision.Tool); !exists {
		utils.WarningPrint("AI推荐的工具 %s 不可用，使用默认工具", aiDecision.Tool)
		return pde.generateDefaultDecision(target, phase, context, riskLevel, strategy), nil
	}

	decision := &PenetrationDecision{
		ID:             fmt.Sprintf("decision_%d", time.Now().Unix()),
		Target:         target,
		Phase:          phase,
		DecisionType:   "ai_generated",
		Tool:           aiDecision.Tool,
		Parameters:     aiDecision.Parameters,
		Reasoning:      aiDecision.Reasoning,
		RiskLevel:      riskLevel,
		ExpectedImpact: aiDecision.ExpectedImpact,
		Timestamp:      time.Now(),
		Executed:       false,
		Success:        false,
	}

	utils.InfoPrint("AI生成决策: 工具=%s, 风险=%s, 预期影响=%s",
		aiDecision.Tool, riskLevel, aiDecision.ExpectedImpact)

	return decision, nil
}

// generateDefaultDecision 生成默认决策
func (pde *PenetrationDecisionEngine) generateDefaultDecision(target, phase, context, riskLevel string, strategy *PenetrationStrategy) *PenetrationDecision {
	// 基于阶段选择默认工具和参数
	var tool string
	var parameters []string
	var reasoning string

	switch phase {
	case "information_gathering":
		tool = "nmap"
		parameters = []string{"-sS", "-sV", "-O", "-T4", target}
		reasoning = "标准信息收集阶段，使用nmap进行端口扫描和服务识别"
	case "vulnerability_scanning":
		tool = "nikto"
		parameters = []string{"-h", target, "-C", "all"}
		reasoning = "漏洞扫描阶段，使用nikto进行Web服务安全扫描"
	case "exploitation":
		tool = "sqlmap"
		parameters = []string{"-u", target, "--batch", "--level=3"}
		reasoning = "漏洞利用阶段，使用sqlmap检测SQL注入漏洞"
	default:
		tool = "nmap"
		parameters = []string{"-sS", "-sV", target}
		reasoning = "默认扫描配置"
	}

	return &PenetrationDecision{
		ID:             fmt.Sprintf("decision_%d", time.Now().Unix()),
		Target:         target,
		Phase:          phase,
		DecisionType:   "default",
		Tool:           tool,
		Parameters:     parameters,
		Reasoning:      reasoning,
		RiskLevel:      riskLevel,
		ExpectedImpact: "标准渗透测试操作",
		Timestamp:      time.Now(),
		Executed:       false,
		Success:        false,
	}
}

// recordDecision 记录决策
func (pde *PenetrationDecisionEngine) recordDecision(decision *PenetrationDecision) {
	pde.HistoryMutex.Lock()
	defer pde.HistoryMutex.Unlock()

	// 限制历史记录数量
	if len(pde.DecisionHistory) >= 100 {
		pde.DecisionHistory = pde.DecisionHistory[1:]
	}

	pde.DecisionHistory = append(pde.DecisionHistory, decision)
}

// formatDecisionHistoryForAI 格式化决策历史供AI使用
func (pde *PenetrationDecisionEngine) formatDecisionHistoryForAI() string {
	pde.HistoryMutex.RLock()
	defer pde.HistoryMutex.RUnlock()

	if len(pde.DecisionHistory) == 0 {
		return "无历史决策记录"
	}

	var result strings.Builder
	for i, decision := range pde.DecisionHistory {
		if i >= 5 { // 只显示最近5条记录
			break
		}
		status := "未执行"
		if decision.Executed {
			if decision.Success {
				status = "成功"
			} else {
				status = "失败"
			}
		}
		result.WriteString(fmt.Sprintf("%d. 工具: %s, 阶段: %s, 状态: %s\n",
			i+1, decision.Tool, decision.Phase, status))
	}

	return result.String()
}

// ExecuteDecision 执行决策
func (pde *PenetrationDecisionEngine) ExecuteDecision(decision *PenetrationDecision) (string, error) {
	// 获取工具
	tool, exists := pde.ToolManager.GetTool(decision.Tool)
	if !exists {
		return "", fmt.Errorf("工具 %s 不存在", decision.Tool)
	}

	if !tool.IsAvailable() {
		return "", fmt.Errorf("工具 %s 不可用", decision.Tool)
	}

	// 执行工具
	utils.InfoPrint("执行决策: %s %s", decision.Tool, strings.Join(decision.Parameters, " "))
	output, err := tool.Run(decision.Parameters...)

	// 更新决策状态
	decision.Executed = true
	decision.Success = err == nil

	if err != nil {
		decision.ActualImpact = fmt.Sprintf("执行失败: %v", err)
		utils.ErrorPrint("决策执行失败: %v", err)
	} else {
		decision.ActualImpact = "执行成功"
		utils.SuccessPrint("决策执行成功")
	}

	return output, err
}

// MakeNextDecision 根据执行结果制定下一步决策
func (pde *PenetrationDecisionEngine) MakeNextDecision(target string, currentPhase string, lastResult string, lastDecision *PenetrationDecision) (*PenetrationDecision, string, error) {
	// 构建AI提示，让AI判断下一步行动
	systemPrompt := `你是一名专业的渗透测试工程师。请根据目标信息、当前阶段、上一次执行结果和历史决策，判断下一步行动。`

	userContent := fmt.Sprintf(`目标: %s
当前阶段: %s
上一次执行结果: %s
上一次决策: %v

历史决策记录:
%s

请判断:
1. 是否继续当前阶段
2. 是否进入下一阶段
3. 如果继续当前阶段，选择最合适的工具和参数
4. 如果进入下一阶段，说明下一阶段的目标和策略

返回JSON格式:
{
  "action": "continue_phase|next_phase|finish",
  "next_phase": "下一阶段名称",
  "tool": "工具名称",
  "parameters": ["参数1", "参数2"],
  "reasoning": "决策理由",
  "expected_impact": "预期影响"
}`,
		target, currentPhase, lastResult, lastDecision, pde.formatDecisionHistoryForAI())

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

	// 调用AI生成下一步决策
	response, err := pde.AIClient.Chat(messages)
	if err != nil {
		utils.WarningPrint("AI生成下一步决策失败: %v", err)
		// 生成默认下一步决策
		nextDecision := pde.generateDefaultDecision(target, currentPhase, lastResult, "low", pde.selectStrategy(target, currentPhase, lastResult))
		return nextDecision, currentPhase, nil
	}

	// 解析AI返回的下一步决策
	var nextAction struct {
		Action         string   `json:"action"`
		NextPhase      string   `json:"next_phase"`
		Tool           string   `json:"tool"`
		Parameters     []string `json:"parameters"`
		Reasoning      string   `json:"reasoning"`
		ExpectedImpact string   `json:"expected_impact"`
	}

	if err := json.Unmarshal([]byte(response), &nextAction); err != nil {
		utils.WarningPrint("AI下一步决策解析失败: %v", err)
		// 生成默认下一步决策
		nextDecision := pde.generateDefaultDecision(target, currentPhase, lastResult, "low", pde.selectStrategy(target, currentPhase, lastResult))
		return nextDecision, currentPhase, nil
	}

	// 确定下一步的阶段
	nextPhase := currentPhase
	if nextAction.Action == "next_phase" && nextAction.NextPhase != "" {
		nextPhase = nextAction.NextPhase
	}

	// 如果AI决定结束，返回nil
	if nextAction.Action == "finish" {
		return nil, nextPhase, nil
	}

	// 生成下一步决策
	decision := &PenetrationDecision{
		ID:             fmt.Sprintf("decision_%d", time.Now().Unix()),
		Target:         target,
		Phase:          nextPhase,
		DecisionType:   "ai_generated",
		Tool:           nextAction.Tool,
		Parameters:     nextAction.Parameters,
		Reasoning:      nextAction.Reasoning,
		RiskLevel:      pde.assessRisk(target, lastResult),
		ExpectedImpact: nextAction.ExpectedImpact,
		Timestamp:      time.Now(),
		Executed:       false,
		Success:        false,
	}

	// 记录决策
	pde.recordDecision(decision)

	utils.InfoPrint("AI生成下一步决策: 动作=%s, 阶段=%s, 工具=%s",
		nextAction.Action, nextPhase, nextAction.Tool)

	return decision, nextPhase, nil
}

// LearnFromDecision 从决策中学习
func (pde *PenetrationDecisionEngine) LearnFromDecision(decision *PenetrationDecision, actualResult string) {
	// 分析执行结果并更新策略库
	if decision.Executed {
		successRate := 0.0
		if decision.Success {
			successRate = 1.0
		}

		// 更新策略成功率
		if strategy, exists := pde.StrategyLibrary.Strategies["web_app_standard"]; exists {
			strategy.SuccessRate = (strategy.SuccessRate*float64(len(pde.DecisionHistory)-1) + successRate) / float64(len(pde.DecisionHistory))
		}

		// 记录经验教训
		decision.LessonsLearned = pde.analyzeLessonsLearned(decision, actualResult)
	}
}

// analyzeLessonsLearned 分析经验教训
func (pde *PenetrationDecisionEngine) analyzeLessonsLearned(decision *PenetrationDecision, actualResult string) string {
	if decision.Success {
		return "决策执行成功，工具和参数选择有效"
	}

	// 分析失败原因
	reasons := []string{}

	if strings.Contains(actualResult, "timeout") {
		reasons = append(reasons, "执行超时，可能需要调整超时设置")
	}

	if strings.Contains(actualResult, "permission denied") {
		reasons = append(reasons, "权限不足，可能需要提升权限")
	}

	if strings.Contains(actualResult, "connection refused") {
		reasons = append(reasons, "连接被拒绝，目标可能不可达")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "未知错误，需要进一步分析")
	}

	return strings.Join(reasons, "; ")
}

// GetDecisionStats 获取决策统计信息
func (pde *PenetrationDecisionEngine) GetDecisionStats() map[string]interface{} {
	pde.HistoryMutex.RLock()
	defer pde.HistoryMutex.RUnlock()

	stats := map[string]interface{}{
		"total_decisions":      len(pde.DecisionHistory),
		"executed_decisions":   0,
		"successful_decisions": 0,
		"success_rate":         0.0,
		"recent_decisions":     []map[string]interface{}{},
	}

	executedCount := 0
	successCount := 0

	// 统计最近10条决策
	recentDecisions := []map[string]interface{}{}
	startIndex := len(pde.DecisionHistory) - 10
	if startIndex < 0 {
		startIndex = 0
	}

	for i := startIndex; i < len(pde.DecisionHistory); i++ {
		decision := pde.DecisionHistory[i]
		if decision.Executed {
			executedCount++
			if decision.Success {
				successCount++
			}
		}

		recentDecisions = append(recentDecisions, map[string]interface{}{
			"tool":    decision.Tool,
			"phase":   decision.Phase,
			"success": decision.Success,
			"risk":    decision.RiskLevel,
		})
	}

	stats["executed_decisions"] = executedCount
	stats["successful_decisions"] = successCount
	if executedCount > 0 {
		stats["success_rate"] = float64(successCount) / float64(executedCount)
	}
	stats["recent_decisions"] = recentDecisions

	return stats
}
