package ai

import (
	"fmt"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"
)

// OptimizedAISystem 优化后的AI系统
type OptimizedAISystem struct {
	AIClient          AIClientInterface
	ToolManager       *ToolManager
	DecisionEngine    *PenetrationDecisionEngine
	ErrorHandler      *ErrorHandler
	HealthChecker     *HealthChecker
	ConnectionMonitor *ConnectionMonitor
}

// NewOptimizedAISystem 创建优化后的AI系统
func NewOptimizedAISystem(configPath string) (*OptimizedAISystem, error) {
	system := &OptimizedAISystem{}

	// 加载配置
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %v", err)
	}

	// 使用客户端工厂创建AI客户端
	factory := NewClientFactory()
	aiClient, err := factory.CreateClient(*cfg)
	if err != nil {
		utils.WarningPrint("创建go-openai客户端失败: %v，尝试使用HTTP客户端", err)
		// 回退到HTTP客户端
		fallbackCfg := *cfg
		fallbackCfg.Provider = "custom"
		aiClient, err = factory.CreateClient(fallbackCfg)
		if err != nil {
			return nil, fmt.Errorf("创建AI客户端失败: %v", err)
		}
	}

	system.AIClient = aiClient

	// 创建错误处理器
	errorHandler := NewErrorHandler("", "info")
	system.ErrorHandler = errorHandler

	// 创建健康检查器
	healthChecker := NewHealthChecker(
		cfg.BaseURL,
		cfg.APIKey,
		time.Duration(cfg.Timeout)*time.Second,
		30*time.Second, // 每30秒检查一次
	)
	system.HealthChecker = healthChecker

	// 创建重试策略
	retryStrategy := NewRetryStrategy(
		cfg.MaxRetries,
		1*time.Second,  // 基础延迟1秒
		15*time.Second, // 最大延迟15秒
	)

	// 创建连接监控器
	connectionMonitor := NewConnectionMonitor(healthChecker, retryStrategy)
	system.ConnectionMonitor = connectionMonitor

	// 扫描系统工具并创建智能工具管理器
	toolManager := ScanSystemTools(aiClient)
	system.ToolManager = toolManager

	// 创建渗透决策引擎
	decisionEngine := NewPenetrationDecisionEngine(aiClient, toolManager)
	system.DecisionEngine = decisionEngine

	// 添加控制台告警通道
	consoleChannel := &ConsoleAlertChannel{}
	errorHandler.AddAlertChannel(consoleChannel)

	utils.SuccessPrint("优化AI系统初始化完成")

	// 记录系统启动
	errorHandler.Log("info", "optimized_ai_system", "AI系统启动成功",
		map[string]interface{}{
			"provider":        cfg.Provider,
			"model":           cfg.Model,
			"available_tools": len(toolManager.GetAvailableToolNames()),
		})

	return system, nil
}

// PerformPenetrationTest 执行渗透测试（按照严格的渗透测试步骤）
func (system *OptimizedAISystem) PerformPenetrationTest(target string, testType string) error {
	// 记录测试开始
	system.ErrorHandler.Log("info", "penetration_test", "开始渗透测试",
		map[string]interface{}{
			"target":    target,
			"test_type": testType,
		})

	utils.InfoPrint("=== 开始渗透测试 ===")
	utils.InfoPrint("目标: %s", target)
	utils.InfoPrint("测试类型: %s", testType)

	// 检查AI服务健康状态
	if !system.HealthChecker.IsHealthy {
		errMsg := "AI服务健康状态异常，建议检查网络连接和API配置"
		system.ErrorHandler.Log("error", "health_check", errMsg, nil)
		return fmt.Errorf("%s", errMsg)
	}

	// 1. 预渗透阶段：规划和准备
	utils.InfoPrint("=== 预渗透阶段：规划和准备 ===")
	system.ErrorHandler.Log("info", "penetration_test", "进入预渗透阶段", nil)

	// 2. 信息收集阶段：被动和主动信息收集
	utils.InfoPrint("=== 信息收集阶段 ===")
	infoResults, err := system.performInformationGathering(target)
	if err != nil {
		system.ErrorHandler.Log("error", "information_gathering", "信息收集阶段失败",
			map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("信息收集失败: %v", err)
	}

	// 3. 漏洞扫描阶段：系统和应用漏洞扫描
	utils.InfoPrint("=== 漏洞扫描阶段 ===")
	vulnResults, err := system.performVulnerabilityScanning(target, infoResults)
	if err != nil {
		system.ErrorHandler.Log("error", "vulnerability_scanning", "漏洞扫描阶段失败",
			map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("漏洞扫描失败: %v", err)
	}

	// 4. 漏洞验证阶段：验证发现的漏洞
	utils.InfoPrint("=== 漏洞验证阶段 ===")
	validatedVulns, err := system.performVulnerabilityValidation(target, vulnResults)
	if err != nil {
		system.ErrorHandler.Log("warning", "vulnerability_validation", "漏洞验证阶段部分失败",
			map[string]interface{}{"error": err.Error()})
	}

	// 5. 漏洞利用阶段：尝试利用已验证的漏洞
	utils.InfoPrint("=== 漏洞利用阶段 ===")
	exploitResults, err := system.performExploitation(target, validatedVulns)
	if err != nil {
		system.ErrorHandler.Log("error", "exploitation", "漏洞利用阶段失败",
			map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("漏洞利用失败: %v", err)
	}

	// 6. 后渗透阶段：权限提升和持久化
	utils.InfoPrint("=== 后渗透阶段 ===")
	postExploitResults, err := system.performPostExploitation(target, exploitResults)
	if err != nil {
		system.ErrorHandler.Log("warning", "post_exploitation", "后渗透阶段部分失败",
			map[string]interface{}{"error": err.Error()})
	}

	// 7. 清理阶段：移除测试留下的痕迹
	utils.InfoPrint("=== 清理阶段 ===")
	system.performCleanup(target)

	// 8. 报告生成阶段：生成完整的测试报告
	utils.InfoPrint("=== 报告生成阶段 ===")
	report, err := system.generateReport(target, infoResults, validatedVulns, exploitResults, postExploitResults)
	if err != nil {
		system.ErrorHandler.Log("error", "report_generation", "报告生成失败",
			map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("报告生成失败: %v", err)
	}

	// 记录测试完成
	system.ErrorHandler.Log("info", "penetration_test", "渗透测试完成",
		map[string]interface{}{
			"target":          target,
			"info_findings":   len(infoResults),
			"vuln_findings":   len(vulnResults),
			"validated_vulns": len(validatedVulns),
			"exploit_results": len(exploitResults),
			"post_exploit":    len(postExploitResults),
		})

	utils.SuccessPrint("=== 渗透测试完成 ===")
	utils.InfoPrint("测试报告: %s", report)

	return nil
}

// performInformationGathering 执行信息收集
func (system *OptimizedAISystem) performInformationGathering(target string) (map[string]string, error) {
	utils.InfoPrint("=== 信息收集阶段 ===")

	// 使用AI决策引擎制定信息收集策略
	decision, err := system.DecisionEngine.MakeDecision(target, "information_gathering",
		"执行全面的信息收集，包括网络扫描、服务识别和目录枚举")
	if err != nil {
		return nil, err
	}

	// 执行决策
	results := make(map[string]string)

	// 使用智能工具管理器执行工具
	if system.ToolManager.SmartManager != nil {
		output, err := system.ToolManager.SmartManager.ExecuteToolWithAI(

			decision.Tool, target, "信息收集阶段")
		if err != nil {
			// 记录决策执行失败
			system.DecisionEngine.LearnFromDecision(decision, err.Error())
			return nil, err
		}

		results[decision.Tool] = output
		system.DecisionEngine.LearnFromDecision(decision, "执行成功")
	}

	// 执行标准信息收集流程
	standardResults, err := PerformInformationGathering(target, system.ToolManager)
	if err != nil {
		system.ErrorHandler.Log("warning", "information_gathering", "标准信息收集部分失败",
			map[string]interface{}{"error": err.Error()})
	} else {
		// 合并结果
		for k, v := range standardResults {
			results[k] = v
		}
	}

	utils.SuccessPrint("信息收集完成，发现 %d 项结果", len(results))
	return results, nil
}

// performVulnerabilityScanning 执行漏洞扫描
func (system *OptimizedAISystem) performVulnerabilityScanning(target string, infoResults map[string]string) (map[string]string, error) {
	utils.InfoPrint("=== 漏洞扫描阶段 ===")

	// 基于信息收集结果制定漏洞扫描策略
	context := system.analyzeInformationForVulnerabilityScanning(infoResults)

	// 使用AI决策引擎制定漏洞扫描策略
	decision, err := system.DecisionEngine.MakeDecision(target, "vulnerability_scanning", context)
	if err != nil {
		return nil, err
	}

	results := make(map[string]string)

	// 使用智能工具管理器执行工具
	if system.ToolManager.SmartManager != nil {
		output, err := system.ToolManager.SmartManager.ExecuteToolWithAI(
			decision.Tool, target, "漏洞扫描阶段")
		if err != nil {
			system.DecisionEngine.LearnFromDecision(decision, err.Error())
			return nil, err
		}

		results[decision.Tool] = output
		system.DecisionEngine.LearnFromDecision(decision, "执行成功")
	}

	// 执行额外的漏洞扫描工具
	additionalTools := system.getVulnerabilityScanningTools(infoResults)
	for _, toolName := range additionalTools {
		if tool, exists := system.ToolManager.GetTool(toolName); exists && tool.IsAvailable() {
			utils.InfoPrint("执行漏洞扫描工具: %s", toolName)

			// 使用智能参数生成
			var output string
			var err error

			if system.ToolManager.SmartManager != nil {
				output, err = system.ToolManager.SmartManager.ExecuteToolWithAI(
					toolName, target, "补充漏洞扫描")
			} else {
				// 使用默认参数
				output, err = tool.Run(target)
			}

			if err != nil {
				system.ErrorHandler.Log("warning", "vulnerability_scanning",
					fmt.Sprintf("工具 %s 执行失败", toolName),
					map[string]interface{}{"error": err.Error()})
			} else {
				results[toolName] = output
			}
		}
	}

	utils.SuccessPrint("漏洞扫描完成，发现 %d 项结果", len(results))
	return results, nil
}

// performExploitation 执行漏洞利用
func (system *OptimizedAISystem) performExploitation(target string, vulnResults map[string]string) (map[string]string, error) {
	utils.InfoPrint("=== 漏洞利用阶段 ===")

	// 分析漏洞扫描结果，识别可利用的漏洞
	exploitableVulns := system.analyzeVulnerabilitiesForExploitation(vulnResults)

	if len(exploitableVulns) == 0 {
		utils.InfoPrint("未发现可利用的漏洞")
		return make(map[string]string), nil
	}

	results := make(map[string]string)

	for _, vuln := range exploitableVulns {
		// 使用AI决策引擎制定漏洞利用策略
		decision, err := system.DecisionEngine.MakeDecision(target, "exploitation",
			fmt.Sprintf("利用漏洞: %s", vuln))
		if err != nil {
			system.ErrorHandler.Log("warning", "exploitation",
				"漏洞利用决策生成失败",
				map[string]interface{}{"vulnerability": vuln, "error": err.Error()})
			continue
		}

		// 执行漏洞利用
		if system.ToolManager.SmartManager != nil {
			output, err := system.ToolManager.SmartManager.ExecuteToolWithAI(
				decision.Tool, target, fmt.Sprintf("利用漏洞: %s", vuln))
			if err != nil {
				system.DecisionEngine.LearnFromDecision(decision, err.Error())
				system.ErrorHandler.Log("warning", "exploitation",
					"漏洞利用执行失败",
					map[string]interface{}{
						"tool":          decision.Tool,
						"vulnerability": vuln,
						"error":         err.Error(),
					})
			} else {
				results[decision.Tool] = output
				system.DecisionEngine.LearnFromDecision(decision, "执行成功")
				system.ErrorHandler.Log("info", "exploitation",
					"漏洞利用执行成功",
					map[string]interface{}{
						"tool":          decision.Tool,
						"vulnerability": vuln,
					})
			}
		}
	}

	utils.SuccessPrint("漏洞利用完成，执行 %d 次利用尝试", len(results))
	return results, nil
}

// analyzeInformationForVulnerabilityScanning 分析信息收集结果以指导漏洞扫描
func (system *OptimizedAISystem) analyzeInformationForVulnerabilityScanning(infoResults map[string]string) string {
	// 简化的分析逻辑，实际中可以使用更复杂的AI分析
	context := "基于信息收集结果进行漏洞扫描"

	for _, result := range infoResults {
		if strings.Contains(strings.ToLower(result), "wordpress") {
			context += ", 发现WordPress系统，建议使用wpscan"
		}
		if strings.Contains(strings.ToLower(result), "apache") {
			context += ", 发现Apache服务器，建议检查常见配置漏洞"
		}
		if strings.Contains(strings.ToLower(result), "mysql") {
			context += ", 发现MySQL数据库，建议检查SQL注入漏洞"
		}
	}

	return context
}

// getVulnerabilityScanningTools 获取漏洞扫描工具列表
func (system *OptimizedAISystem) getVulnerabilityScanningTools(infoResults map[string]string) []string {
	tools := []string{"nikto", "nuclei"}

	// 基于信息收集结果推荐工具
	for _, result := range infoResults {
		resultLower := strings.ToLower(result)

		if strings.Contains(resultLower, "wordpress") {
			tools = append(tools, "wpscan")
		}
		if strings.Contains(resultLower, "joomla") {
			tools = append(tools, "joomscan")
		}
		if strings.Contains(resultLower, "sql") {
			tools = append(tools, "sqlmap")
		}
	}

	return tools
}

// performVulnerabilityValidation 执行漏洞验证
func (system *OptimizedAISystem) performVulnerabilityValidation(target string, vulnResults map[string]string) (map[string]string, error) {
	validatedVulns := make(map[string]string)

	if len(vulnResults) == 0 {
		utils.InfoPrint("没有发现可验证的漏洞")
		return validatedVulns, nil
	}

	utils.InfoPrint("正在验证发现的漏洞...")

	for tool, result := range vulnResults {
		// 使用AI决策引擎制定漏洞验证策略
		decision, err := system.DecisionEngine.MakeDecision(target, "vulnerability_validation",
			fmt.Sprintf("验证由 %s 发现的漏洞，结果: %s", tool, result))
		if err != nil {
			utils.WarningPrint("漏洞验证决策生成失败: %v", err)
			continue
		}

		// 执行漏洞验证
		if system.ToolManager.SmartManager != nil {
			output, err := system.ToolManager.SmartManager.ExecuteToolWithAI(
				decision.Tool, target, "漏洞验证阶段")
			if err != nil {
				// 记录决策执行失败
				system.DecisionEngine.LearnFromDecision(decision, err.Error())
				utils.WarningPrint("漏洞验证执行失败: %v", err)
			} else {
				validatedVulns[tool] = output
				system.DecisionEngine.LearnFromDecision(decision, "验证成功")
				utils.SuccessPrint("成功验证漏洞: %s", tool)
			}
		}
	}

	utils.SuccessPrint("漏洞验证完成，验证了 %d 个漏洞", len(validatedVulns))
	return validatedVulns, nil
}

// performPostExploitation 执行后渗透阶段
func (system *OptimizedAISystem) performPostExploitation(target string, exploitResults map[string]string) (map[string]string, error) {
	postExploitResults := make(map[string]string)

	if len(exploitResults) == 0 {
		utils.InfoPrint("没有可执行的后渗透操作")
		return postExploitResults, nil
	}

	utils.InfoPrint("正在执行后渗透操作...")

	for tool, result := range exploitResults {
		// 使用AI决策引擎制定后渗透策略
		decision, err := system.DecisionEngine.MakeDecision(target, "post_exploitation",
			fmt.Sprintf("对目标 %s 执行后渗透操作，基于之前的利用结果: %s", target, result))
		if err != nil {
			utils.WarningPrint("后渗透决策生成失败: %v", err)
			continue
		}

		// 执行后渗透操作
		if system.ToolManager.SmartManager != nil {
			output, err := system.ToolManager.SmartManager.ExecuteToolWithAI(
				decision.Tool, target, "后渗透阶段")
			if err != nil {
				// 记录决策执行失败
				system.DecisionEngine.LearnFromDecision(decision, err.Error())
				utils.WarningPrint("后渗透操作执行失败: %v", err)
			} else {
				postExploitResults[tool] = output
				system.DecisionEngine.LearnFromDecision(decision, "执行成功")
				utils.SuccessPrint("成功执行后渗透操作: %s", tool)
			}
		}
	}

	utils.SuccessPrint("后渗透阶段完成，执行了 %d 个操作", len(postExploitResults))
	return postExploitResults, nil
}

// performCleanup 执行清理操作
func (system *OptimizedAISystem) performCleanup(target string) {
	utils.InfoPrint("正在执行清理操作...")

	// 使用AI决策引擎制定清理策略
	decision, err := system.DecisionEngine.MakeDecision(target, "cleanup",
		"执行清理操作，移除测试留下的痕迹")
	if err != nil {
		utils.WarningPrint("清理决策生成失败: %v", err)
		return
	}

	// 执行清理操作
	if system.ToolManager.SmartManager != nil {
		output, err := system.ToolManager.SmartManager.ExecuteToolWithAI(
			decision.Tool, target, "清理阶段")
		if err != nil {
			// 记录决策执行失败
			system.DecisionEngine.LearnFromDecision(decision, err.Error())
			utils.WarningPrint("清理操作执行失败: %v", err)
		} else {
			system.DecisionEngine.LearnFromDecision(decision, "执行成功")
			utils.SuccessPrint("清理操作执行成功")
			utils.InfoPrint("清理结果: %s", output)
		}
	}

	utils.SuccessPrint("清理阶段完成")
}

// analyzeVulnerabilitiesForExploitation 分析漏洞以识别可利用的漏洞
func (system *OptimizedAISystem) analyzeVulnerabilitiesForExploitation(vulnResults map[string]string) []string {
	var exploitableVulns []string

	// 简化的漏洞分析逻辑
	for tool, result := range vulnResults {
		resultLower := strings.ToLower(result)

		// 检测高危漏洞关键词
		if strings.Contains(resultLower, "sql injection") ||
			strings.Contains(resultLower, "remote code execution") ||
			strings.Contains(resultLower, "critical") ||
			strings.Contains(resultLower, "high severity") ||
			strings.Contains(resultLower, "cve-") ||
			strings.Contains(resultLower, "exploit") ||
			strings.Contains(resultLower, "vulnerable") {
			exploitableVulns = append(exploitableVulns, fmt.Sprintf("%s发现的漏洞", tool))
		}
	}

	return exploitableVulns
}

// formatResultsForAI 格式化结果供AI使用
func (system *OptimizedAISystem) formatResultsForAI(results map[string]string) string {
	if len(results) == 0 {
		return "无结果"
	}

	var formatted strings.Builder
	for tool, result := range results {
		// 截断过长的结果
		if len(result) > 500 {
			result = result[:500] + "... (内容截断)"
		}
		formatted.WriteString(fmt.Sprintf("%s: %s\n", tool, result))
	}

	return formatted.String()
}

// generateReport 生成测试报告
func (system *OptimizedAISystem) generateReport(target string, infoResults, vulnResults, exploitResults, postExploitResults map[string]string) (string, error) {
	utils.InfoPrint("=== 生成测试报告 ===")

	// 使用AI生成专业报告
	if system.AIClient != nil {
		systemPrompt := `你是一名专业的渗透测试工程师。请根据提供的测试结果生成专业的渗透测试报告。`

		userContent := fmt.Sprintf(`目标: %s

信息收集结果:
%s

漏洞扫描结果:
%s

漏洞利用结果:
%s

后渗透结果:
%s

请生成包含以下内容的专业报告:
1. 执行摘要
2. 发现的安全问题
3. 风险评估
4. 修复建议
5. 技术细节`,
			target,
			system.formatResultsForAI(infoResults),
			system.formatResultsForAI(vulnResults),
			system.formatResultsForAI(exploitResults),
			system.formatResultsForAI(postExploitResults))

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

		report, err := system.AIClient.Chat(messages)
		if err != nil {
			system.ErrorHandler.Log("warning", "report_generation",
				"AI报告生成失败，使用默认报告",
				map[string]interface{}{"error": err.Error()})
			return system.generateDefaultReport(target, infoResults, vulnResults, exploitResults, postExploitResults), nil
		}

		return report, nil
	}

	return system.generateDefaultReport(target, infoResults, vulnResults, exploitResults, postExploitResults), nil
}

// generateDefaultReport 生成默认报告
func (system *OptimizedAISystem) generateDefaultReport(target string, infoResults, vulnResults, exploitResults, postExploitResults map[string]string) string {
	report := fmt.Sprintf(`渗透测试报告
目标: %s
测试时间: %s

=== 执行摘要 ===
信息收集: %d 项结果
漏洞扫描: %d 项结果
漏洞利用: %d 项结果
后渗透操作: %d 项结果

=== 风险评估 ===
基于发现的安全问题进行风险评估...

=== 修复建议 ===
1. 及时更新系统和应用补丁
2. 加强访问控制和认证机制
3. 定期进行安全扫描和渗透测试
4. 实施最小权限原则
5. 配置适当的防火墙规则

=== 技术细节 ===
详细信息请参考各工具的输出结果。`,
		target, time.Now().Format("2006-01-02 15:04:05"),
		len(infoResults), len(vulnResults), len(exploitResults), len(postExploitResults))

	return report
}

// GetSystemStats 获取系统统计信息
func (system *OptimizedAISystem) GetSystemStats() map[string]interface{} {
	stats := map[string]interface{}{
		"ai_client": map[string]interface{}{
			"health": system.HealthChecker.IsHealthy,
		},
		"tools":           system.ToolManager.GetAvailableToolNames(),
		"decision_engine": system.DecisionEngine.GetDecisionStats(),
		"error_handler":   system.ErrorHandler.GetErrorStats(),
	}

	return stats
}

// Close 关闭系统资源
func (system *OptimizedAISystem) Close() {
	system.ErrorHandler.Log("info", "optimized_ai_system", "AI系统关闭", nil)
	// 可以在这里添加资源清理逻辑
}
