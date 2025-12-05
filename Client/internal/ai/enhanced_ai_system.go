package ai

import (
	"fmt"
	"strings"
	"time"

	"GYscan/internal/utils"
)

// EnhancedAISystem 增强的AI系统
type EnhancedAISystem struct {
	OptimizedAISystem
	ComplianceManager *ComplianceManager
	AsyncToolManager  *AsyncToolManager
}

// NewEnhancedAISystem 创建增强的AI系统
func NewEnhancedAISystem(configPath string) (*EnhancedAISystem, error) {
	// 创建基础AI系统
	baseSystem, err := NewOptimizedAISystem(configPath)
	if err != nil {
		return nil, fmt.Errorf("创建基础AI系统失败: %v", err)
	}

	// 创建合规管理器
	complianceManager := NewComplianceManager()

	// 创建异步工具管理器
	asyncToolManager := NewAsyncToolManager(baseSystem.ToolManager)

	return &EnhancedAISystem{
		OptimizedAISystem: *baseSystem,
		ComplianceManager: complianceManager,
		AsyncToolManager:  asyncToolManager,
	}, nil
}

// PerformEnhancedPenetrationTest 执行增强的渗透测试
func (system *EnhancedAISystem) PerformEnhancedPenetrationTest(target string, testType string, clientIP string) error {
	// 记录测试开始
	system.ErrorHandler.Log("info", "enhanced_penetration_test", "开始增强渗透测试",
		map[string]interface{}{
			"target":    target,
			"test_type": testType,
			"client_ip": clientIP,
		})

	utils.InfoPrint("=== 开始增强渗透测试 ===")
	utils.InfoPrint("目标: %s", target)
	utils.InfoPrint("测试类型: %s", testType)
	utils.InfoPrint("客户端IP: %s", clientIP)

	// 检查AI服务健康状态
	if !system.HealthChecker.IsHealthy {
		errMsg := "AI服务健康状态异常，建议检查网络连接和API配置"
		system.ErrorHandler.Log("error", "health_check", errMsg, nil)
		return fmt.Errorf("%s", errMsg)
	}

	// 2. 合规校验：检查目标和工具是否授权
	utils.InfoPrint("=== 合规校验阶段 ===")
	
	// 验证目标合法性
	isValid, err := system.ComplianceManager.ValidateTarget(target)
	if err != nil {
		utils.ErrorPrint("目标验证失败: %v", err)
		return fmt.Errorf("目标验证失败: %v", err)
	}
	
	if !isValid {
		utils.ErrorPrint("无效的目标格式: %s", target)
		return fmt.Errorf("无效的目标格式")
	}

	// 初始化AI驱动的闭环渗透测试流程
	currentPhase := "information_gathering"
	var lastResult string
	var lastDecision *PenetrationDecision
	var allResults map[string]map[string]string = make(map[string]map[string]string)

	// 初始化各阶段结果存储
	allResults["information_gathering"] = make(map[string]string)
	allResults["vulnerability_scanning"] = make(map[string]string)
	allResults["vulnerability_validation"] = make(map[string]string)
	allResults["exploitation"] = make(map[string]string)
	allResults["post_exploitation"] = make(map[string]string)

	// 执行AI驱动的闭环流程
	for {
		// 记录当前阶段
		utils.InfoPrint("=== 当前阶段: %s ===", currentPhase)
		system.ErrorHandler.Log("info", "penetration_test", fmt.Sprintf("进入阶段: %s", currentPhase), nil)

		// 生成当前阶段的初始决策
		var decision *PenetrationDecision
		var err error

		if lastDecision == nil {
			// 第一次决策
			decision, err = system.DecisionEngine.MakeDecision(target, currentPhase, 
				fmt.Sprintf("开始%s阶段，执行全面的%s操作", currentPhase, currentPhase))
		} else {
			// 根据上一次执行结果生成下一步决策
			decision, currentPhase, err = system.DecisionEngine.MakeNextDecision(
				target, currentPhase, lastResult, lastDecision)
		}

		if err != nil {
			utils.ErrorPrint("生成决策失败: %v", err)
			// 尝试生成默认决策
			decision, err = system.DecisionEngine.MakeDecision(target, currentPhase, 
				fmt.Sprintf("生成默认决策，执行%s操作", currentPhase))
			if err != nil {
				return fmt.Errorf("生成默认决策失败: %v", err)
			}
		}

		// 如果AI决定结束测试，跳出循环
		if decision == nil {
			utils.InfoPrint("AI决定结束渗透测试")
			break
		}

		// 执行决策
		lastResult, err = system.DecisionEngine.ExecuteDecision(decision)
		if err != nil {
			utils.ErrorPrint("执行决策失败: %v", err)
			// 记录失败结果，但继续流程
			lastResult = fmt.Sprintf("执行失败: %v", err)
		}

		// 保存执行结果到对应阶段
		if _, exists := allResults[currentPhase]; exists {
			allResults[currentPhase][decision.Tool] = lastResult
		}

		// 更新上一次决策
		lastDecision = decision

		// 从决策中学习
		system.DecisionEngine.LearnFromDecision(decision, lastResult)

		// 检查是否需要进入清理阶段
		if currentPhase == "cleanup" {
			utils.InfoPrint("清理阶段完成，结束测试")
			break
		}
	}

	// 9. 报告生成阶段：生成完整的测试报告
	utils.InfoPrint("=== 报告生成阶段 ===")
	report, err := system.generateReport(
		target,
		allResults["information_gathering"],
		allResults["vulnerability_scanning"],
		allResults["exploitation"],
		allResults["post_exploitation"])
	if err != nil {
		system.ErrorHandler.Log("error", "report_generation", "报告生成失败",
			map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("报告生成失败: %v", err)
	}

	// 记录测试完成
	system.ErrorHandler.Log("info", "penetration_test", "渗透测试完成",
		map[string]interface{}{
			"target":          target,
			"info_findings":   len(allResults["information_gathering"]),
			"vuln_findings":   len(allResults["vulnerability_scanning"]),
			"validated_vulns": len(allResults["vulnerability_validation"]),
			"exploit_results": len(allResults["exploitation"]),
			"post_exploit":    len(allResults["post_exploitation"]),
		})

	// 记录到合规日志
	system.ComplianceManager.LogAction("penetration_test", target, "ai_mcp", "completed")

	utils.SuccessPrint("=== 增强渗透测试完成 ===")
	utils.InfoPrint("测试报告: %s", report)

	return nil
}

// GetEnhancedSystemStats 获取增强系统统计信息
func (system *EnhancedAISystem) GetEnhancedSystemStats() map[string]interface{} {
	baseStats := system.GetSystemStats()
	baseStats["compliance_manager"] = map[string]interface{}{
		"status": "active",
		"enabled": true,
	}
	baseStats["async_tool_manager"] = map[string]interface{}{
		"status": "active",
		"enabled": true,
	}
	return baseStats
}

// performInformationGathering 执行信息收集（增强版）
func (system *EnhancedAISystem) performInformationGathering(target string) (map[string]string, error) {
	utils.InfoPrint("=== 增强信息收集阶段 ===")

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
			decision.Tool, target, "增强信息收集阶段")
		if err != nil {
			// 记录决策执行失败
			system.DecisionEngine.LearnFromDecision(decision, err.Error())
			return nil, err
		}

		results[decision.Tool] = output
		system.DecisionEngine.LearnFromDecision(decision, "执行成功")
	}

	// 异步执行标准信息收集流程
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

	utils.SuccessPrint("增强信息收集完成，发现 %d 项结果", len(results))
	return results, nil
}

// performVulnerabilityScanning 执行漏洞扫描（增强版）
func (system *EnhancedAISystem) performVulnerabilityScanning(target string, infoResults map[string]string) (map[string]string, error) {
	utils.InfoPrint("=== 增强漏洞扫描阶段 ===")

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
			decision.Tool, target, "增强漏洞扫描阶段")
		if err != nil {
			system.DecisionEngine.LearnFromDecision(decision, err.Error())
			return nil, err
		}

		results[decision.Tool] = output
		system.DecisionEngine.LearnFromDecision(decision, "执行成功")
	}

	// 异步执行额外的漏洞扫描工具
	additionalTools := system.getVulnerabilityScanningTools(infoResults)
	if len(additionalTools) > 0 {
		asyncResults := system.AsyncToolManager.ExecuteToolsAsync(target, additionalTools, "增强漏洞扫描")
		for k, v := range asyncResults {
			results[k] = v
		}
	}

	utils.SuccessPrint("增强漏洞扫描完成，发现 %d 项结果", len(results))
	return results, nil
}

// performVulnerabilityValidation 执行漏洞验证（增强版）
func (system *EnhancedAISystem) performVulnerabilityValidation(target string, vulnResults map[string]string) (map[string]string, error) {
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
				decision.Tool, target, "增强漏洞验证阶段")
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

	utils.SuccessPrint("增强漏洞验证完成，验证了 %d 个漏洞", len(validatedVulns))
	return validatedVulns, nil
}

// performExploitation 执行漏洞利用（增强版）
func (system *EnhancedAISystem) performExploitation(target string, validatedVulns map[string]string) (map[string]string, error) {
	utils.InfoPrint("=== 增强漏洞利用阶段 ===")

	// 分析漏洞扫描结果，识别可利用的漏洞
	exploitableVulns := system.analyzeVulnerabilitiesForExploitation(validatedVulns)

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

	utils.SuccessPrint("增强漏洞利用完成，执行 %d 次利用尝试", len(results))
	return results, nil
}

// performPostExploitation 执行后渗透阶段（增强版）
func (system *EnhancedAISystem) performPostExploitation(target string, exploitResults map[string]string) (map[string]string, error) {
	postExploitResults := make(map[string]string)

	if len(exploitResults) == 0 {
		utils.InfoPrint("没有可执行的后渗透操作")
		return postExploitResults, nil
	}

	utils.InfoPrint("正在执行增强后渗透操作...")

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
				decision.Tool, target, "增强后渗透阶段")
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

	utils.SuccessPrint("增强后渗透阶段完成，执行了 %d 个操作", len(postExploitResults))
	return postExploitResults, nil
}

// performCleanup 执行清理操作（增强版）
func (system *EnhancedAISystem) performCleanup(target string) {
	utils.InfoPrint("正在执行增强清理操作...")

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
			decision.Tool, target, "增强清理阶段")
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

	utils.SuccessPrint("增强清理阶段完成")
}

// generateReport 生成测试报告（增强版）
func (system *EnhancedAISystem) generateReport(target string, infoResults, vulnResults, exploitResults, postExploitResults map[string]string) (string, error) {
	utils.InfoPrint("=== 生成增强测试报告 ===")

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

// formatResultsForAI 格式化结果供AI使用（增强版）
func (system *EnhancedAISystem) formatResultsForAI(results map[string]string) string {
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

// generateDefaultReport 生成默认报告（增强版）
func (system *EnhancedAISystem) generateDefaultReport(target string, infoResults, vulnResults, exploitResults, postExploitResults map[string]string) string {
	report := fmt.Sprintf(`AI-MCP 增强渗透测试报告
目标: %s
测试时间: %s

=== 执行摘要 ===
信息收集: %d 项结果
漏洞扫描: %d 项结果
漏洞利用: %d 项结果
后渗透操作: %d 项结果

=== 合规性检查 ===
已通过所有预定义合规性检查

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

// analyzeInformationForVulnerabilityScanning 分析信息收集结果以指导漏洞扫描（增强版）
func (system *EnhancedAISystem) analyzeInformationForVulnerabilityScanning(infoResults map[string]string) string {
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

// getVulnerabilityScanningTools 获取漏洞扫描工具列表（增强版）
func (system *EnhancedAISystem) getVulnerabilityScanningTools(infoResults map[string]string) []string {
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

// analyzeVulnerabilitiesForExploitation 分析漏洞以识别可利用的漏洞（增强版）
func (system *EnhancedAISystem) analyzeVulnerabilitiesForExploitation(vulnResults map[string]string) []string {
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
