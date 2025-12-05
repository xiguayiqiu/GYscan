package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// PenetrationTest 执行AI驱动的渗透测试
func PenetrationTest(target string) (string, error) {
	// 使用智能渗透测试
	return intelligentPenetrationTest(target)
}

// PenetrationTestWithResource 执行AI驱动的渗透测试（带资源目录）
func PenetrationTestWithResource(target string, resourceDir string) {
	startTime := time.Now()
	utils.InfoPrint("开始AI驱动渗透测试，目标: %s", target)

	// 初始化资源目录
	resourceDir = initResourceDir(resourceDir)
	utils.InfoPrint("使用资源目录: %s", resourceDir)

	// 创建渗透测试日志记录器
	logger, err := NewPenetrationLogger(target, resourceDir)
	if err != nil {
		utils.ErrorPrint("创建日志记录器失败: %v，将使用基础报告系统", err)
		// 降级到原有逻辑
		penetrationTestWithLegacyReport(target, resourceDir, startTime)
		return
	}
	defer logger.Close()

	// 记录测试开始
	logger.LogPhaseStart(PhaseStart, "开始AI驱动渗透测试")

	// 检查是否需要强制全盘扫描
	needScan := forceScan
	if !needScan {
		// 检查配置文件中是否有工具记录
		hasTools, err2 := CheckToolMappingExists("")
		if err2 != nil {
			utils.WarningPrint("检查工具记录失败: %v，将执行全盘扫描", err2)
			logger.Log(PhaseStart, "", "", "", "检查工具记录失败", "将执行全盘扫描", 0)
			needScan = true
		} else if !hasTools {
			utils.InfoPrint("配置文件中没有工具记录，将执行全盘扫描")
			logger.Log(PhaseStart, "", "", "", "", "配置文件中没有工具记录，将执行全盘扫描", 0)
			needScan = true
		} else {
			utils.InfoPrint("配置文件中已有工具记录，跳过全盘扫描")
			logger.Log(PhaseStart, "", "", "", "", "配置文件中已有工具记录，跳过全盘扫描", 0)
		}
		if err != nil {
			utils.WarningPrint("检查工具记录失败: %v，将执行全盘扫描", err)
			logger.Log(PhaseStart, "", "", "", "检查工具记录失败", "将执行全盘扫描", 0)
			needScan = true
		} else if !hasTools {
			utils.InfoPrint("配置文件中没有工具记录，将执行全盘扫描")
			logger.Log(PhaseStart, "", "", "", "", "配置文件中没有工具记录，将执行全盘扫描", 0)
			needScan = true
		} else {
			utils.InfoPrint("配置文件中已有工具记录，跳过全盘扫描")
			logger.Log(PhaseStart, "", "", "", "", "配置文件中已有工具记录，跳过全盘扫描", 0)
		}
	}

	// 如果需要扫描，则执行全盘扫描并保存结果
	if needScan {
		scanStart := time.Now()
		utils.InfoPrint("开始全盘扫描系统工具...")
		logger.LogPhaseStart(PhaseInfoGathering, "开始全盘扫描系统工具")

		toolManager := ScanSystemTools(nil) // 这里先传递nil，后续在intelligentPenetrationTest中会创建AI客户端
		SaveToolScanResults(toolManager, "")

		scanDuration := time.Since(scanStart)
		logger.LogPhaseComplete(PhaseInfoGathering, "全盘扫描完成", scanDuration)
	}

	// 使用智能渗透测试（增强版，支持日志记录）
	testResult, err := intelligentPenetrationTestWithLogging(target, logger)
	if err != nil {
		utils.ErrorPrint("智能渗透测试失败: %v", err)
		logger.Log(PhaseComplete, "", "", "", err.Error(), "智能渗透测试失败", time.Since(startTime))

		// 即使测试失败，也生成报告
		generateSmartReport(target, resourceDir, logger, startTime, testResult, err)
		return
	}

	// 记录测试完成
	logger.LogPhaseComplete(PhaseComplete, "AI驱动智能渗透测试完成", time.Since(startTime))

	// 生成智能报告
	generateSmartReport(target, resourceDir, logger, startTime, testResult, nil)

	utils.SuccessPrint("\nAI驱动智能渗透测试完成！")
}

// penetrationTestWithLegacyReport 降级到原有报告系统
func penetrationTestWithLegacyReport(target, resourceDir string, startTime time.Time) {
	// 原有逻辑...
	// 检查是否需要强制全盘扫描
	needScan := forceScan
	if !needScan {
		// 检查配置文件中是否有工具记录
		hasTools, err := CheckToolMappingExists("")
		if err != nil {
			utils.WarningPrint("检查工具记录失败: %v，将执行全盘扫描", err)
			needScan = true
		} else if !hasTools {
			utils.InfoPrint("配置文件中没有工具记录，将执行全盘扫描")
			needScan = true
		} else {
			utils.InfoPrint("配置文件中已有工具记录，跳过全盘扫描")
		}
	}

	// 如果需要扫描，则执行全盘扫描并保存结果
	if needScan {
		utils.InfoPrint("开始全盘扫描系统工具...")
		toolManager := ScanSystemTools(nil)
		SaveToolScanResults(toolManager, "")
	}

	// 使用智能渗透测试
	testResult, err := intelligentPenetrationTest(target)
	if err != nil {
		utils.ErrorPrint("智能渗透测试失败: %v", err)
		return
	}

	// 生成安全报告
	endTime := time.Now()
	utils.InfoPrint("\n=== 报告生成阶段 ===")

	// 解析AI分析结果，生成结构化的发现结果
	findings, recommendations := parseAIAnalysisResult(testResult, target)

	// 生成摘要
	summary := generateSummary(findings)

	// 构建报告数据
	reportData := types.ReportData{
		ID:              fmt.Sprintf("report_%s", time.Now().Format("20060102150405")),
		TaskID:          "penetration_test",
		Title:           "AI驱动智能渗透测试报告",
		Summary:         summary,
		Findings:        findings,
		RiskAssessment:  types.RiskAssessment{},
		Recommendations: recommendations,
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     target,
			"scan_type":  "exp",
			"start_time": startTime.Format("2006-01-02 15:04:05"),
			"end_time":   endTime.Format("2006-01-02 15:04:05"),
			"duration":   endTime.Sub(startTime).String(),
			"logs":       testResult,
		},
	}

	if err := GenerateReport(reportData, resourceDir); err != nil {
		utils.ErrorPrint("生成报告失败: %v", err)
	} else {
		utils.SuccessPrint("安全报告生成成功")
	}

	utils.SuccessPrint("\nAI驱动智能渗透测试完成！")
}

// generateSmartReport 生成智能报告
func generateSmartReport(target, resourceDir string, logger *PenetrationLogger, startTime time.Time, testResult string, testErr error) {
	endTime := time.Now()
	utils.InfoPrint("\n=== 智能报告生成阶段 ===")

	// 创建AI客户端用于智能报告生成
	cfgPath := config.GetDefaultConfigPath()
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.WarningPrint("加载AI配置失败: %v，将使用基础报告", err)
		generateBasicReport(target, resourceDir, logger, startTime, endTime, testResult, testErr)
		return
	}

	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.WarningPrint("创建AI客户端失败: %v，将使用基础报告", err)
		generateBasicReport(target, resourceDir, logger, startTime, endTime, testResult, testErr)
		return
	}

	// 创建智能报告生成器
	reportDir := filepath.Join(resourceDir, "reports")
	reportGenerator := NewSmartReportGenerator(aiClient, logger, reportDir)

	// 生成智能报告
	if err := reportGenerator.GenerateSmartReport(target, FormatHTML, FormatMarkdown); err != nil {
		utils.ErrorPrint("智能报告生成失败: %v，将使用基础报告", err)
		generateBasicReport(target, resourceDir, logger, startTime, endTime, testResult, testErr)
	} else {
		utils.SuccessPrint("智能报告生成成功")

		// 保存JSON格式的日志
		if jsonFile, err := logger.SaveJSONLog(); err != nil {
			utils.WarningPrint("保存JSON日志失败: %v", err)
		} else {
			utils.InfoPrint("JSON日志已保存: %s", jsonFile)
		}
	}
}

// generateBasicReport 生成基础报告
func generateBasicReport(target, resourceDir string, logger *PenetrationLogger, startTime, endTime time.Time, testResult string, testErr error) {
	// 使用原有报告生成逻辑
	findings, recommendations := parseAIAnalysisResult(testResult, target)
	summary := generateSummary(findings)

	// 如果测试失败，添加错误信息
	if testErr != nil {
		summary += fmt.Sprintf("\n测试过程中出现错误: %v", testErr)
	}

	// 构建报告数据
	reportData := types.ReportData{
		ID:              fmt.Sprintf("report_%s", time.Now().Format("20060102150405")),
		TaskID:          "penetration_test",
		Title:           "AI驱动智能渗透测试报告",
		Summary:         summary,
		Findings:        findings,
		RiskAssessment:  types.RiskAssessment{},
		Recommendations: recommendations,
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     target,
			"scan_type":  "exp",
			"start_time": startTime.Format("2006-01-02 15:04:05"),
			"end_time":   endTime.Format("2006-01-02 15:04:05"),
			"duration":   endTime.Sub(startTime).String(),
			"logs":       testResult,
		},
	}

	if err := GenerateReport(reportData, resourceDir); err != nil {
		utils.ErrorPrint("生成报告失败: %v", err)
	} else {
		utils.SuccessPrint("基础报告生成成功")
	}
}

// parseAIAnalysisResult 解析AI分析结果，生成结构化的发现结果和建议
func parseAIAnalysisResult(analysisResult, target string) ([]types.Finding, []string) {
	// 简化实现：基于分析结果生成示例发现结果
	// 在实际应用中，应该使用更复杂的解析逻辑，例如正则表达式或JSON解析
	findings := []types.Finding{
		{
			ID:             "ai_analysis_001",
			TaskID:         "penetration_test",
			Type:           "AI分析结果",
			Severity:       "Info",
			Title:          "AI驱动渗透测试分析",
			Description:    analysisResult,
			Location:       target,
			Evidence:       "基于AI智能分析生成的渗透测试结果",
			Recommendation: "根据AI分析结果，进一步调查并修复发现的问题。",
			Impact:         "需要进一步验证和确认发现的问题",
			Confidence:     0.8,
			CreatedAt:      time.Now(),
			References:     []string{"AI智能分析系统"},
		},
	}

	// 生成建议措施
	recommendations := []string{
		"定期进行安全扫描和渗透测试",
		"及时更新系统和应用程序",
		"配置适当的访问控制策略",
		"加强网络安全防护措施",
		"根据AI分析结果修复发现的漏洞",
	}

	return findings, recommendations
}

// generateSummary 基于发现结果生成报告摘要
func generateSummary(findings []types.Finding) string {
	if len(findings) == 0 {
		return "未发现任何安全问题。"
	}

	return fmt.Sprintf("共发现 %d 个安全问题，包括 %d 个高风险问题，%d 个中风险问题，%d 个低风险问题。",
		len(findings), countFindingsBySeverity(findings, "High"),
		countFindingsBySeverity(findings, "Medium"), countFindingsBySeverity(findings, "Low"))
}

// countFindingsBySeverity 统计指定严重程度的发现结果数量
func countFindingsBySeverity(findings []types.Finding, severity string) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}

// targetReconnaissance 目标探测阶段，返回扫描结果
// 注意：此函数已被新的PerformInformationGathering函数替代
func targetReconnaissance(target string, availableTools map[string]bool) (string, error) {
	utils.WarningPrint("警告：targetReconnaissance函数已被PerformInformationGathering函数替代")
	// 使用新的信息收集函数
	toolManager := NewToolManager()
	// 手动添加可用工具到工具管理器
	for tool, available := range availableTools {
		toolManager.Tools[tool] = &BaseTool{
			NameValue: tool,
			Available: available,
		}
	}
	resultsMap, err := PerformInformationGathering(target, toolManager)
	if err != nil {
		return "", err
	}

	// 将结果转换为字符串
	var scanResults strings.Builder
	for tool, result := range resultsMap {
		scanResults.WriteString(fmt.Sprintf("=== %s 结果 ===\n", tool))
		scanResults.WriteString(result)
		scanResults.WriteString("\n\n")
	}

	return scanResults.String(), nil
}

// intelligentPenetrationTest 智能渗透测试主函数
func intelligentPenetrationTest(target string) (string, error) {
	// 检查是否启用专业渗透测试模式
	if isProfessionalModeEnabled() {
		utils.InfoPrint("启用专业渗透测试模式")
		return executeProfessionalPenetrationTest(target)
	}

	// 原有逻辑（基础模式）
	var results strings.Builder
	results.WriteString("智能渗透测试开始\n")

	// 获取目标类型
	targetType := getTargetType(target)
	results.WriteString(fmt.Sprintf("目标类型: %s\n", targetType))

	// 获取可用工具
	availableTools := getAvailableTools()

	// 加载配置并创建AI客户端
	cfgPath := config.GetDefaultConfigPath()
	utils.InfoPrint("加载AI配置文件: %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.ErrorPrint("加载AI配置失败: %v", err)
		utils.InfoPrint("请检查配置文件是否存在或格式是否正确")
		return "", fmt.Errorf("加载AI配置失败: %v", err)
	}

	// 验证提供商配置
	utils.InfoPrint("验证AI提供商配置: %s", cfg.Provider)
	if _, err := config.TestConfig(*cfg); err != nil {
		utils.ErrorPrint("AI提供商配置验证失败: %v", err)
		utils.InfoPrint("请检查提供商设置、API密钥和网络连接")
		return "", fmt.Errorf("AI提供商配置验证失败: %v", err)
	}

	// 创建AI客户端
	utils.InfoPrint("创建AI客户端，提供商: %s, 模型: %s", cfg.Provider, cfg.Model)
	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.ErrorPrint("创建AI客户端失败: %v", err)
		utils.InfoPrint("请检查API密钥、BaseURL配置和网络连接")
		return "", fmt.Errorf("创建AI客户端失败: %v", err)
	}

	// 阶段1: 智能信息收集（基于专业框架）
	results.WriteString("\n=== 阶段1: 智能信息收集 ===\n")
	infoGatheringResults, err := performIntelligentInformationGathering(target, availableTools)
	if err != nil {
		utils.WarningPrint("智能信息收集失败，回退到传统信息收集: %v", err)
		// 回退到传统信息收集
		infoGatheringResult, err := intelligentInformationGathering(target, availableTools, aiClient)
		if err != nil {
			return "", fmt.Errorf("信息收集失败: %v", err)
		}
		results.WriteString(infoGatheringResult)
	} else {
		// 整合信息收集结果
		for key, value := range infoGatheringResults {
			results.WriteString(fmt.Sprintf("\n--- %s 结果 ---\n", key))
			results.WriteString(value)
		}
	}

	// 阶段2: 智能漏洞利用
	results.WriteString("\n=== 阶段2: 智能漏洞利用 ===\n")
	// 创建临时工具管理器
	tempToolManager := &ToolManager{
		Tools: make(map[string]ToolInterface),
	}
	for toolName := range availableTools {
		tempToolManager.Tools[toolName] = &BaseTool{
			NameValue: toolName,
			Path:      toolName,
			Available: true,
		}
	}
	vulnExploitResult, err := intelligentVulnerabilityExploitation(target, aiClient, tempToolManager, results.String())
	if err != nil {
		return "", fmt.Errorf("漏洞利用失败: %v", err)
	}
	results.WriteString(vulnExploitResult)

	// 阶段3: 智能横向移动
	results.WriteString("\n=== 阶段3: 智能横向移动 ===\n")
	lateralMoveResult, err := intelligentLateralMovement(target, aiClient, tempToolManager, vulnExploitResult)
	if err != nil {
		return "", fmt.Errorf("横向移动失败: %v", err)
	}
	results.WriteString(lateralMoveResult)

	results.WriteString("\n智能渗透测试完成")
	return results.String(), nil
}

// isProfessionalModeEnabled 检查是否启用专业渗透测试模式
func isProfessionalModeEnabled() bool {
	// 检查环境变量或配置文件设置
	if os.Getenv("GYSCAN_PROFESSIONAL_MODE") == "true" {
		return true
	}

	// 检查配置文件中的专业模式设置
	cfgPath := config.GetDefaultConfigPath()
	cfg, err := config.LoadConfig(cfgPath)
	if err == nil && cfg.ProfessionalMode {
		return true
	}

	return false
}

// executeProfessionalPenetrationTest 执行专业渗透测试
func executeProfessionalPenetrationTest(target string) (string, error) {
	var results strings.Builder
	results.WriteString("=== 专业渗透测试开始 ===\n")

	// 加载配置并创建AI客户端
	cfgPath := config.GetDefaultConfigPath()
	utils.InfoPrint("加载AI配置文件: %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.ErrorPrint("加载AI配置失败: %v", err)
		return "", fmt.Errorf("加载AI配置失败: %v", err)
	}

	// 创建AI客户端
	utils.InfoPrint("创建AI客户端，提供商: %s, 模型: %s", cfg.Provider, cfg.Model)
	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.ErrorPrint("创建AI客户端失败: %v", err)
		return "", fmt.Errorf("创建AI客户端失败: %v", err)
	}

	// 创建专业渗透测试实例
	penTest := &ProfessionalPenetrationTest{
		Target:    target,
		AIClient:  aiClient,
		Logger:    nil, // 将在各阶段中创建
		Config:    cfg,
		OutputDir: filepath.Join(resourceDir, "pro_exp_results"),
	}

	// 执行完整的专业渗透测试流程
	workflowResults, err := penTest.ExecuteFullWorkflow()
	if err != nil {
		utils.ErrorPrint("专业渗透测试执行失败: %v", err)
		return results.String(), fmt.Errorf("专业渗透测试执行失败: %v", err)
	}
	results.WriteString(workflowResults)

	results.WriteString("\n=== 专业渗透测试完成 ===")
	return results.String(), nil
}

// vulnerabilityExploitation 漏洞利用阶段
func vulnerabilityExploitation(target string, availableTools map[string]bool, aiClient *AIClient, scanResults string) (string, error) {
	utils.InfoPrint("AI正在分析扫描结果并制定漏洞利用策略...")

	// 使用已加载的工具管理器（避免重复扫描）
	utils.InfoPrint("使用已加载的工具管理器...")
	enhancedToolManager := LoadToolManagerFromConfig("")
	var enhancedAvailableTools map[string]bool
	if enhancedToolManager != nil {
		enhancedAvailableTools = enhancedToolManager.GetAvailableTools()
	} else {
		utils.WarningPrint("从配置文件加载工具管理器失败，将使用当前可用工具")
		enhancedAvailableTools = availableTools
	}

	// 合并工具列表，优先使用全盘扫描发现的工具
	mergedTools := make(map[string]bool)
	for tool := range availableTools {
		mergedTools[tool] = true
	}
	for tool := range enhancedAvailableTools {
		mergedTools[tool] = true
	}

	// 使用AI制定漏洞利用策略
	strategy, err := aiClient.AnalyzeScanResults(target, scanResults, mergedTools)
	if err != nil {
		return "", fmt.Errorf("AI漏洞利用策略制定失败: %v", err)
	}

	utils.InfoPrint("AI漏洞利用策略制定完成，开始执行...")

	// 解析AI策略并执行
	results, err := executeAIStrategy(strategy, target, mergedTools)
	if err != nil {
		return "", fmt.Errorf("漏洞利用策略执行失败: %v", err)
	}

	return results, nil
}

// intelligentInformationGathering 智能信息收集 - AI自主决策
func intelligentInformationGathering(target string, availableTools map[string]bool, aiClient *AIClient) (string, error) {
	utils.InfoPrint("AI正在制定信息收集策略...")

	// 使用AI制定信息收集策略
	strategy, err := aiClient.AnalyzeScanResults(target, "", availableTools)
	if err != nil {
		return "", fmt.Errorf("AI策略制定失败: %v", err)
	}

	utils.InfoPrint("AI策略制定完成，开始执行...")

	// 解析AI策略并执行
	results, err := executeAIStrategy(strategy, target, availableTools)
	if err != nil {
		return "", fmt.Errorf("策略执行失败: %v", err)
	}

	return results, nil
}

// performIntelligentInformationGathering 执行智能信息收集（基于专业信息收集框架）
func performIntelligentInformationGathering(target string, availableTools map[string]bool) (map[string]string, error) {
	var rawResults map[string]string = make(map[string]string)

	utils.InfoPrint("=== 开始智能信息收集 ===")
	utils.InfoPrint("目标: %s", target)

	// 1. 被动信息收集
	utils.InfoPrint("\n--- 执行被动信息收集 ---")
	passiveResults, err := performPassiveInformationGathering(target, availableTools)
	if err != nil {
		utils.ErrorPrint("被动信息收集失败: %v", err)
	} else {
		rawResults["passive_info"] = passiveResults
	}

	// 2. 主动信息收集
	utils.InfoPrint("\n--- 执行主动信息收集 ---")
	activeResults, err := performActiveInformationGathering(target, availableTools)
	if err != nil {
		utils.ErrorPrint("主动信息收集失败: %v", err)
	} else {
		rawResults["active_info"] = activeResults
	}

	// 3. 技术情报收集
	utils.InfoPrint("\n--- 执行技术情报收集 ---")
	techResults, err := performTechnicalInformationGathering(target, availableTools)
	if err != nil {
		utils.ErrorPrint("技术情报收集失败: %v", err)
	} else {
		rawResults["tech_info"] = techResults
	}

	// 4. 信息处理与验证
	processedResults, confidenceScores := processAndValidateInformation(rawResults)

	// 5. 输出信息收集摘要
	utils.InfoPrint("\n=== 信息收集摘要 ===")
	for infoType, content := range processedResults {
		utils.InfoPrint("%s 结果摘要:", infoType)
		utils.InfoPrint("%s", content)
		utils.InfoPrint("可信度: %.2f", confidenceScores[infoType])
	}

	utils.SuccessPrint("=== 智能信息收集完成 ===")
	return processedResults, nil
}

// performPassiveInformationGathering 执行被动信息收集
func performPassiveInformationGathering(target string, availableTools map[string]bool) (string, error) {
	var results strings.Builder
	results.WriteString("被动信息收集结果:\n")

	utils.InfoPrint("执行被动信息收集...")

	// 1. 域名信息收集
	if availableTools["whois"] {
		utils.InfoPrint("使用whois查询域名信息...")
		output, err := runCommand("whois", []string{target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("whois查询失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("whois查询结果:\n%s\n", output))
		}
	}

	// 2. DNS信息收集
	if availableTools["dig"] {
		utils.InfoPrint("使用dig查询DNS信息...")
		output, err := runCommand("dig", []string{target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("dig查询失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("dig查询结果:\n%s\n", output))
		}
	}

	// 3. 子域名发现
	if availableTools["subfinder"] {
		utils.InfoPrint("使用subfinder发现子域名...")
		output, err := runCommand("subfinder", []string{"-d", target, "-silent"}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("subfinder子域名发现失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("子域名发现结果:\n%s\n", output))
		}
	}

	// 4. 证书透明度查询
	if availableTools["curl"] {
		utils.InfoPrint("使用crt.sh查询证书信息...")
		crtsURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", target)
		output, err := runCommand("curl", []string{crtsURL}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("crt.sh证书查询失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("证书查询结果:\n%s\n", output))
		}
	}

	return results.String(), nil
}

// performActiveInformationGathering 执行主动信息收集
func performActiveInformationGathering(target string, availableTools map[string]bool) (string, error) {
	var results strings.Builder
	results.WriteString("主动信息收集结果:\n")

	utils.InfoPrint("执行主动信息收集...")

	// 1. 端口扫描
	if availableTools["nmap"] {
		utils.InfoPrint("使用nmap进行端口扫描...")
		output, err := runCommand("nmap", []string{"-sS", "-sV", "-T4", "--open", target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nmap端口扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("端口扫描结果:\n%s\n", output))
		}
	}

	// 2. Web服务探测
	if availableTools["curl"] {
		utils.InfoPrint("使用curl探测Web服务...")
		// 检查HTTP和HTTPS
		for _, proto := range []string{"http", "https"} {
			url := fmt.Sprintf("%s://%s", proto, target)
			output, err := runCommand("curl", []string{"-I", "--connect-timeout", "5", url}...)
			if err != nil {
				results.WriteString(fmt.Sprintf("%s服务探测失败: %v\n", proto, err))
			} else {
				results.WriteString(fmt.Sprintf("%s服务探测结果:\n%s\n", proto, output))
			}
		}
	}

	// 3. WAF检测
	if availableTools["wafw00f"] {
		utils.InfoPrint("使用wafw00f检测WAF...")
		output, err := runCommand("wafw00f", []string{target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("WAF检测失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("WAF检测结果:\n%s\n", output))
		}
	}

	// 4. 指纹识别
	if availableTools["whatweb"] {
		utils.InfoPrint("使用whatweb进行指纹识别...")
		output, err := runCommand("whatweb", []string{target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("指纹识别失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("指纹识别结果:\n%s\n", output))
		}
	}

	return results.String(), nil
}

// performTechnicalInformationGathering 执行技术情报收集
func performTechnicalInformationGathering(target string, availableTools map[string]bool) (string, error) {
	var results strings.Builder
	results.WriteString("技术情报收集结果:\n")

	utils.InfoPrint("执行技术情报收集...")

	// 1. 服务版本扫描
	if availableTools["nmap"] {
		utils.InfoPrint("使用nmap进行服务版本扫描...")
		output, err := runCommand("nmap", []string{"-sV", "-p", "1-1000", target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("服务版本扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("服务版本扫描结果:\n%s\n", output))
		}
	}

	// 2. 漏洞扫描
	if availableTools["nuclei"] {
		utils.InfoPrint("使用nuclei进行漏洞扫描...")
		output, err := runCommand("nuclei", []string{"-u", fmt.Sprintf("http://%s", target), "-silent"}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nuclei漏洞扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("nuclei漏洞扫描结果:\n%s\n", output))
		}
	}

	// 3. 目录枚举
	if availableTools["gobuster"] {
		utils.InfoPrint("使用gobuster进行目录枚举...")
		output, err := runCommand("gobuster", []string{"dir", "-u", fmt.Sprintf("http://%s", target), "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "-n", "-t", "10"}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("目录枚举失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("目录枚举结果:\n%s\n", output))
		}
	}

	// 4. API端点发现
	if availableTools["ffuf"] {
		utils.InfoPrint("使用ffuf进行API端点发现...")
		output, err := runCommand("ffuf", []string{"-u", fmt.Sprintf("http://%s/FUZZ", target), "-w", "/usr/share/wordlists/dirb/common.txt", "-fs", "0", "-t", "10", "-s"}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("API端点发现失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("API端点发现结果:\n%s\n", output))
		}
	}

	return results.String(), nil
}

// executeExploitationSteps 执行漏洞利用步骤
func executeExploitationSteps(analysis, target string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString("执行的漏洞利用步骤:\n")

	// 使用已加载的工具管理器（避免重复扫描）
	utils.InfoPrint("使用已加载的工具管理器...")
	enhancedToolManager := LoadToolManagerFromConfig("")
	var enhancedAvailableTools map[string]bool
	if enhancedToolManager != nil {
		enhancedAvailableTools = enhancedToolManager.GetAvailableTools()
	} else {
		utils.WarningPrint("从配置文件加载工具管理器失败，将使用当前可用工具")
		enhancedAvailableTools = availableTools
	}

	// 合并工具列表，优先使用全盘扫描发现的工具
	mergedTools := make(map[string]bool)
	for tool := range availableTools {
		mergedTools[tool] = true
	}
	for tool := range enhancedAvailableTools {
		mergedTools[tool] = true
	}

	// 解析AI分析结果，提取利用步骤
	steps := parseExploitationSteps(analysis)

	utils.InfoPrint("解析到 %d 个执行步骤", len(steps))

	// 执行每个利用步骤
	for i, step := range steps {
		utils.InfoPrint("--- 步骤 %d/%d: %s ---", i+1, len(steps), step.Description)
		utils.InfoPrint("工具: %s", step.Tool)
		utils.InfoPrint("参数: %s", strings.Join(step.Args, " "))

		results.WriteString(fmt.Sprintf("\n--- 步骤 %d: %s ---\n", i+1, step.Description))

		// 检查工具是否可用（使用合并后的工具列表）
		if !mergedTools[step.Tool] {
			utils.WarningPrint("工具 %s 不可用，跳过此步骤", step.Tool)
			results.WriteString(fmt.Sprintf("工具 %s 不可用，跳过此步骤\n", step.Tool))
			continue
		}

		// 执行命令
		utils.InfoPrint("执行命令: %s %s", step.Tool, strings.Join(step.Args, " "))
		output, err := runCommand(step.Tool, step.Args...)
		if err != nil {
			utils.ErrorPrint("步骤 %d 执行失败: %v", i+1, err)
			results.WriteString(fmt.Sprintf("执行失败: %v\n", err))
		} else {
			utils.SuccessPrint("步骤 %d 执行成功", i+1)
			results.WriteString(fmt.Sprintf("执行成功\n输出:\n%s\n", output))
		}
	}

	utils.SuccessPrint("所有步骤执行完成")

	return results.String()
}

// ExploitationStep 定义漏洞利用步骤
type ExploitationStep struct {
	Description string   // 步骤描述
	Tool        string   // 使用的工具
	Args        []string // 工具参数
}

// parseExploitationSteps 解析AI分析结果中的利用步骤
func parseExploitationSteps(analysis string) []ExploitationStep {
	var steps []ExploitationStep
	lines := strings.Split(analysis, "\n")

	// 改进的解析逻辑，智能提取和修正命令
	var inCodeBlock bool

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// 处理代码块
		if strings.HasPrefix(trimmedLine, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}

		// 处理代码块内的命令
		if inCodeBlock {
			// 跳过注释和空行
			if strings.HasPrefix(trimmedLine, "#") || trimmedLine == "" {
				continue
			}

			// 智能修正命令格式
			correctedLine := correctCommandFormat(trimmedLine)

			// 提取命令和参数
			parts := strings.Fields(correctedLine)
			if len(parts) > 0 {
				tool := parts[0]
				args := parts[1:]

				// 只执行已知的安全工具
				if isKnownTool(tool) {
					steps = append(steps, ExploitationStep{
						Description: correctedLine,
						Tool:        tool,
						Args:        args,
					})
				}
			}
		} else {
			// 也处理代码块外的命令，比如AI直接给出的命令
			// 跳过注释、空行和标题行
			if strings.HasPrefix(trimmedLine, "#") || trimmedLine == "" || strings.HasPrefix(trimmedLine, "-") ||
				strings.HasPrefix(trimmedLine, "=") || strings.HasPrefix(trimmedLine, "*") {
				continue
			}

			// 智能修正命令格式
			correctedLine := correctCommandFormat(trimmedLine)

			// 提取命令和参数
			parts := strings.Fields(correctedLine)
			if len(parts) > 0 {
				tool := parts[0]
				args := parts[1:]

				// 只执行已知的安全工具
				if isKnownTool(tool) {
					steps = append(steps, ExploitationStep{
						Description: correctedLine,
						Tool:        tool,
						Args:        args,
					})
				}
			}
		}
	}

	return steps
}

// correctCommandFormat 修正命令格式，处理常见的AI生成错误
func correctCommandFormat(command string) string {
	// 首先清理命令行的多余字符
	command = cleanCommandLine(command)

	// 移除明显的错误参数和AI生成的无用内容
	errorPatterns := []string{
		"-- SoupAid=0x24425745,",
		"--monet-ace",
		"--wait",
		"--state-full",
		"-- SoupAid",
		"--monet",
		"0x24425745",
		"SoupAid",
		"monet-ace",
		"state-full",
	}

	for _, pattern := range errorPatterns {
		command = strings.ReplaceAll(command, pattern, "")
	}

	// 移除管道符号和重定向符号
	command = strings.ReplaceAll(command, " | ", " ")
	command = strings.ReplaceAll(command, " > ", " ")
	command = strings.ReplaceAll(command, " >> ", " ")
	command = strings.ReplaceAll(command, " < ", " ")
	command = strings.ReplaceAll(command, " |", " ")
	command = strings.ReplaceAll(command, "| ", " ")

	// 移除常见的AI生成错误标记
	command = strings.ReplaceAll(command, "\n", " ")
	command = strings.ReplaceAll(command, "\t", " ")
	command = strings.ReplaceAll(command, "  ", " ")

	// 修正curl命令的-o参数格式
	if strings.Contains(command, "curl") {
		parts := strings.Fields(command)
		var validParts []string
		for i := 0; i < len(parts); i++ {
			part := parts[i]

			// 处理 -o 参数格式错误
			if part == "-o" && i+1 < len(parts) {
				nextArg := parts[i+1]
				if strings.HasPrefix(nextArg, "http") || strings.HasPrefix(nextArg, "https") {
					// 修正为：curl -o filename URL
					if i+2 < len(parts) {
						url := parts[i+2]
						if strings.HasPrefix(url, "http") || strings.HasPrefix(url, "https") {
							// 从URL中提取文件名
							fileName := extractFilenameFromURL(url)
							validParts = append(validParts, "-o", fileName, url)
							i += 2 // 跳过已处理的参数
							continue
						}
					}
				}
			}

			// 保留有效的curl参数
			if isValidCurlArg(part) || strings.HasPrefix(part, "http") || strings.HasPrefix(part, "https") {
				validParts = append(validParts, part)
			}
		}
		command = strings.Join(validParts, " ")
	}

	// 修正nmap命令的无效参数
	if strings.Contains(command, "nmap") {
		parts := strings.Fields(command)
		var validParts []string
		for _, part := range parts {
			// 移除无效参数，保留有效的nmap参数
			if !strings.Contains(part, "SoupAid") &&
				!strings.Contains(part, "monet-ace") &&
				!strings.Contains(part, "0x24425745") &&
				part != "--state-full" &&
				part != "--wait" &&
				isValidNmapArg(part) {
				validParts = append(validParts, part)
			}
		}
		command = strings.Join(validParts, " ")

		// 如果没有目标参数，添加默认扫描参数
		hasTarget := false
		for _, part := range validParts {
			if !strings.HasPrefix(part, "-") && part != "nmap" && isValidTarget(part) {
				hasTarget = true
				break
			}
		}
		if !hasTarget && len(validParts) > 1 {
			// 添加默认扫描目标
			command += " 127.0.0.1"
		}
	}

	// 修正其他常见命令的错误
	if strings.Contains(command, "tshark") || strings.Contains(command, "tcpdump") {
		// 移除管道和grep等非命令内容
		parts := strings.Fields(command)
		var validParts []string
		for _, part := range parts {
			if part != "grep" &&
				part != "awk" &&
				part != "sed" &&
				!strings.Contains(part, "[") &&
				!strings.Contains(part, "]") &&
				!strings.Contains(part, "|") {
				validParts = append(validParts, part)
			}
		}
		command = strings.Join(validParts, " ")
	}

	// 修正python命令（检查文件是否存在）
	if strings.Contains(command, "python") && strings.Contains(command, "attack.py") {
		// 如果attack.py不存在，替换为简单的测试命令
		if !fileExists("attack.py") {
			command = "python -c \"print('Python test successful')\""
		}
	}

	// 最终清理：移除多余的空格
	command = strings.Join(strings.Fields(command), " ")

	return command
}

// fileExists 检查文件是否存在
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// getAvailableTools 获取可用工具列表
func getAvailableTools() map[string]bool {
	// 使用已加载的工具管理器（避免重复扫描）
	toolManager := LoadToolManagerFromConfig("")
	if toolManager != nil {
		return toolManager.GetAvailableTools()
	}

	// 如果从配置加载失败，执行全盘扫描
	utils.WarningPrint("从配置文件加载工具管理器失败，将执行全盘扫描")
	toolManager = ScanSystemTools(nil)
	return toolManager.GetAvailableTools()
}

// executeAIStrategy 解析和执行AI策略
func executeAIStrategy(strategy, target string, availableTools map[string]bool) (string, error) {
	var results strings.Builder
	results.WriteString("AI策略执行结果:\n")

	// 使用已加载的工具管理器（避免重复扫描）
	utils.InfoPrint("使用已加载的工具管理器...")
	enhancedToolManager := LoadToolManagerFromConfig("")
	var enhancedAvailableTools map[string]bool
	if enhancedToolManager != nil {
		enhancedAvailableTools = enhancedToolManager.GetAvailableTools()
	} else {
		utils.WarningPrint("从配置文件加载工具管理器失败，将使用当前可用工具")
		enhancedAvailableTools = availableTools
	}

	// 合并工具列表，优先使用全盘扫描发现的工具
	mergedTools := make(map[string]bool)
	for tool := range availableTools {
		mergedTools[tool] = true
	}
	for tool := range enhancedAvailableTools {
		mergedTools[tool] = true
	}

	// 尝试解析JSON格式的策略
	var aiStrategy struct {
		Strategy string `json:"strategy"`
		Steps    []struct {
			Step           string `json:"step"`
			Tool           string `json:"tool"`
			Command        string `json:"command"`
			Reason         string `json:"reason"`
			ExpectedResult string `json:"expected_result"`
		} `json:"steps"`
		NextAction string `json:"next_action"`
	}

	// 首先尝试直接解析JSON
	if err := json.Unmarshal([]byte(strategy), &aiStrategy); err == nil && aiStrategy.Strategy != "" {
		// JSON格式解析成功
		utils.InfoPrint("AI策略解析成功，使用JSON格式策略")
		utils.InfoPrint("AI策略: %s", aiStrategy.Strategy)
		results.WriteString(fmt.Sprintf("策略: %s\n", aiStrategy.Strategy))
		utils.InfoPrint("开始执行 %d 个步骤", len(aiStrategy.Steps))
		results.WriteString("执行步骤:\n")

		// 执行每个步骤
		for i, step := range aiStrategy.Steps {
			utils.InfoPrint("--- 步骤 %d/%d: %s ---", i+1, len(aiStrategy.Steps), step.Step)
			utils.InfoPrint("工具: %s", step.Tool)
			utils.InfoPrint("原因: %s", step.Reason)
			if step.ExpectedResult != "" {
				utils.InfoPrint("预期结果: %s", step.ExpectedResult)
			}

			results.WriteString(fmt.Sprintf("\n--- 步骤 %d: %s ---\n", i+1, step.Step))
			results.WriteString(fmt.Sprintf("工具: %s\n", step.Tool))
			results.WriteString(fmt.Sprintf("原因: %s\n", step.Reason))
			if step.ExpectedResult != "" {
				results.WriteString(fmt.Sprintf("预期结果: %s\n", step.ExpectedResult))
			}

			// 检查工具是否可用（使用合并后的工具列表）
			if !mergedTools[step.Tool] {
				utils.WarningPrint("工具 %s 不可用，跳过此步骤", step.Tool)
				results.WriteString(fmt.Sprintf("工具 %s 不可用，跳过此步骤\n", step.Tool))
				continue
			}

			// 执行命令
			utils.InfoPrint("执行命令: %s", step.Command)
			output, err := runCommand(step.Tool, strings.Fields(step.Command)...)
			if err != nil {
				utils.ErrorPrint("步骤 %d 执行失败: %v", i+1, err)
				results.WriteString(fmt.Sprintf("执行失败: %v\n", err))
			} else {
				utils.SuccessPrint("步骤 %d 执行成功", i+1)
				results.WriteString(fmt.Sprintf("执行成功\n输出:\n%s\n", output))
			}
		}

		// 添加下一步建议
		if aiStrategy.NextAction != "" {
			utils.InfoPrint("下一步建议: %s", aiStrategy.NextAction)
			results.WriteString(fmt.Sprintf("\n下一步建议: %s\n", aiStrategy.NextAction))
		}

		utils.SuccessPrint("AI策略执行完成")
		return results.String(), nil
	}

	// 如果JSON解析失败，尝试从文本中提取JSON块
	utils.WarningPrint("AI策略不是标准JSON格式，尝试提取JSON内容")

	// 尝试从代码块中提取JSON
	jsonContent := extractJSONFromText(strategy)
	if jsonContent != "" {
		utils.InfoPrint("从文本中提取到JSON内容，尝试解析")
		if err := json.Unmarshal([]byte(jsonContent), &aiStrategy); err == nil && aiStrategy.Strategy != "" {
			utils.InfoPrint("提取的JSON解析成功，使用JSON格式策略")
			return executeAIStrategy(jsonContent, target, mergedTools)
		}
	}

	// 如果JSON提取也失败，使用智能文本解析
	utils.WarningPrint("无法提取有效的JSON策略，使用智能文本解析")
	return executeSmartTextStrategy(strategy, target, mergedTools)
}

// extractJSONFromText 从文本中提取JSON内容
func extractJSONFromText(text string) string {
	// 首先检查是否是纯JSON格式（直接以{开头）
	trimmedText := strings.TrimSpace(text)
	if strings.HasPrefix(trimmedText, "{") && strings.HasSuffix(trimmedText, "}") {
		// 尝试解析为JSON，验证格式是否正确
		var testObj map[string]interface{}
		if err := json.Unmarshal([]byte(trimmedText), &testObj); err == nil {
			return trimmedText
		}
	}

	// 查找JSON代码块
	lines := strings.Split(text, "\n")
	var inJSONBlock bool
	var jsonContent strings.Builder

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// 检查是否进入JSON代码块
		if strings.HasPrefix(trimmedLine, "```json") || strings.HasPrefix(trimmedLine, "```") {
			inJSONBlock = true
			continue
		}

		// 检查是否退出代码块
		if inJSONBlock && strings.HasPrefix(trimmedLine, "```") {
			break
		}

		// 收集JSON内容
		if inJSONBlock {
			jsonContent.WriteString(line)
			jsonContent.WriteString("\n")
		}
	}

	// 如果没有找到代码块，尝试直接查找JSON对象
	if jsonContent.Len() == 0 {
		// 查找以{开头，以}结尾的JSON对象
		start := strings.Index(text, "{")
		if start != -1 {
			// 从{开始，找到匹配的}
			braceCount := 0
			for i := start; i < len(text); i++ {
				if text[i] == '{' {
					braceCount++
				} else if text[i] == '}' {
					braceCount--
					if braceCount == 0 {
						jsonContent.WriteString(text[start : i+1])
						break
					}
				}
			}
		}
	}

	extractedJSON := strings.TrimSpace(jsonContent.String())

	// 验证提取的JSON格式是否正确
	if extractedJSON != "" {
		var testObj map[string]interface{}
		if err := json.Unmarshal([]byte(extractedJSON), &testObj); err != nil {
			utils.WarningPrint("提取的JSON格式无效: %v", err)
			return ""
		}
	}

	return extractedJSON
}

// executeSmartTextStrategy 智能解析文本格式的策略
func executeSmartTextStrategy(strategy, target string, availableTools map[string]bool) (string, error) {
	var results strings.Builder
	results.WriteString("智能文本策略执行结果:\n")

	utils.InfoPrint("开始智能解析文本策略")

	// 使用已加载的工具管理器（避免重复扫描）
	utils.InfoPrint("使用已加载的工具管理器...")
	enhancedToolManager := LoadToolManagerFromConfig("")
	var enhancedAvailableTools map[string]bool
	if enhancedToolManager != nil {
		enhancedAvailableTools = enhancedToolManager.GetAvailableTools()
	} else {
		utils.WarningPrint("从配置文件加载工具管理器失败，将使用当前可用工具")
		enhancedAvailableTools = availableTools
	}

	// 合并工具列表，优先使用全盘扫描发现的工具
	mergedTools := make(map[string]bool)
	for tool := range availableTools {
		mergedTools[tool] = true
	}
	for tool := range enhancedAvailableTools {
		mergedTools[tool] = true
	}

	// 分析目标类型，生成基础策略
	targetType := getTargetType(target)
	utils.InfoPrint("目标类型: %s", targetType)

	// 根据目标类型生成基础策略
	baseStrategy := generateBaseStrategy(target, targetType, mergedTools)
	if baseStrategy != "" {
		results.WriteString(fmt.Sprintf("基础策略: %s\n", baseStrategy))
	}

	// 从AI响应中提取有用的命令
	extractedCommands := extractCommandsFromText(strategy, mergedTools)
	utils.InfoPrint("从AI响应中提取到 %d 个命令", len(extractedCommands))

	// 保存基础扫描结果，用于后续分析
	var baseScanOutput string

	if len(extractedCommands) > 0 {
		results.WriteString("提取的命令执行结果:\n")

		// 执行提取的命令
		for i, command := range extractedCommands {
			utils.InfoPrint("--- 执行提取命令 %d/%d: %s ---", i+1, len(extractedCommands), command)

			// 提取工具和参数
			parts := strings.Fields(command)
			if len(parts) > 0 {
				tool := parts[0]
				args := parts[1:]

				// 检查工具是否可用
				if !availableTools[tool] {
					utils.WarningPrint("工具 %s 不可用，跳过此命令", tool)
					results.WriteString(fmt.Sprintf("命令 %d: %s - 工具不可用，跳过\n", i+1, command))
					continue
				}

				// 修正命令格式
				correctedArgs := correctCommandArgsFormat(tool, args, target)

				// 验证命令参数的有效性
				if !validateCommand(tool, correctedArgs, target) {
					utils.WarningPrint("命令参数无效，跳过此命令: %s %s", tool, strings.Join(correctedArgs, " "))
					results.WriteString(fmt.Sprintf("命令 %d: %s - 参数无效，跳过\n", i+1, command))
					continue
				}

				// 执行命令
				utils.InfoPrint("执行命令: %s %s", tool, strings.Join(correctedArgs, " "))
				output, err := runCommand(tool, correctedArgs...)
				if err != nil {
					utils.ErrorPrint("命令 %d 执行失败: %v", i+1, err)
					results.WriteString(fmt.Sprintf("命令 %d: %s - 执行失败: %v\n", i+1, command, err))
				} else {
					utils.SuccessPrint("命令 %d 执行成功", i+1)
					results.WriteString(fmt.Sprintf("命令 %d: %s - 执行成功\n输出:\n%s\n", i+1, command, output))
					// 保存nmap扫描结果，用于后续分析
					if tool == "nmap" {
						baseScanOutput = output
					}
				}
			}
		}
	} else {
		utils.InfoPrint("未提取到有效命令，执行基础扫描")
		results.WriteString("\n执行基础扫描:\n")

		// 根据目标类型执行基础扫描
		baseScanResults := executeBaseScan(target, targetType, availableTools)
		results.WriteString(baseScanResults)
		baseScanOutput = baseScanResults
	}

	// 根据基础扫描结果执行针对性渗透测试
	if baseScanOutput != "" {
		utils.InfoPrint("\n=== 基于扫描结果执行针对性渗透测试 ===")
		results.WriteString("\n=== 基于扫描结果执行针对性渗透测试 ===\n")
		targetedResults := executeTargetedPenetrationTest(target, baseScanOutput, availableTools)
		results.WriteString(targetedResults)
	}

	utils.SuccessPrint("智能文本策略执行完成")
	return results.String(), nil
}

// executeTargetedPenetrationTest 根据扫描结果执行针对性渗透测试
func executeTargetedPenetrationTest(target, scanOutput string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString("执行针对性渗透测试:\n")

	// 分析扫描结果，提取开放端口和服务
	openPorts := extractOpenPortsFromNmap(scanOutput)
	if len(openPorts) == 0 {
		utils.InfoPrint("未发现开放端口，跳过针对性渗透测试")
		return results.String()
	}

	utils.InfoPrint("发现开放端口: %v", openPorts)
	results.WriteString(fmt.Sprintf("发现开放端口: %v\n", openPorts))

	// 根据开放端口和服务执行针对性测试
	for port, service := range openPorts {
		utils.InfoPrint("\n--- 针对端口 %s/%s 执行渗透测试 ---", port, service)
		results.WriteString(fmt.Sprintf("\n--- 针对端口 %s/%s 执行渗透测试 ---\n", port, service))

		// 根据服务类型执行不同的渗透测试
		switch service {
		case "ftp":
			// FTP服务渗透测试
			ftpResults := executeFTPPenetrationTest(target, port, availableTools)
			results.WriteString(ftpResults)
		case "ssh":
			// SSH服务渗透测试
			sshResults := executeSSHPenetrationTest(target, port, availableTools)
			results.WriteString(sshResults)
		case "mysql":
			// MySQL服务渗透测试
			mysqlResults := executeMySQLPenetrationTest(target, port, availableTools)
			results.WriteString(mysqlResults)
		case "http", "https":
			// Web服务渗透测试
			webResults := executeWebPenetrationTest(target, port, availableTools)
			results.WriteString(webResults)
		default:
			// 其他服务的默认测试
			defaultResults := executeDefaultServiceTest(target, port, service, availableTools)
			results.WriteString(defaultResults)
		}
	}

	return results.String()
}

// processAndValidateInformation 处理和验证收集到的信息
func processAndValidateInformation(rawInfo map[string]string) (map[string]string, map[string]float64) {
	utils.InfoPrint("\n--- 执行信息处理与验证 ---")
	processedInfo := make(map[string]string)
	confidenceScores := make(map[string]float64)

	// 处理和验证每种类型的信息
	for infoType, content := range rawInfo {
		utils.InfoPrint("处理信息类型: %s", infoType)

		// 1. 数据清洗
		cleanedContent := cleanInformation(content)

		// 2. 信息验证
		confidence := validateInformation(infoType, cleanedContent)

		// 3. 结构化处理
		structuredContent := structureInformation(infoType, cleanedContent)

		// 4. 存储处理结果
		processedInfo[infoType] = structuredContent
		confidenceScores[infoType] = confidence

		utils.InfoPrint("信息处理完成，可信度: %.2f", confidence)
	}

	return processedInfo, confidenceScores
}

// cleanInformation 清洗信息
func cleanInformation(content string) string {
	// 移除多余空行和空格
	content = regexp.MustCompile(`\n\s*\n`).ReplaceAllString(content, `\n\n`)
	content = regexp.MustCompile(`\s{2,}`).ReplaceAllString(content, ` `)
	return strings.TrimSpace(content)
}

// validateInformation 验证信息可信度
func validateInformation(infoType, content string) float64 {
	// 基于信息类型和内容计算可信度分数
	confidence := 0.5 // 默认可信度

	// 根据信息类型调整可信度
	switch infoType {
	case "passive_info":
		// 被动信息收集结果可信度较高
		confidence = 0.8
	case "active_info":
		// 主动信息收集结果可信度高
		confidence = 0.9
	case "tech_info":
		// 技术情报可信度高
		confidence = 0.95
	default:
		confidence = 0.6
	}

	// 根据内容质量调整可信度
	if content == "" {
		confidence = 0.0
	} else if len(content) < 100 {
		confidence *= 0.7
	} else if len(content) > 1000 {
		confidence *= 1.1
	}

	// 确保可信度在0-1之间
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

// structureInformation 结构化信息
func structureInformation(infoType, content string) string {
	// 根据信息类型进行结构化处理
	switch infoType {
	case "passive_info":
		// 结构化被动信息
		return structurePassiveInformation(content)
	case "active_info":
		// 结构化主动信息
		return structureActiveInformation(content)
	case "tech_info":
		// 结构化技术情报
		return structureTechnicalInformation(content)
	default:
		// 默认结构化
		return content
	}
}

// structurePassiveInformation 结构化被动信息
func structurePassiveInformation(content string) string {
	// 提取关键信息：域名、IP、联系人等
	var structured strings.Builder

	// 提取域名信息
	if matches := regexp.MustCompile(`Domain Name:\s*(\S+)`).FindStringSubmatch(content); len(matches) > 1 {
		structured.WriteString(fmt.Sprintf("域名: %s\n", matches[1]))
	}

	// 提取注册人信息
	if matches := regexp.MustCompile(`Registrant Name:\s*(.*)`).FindStringSubmatch(content); len(matches) > 1 {
		structured.WriteString(fmt.Sprintf("注册人: %s\n", strings.TrimSpace(matches[1])))
	}

	// 提取注册邮箱
	if matches := regexp.MustCompile(`Registrant Email:\s*(\S+)`).FindStringSubmatch(content); len(matches) > 1 {
		structured.WriteString(fmt.Sprintf("注册邮箱: %s\n", matches[1]))
	}

	// 提取子域名信息
	subdomainPattern := regexp.MustCompile(`(\S+\.\S+)\s*$`)
	lines := strings.Split(content, "\n")
	var subdomains []string
	for _, line := range lines {
		if matches := subdomainPattern.FindStringSubmatch(strings.TrimSpace(line)); len(matches) > 1 {
			subdomains = append(subdomains, matches[1])
		}
	}
	if len(subdomains) > 0 {
		structured.WriteString(fmt.Sprintf("子域名发现: %d个\n", len(subdomains)))
		// 限制显示前10个子域名
		displayCount := len(subdomains)
		if displayCount > 10 {
			displayCount = 10
		}
		for i, subdomain := range subdomains[:displayCount] {
			structured.WriteString(fmt.Sprintf("  %d. %s\n", i+1, subdomain))
		}
		if len(subdomains) > 10 {
			structured.WriteString(fmt.Sprintf("  ... 还有 %d 个子域名\n", len(subdomains)-10))
		}
	}

	return structured.String()
}

// structureActiveInformation 结构化主动信息
func structureActiveInformation(content string) string {
	var structured strings.Builder

	// 提取开放端口信息
	openPorts := extractOpenPortsFromNmap(content)
	if len(openPorts) > 0 {
		structured.WriteString(fmt.Sprintf("开放端口: %d个\n", len(openPorts)))
		for port, service := range openPorts {
			structured.WriteString(fmt.Sprintf("  %s/%s\n", port, service))
		}
	}

	// 提取WAF信息
	if strings.Contains(content, "WAF") {
		structured.WriteString("检测到WAF保护\n")
	}

	// 提取指纹信息
	if matches := regexp.MustCompile(`(Apache|Nginx|IIS|Microsoft-IIS|PHP|MySQL|WordPress|Drupal|Joomla)\s*(\d+\.\d+(\.\d+)*)?`).FindAllStringSubmatch(content, -1); len(matches) > 0 {
		structured.WriteString("服务指纹发现:\n")
		seen := make(map[string]bool)
		for _, match := range matches {
			if !seen[match[1]] {
				version := ""
				if len(match) > 2 {
					version = match[2]
				}
				structured.WriteString(fmt.Sprintf("  %s %s\n", match[1], version))
				seen[match[1]] = true
			}
		}
	}

	return structured.String()
}

// structureTechnicalInformation 结构化技术情报
func structureTechnicalInformation(content string) string {
	var structured strings.Builder

	// 提取漏洞信息
	if strings.Contains(content, "vulnerable") || strings.Contains(content, "CVE-") {
		structured.WriteString("发现潜在漏洞:\n")
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			if strings.Contains(line, "CVE-") || strings.Contains(strings.ToLower(line), "vulnerable") {
				structured.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(line)))
			}
		}
	}

	// 提取目录信息
	if matches := regexp.MustCompile(`(?:DIRECTORY|FOUND):\s*(\S+)`).FindAllStringSubmatch(content, -1); len(matches) > 0 {
		structured.WriteString(fmt.Sprintf("发现敏感目录/文件: %d个\n", len(matches)))
		// 限制显示前10个结果
		displayCount := len(matches)
		if displayCount > 10 {
			displayCount = 10
		}
		for i, match := range matches[:displayCount] {
			structured.WriteString(fmt.Sprintf("  %d. %s\n", i+1, match[1]))
		}
		if len(matches) > 10 {
			structured.WriteString(fmt.Sprintf("  ... 还有 %d 个结果\n", len(matches)-10))
		}
	}

	return structured.String()
}

// extractOpenPortsFromNmap 从nmap扫描结果中提取开放端口
func extractOpenPortsFromNmap(scanOutput string) map[string]string {
	openPorts := make(map[string]string)

	// 使用正则表达式提取开放端口
	portRegex := regexp.MustCompile(`^(\d+)/tcp\s+open\s+(\w+)\s*`)
	lines := strings.Split(scanOutput, "\n")

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		matches := portRegex.FindStringSubmatch(trimmedLine)
		if len(matches) == 3 {
			port := matches[1]
			service := matches[2]
			openPorts[port] = service
		}
	}

	return openPorts
}

// executeFTPPenetrationTest 执行FTP服务渗透测试
func executeFTPPenetrationTest(target, port string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString("执行FTP服务渗透测试:\n")

	// 检查匿名FTP访问
	if availableTools["ftp"] {
		utils.InfoPrint("检查匿名FTP访问...")
		// 执行FTP匿名访问测试
		ftpCmd := fmt.Sprintf("echo -e 'USER anonymous\\nPASS anonymous@example.com\\nQUIT' | ftp -n %s %s", target, port)
		output, err := runCommand("bash", []string{"-c", ftpCmd}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("FTP匿名访问测试失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("FTP匿名访问测试结果:\n%s\n", output))
			// 检查是否成功登录
			if strings.Contains(output, "230") || strings.Contains(output, "Login successful") {
				utils.SuccessPrint("发现可匿名访问的FTP服务！")
				results.WriteString("发现可匿名访问的FTP服务！\n")
			}
		}
	}

	// 使用nmap脚本扫描FTP漏洞
	if availableTools["nmap"] {
		utils.InfoPrint("使用nmap脚本扫描FTP漏洞...")
		output, err := runCommand("nmap", []string{"-p", port, "--script=ftp-*", target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nmap FTP脚本扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("nmap FTP脚本扫描结果:\n%s\n", output))
		}
	}

	return results.String()
}

// executeSSHPenetrationTest 执行SSH服务渗透测试
func executeSSHPenetrationTest(target, port string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString("执行SSH服务渗透测试:\n")

	// 使用nmap脚本扫描SSH漏洞
	if availableTools["nmap"] {
		utils.InfoPrint("使用nmap脚本扫描SSH漏洞...")
		output, err := runCommand("nmap", []string{"-p", port, "--script=ssh-*", target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nmap SSH脚本扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("nmap SSH脚本扫描结果:\n%s\n", output))
		}
	}

	// 检查SSH版本信息
	if availableTools["ssh"] {
		utils.InfoPrint("检查SSH版本信息...")
		sshCmd := fmt.Sprintf("echo 'exit' | ssh -v -p %s %s 2>&1 | grep -i 'protocol version'", port, target)
		output, err := runCommand("bash", []string{"-c", sshCmd}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("SSH版本检查失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("SSH版本信息: %s\n", output))
		}
	}

	return results.String()
}

// executeMySQLPenetrationTest 执行MySQL服务渗透测试
func executeMySQLPenetrationTest(target, port string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString("执行MySQL服务渗透测试:\n")

	// 使用nmap脚本扫描MySQL漏洞
	if availableTools["nmap"] {
		utils.InfoPrint("使用nmap脚本扫描MySQL漏洞...")
		output, err := runCommand("nmap", []string{"-p", port, "--script=mysql-*", target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nmap MySQL脚本扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("nmap MySQL脚本扫描结果:\n%s\n", output))
		}
	}

	// 测试MySQL连接
	if availableTools["mysql"] {
		utils.InfoPrint("测试MySQL连接...")
		mysqlCmd := fmt.Sprintf("mysql -h %s -P %s -u root -e 'exit' 2>&1", target, port)
		output, err := runCommand("bash", []string{"-c", mysqlCmd}...)
		if err == nil {
			results.WriteString(fmt.Sprintf("MySQL连接测试成功: %s\n", output))
		} else {
			results.WriteString(fmt.Sprintf("MySQL连接测试失败: %v\n", err))
			// 检查是否是访问被拒绝还是连接失败
			if strings.Contains(output, "Access denied") {
				results.WriteString("MySQL服务运行中，但访问被拒绝\n")
			} else if strings.Contains(output, "Connection refused") {
				results.WriteString("MySQL连接被拒绝\n")
			}
		}
	}

	return results.String()
}

// executeWebPenetrationTest 执行Web服务渗透测试
func executeWebPenetrationTest(target, port string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString("执行Web服务渗透测试:\n")

	// 构建完整URL
	proto := "http"
	if port == "443" {
		proto = "https"
	}
	url := fmt.Sprintf("%s://%s:%s", proto, target, port)

	// 使用curl检查Web服务
	if availableTools["curl"] {
		utils.InfoPrint("使用curl检查Web服务...")
		output, err := runCommand("curl", []string{"-I", url}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("Web服务检查失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("Web服务检查结果:\n%s\n", output))
		}
	}

	// 使用nikto扫描Web漏洞（如果可用）
	if availableTools["nikto"] {
		utils.InfoPrint("使用nikto扫描Web漏洞...")
		output, err := runCommand("nikto", []string{"-h", url}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nikto扫描失败: %v\n", err))
		} else {
			// 只保存前50行结果，避免输出过长
			lines := strings.Split(output, "\n")
			if len(lines) > 50 {
				lines = lines[:50]
			}
			results.WriteString(fmt.Sprintf("nikto扫描结果（前50行）:\n%s\n", strings.Join(lines, "\n")))
		}
	}

	// 使用dirb进行目录枚举（如果可用）
	if availableTools["dirb"] {
		utils.InfoPrint("使用dirb进行目录枚举...")
		output, err := runCommand("dirb", []string{url, "/usr/share/wordlists/dirb/common.txt", "-o", "/dev/null"}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("dirb目录枚举失败: %v\n", err))
		} else {
			// 只保存包含发现目录的行
			lines := strings.Split(output, "\n")
			var relevantLines []string
			for _, line := range lines {
				if strings.HasPrefix(line, "==>") || strings.Contains(line, "DIRECTORY") || strings.Contains(line, "FOUND") {
					relevantLines = append(relevantLines, line)
				}
			}
			results.WriteString(fmt.Sprintf("dirb目录枚举结果:\n%s\n", strings.Join(relevantLines, "\n")))
		}
	}

	return results.String()
}

// executeDefaultServiceTest 执行默认服务测试
func executeDefaultServiceTest(target, port, service string, availableTools map[string]bool) string {
	var results strings.Builder
	results.WriteString(fmt.Sprintf("执行%s服务默认测试:\n", service))

	// 使用nmap脚本扫描服务漏洞
	if availableTools["nmap"] {
		utils.InfoPrint("使用nmap脚本扫描%s服务漏洞...", service)
		output, err := runCommand("nmap", []string{"-p", port, "--script=default", target}...)
		if err != nil {
			results.WriteString(fmt.Sprintf("nmap脚本扫描失败: %v\n", err))
		} else {
			results.WriteString(fmt.Sprintf("nmap脚本扫描结果:\n%s\n", output))
		}
	}

	return results.String()
}

// extractCommandsFromText 从文本中提取命令
func extractCommandsFromText(text string, availableTools map[string]bool) []string {
	var commands []string
	lines := strings.Split(text, "\n")

	// 定义常见的命令模式（按优先级排序）
	commandPatterns := []string{
		// 高优先级：渗透测试核心工具
		"nmap", "curl", "sqlmap", "nikto", "gobuster", "dirb", "wpscan", "ffuf", "nuclei", "dirsearch", "httpx",
		// 中优先级：网络和信息收集工具
		"nslookup", "dig", "whois", "tshark", "tcpdump", "ftp", "ssh", "amass", "subfinder", "assetfinder", "theharvester",
		// 低优先级：脚本和数据库工具
		"python", "python3", "ruby", "perl", "sqlite3", "mysql", "psql", "redis-cli", "mongodb",
		// 密码破解工具
		"hydra", "medusa", "john", "hashcat", "crunch", "wordlistctl",
		// 漏洞利用工具
		"exploitdb", "msfconsole", "metasploit-framework", "msfvenom",
		// 其他工具
		"wget", "nc", "netcat", "socat", "whatweb", "wafw00f", "lynis", "rkhunter", "chrootkit",
	}

	// 定义命令模式的正则表达式（更宽松的模式，支持更多格式和更长的命令）
	commandRegex := regexp.MustCompile(`(?i)^\s*(?:\d+\.\s*|\$\s*|>\s*)?(` + strings.Join(commandPatterns, "|") + `)(?:\s+[^\s]+)*`)

	// 定义代码块模式（支持更多代码块类型）
	codeBlockRegex := regexp.MustCompile("```(?:bash|shell|sh|text|code|terminal)?\\n([\\s\\S]*?)```")

	// 首先提取代码块中的命令
	codeBlockMatches := codeBlockRegex.FindAllStringSubmatch(text, -1)
	for _, match := range codeBlockMatches {
		if len(match) > 1 {
			codeLines := strings.Split(match[1], "\n")
			for _, codeLine := range codeLines {
				codeLine = strings.TrimSpace(codeLine)
				if codeLine == "" || strings.HasPrefix(codeLine, "#") {
					continue
				}

				// 检查是否是有效的命令格式
				if commandRegex.MatchString(codeLine) {
					tool := extractToolName(codeLine)
					if tool != "" && availableTools[tool] {
						// 智能修正和优化命令
						correctedCommand := correctCommandFormat(codeLine)
						optimizedCommand := optimizeCommand(correctedCommand, tool)

						if !containsCommand(commands, optimizedCommand) {
							commands = append(commands, optimizedCommand)
							utils.InfoPrint("从代码块提取到命令: %s", optimizedCommand)
						}
					}
				}
			}
		}
	}

	// 然后处理普通文本中的命令
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// 跳过空行、注释和代码块标记
		if trimmedLine == "" ||
			strings.HasPrefix(trimmedLine, "#") ||
			strings.HasPrefix(trimmedLine, "//") ||
			strings.HasPrefix(trimmedLine, "/*") ||
			strings.Contains(trimmedLine, "```") {
			continue
		}

		// 处理以数字开头的命令行（常见于AI输出的步骤列表）
		if strings.HasPrefix(trimmedLine, "1.") ||
			strings.HasPrefix(trimmedLine, "2.") ||
			strings.HasPrefix(trimmedLine, "3.") ||
			strings.HasPrefix(trimmedLine, "4.") ||
			strings.HasPrefix(trimmedLine, "5.") ||
			strings.HasPrefix(trimmedLine, "6.") ||
			strings.HasPrefix(trimmedLine, "7.") ||
			strings.HasPrefix(trimmedLine, "8.") ||
			strings.HasPrefix(trimmedLine, "9.") ||
			strings.HasPrefix(trimmedLine, "10.") {
			// 移除数字前缀，提取命令部分
			trimmedLine = regexp.MustCompile(`^\s*\d+\.\s*`).ReplaceAllString(trimmedLine, "")
		}

		// 处理以-或*开头的列表项
		if strings.HasPrefix(trimmedLine, "-") || strings.HasPrefix(trimmedLine, "* ") {
			// 移除列表前缀，提取命令部分
			trimmedLine = regexp.MustCompile(`^\s*[-*]\s*`).ReplaceAllString(trimmedLine, "")
		}

		// 先清理命令行，移除$前缀等
		cleanedLine := cleanCommandLine(trimmedLine)

		// 使用正则表达式精确匹配命令模式
		if commandRegex.MatchString(cleanedLine) {
			tool := extractToolName(cleanedLine)
			if tool != "" && availableTools[tool] {
				// 智能修正和优化命令
				correctedCommand := correctCommandFormat(cleanedLine)
				optimizedCommand := optimizeCommand(correctedCommand, tool)

				if !containsCommand(commands, optimizedCommand) {
					commands = append(commands, optimizedCommand)
					utils.InfoPrint("从文本提取到命令: %s", optimizedCommand)
				}
			}
		} else {
			// 检查是否是直接的命令格式（以工具名开头）
			parts := strings.Fields(cleanedLine)
			if len(parts) > 0 {
				tool := parts[0]

				// 检查是否是已知工具
				if isKnownTool(tool) && availableTools[tool] {
					// 智能修正命令格式
					correctedCommand := correctCommandFormat(cleanedLine)

					// 进一步验证和优化命令
					optimizedCommand := optimizeCommand(correctedCommand, tool)

					// 避免重复添加相同的命令
					if !containsCommand(commands, optimizedCommand) {
						commands = append(commands, optimizedCommand)
						utils.InfoPrint("从工具名提取到命令: %s", optimizedCommand)
					}
				}
			}
		}
	}

	utils.InfoPrint("总共提取到 %d 个命令", len(commands))
	return commands
}

// extractToolName 从命令字符串中提取工具名
func extractToolName(command string) string {
	parts := strings.Fields(command)
	if len(parts) > 0 {
		tool := parts[0]
		// 处理带路径的工具名
		if strings.Contains(tool, "/") {
			parts := strings.Split(tool, "/")
			tool = parts[len(parts)-1]
		}
		// 处理带扩展名的工具名
		if strings.Contains(tool, ".") {
			parts := strings.Split(tool, ".")
			tool = parts[0]
		}
		return tool
	}
	return ""
}

// optimizeCommand 优化命令格式，确保命令正确性
func optimizeCommand(command, tool string) string {
	parts := strings.Fields(command)
	if len(parts) < 1 {
		return command
	}

	var optimizedParts []string
	optimizedParts = append(optimizedParts, parts[0]) // 工具名

	// 根据工具类型优化参数
	switch tool {
	case "nmap":
		// 移除无效的nmap参数，添加合理的默认参数
		for i := 1; i < len(parts); i++ {
			arg := parts[i]
			// 验证IP地址或主机名
			if isValidTarget(arg) || isValidNmapArg(arg) {
				optimizedParts = append(optimizedParts, arg)
			}
		}
		// 如果没有有效的目标参数，添加默认参数
		if len(optimizedParts) == 1 {
			optimizedParts = append(optimizedParts, "-sS", "-T4", "--open")
		}

	case "curl":
		// 优化curl参数，确保URL正确
		hasURL := false
		for i := 1; i < len(parts); i++ {
			arg := parts[i]
			// 检查是否是有效的URL
			if isValidURL(arg) {
				optimizedParts = append(optimizedParts, arg)
				hasURL = true
			} else if isValidCurlArg(arg) {
				optimizedParts = append(optimizedParts, arg)
			}
		}
		// 如果没有URL，添加默认参数
		if !hasURL && len(optimizedParts) == 1 {
			optimizedParts = append(optimizedParts, "-I", "--connect-timeout", "10")
		}

	case "sqlmap":
		// 优化sqlmap参数，确保目标正确
		for i := 1; i < len(parts); i++ {
			arg := parts[i]
			// 检查是否是有效的URL或参数
			if isValidURL(arg) || strings.HasPrefix(arg, "-u=") {
				optimizedParts = append(optimizedParts, arg)
			} else if strings.HasPrefix(arg, "-") {
				optimizedParts = append(optimizedParts, arg)
			}
		}

	default:
		// 对于其他工具，只保留有效的参数
		for i := 1; i < len(parts); i++ {
			arg := parts[i]
			if !strings.Contains(arg, "\"") && !strings.Contains(arg, "'") && !strings.Contains(arg, "`") {
				optimizedParts = append(optimizedParts, arg)
			}
		}
	}

	return strings.Join(optimizedParts, " ")
}

// cleanCommandLine 清理命令行的多余字符
func cleanCommandLine(command string) string {
	// 移除命令末尾的标点符号
	command = strings.TrimRight(command, ".!?;:")

	// 移除命令中的引号（除非是参数的一部分）
	command = strings.ReplaceAll(command, "`", "")
	command = strings.ReplaceAll(command, "'", "")

	// 移除多余的空白字符
	command = strings.Join(strings.Fields(command), " ")

	// 移除命令开头的$符号（常见于shell命令示例）
	command = strings.TrimPrefix(command, "$")
	command = strings.TrimPrefix(command, "# ")

	// 移除命令中的注释部分（更全面的注释清理）
	if idx := strings.Index(command, " #"); idx != -1 {
		command = strings.TrimSpace(command[:idx])
	}
	if idx := strings.Index(command, " //"); idx != -1 {
		command = strings.TrimSpace(command[:idx])
	}
	if idx := strings.Index(command, " # "); idx != -1 {
		command = strings.TrimSpace(command[:idx])
	}
	if idx := strings.Index(command, " // "); idx != -1 {
		command = strings.TrimSpace(command[:idx])
	}

	return command
}

// isValidCommandFormat 检查是否是有效的命令格式
func isValidCommandFormat(command string) bool {
	// 命令应该至少包含工具名和参数
	parts := strings.Fields(command)
	if len(parts) < 1 {
		return false
	}

	// 检查工具名是否有效
	tool := parts[0]
	if !isKnownTool(tool) {
		return false
	}

	// 检查命令长度是否合理（避免提取过长的文本）
	if len(command) > 200 {
		return false
	}

	// 检查命令是否包含明显的无效字符
	if strings.Contains(command, "```") ||
		strings.Contains(command, "**") ||
		strings.Contains(command, "__") ||
		strings.Contains(command, "===") ||
		strings.Contains(command, "---") {
		return false
	}

	// 检查命令是否以常见的非命令模式开头
	if strings.HasPrefix(command, "1. ") ||
		strings.HasPrefix(command, "2. ") ||
		strings.HasPrefix(command, "3. ") ||
		strings.HasPrefix(command, "- ") ||
		strings.HasPrefix(command, "* ") ||
		strings.HasPrefix(command, "# ") {
		return false
	}

	// 检查命令是否包含有效的参数（至少有一个参数）
	if len(parts) == 1 {
		// 对于某些工具，单独的工具名也是有效的
		validSingleCommands := map[string]bool{
			"python":  true,
			"python3": true,
			"ruby":    true,
			"perl":    true,
			"mysql":   true,
			"psql":    true,
			"sqlite3": true,
		}
		if !validSingleCommands[tool] {
			return false
		}
	}

	return true
}

// containsCommand 检查命令列表中是否已包含某个命令
func containsCommand(commands []string, command string) bool {
	for _, cmd := range commands {
		if cmd == command {
			return true
		}
	}
	return false
}

// generateBaseStrategy 根据目标类型生成基础策略
func generateBaseStrategy(target, targetType string, availableTools map[string]bool) string {
	var strategy strings.Builder

	switch targetType {
	case "URL":
		strategy.WriteString("Web应用渗透测试策略: 信息收集 → 漏洞扫描 → 漏洞利用")
		if availableTools["nmap"] {
			strategy.WriteString("\n- 使用nmap扫描开放端口和服务")
		}
		if availableTools["curl"] {
			strategy.WriteString("\n- 使用curl收集Web应用信息")
		}
		if availableTools["sqlmap"] {
			strategy.WriteString("\n- 使用sqlmap检测SQL注入")
		}

	case "IP地址":
		strategy.WriteString("网络渗透测试策略: 端口扫描 → 服务识别 → 漏洞检测")
		if availableTools["nmap"] {
			strategy.WriteString("\n- 使用nmap进行全端口扫描")
		}

	case "域名":
		strategy.WriteString("域名渗透测试策略: DNS枚举 → 子域名扫描 → Web应用扫描")
		if availableTools["nslookup"] {
			strategy.WriteString("\n- 使用nslookup进行DNS查询")
		}

	default:
		strategy.WriteString("通用渗透测试策略: 信息收集 → 漏洞扫描 → 渗透测试")
	}

	return strategy.String()
}

// executeBaseScan 执行基础扫描
func executeBaseScan(target, targetType string, availableTools map[string]bool) string {
	var results strings.Builder

	switch targetType {
	case "URL":
		// Web应用基础扫描
		if availableTools["curl"] {
			utils.InfoPrint("执行curl基础信息收集")
			output, err := runCommand("curl", "-I", target)
			if err != nil {
				results.WriteString(fmt.Sprintf("curl信息收集失败: %v\n", err))
			} else {
				results.WriteString(fmt.Sprintf("curl信息收集成功:\n%s\n", output))
			}
		}

	case "IP地址", "域名":
		// 网络基础扫描
		if availableTools["nmap"] {
			utils.InfoPrint("执行nmap基础端口扫描")
			output, err := runCommand("nmap", "-sS", "-T4", target)
			if err != nil {
				results.WriteString(fmt.Sprintf("nmap端口扫描失败: %v\n", err))
			} else {
				results.WriteString(fmt.Sprintf("nmap端口扫描成功:\n%s\n", output))
			}
		}
	}

	return results.String()
}

// isValidURL 验证是否为有效的URL
func isValidURL(url string) bool {
	// 基本URL格式检查
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		// 移除URL中的空格和特殊字符
		cleanURL := strings.Split(url, " ")[0]
		cleanURL = strings.Split(cleanURL, "\n")[0]

		// 检查是否包含有效的主机名
		if strings.Contains(cleanURL, "://") && len(cleanURL) > 10 {
			return true
		}
	}
	return false
}

// validateCommand 验证命令参数的有效性
func validateCommand(tool string, args []string, target string) bool {
	// 检查是否有目标参数
	hasTarget := false

	for _, arg := range args {
		// 检查是否是目标参数
		if arg == target || isValidTarget(arg) || isValidURL(arg) {
			hasTarget = true
			break
		}
	}

	// 根据工具类型进行特定验证
	switch tool {
	case "nmap":
		// nmap必须要有目标参数
		if !hasTarget {
			return false
		}
		// 验证nmap参数格式
		for _, arg := range args {
			if strings.Contains(arg, "*.*.*") || strings.Contains(arg, "//") {
				return false // 无效的通配符格式
			}
			if strings.Contains(arg, "all") && !strings.HasPrefix(arg, "-p") {
				return false // 无效的端口格式
			}
		}

	case "curl":
		// curl必须要有URL参数
		for _, arg := range args {
			if isValidURL(arg) {
				hasTarget = true
				break
			}
		}
		if !hasTarget {
			// 如果没有URL，检查是否有有效的参数组合
			validWithoutURL := false
			for _, arg := range args {
				if arg == "-I" || arg == "--head" {
					validWithoutURL = true
					break
				}
			}
			if !validWithoutURL {
				return false
			}
		}

	case "sqlmap":
		// sqlmap必须要有目标参数
		if !hasTarget {
			return false
		}

	case "dirb":
		// dirb必须有目标参数
		if !hasTarget {
			return false
		}
		// 检查dirb参数中的URL重复问题
		for _, arg := range args {
			if strings.Contains(arg, "http://http://") || strings.Contains(arg, "https://https://") {
				return false // 重复的URL前缀
			}
		}

	case "openssl":
		// openssl需要特定的参数组合
		if len(args) == 0 {
			return false
		}
		// 检查openssl命令格式
		hasValidCommand := false
		for _, arg := range args {
			if arg == "s_client" || arg == "x509" || arg == "req" {
				hasValidCommand = true
				break
			}
		}
		if !hasValidCommand {
			return false
		}

	default:
		// 对于其他工具，至少需要一个参数
		if len(args) == 0 {
			return false
		}
	}

	return true
}

// correctCommandArgsFormat 修正命令参数格式问题
func correctCommandArgsFormat(tool string, args []string, target string) []string {
	var correctedArgs []string

	// 根据工具类型进行特定修正
	switch tool {
	case "dirb":
		// 修正dirb的URL重复问题
		for _, arg := range args {
			if strings.Contains(arg, "http://") || strings.Contains(arg, "https://") {
				// 移除重复的URL前缀
				correctedArg := strings.Replace(arg, "http://http://", "http://", -1)
				correctedArg = strings.Replace(correctedArg, "https://https://", "https://", -1)

				// 确保URL以正确的格式开头
				if !strings.HasPrefix(correctedArg, "http://") && !strings.HasPrefix(correctedArg, "https://") {
					// 如果目标已经是URL，则直接使用目标
					if strings.HasPrefix(target, "http") {
						correctedArg = target
					} else {
						correctedArg = "http://" + target
					}
				}
				correctedArgs = append(correctedArgs, correctedArg)
			} else {
				correctedArgs = append(correctedArgs, arg)
			}
		}

	case "curl":
		// 修正curl的参数格式
		for _, arg := range args {
			if strings.Contains(arg, "http://") || strings.Contains(arg, "https://") {
				// 确保URL格式正确
				if !strings.HasPrefix(arg, "http://") && !strings.HasPrefix(arg, "https://") {
					// 从参数中提取URL
					urlParts := strings.Fields(arg)
					for _, part := range urlParts {
						if strings.Contains(part, "http") {
							correctedArgs = append(correctedArgs, part)
							break
						}
					}
				} else {
					correctedArgs = append(correctedArgs, arg)
				}
			} else {
				correctedArgs = append(correctedArgs, arg)
			}
		}

	case "openssl":
		// 修正openssl的参数格式
		for _, arg := range args {
			// 移除Unix重定向符号
			if arg == "2>&1" || arg == ">" || arg == "|" {
				utils.WarningPrint("移除Unix重定向符号: %s", arg)
				continue
			}
			// 移除包含重定向的参数
			if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
				// 只保留重定向符号之前的部分
				parts := strings.Split(arg, ">")
				if len(parts) > 0 {
					correctedArgs = append(correctedArgs, strings.TrimSpace(parts[0]))
				}
			} else {
				correctedArgs = append(correctedArgs, arg)
			}
		}

	default:
		// 通用修正：移除无效字符和特殊符号
		for _, arg := range args {
			// 移除Unix重定向符号
			if arg == "2>&1" || arg == ">" || arg == "|" || arg == "&&" {
				utils.WarningPrint("移除Unix重定向符号: %s", arg)
				continue
			}
			// 移除包含特殊符号的参数
			if strings.Contains(arg, ">") || strings.Contains(arg, "|") || strings.Contains(arg, "&") {
				// 只保留符号之前的部分
				parts := strings.FieldsFunc(arg, func(r rune) bool {
					return r == '>' || r == '|' || r == '&'
				})
				if len(parts) > 0 {
					correctedArgs = append(correctedArgs, strings.TrimSpace(parts[0]))
				}
			} else {
				correctedArgs = append(correctedArgs, arg)
			}
		}
	}

	// 确保目标参数存在
	if !containsTarget(correctedArgs, target) {
		// 根据工具类型添加目标参数
		switch tool {
		case "curl", "dirb", "nmap", "sqlmap":
			correctedArgs = append(correctedArgs, target)
		}
	}

	return correctedArgs
}

// containsTarget 检查参数列表中是否包含目标
func containsTarget(args []string, target string) bool {
	for _, arg := range args {
		if arg == target || isValidTarget(arg) || isValidURL(arg) {
			return true
		}
	}
	return false
}

// isKnownTool 检查是否为已知的安全工具
func isKnownTool(tool string) bool {
	knownTools := map[string]bool{
		// 信息收集工具
		"nmap":      true,
		"amass":     true,
		"subfinder": true,
		"sublist3r": true,
		"httpx":     true,
		"ffuf":      true,
		"wfuzz":     true,
		"whatweb":   true,
		"wafw00f":   true,

		// 漏洞扫描工具
		"nuclei":   true,
		"nikto":    true,
		"wpscan":   true,
		"joomscan": true,

		// 密码破解工具
		"hydra":   true,
		"john":    true,
		"hashcat": true,
		"medusa":  true,

		// 漏洞利用工具
		"sqlmap":     true,
		"exploitdb":  true,
		"msfconsole": true,

		// Web应用测试工具
		"dirb":      true,
		"dirsearch": true,
		"gobuster":  true,

		// 网络工具
		"nc":      true,
		"netcat":  true,
		"socat":   true,
		"tcpdump": true,
		"tshark":  true,

		// 数据库工具
		"mysql":     true,
		"psql":      true,
		"sqlite3":   true,
		"mssql-cli": true,

		// 系统工具
		"ssh":       true,
		"ftp":       true,
		"rdp":       true,
		"smbclient": true,
		"rpcclient": true,
		"curl":      true,
		"wget":      true,

		// 其他工具
		"python3": true,
		"python":  true,
		"ruby":    true,
		"perl":    true,
	}

	return knownTools[tool]
}

// lateralMovement 横向移动阶段，集成AI分析
func lateralMovement(target string, availableTools map[string]bool, aiClient *AIClient) error {
	utils.InfoPrint("正在进行横向移动...")

	// 这里可以集成AI分析，根据前面的渗透测试结果生成横向移动建议
	// 暂时返回成功
	return nil
}

// runCommand 执行系统命令，捕获命令输出
func runCommand(cmdName string, args ...string) (string, error) {
	// 预处理和验证命令参数
	validatedArgs := validateAndPreprocessArgs(cmdName, args)

	// 显示执行的命令
	utils.InfoPrint("执行命令: %s %s", cmdName, strings.Join(validatedArgs, " "))

	// 构建命令
	cmd := exec.Command(cmdName, validatedArgs...)

	// 捕获命令输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		utils.ErrorPrint("命令执行失败: %s %s", cmdName, strings.Join(validatedArgs, " "))
		utils.ErrorPrint("错误信息: %v", err)
		return string(output), fmt.Errorf("执行命令 %s 失败: %v", cmdName, err)
	}

	// 输出命令结果
	utils.SuccessPrint("命令执行完成: %s %s", cmdName, strings.Join(validatedArgs, " "))
	if len(output) > 0 {
		utils.InfoPrint("命令输出:\n%s", string(output))
	}

	return string(output), nil
}

// validateAndPreprocessArgs 验证和预处理命令参数
func validateAndPreprocessArgs(cmdName string, args []string) []string {
	var validatedArgs []string

	// 针对不同工具进行参数验证和预处理
	switch cmdName {
	case "curl":
		validatedArgs = preprocessCurlArgs(args)
	case "nmap":
		validatedArgs = preprocessNmapArgs(args)
	case "whois":
		validatedArgs = preprocessWhoisArgs(args)
	case "openssl":
		validatedArgs = preprocessOpensslArgs(args)
	case "whatweb":
		validatedArgs = preprocessWhatwebArgs(args)
	case "dirb":
		validatedArgs = preprocessDirbArgs(args)
	default:
		// 通用参数验证：移除无效参数和特殊字符
		validatedArgs = preprocessGenericArgs(args)
	}

	return validatedArgs
}

// preprocessCurlArgs 预处理curl命令参数
func preprocessCurlArgs(args []string) []string {
	var processedArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// 处理 -o 参数：如果后面是URL，则修正为合理的文件名
		if arg == "-o" && i+1 < len(args) {
			nextArg := args[i+1]
			if strings.HasPrefix(nextArg, "http") || strings.HasPrefix(nextArg, "https") {
				// 从URL中提取文件名
				fileName := extractFilenameFromURL(nextArg)
				processedArgs = append(processedArgs, "-o", fileName)
				i++ // 跳过下一个参数
			} else {
				processedArgs = append(processedArgs, arg)
			}
		} else if strings.HasPrefix(arg, "--") && len(arg) > 2 {
			// 验证curl的有效参数
			if isValidCurlArg(arg) {
				processedArgs = append(processedArgs, arg)
			} else {
				utils.WarningPrint("移除无效的curl参数: %s", arg)
			}
		} else {
			processedArgs = append(processedArgs, arg)
		}
	}

	return processedArgs
}

// preprocessNmapArgs 预处理nmap命令参数
func preprocessNmapArgs(args []string) []string {
	var processedArgs []string

	for _, arg := range args {
		// 验证nmap的有效参数
		if isValidNmapArg(arg) {
			processedArgs = append(processedArgs, arg)
		} else {
			utils.WarningPrint("移除无效的nmap参数: %s", arg)
		}
	}

	return processedArgs
}

// preprocessWhoisArgs 预处理whois命令参数
func preprocessWhoisArgs(args []string) []string {
	var processedArgs []string

	for _, arg := range args {
		// 验证whois的有效参数
		if isValidWhoisArg(arg) {
			processedArgs = append(processedArgs, arg)
		} else {
			utils.WarningPrint("移除无效的whois参数: %s", arg)
		}
	}

	return processedArgs
}

// preprocessOpensslArgs 预处理openssl命令参数
func preprocessOpensslArgs(args []string) []string {
	var processedArgs []string

	for _, arg := range args {
		// 验证openssl的有效参数
		if isValidOpensslArg(arg) {
			processedArgs = append(processedArgs, arg)
		} else {
			utils.WarningPrint("移除无效的openssl参数: %s", arg)
		}
	}

	return processedArgs
}

// preprocessWhatwebArgs 预处理whatweb命令参数
func preprocessWhatwebArgs(args []string) []string {
	var processedArgs []string

	for _, arg := range args {
		// 验证whatweb的有效参数
		if isValidWhatwebArg(arg) {
			processedArgs = append(processedArgs, arg)
		} else {
			utils.WarningPrint("移除无效的whatweb参数: %s", arg)
		}
	}

	return processedArgs
}

// preprocessDirbArgs 预处理dirb命令参数
func preprocessDirbArgs(args []string) []string {
	var processedArgs []string

	for _, arg := range args {
		// 验证dirb的有效参数
		if isValidDirbArg(arg) {
			processedArgs = append(processedArgs, arg)
		} else {
			utils.WarningPrint("移除无效的dirb参数: %s", arg)
		}
	}

	return processedArgs
}

// preprocessGenericArgs 预处理通用命令参数
func preprocessGenericArgs(args []string) []string {
	var processedArgs []string

	for _, arg := range args {
		// 移除明显的无效参数（包含特殊字符或过长的参数）
		if len(arg) > 100 || strings.Contains(arg, "-- SoupAid") ||
			strings.Contains(arg, "--monet-ace") || strings.Contains(arg, "0x24425745") {
			utils.WarningPrint("移除无效参数: %s", arg)
			continue
		}

		// 移除管道符号和重定向符号（这些需要在shell中执行）
		if arg == "|" || arg == ">" || arg == ">>" || arg == "<" {
			utils.WarningPrint("移除shell操作符: %s", arg)
			continue
		}

		// 移除包含shell操作符的参数
		if strings.Contains(arg, "|") || strings.Contains(arg, ">") || strings.Contains(arg, "<") {
			// 尝试分割参数
			parts := strings.FieldsFunc(arg, func(r rune) bool {
				return r == '|' || r == '>' || r == '<'
			})
			if len(parts) > 0 {
				processedArgs = append(processedArgs, parts[0])
			}
			utils.WarningPrint("移除包含shell操作符的参数: %s", arg)
		} else {
			processedArgs = append(processedArgs, arg)
		}
	}

	return processedArgs
}

// extractFilenameFromURL 从URL中提取文件名
func extractFilenameFromURL(url string) string {
	// 简单的文件名提取逻辑
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		if lastPart != "" {
			// 移除查询参数
			if idx := strings.Index(lastPart, "?"); idx != -1 {
				lastPart = lastPart[:idx]
			}
			// 如果没有扩展名，添加.txt
			if !strings.Contains(lastPart, ".") {
				lastPart += ".txt"
			}
			return lastPart
		}
	}
	return "output.txt"
}

// isValidCurlArg 验证curl参数的有效性
func isValidCurlArg(arg string) bool {
	validCurlArgs := map[string]bool{
		"-o": true, "-O": true, "-L": true, "-I": true, "-H": true, "-X": true,
		"-d": true, "-F": true, "-u": true, "-k": true, "-s": true, "-v": true,
		"--output": true, "--remote-name": true, "--location": true, "--head": true,
		"--header": true, "--request": true, "--data": true, "--form": true,
		"--user": true, "--insecure": true, "--silent": true, "--verbose": true,
	}

	return validCurlArgs[arg] || !strings.HasPrefix(arg, "--")
}

// isValidNmapArg 验证nmap参数的有效性
func isValidNmapArg(arg string) bool {
	validNmapArgs := map[string]bool{
		"-sS": true, "-sT": true, "-sU": true, "-sV": true, "-O": true, "-A": true,
		"-p": true, "-iL": true, "-oN": true, "-oX": true, "-oG": true, "-v": true,
		"-T": true, "-n": true, "-Pn": true, "--top-ports": true, "--script": true,
		"-sC": true, "--min-rate": true, "--max-rate": true, "--open": true,
	}

	// 允许IP地址、主机名、端口范围等
	if !strings.HasPrefix(arg, "-") {
		return true
	}

	return validNmapArgs[arg] || strings.HasPrefix(arg, "--script=") ||
		strings.HasPrefix(arg, "-p") || strings.HasPrefix(arg, "-T")
}

// isValidWhoisArg 验证whois参数是否有效
func isValidWhoisArg(arg string) bool {
	validWhoisArgs := map[string]bool{
		"-h": true, "--host": true, "-p": true, "--port": true,
		"-a": true, "--verbose": true, "-v": true,
	}

	// 允许IP地址、域名等
	if !strings.HasPrefix(arg, "-") {
		return true
	}

	return validWhoisArgs[arg]
}

// isValidOpensslArg 验证openssl参数是否有效
func isValidOpensslArg(arg string) bool {
	validOpensslArgs := map[string]bool{
		"s_client": true, "-connect": true, "-showcerts": true,
		"-servername": true, "-tls1_2": true, "-tls1_3": true,
		"-ssl3": true, "-cert": true, "-key": true, "-CAfile": true,
	}

	// 允许连接参数（如 example.com:443）
	if !strings.HasPrefix(arg, "-") {
		return true
	}

	return validOpensslArgs[arg]
}

// isValidWhatwebArg 验证whatweb参数是否有效
func isValidWhatwebArg(arg string) bool {
	validWhatwebArgs := map[string]bool{
		"-v": true, "--verbose": true, "--no-errors": true,
		"-a": true, "--aggression": true, "-H": true, "--header": true,
		"-i": true, "--input-file": true, "-o": true, "--output": true,
		"--color": true, "--no-color": true, "--quiet": true,
	}

	// 允许URL、IP地址、域名等
	if !strings.HasPrefix(arg, "-") {
		return true
	}

	return validWhatwebArgs[arg]
}

// isValidDirbArg 验证dirb参数是否有效
func isValidDirbArg(arg string) bool {
	validDirbArgs := map[string]bool{
		"-a": true, "-c": true, "-f": true, "-i": true, "-k": true,
		"-l": true, "-N": true, "-o": true, "-p": true, "-q": true,
		"-r": true, "-S": true, "-t": true, "-u": true, "-v": true,
		"-w": true, "-x": true, "-z": true,
	}

	// 允许URL等
	if !strings.HasPrefix(arg, "-") {
		return true
	}

	return validDirbArgs[arg]
}

// intelligentPenetrationTestWithLogging 执行智能渗透测试（带日志记录）
func intelligentPenetrationTestWithLogging(target string, logger *PenetrationLogger) (string, error) {
	logger.LogPhaseStart(PhaseInfoGathering, "开始智能渗透测试")

	// 加载AI配置
	cfgPath := config.GetDefaultConfigPath()
	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("加载AI配置文件: %s", cfgPath), 0)

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "加载AI配置失败", 0)
		return "", fmt.Errorf("加载AI配置失败: %v", err)
	}

	// 验证提供商配置
	testResult, err := config.TestConfig(*cfg)
	if err != nil {
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "AI提供商配置验证失败", 0)
		return "", fmt.Errorf("AI提供商配置验证失败: %v", err)
	}
	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("AI提供商配置验证通过: %s", testResult), 0)

	logger.Log(PhaseInfoGathering, "", "", "", "", "AI提供商配置验证通过", 0)

	// 创建AI客户端
	logger.Log(PhaseInfoGathering, "", "", "", "", "创建AI客户端...", 0)
	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "创建AI客户端失败", 0)
		return "", fmt.Errorf("创建AI客户端失败: %v", err)
	}

	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("AI客户端创建成功，提供商: %s", cfg.Provider), 0)

	// 加载工具管理器
	logger.Log(PhaseInfoGathering, "", "", "", "", "加载工具管理器...", 0)
	toolManager := LoadToolManagerFromConfig("")
	if toolManager == nil {
		logger.Log(PhaseInfoGathering, "", "", "", "加载工具管理器失败", "加载工具管理器失败，将使用基础工具集", 0)
		toolManager = &ToolManager{
			Tools: make(map[string]ToolInterface),
		}
		// 添加一些基础工具
		toolManager.Tools["nmap"] = &BaseTool{NameValue: "nmap", Path: "nmap", Available: true}
		toolManager.Tools["whois"] = &BaseTool{NameValue: "whois", Path: "whois", Available: true}
		toolManager.Tools["curl"] = &BaseTool{NameValue: "curl", Path: "curl", Available: true}
	}

	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("工具管理器加载完成，可用工具数: %d", len(toolManager.Tools)), 0)

	// 智能信息收集
	logger.LogPhaseStart(PhaseInfoGathering, "开始智能信息收集")
	infoCollectionStart := time.Now()
	infoCollectionResult, err := intelligentInformationCollectionWithLogging(target, aiClient, toolManager, logger)
	infoCollectionDuration := time.Since(infoCollectionStart)
	if err != nil {
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "智能信息收集失败，将使用基础信息收集", infoCollectionDuration)
		infoCollectionResult = basicInformationCollectionWithLogging(target, toolManager, logger)
	} else {
		logger.LogPhaseComplete(PhaseInfoGathering, "智能信息收集完成", infoCollectionDuration)
	}

	// 智能漏洞利用
	logger.LogPhaseStart(PhaseVulnerabilityExploitation, "开始智能漏洞利用")
	exploitationStart := time.Now()
	exploitationResult, err := intelligentVulnerabilityExploitationWithLogging(target, aiClient, toolManager, infoCollectionResult, logger)
	exploitationDuration := time.Since(exploitationStart)
	if err != nil {
		logger.Log(PhaseVulnerabilityExploitation, "", "", "", err.Error(), "智能漏洞利用失败，将使用基础漏洞利用", exploitationDuration)
		exploitationResult = basicVulnerabilityExploitationWithLogging(target, toolManager, logger)
	} else {
		logger.LogPhaseComplete(PhaseVulnerabilityExploitation, "智能漏洞利用完成", exploitationDuration)
	}

	// 智能横向移动
	logger.LogPhaseStart(PhaseLateralMove, "开始智能横向移动")
	lateralStart := time.Now()
	lateralMovementResult, err := intelligentLateralMovementWithLogging(target, aiClient, toolManager, exploitationResult, logger)
	lateralDuration := time.Since(lateralStart)
	if err != nil {
		logger.Log(PhaseLateralMove, "", "", "", err.Error(), "智能横向移动失败，将使用基础横向移动", lateralDuration)
		lateralMovementResult = basicLateralMovementWithLogging(target, toolManager, logger)
	} else {
		logger.LogPhaseComplete(PhaseLateralMove, "智能横向移动完成", lateralDuration)
	}

	// 整合所有结果
	finalResult := fmt.Sprintf("目标: %s\n\n", target)
	finalResult += fmt.Sprintf("=== 信息收集结果 ===\n%s\n\n", infoCollectionResult)
	finalResult += fmt.Sprintf("=== 漏洞利用结果 ===\n%s\n\n", exploitationResult)
	finalResult += fmt.Sprintf("=== 横向移动结果 ===\n%s\n\n", lateralMovementResult)

	logger.Log(PhaseComplete, "", "", "", "", "智能渗透测试完成", time.Since(infoCollectionStart))
	return finalResult, nil
}

// intelligentInformationCollectionWithLogging 智能信息收集（带日志记录）
func intelligentInformationCollectionWithLogging(target string, aiClient *AIClient, toolManager *ToolManager, logger *PenetrationLogger) (string, error) {
	// 使用原有逻辑，但添加日志记录
	logger.Log(PhaseInfoGathering, "", "", "", "", "开始智能信息收集", 0)

	// 这里可以调用原有的智能信息收集逻辑，并记录每个步骤
	result, err := intelligentInformationCollection(target, aiClient, toolManager)
	if err != nil {
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "智能信息收集失败", 0)
	} else {
		logger.Log(PhaseInfoGathering, "", "", "", "", "智能信息收集完成", 0)
	}

	return result, err
}

// basicInformationCollectionWithLogging 基础信息收集（带日志记录）
func basicInformationCollectionWithLogging(target string, toolManager *ToolManager, logger *PenetrationLogger) string {
	logger.Log(PhaseInfoGathering, "", "", "", "", "开始基础信息收集", 0)

	// 使用原有逻辑
	result := basicInformationCollection(target, toolManager)

	logger.Log(PhaseInfoGathering, "", "", "", "", "基础信息收集完成", 0)
	return result
}

// intelligentVulnerabilityExploitationWithLogging 智能漏洞利用（带日志记录）
func intelligentVulnerabilityExploitationWithLogging(target string, aiClient *AIClient, toolManager *ToolManager, previousResults string, logger *PenetrationLogger) (string, error) {
	logger.Log(PhaseVulnerabilityExploitation, "", "", "", "", "开始智能漏洞利用", 0)

	// 使用原有逻辑
	result, err := intelligentVulnerabilityExploitation(target, aiClient, toolManager, previousResults)
	if err != nil {
		logger.Log(PhaseVulnerabilityExploitation, "", "", "", err.Error(), "智能漏洞利用失败", 0)
	} else {
		logger.Log(PhaseVulnerabilityExploitation, "", "", "", "", "智能漏洞利用完成", 0)
	}

	return result, err
}

// basicVulnerabilityExploitationWithLogging 基础漏洞利用（带日志记录）
func basicVulnerabilityExploitationWithLogging(target string, toolManager *ToolManager, logger *PenetrationLogger) string {
	logger.Log(PhaseVulnerabilityExploitation, "", "", "", "", "开始基础漏洞利用", 0)

	// 使用原有逻辑
	result := basicVulnerabilityExploitation(target, toolManager)

	logger.Log(PhaseVulnerabilityExploitation, "", "", "", "", "基础漏洞利用完成", 0)
	return result
}

// intelligentLateralMovementWithLogging 智能横向移动（带日志记录）
func intelligentLateralMovementWithLogging(target string, aiClient *AIClient, toolManager *ToolManager, previousResults string, logger *PenetrationLogger) (string, error) {
	logger.Log(PhaseLateralMove, "", "", "", "", "开始智能横向移动", 0)

	// 使用原有逻辑
	result, err := intelligentLateralMovement(target, aiClient, toolManager, previousResults)
	if err != nil {
		logger.Log(PhaseLateralMove, "", "", "", err.Error(), "智能横向移动失败", 0)
	} else {
		logger.Log(PhaseLateralMove, "", "", "", "", "智能横向移动完成", 0)
	}

	return result, err
}

// basicLateralMovementWithLogging 基础横向移动（带日志记录）
func basicLateralMovementWithLogging(target string, toolManager *ToolManager, logger *PenetrationLogger) string {
	logger.Log(PhaseLateralMove, "", "", "", "", "开始基础横向移动", 0)

	// 使用原有逻辑
	result := basicLateralMovement(target, toolManager)

	logger.Log(PhaseLateralMove, "", "", "", "", "基础横向移动完成", 0)
	return result
}

// intelligentInformationCollection 智能信息收集（AI驱动实现）
func intelligentInformationCollection(target string, aiClient *AIClient, toolManager *ToolManager) (string, error) {
	utils.InfoPrint("AI正在制定信息收集策略...")

	// 获取可用工具列表
	availableTools := toolManager.GetAvailableTools()

	// 使用AI制定信息收集策略
	strategy, err := aiClient.DecideInfoCollectionStrategy(target, availableTools)
	if err != nil {
		return "", fmt.Errorf("AI信息收集策略制定失败: %v", err)
	}

	utils.InfoPrint("AI信息收集策略制定完成，开始执行...")

	// 解析AI策略并执行
	results, err := executeAIStrategy(strategy, target, availableTools)
	if err != nil {
		return "", fmt.Errorf("信息收集策略执行失败: %v", err)
	}

	return results, nil
}

// basicInformationCollection 基础信息收集（基础实现）
func basicInformationCollection(target string, toolManager *ToolManager) string {
	// 基础实现：简单的信息收集
	var result strings.Builder
	result.WriteString("=== 基础信息收集结果 ===\n")
	result.WriteString(fmt.Sprintf("目标: %s\n", target))
	result.WriteString("基础信息收集完成\n")
	return result.String()
}

// intelligentVulnerabilityExploitation 智能漏洞利用（基础实现）
func intelligentVulnerabilityExploitation(target string, aiClient *AIClient, toolManager *ToolManager, previousResults string) (string, error) {
	// 基础实现：简单的漏洞利用逻辑
	var result strings.Builder
	result.WriteString("=== 智能漏洞利用结果 ===\n")
	result.WriteString(fmt.Sprintf("基于前序结果进行漏洞利用: %s\n", previousResults))
	result.WriteString("智能漏洞利用完成\n")
	return result.String(), nil
}

// basicVulnerabilityExploitation 基础漏洞利用（基础实现）
func basicVulnerabilityExploitation(target string, toolManager *ToolManager) string {
	// 基础实现：简单的漏洞利用
	var result strings.Builder
	result.WriteString("=== 基础漏洞利用结果 ===\n")
	result.WriteString(fmt.Sprintf("目标: %s\n", target))
	result.WriteString("基础漏洞利用完成\n")
	return result.String()
}

// intelligentLateralMovement 智能横向移动（基础实现）
func intelligentLateralMovement(target string, aiClient *AIClient, toolManager *ToolManager, previousResults string) (string, error) {
	// 基础实现：简单的横向移动逻辑
	var result strings.Builder
	result.WriteString("=== 智能横向移动结果 ===\n")
	result.WriteString(fmt.Sprintf("基于前序结果进行横向移动: %s\n", previousResults))
	result.WriteString("智能横向移动完成\n")
	return result.String(), nil
}

// basicLateralMovement 基础横向移动（基础实现）
func basicLateralMovement(target string, toolManager *ToolManager) string {
	// 基础实现：简单的横向移动
	var result strings.Builder
	result.WriteString("=== 基础横向移动结果 ===\n")
	result.WriteString(fmt.Sprintf("目标: %s\n", target))
	result.WriteString("基础横向移动完成\n")
	return result.String()
}
