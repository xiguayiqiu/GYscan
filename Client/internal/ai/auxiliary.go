package ai

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// AuxiliaryScan 执行AI辅助探测功能
func AuxiliaryScan(target string) {
	// 使用默认资源目录
	AuxiliaryScanWithResource(target, "")
}

// AuxiliaryScanWithResource 执行AI辅助探测功能（带资源目录）
func AuxiliaryScanWithResource(target string, resourceDir string) {
	// 检查是否启用专业渗透测试模式
	if isProfessionalModeEnabled() {
		utils.InfoPrint("启用专业渗透测试模式进行辅助探测")
		executeProfessionalAuxiliaryScan(target, resourceDir)
		return
	}

	// 原有逻辑（基础模式）
	startTime := time.Now()
	utils.InfoPrint("开始AI辅助安全探测，目标: %s", target)

	// 初始化资源目录
	resourceDir = initResourceDir(resourceDir)
	utils.InfoPrint("使用资源目录: %s", resourceDir)

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
	var toolManager *ToolManager
	if needScan {
		utils.InfoPrint("开始全盘扫描系统工具...")
		toolManager = ScanSystemTools(nil) // 这里先传递nil，后续在targetInfoCollection中会创建AI客户端
		SaveToolScanResults(toolManager, "")
	} else {
		// 从配置文件中加载工具管理器
		toolManager = LoadToolManagerFromConfig("")
		if toolManager == nil {
			utils.WarningPrint("从配置文件加载工具管理器失败，将执行全盘扫描")
			toolManager = ScanSystemTools(nil)
			SaveToolScanResults(toolManager, "")
		}
	}

	// 2. 获取默认配置路径并保存工具扫描结果
	cfgPath := config.GetDefaultConfigPath()
	if err := SaveToolScanResults(toolManager, cfgPath); err != nil {
		utils.ErrorPrint("保存工具配置失败: %v", err)
		return
	}

	// 3. 直接从toolManager获取可用工具列表，无需加载配置
	availableTools := toolManager.GetAvailableTools()

	// 5. 执行辅助探测流程
	utils.InfoPrint("开始执行辅助探测流程...")
	var scanResults string

	// 目标信息收集阶段 - 使用新的带日志记录的信息收集功能
	utils.InfoPrint("\n=== 目标信息收集阶段 ===")
	if result, err := targetInfoCollectionWithLogging(target, availableTools); err != nil {
		utils.ErrorPrint("目标信息收集失败: %v", err)
		return
	} else {
		scanResults += result + "\n"
	}

	// 可用漏洞检测阶段
	utils.InfoPrint("\n=== 可用漏洞检测阶段 ===")
	if result, err := vulnerabilityDetection(target, availableTools); err != nil {
		utils.ErrorPrint("漏洞检测失败: %v", err)
		return
	} else {
		scanResults += result + "\n"
	}

	// 安全配置评估阶段
	utils.InfoPrint("\n=== 安全配置评估阶段 ===")
	if result, err := securityConfigAssessment(target, availableTools); err != nil {
		utils.ErrorPrint("安全配置评估失败: %v", err)
		return
	} else {
		scanResults += result + "\n"
	}

	// 生成安全报告
	endTime := time.Now()
	utils.InfoPrint("\n=== 报告生成阶段 ===")
	reportData := types.ReportData{
		ID:              "aux_scan_" + time.Now().Format("20060102150405"),
		TaskID:          "aux_task_" + time.Now().Format("20060102150405"),
		Title:           "AI辅助探测报告",
		Summary:         "基于AI辅助的安全探测结果 - 目标: " + target,
		Findings:        []types.Finding{},
		RiskAssessment:  types.RiskAssessment{},
		Recommendations: []string{},
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     target,
			"scan_type":  "aux",
			"start_time": startTime.Format("2006-01-02 15:04:05"),
			"end_time":   endTime.Format("2006-01-02 15:04:05"),
			"duration":   endTime.Sub(startTime).String(),
			"log":        scanResults,
		},
	}

	if err := GenerateReport(reportData, resourceDir, FormatHTML); err != nil {
		utils.ErrorPrint("生成报告失败: %v", err)
	} else {
		utils.SuccessPrint("安全报告生成成功")
	}

	utils.SuccessPrint("\nAI辅助探测完成！")
}

// executeProfessionalAuxiliaryScan 执行专业辅助渗透测试
func executeProfessionalAuxiliaryScan(target string, resourceDir string) {
	startTime := time.Now()
	utils.InfoPrint("=== 专业辅助渗透测试开始 ===")
	utils.InfoPrint("目标: %s", target)

	// 初始化资源目录
	resourceDir = initResourceDir(resourceDir)
	utils.InfoPrint("使用资源目录: %s", resourceDir)

	// 加载配置并创建AI客户端
	cfgPath := config.GetDefaultConfigPath()
	utils.InfoPrint("加载AI配置文件: %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.ErrorPrint("加载AI配置失败: %v", err)
		return
	}

	// 创建AI客户端
	utils.InfoPrint("创建AI客户端，提供商: %s, 模型: %s", cfg.Provider, cfg.Model)
	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.ErrorPrint("创建AI客户端失败: %v", err)
		return
	}

	// 创建专业渗透测试实例
	penTest := &ProfessionalPenetrationTest{
		Target:    target,
		AIClient:  aiClient,
		Logger:    nil,
		Config:    cfg,
		OutputDir: filepath.Join(resourceDir, "pro_aux_results"),
	}

	// 执行专业辅助探测流程（使用完整工作流程）
	utils.InfoPrint("\n=== 执行专业辅助渗透测试流程 ===")
	results, err := penTest.ExecuteFullWorkflow()
	if err != nil {
		utils.ErrorPrint("专业辅助渗透测试失败: %v", err)
		results = "专业辅助渗透测试失败: " + err.Error()
	}

	// 生成专业报告
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	utils.InfoPrint("\n=== 报告生成阶段 ===")

	// 使用字符串拼接而不是WriteString
	results += "\n=== 测试总结 ===\n"
	results += fmt.Sprintf("结束时间: %s\n", endTime.Format("2006-01-02 15:04:05"))
	results += fmt.Sprintf("总耗时: %s\n", duration)
	results += "测试类型: 专业辅助渗透测试\n"

	// 生成HTML格式的专业报告
	reportData := types.ReportData{
		ID:              "pro_aux_scan_" + time.Now().Format("20060102150405"),
		TaskID:          "pro_aux_task_" + time.Now().Format("20060102150405"),
		Title:           "专业辅助渗透测试报告",
		Summary:         "基于专业渗透测试流程的辅助探测结果 - 目标: " + target,
		Findings:        []types.Finding{},
		RiskAssessment:  types.RiskAssessment{},
		Recommendations: []string{},
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     target,
			"scan_type":  "pro_aux",
			"start_time": startTime.Format("2006-01-02 15:04:05"),
			"end_time":   endTime.Format("2006-01-02 15:04:05"),
			"duration":   duration.String(),
			"mode":       "professional",
			"log":        results,
		},
	}

	if err := GenerateReport(reportData, resourceDir, FormatHTML); err != nil {
		utils.ErrorPrint("生成专业报告失败: %v", err)
	} else {
		utils.SuccessPrint("专业辅助渗透测试报告生成成功")
	}

	utils.SuccessPrint("\n=== 专业辅助渗透测试完成 ===")
	utils.SuccessPrint("报告已保存到资源目录: %s", resourceDir)
}

// targetInfoCollection 目标信息收集阶段 - 让AI自主决策信息收集策略（优化版，使用已加载的工具管理器）
func targetInfoCollection(target string, availableTools map[string]bool) (string, error) {
	utils.InfoPrint("正在收集目标信息: %s", target)
	var results string

	// 1. 创建AI客户端进行自主决策
	utils.InfoPrint("正在让AI分析目标并制定专业信息收集策略...")

	// 获取AI配置
	cfgPath := config.GetDefaultConfigPath()
	utils.InfoPrint("加载AI配置文件: %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.ErrorPrint("加载AI配置失败: %v", err)
		utils.InfoPrint("请检查配置文件是否存在或格式是否正确")
		utils.WarningPrint("将使用默认工具进行信息收集")
		return enhancedBasicInfoCollection(target, availableTools)
	}

	// 验证提供商配置
	utils.InfoPrint("验证AI提供商配置: %s", cfg.Provider)
	if _, testErr := config.TestConfig(*cfg); testErr != nil {
		utils.ErrorPrint("AI提供商配置验证失败: %v", err)
		utils.InfoPrint("请检查提供商设置、API密钥和网络连接")
		utils.WarningPrint("将使用默认工具进行信息收集")
		return enhancedBasicInfoCollection(target, availableTools)
	}

	// 创建AI客户端
	utils.InfoPrint("创建AI客户端，提供商: %s, 模型: %s", cfg.Provider, cfg.Model)
	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.ErrorPrint("创建AI客户端失败: %v", err)
		utils.InfoPrint("请检查API密钥、BaseURL配置和网络连接")
		utils.WarningPrint("将使用默认工具进行信息收集")
		return enhancedBasicInfoCollection(target, availableTools)
	}

	// 2. 使用已加载的工具管理器（避免重复扫描）
	utils.InfoPrint("使用已加载的工具管理器...")
	enhancedToolManager := LoadToolManagerFromConfig("")
	if enhancedToolManager == nil {
		utils.WarningPrint("从配置文件加载工具管理器失败，将执行全盘扫描")
		enhancedToolManager = ScanSystemTools(aiClient)
		SaveToolScanResults(enhancedToolManager, "")
	}

	// 更新可用工具列表
	enhancedAvailableTools := enhancedToolManager.GetAvailableTools()

	// 合并工具列表（确保不丢失原有工具）
	for tool, available := range enhancedAvailableTools {
		availableTools[tool] = available
	}

	// 3. 让AI自主制定专业信息收集策略（基于增强的工具列表）
	// 特别提示AI使用Ollama进行本地高效处理
	if cfg.Provider == "ollama" {
		utils.InfoPrint("使用本地Ollama服务进行专业信息收集策略制定...")
	}
	strategy, err := aiClient.DecideInfoCollectionStrategy(target, availableTools)
	if err != nil {
		utils.WarningPrint("AI决策失败，使用增强的默认工具: %v", err)
		return enhancedBasicInfoCollection(target, availableTools)
	}

	// 4. 解析AI的策略并执行
	utils.InfoPrint("AI制定的专业信息收集策略: %s", strategy)

	// 解析JSON格式的策略
	var aiStrategy struct {
		Strategy string `json:"strategy"`
		Steps    []struct {
			Step    string `json:"step"`
			Tool    string `json:"tool"`
			Command string `json:"command"`
			Reason  string `json:"reason"`
		} `json:"steps"`
	}

	if err := json.Unmarshal([]byte(strategy), &aiStrategy); err != nil {
		utils.WarningPrint("解析AI策略失败，使用增强的默认工具: %v", err)
		return enhancedBasicInfoCollection(target, availableTools)
	}

	// 5. 执行AI制定的专业信息收集策略步骤
	utils.InfoPrint("开始执行AI制定的专业信息收集步骤...")
	for i, step := range aiStrategy.Steps {
		utils.InfoPrint("执行步骤 %d/%d: %s", i+1, len(aiStrategy.Steps), step.Step)
		utils.InfoPrint("工具: %s, 原因: %s", step.Tool, step.Reason)

		// 检查工具是否可用（使用增强的工具管理器）
		if !availableTools[step.Tool] {
			// 尝试使用增强的工具管理器查找工具
			if tool, exists := enhancedToolManager.GetTool(step.Tool); exists && tool.IsAvailable() {
				utils.InfoPrint("通过全盘扫描发现工具: %s", step.Tool)
			} else {
				utils.WarningPrint("工具 %s 不可用，跳过此步骤", step.Tool)
				continue
			}
		}

		// 执行命令
		output, err := executeAIStep(step.Command)
		if err != nil {
			utils.WarningPrint("执行步骤失败: %v", err)
			results += fmt.Sprintf("步骤失败: %s - %v\n", step.Step, err)
		} else {
			utils.SuccessPrint("步骤执行成功")
			results += fmt.Sprintf("=== %s ===\n", step.Step)
			results += fmt.Sprintf("工具: %s\n", step.Tool)
			results += fmt.Sprintf("命令: %s\n", step.Command)
			results += fmt.Sprintf("结果:\n%s\n\n", output)
		}
	}

	return results, nil
}

// enhancedBasicInfoCollection 增强版基础信息收集（AI决策失败时的降级方案）
func enhancedBasicInfoCollection(target string, availableTools map[string]bool) (string, error) {
	utils.InfoPrint("使用增强版基础信息收集策略...")
	var results string

	// 根据目标类型选择基础工具
	targetType := getTargetType(target)
	utils.InfoPrint("目标类型: %s", targetType)

	// 增强版信息收集策略 - 更全面的信息收集
	// 1. 通用信息收集（适用于所有目标类型）
	if targetType == "域名" {
		// DNS信息收集
		if availableTools["nslookup"] {
			utils.InfoPrint("对域名进行详细DNS查询...")
			output, err := RunCommand("nslookup", "-type=A", target)
			if err != nil {
				utils.WarningPrint("nslookup A记录查询失败: %v", err)
			} else {
				results += "=== DNS A记录查询结果 ===\n" + output + "\n\n"
			}

			output, err = RunCommand("nslookup", "-type=MX", target)
			if err != nil {
				utils.WarningPrint("nslookup MX记录查询失败: %v", err)
			} else {
				results += "=== DNS MX记录查询结果 ===\n" + output + "\n\n"
			}

			output, err = RunCommand("nslookup", "-type=NS", target)
			if err != nil {
				utils.WarningPrint("nslookup NS记录查询失败: %v", err)
			} else {
				results += "=== DNS NS记录查询结果 ===\n" + output + "\n\n"
			}
		}

		// WHOIS查询
		if availableTools["whois"] {
			utils.InfoPrint("对域名进行WHOIS查询...")
			output, err := RunCommand("whois", target)
			if err != nil {
				utils.WarningPrint("whois查询失败: %v", err)
			} else {
				results += "=== WHOIS查询结果 ===\n" + output + "\n\n"
			}
		}
	}

	// 2. 网络信息收集
	if availableTools["nmap"] {
		utils.InfoPrint("进行全面的端口扫描和服务识别...")
		// 根据目标类型调整nmap参数
		var nmapArgs []string
		if targetType == "IP地址" {
			nmapArgs = []string{"-sS", "-sV", "-O", "-A", "-p-", "--script=default,discovery", target}
		} else {
			nmapArgs = []string{"-sS", "-sV", "-O", "-A", "-p1-10000", "--script=default,discovery", target}
		}
		output, err := RunCommand("nmap", nmapArgs...)
		if err != nil {
			utils.WarningPrint("nmap全面扫描失败: %v", err)
			// 回退到基础扫描
			output, err = RunCommand("nmap", "-sS", "-sV", "-p1-1000", target)
			if err != nil {
				utils.WarningPrint("nmap基础扫描也失败: %v", err)
			} else {
				results += "=== 基础端口扫描结果 ===\n" + output + "\n\n"
			}
		} else {
			results += "=== 全面端口扫描和服务识别结果 ===\n" + output + "\n\n"
		}
	}

	// 3. Web信息收集（如果是域名或URL）
	if targetType == "URL" || targetType == "域名" {
		webTarget := target
		if targetType == "域名" {
			webTarget = "http://" + target
		}

		// HTTP头信息收集
		if availableTools["curl"] {
			utils.InfoPrint("收集HTTP头信息...")
			output, err := RunCommand("curl", "-I", "-v", webTarget)
			if err != nil {
				utils.WarningPrint("curl HTTP头收集失败: %v", err)
			} else {
				results += "=== HTTP头信息 ===\n" + output + "\n\n"
			}
		}

		// SSL/TLS信息收集
		if availableTools["openssl"] {
			utils.InfoPrint("收集SSL/TLS证书信息...")
			httpsTarget := strings.Replace(webTarget, "http://", "https://", 1)
			// 提取主机名和端口
			hostPort := strings.TrimPrefix(httpsTarget, "https://")
			if !strings.Contains(hostPort, ":") {
				hostPort += ":443"
			}
			output, err := RunCommand("openssl", "s_client", "-connect", hostPort, "-showcerts")
			if err != nil {
				utils.WarningPrint("openssl SSL/TLS信息收集失败: %v", err)
			} else {
				results += "=== SSL/TLS证书信息 ===\n" + output + "\n\n"
			}
		}

		// 目录扫描（如果有dirb工具）
		if availableTools["dirb"] {
			utils.InfoPrint("进行目录扫描...")
			output, err := RunCommand("dirb", webTarget, "/usr/share/wordlists/dirb/common.txt", "-S")
			if err != nil {
				utils.WarningPrint("dirb目录扫描失败: %v", err)
			} else {
				results += "=== 目录扫描结果 ===\n" + output + "\n\n"
			}
		}

		// 技术栈识别（如果有whatweb工具）
		if availableTools["whatweb"] {
			utils.InfoPrint("识别网站技术栈...")
			output, err := RunCommand("whatweb", webTarget)
			if err != nil {
				utils.WarningPrint("whatweb技术栈识别失败: %v", err)
			} else {
				results += "=== 网站技术栈识别结果 ===\n" + output + "\n\n"
			}
		}
	}

	return results, nil
}

// executeAIStep 执行AI制定的步骤
func executeAIStep(command string) (string, error) {
	// 解析命令为命令和参数
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", fmt.Errorf("空命令")
	}

	cmd := parts[0]
	args := parts[1:]

	return RunCommand(cmd, args...)
}

// vulnerabilityDetection 可用漏洞检测阶段
func vulnerabilityDetection(target string, availableTools map[string]bool) (string, error) {
	utils.InfoPrint("正在检测目标漏洞...")
	var results string

	// 这里将实现漏洞检测逻辑
	// 暂时返回空结果
	return results, nil
}

// securityConfigAssessment 安全配置评估阶段
func securityConfigAssessment(target string, availableTools map[string]bool) (string, error) {
	utils.InfoPrint("正在评估目标安全配置...")
	var results string

	// 这里将实现安全配置评估逻辑
	// 暂时返回空结果
	return results, nil
}

// targetInfoCollectionWithLogging 带日志记录的目标信息收集
func targetInfoCollectionWithLogging(target string, availableTools map[string]bool) (string, error) {
	// 创建渗透测试日志记录器
	logger, err := NewPenetrationLogger(target, "")
	if err != nil {
		utils.ErrorPrint("创建日志记录器失败: %v，将使用基础信息收集", err)
		return targetInfoCollection(target, availableTools)
	}
	defer logger.Close()

	// 记录测试开始
	logger.LogPhaseStart(PhaseStart, "开始AI驱动目标信息收集")

	// 获取AI配置
	cfgPath := config.GetDefaultConfigPath()
	utils.InfoPrint("加载AI配置文件: %s", cfgPath)
	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("加载AI配置文件: %s", cfgPath), 0)

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.ErrorPrint("加载AI配置失败: %v", err)
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "加载AI配置失败", 0)
		utils.InfoPrint("将使用增强版基础信息收集策略")
		// 降级到增强版基础信息收集
		result, err2 := enhancedBasicInfoCollectionWithLogging(target, availableTools, logger)
		if err2 != nil {
			err = err2
		}

		// 生成报告
		generateSmartReportForAux(target, logger, time.Now(), result, err)
		return result, err
	}

	// 验证提供商配置
	utils.InfoPrint("验证AI提供商配置: %s", cfg.Provider)
	if _, err = config.TestConfig(*cfg); err != nil {
		utils.ErrorPrint("AI提供商配置验证失败: %v", err)
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "AI提供商配置验证失败", 0)
		utils.InfoPrint("请检查配置文件中的provider、api_key、base_url等设置")
		utils.InfoPrint("将使用增强版基础信息收集策略")
		// 降级到增强版基础信息收集
		result, err2 := enhancedBasicInfoCollectionWithLogging(target, availableTools, logger)
		if err2 != nil {
			err = err2
		}

		// 生成报告
		generateSmartReportForAux(target, logger, time.Now(), result, err)
		return result, err
	}

	utils.InfoPrint("AI提供商配置验证通过")
	logger.Log(PhaseInfoGathering, "", "", "", "", "AI提供商配置验证通过", 0)

	// 创建AI客户端
	utils.InfoPrint("创建AI客户端...")
	logger.Log(PhaseInfoGathering, "", "", "", "", "创建AI客户端...", 0)
	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.ErrorPrint("创建AI客户端失败: %v", err)
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "创建AI客户端失败", 0)
		utils.InfoPrint("请检查网络连接和API密钥设置")
		utils.InfoPrint("将使用增强版基础信息收集策略")
		// 降级到增强版基础信息收集
		result, err2 := enhancedBasicInfoCollectionWithLogging(target, availableTools, logger)
		if err2 != nil {
			err = err2
		}

		// 生成报告
		generateSmartReportForAux(target, logger, time.Now(), result, err)
		return result, err
	}

	utils.InfoPrint("AI客户端创建成功，提供商: %s", cfg.Provider)
	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("AI客户端创建成功，提供商: %s", cfg.Provider), 0)

	// 使用AI进行智能信息收集
	utils.InfoPrint("\n=== AI智能信息收集阶段 ===")
	logger.LogPhaseStart(PhaseInfoGathering, "开始AI智能信息收集")
	infoCollectionStart := time.Now()
	// 创建一个基础的ToolManager来传递可用工具信息
	baseToolManager := &ToolManager{
		Tools: make(map[string]ToolInterface),
	}
	// 将availableTools转换为ToolManager可以使用的格式
	for toolName, isAvailable := range availableTools {
		if isAvailable {
			baseToolManager.Tools[toolName] = &BaseTool{
				NameValue: toolName,
				Path:      "", // 路径将在需要时查找
				Available: true,
			}
		}
	}
	infoCollectionResult, err := intelligentInformationCollectionWithLogging(target, aiClient, baseToolManager, logger)
	infoCollectionDuration := time.Since(infoCollectionStart)

	if err != nil {
		utils.WarningPrint("AI智能信息收集失败: %v，将使用增强版基础信息收集", err)
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "AI智能信息收集失败，将使用增强版基础信息收集", infoCollectionDuration)
		// 降级到增强版基础信息收集
		result, err := enhancedBasicInfoCollectionWithLogging(target, availableTools, logger)

		// 生成报告
		generateSmartReportForAux(target, logger, time.Now(), result, err)
		return result, err
	}

	logger.LogPhaseComplete(PhaseInfoGathering, "AI智能信息收集完成", infoCollectionDuration)

	// 生成智能报告
	generateSmartReportForAux(target, logger, time.Now(), infoCollectionResult, nil)

	return infoCollectionResult, nil
}

// enhancedBasicInfoCollectionWithLogging 增强版基础信息收集（带日志记录）
func enhancedBasicInfoCollectionWithLogging(target string, availableTools map[string]bool, logger *PenetrationLogger) (string, error) {
	logger.LogPhaseStart(PhaseInfoGathering, "开始增强版基础信息收集")

	// 原有逻辑，但添加日志记录
	utils.InfoPrint("执行增强版基础信息收集策略")
	var results string

	// 根据目标类型选择基础工具
	targetType := getTargetType(target)
	utils.InfoPrint("目标类型: %s", targetType)
	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("目标类型: %s", targetType), 0)

	// 增强版信息收集策略 - 更全面的信息收集
	// 1. 通用信息收集（适用于所有目标类型）
	if targetType == "域名" {
		// DNS信息收集
		if availableTools["nslookup"] {
			utils.InfoPrint("对域名进行详细DNS查询...")
			logger.Log(PhaseInfoGathering, "nslookup", "", "", "", "开始DNS查询", 0)

			output, err := RunCommand("nslookup", "-type=A", target)
			if err != nil {
				utils.WarningPrint("nslookup A记录查询失败: %v", err)
				logger.Log(PhaseInfoGathering, "nslookup", "", "", err.Error(), "nslookup A记录查询失败", 0)
			} else {
				results += "=== DNS A记录查询结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "nslookup", "", "", "", "nslookup A记录查询完成", 0)
			}

			output, err = RunCommand("nslookup", "-type=MX", target)
			if err != nil {
				utils.WarningPrint("nslookup MX记录查询失败: %v", err)
				logger.Log(PhaseInfoGathering, "nslookup", "", "", err.Error(), "nslookup MX记录查询失败", 0)
			} else {
				results += "=== DNS MX记录查询结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "nslookup", "", "", "", "nslookup MX记录查询完成", 0)
			}

			output, err = RunCommand("nslookup", "-type=NS", target)
			if err != nil {
				utils.WarningPrint("nslookup NS记录查询失败: %v", err)
				logger.Log(PhaseInfoGathering, "nslookup", "", "", err.Error(), "nslookup NS记录查询失败", 0)
			} else {
				results += "=== DNS NS记录查询结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "nslookup", "", "", "", "nslookup NS记录查询完成", 0)
			}
		}

		// WHOIS查询
		if availableTools["whois"] {
			utils.InfoPrint("对域名进行WHOIS查询...")
			logger.Log(PhaseInfoGathering, "whois", "", "", "", "开始WHOIS查询", 0)

			output, err := RunCommand("whois", target)
			if err != nil {
				utils.WarningPrint("whois查询失败: %v", err)
				logger.Log(PhaseInfoGathering, "whois", "", "", err.Error(), "WHOIS查询失败", 0)
			} else {
				results += "=== WHOIS查询结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "whois", "", "", "", "WHOIS查询完成", 0)
			}
		}
	}

	// 2. 网络信息收集
	if availableTools["nmap"] {
		utils.InfoPrint("进行全面的端口扫描和服务识别...")
		logger.Log(PhaseInfoGathering, "nmap", "", "", "", "开始端口扫描", 0)

		// 根据目标类型调整nmap参数
		var nmapArgs []string
		if targetType == "IP地址" {
			nmapArgs = []string{"-sS", "-sV", "-O", "-A", "-p-", "--script=default,discovery", target}
		} else {
			nmapArgs = []string{"-sS", "-sV", "-O", "-A", "-p1-10000", "--script=default,discovery", target}
		}

		output, err := RunCommand("nmap", nmapArgs...)
		if err != nil {
			utils.WarningPrint("nmap全面扫描失败: %v", err)
			logger.Log(PhaseInfoGathering, "nmap", "", "", err.Error(), "nmap全面扫描失败", 0)
			// 回退到基础扫描
			output, err = RunCommand("nmap", "-sS", "-sV", "-p1-1000", target)
			if err != nil {
				utils.WarningPrint("nmap基础扫描也失败: %v", err)
				logger.Log(PhaseInfoGathering, "nmap", "", "", err.Error(), "nmap基础扫描失败", 0)
			} else {
				results += "=== 基础端口扫描结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "nmap", "", "", "", "nmap基础扫描完成", 0)
			}
		} else {
			results += "=== 全面端口扫描和服务识别结果 ===\n" + output + "\n\n"
			logger.Log(PhaseInfoGathering, "nmap", "", "", "", "nmap全面扫描完成", 0)
		}
	}

	// 3. Web信息收集（如果是域名或URL）
	if targetType == "URL" || targetType == "域名" {
		webTarget := target
		if targetType == "域名" {
			webTarget = "http://" + target
		}

		// HTTP头信息收集
		if availableTools["curl"] {
			utils.InfoPrint("收集HTTP头信息...")
			logger.Log(PhaseInfoGathering, "curl", "", "", "", "开始HTTP头信息收集", 0)

			output, err := RunCommand("curl", "-I", "-v", webTarget)
			if err != nil {
				utils.WarningPrint("curl HTTP头收集失败: %v", err)
				logger.Log(PhaseInfoGathering, "curl", "", "", err.Error(), "HTTP头信息收集失败", 0)
			} else {
				results += "=== HTTP头信息 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "curl", "", "", "", "HTTP头信息收集完成", 0)
			}
		}

		// SSL/TLS信息收集
		if availableTools["openssl"] {
			utils.InfoPrint("收集SSL/TLS证书信息...")
			logger.Log(PhaseInfoGathering, "openssl", "", "", "", "开始SSL/TLS证书信息收集", 0)

			httpsTarget := strings.Replace(webTarget, "http://", "https://", 1)
			// 提取主机名和端口
			hostPort := strings.TrimPrefix(httpsTarget, "https://")
			if !strings.Contains(hostPort, ":") {
				hostPort += ":443"
			}

			output, err := RunCommand("openssl", "s_client", "-connect", hostPort, "-showcerts")
			if err != nil {
				utils.WarningPrint("openssl SSL/TLS信息收集失败: %v", err)
				logger.Log(PhaseInfoGathering, "openssl", "", "", err.Error(), "SSL/TLS证书信息收集失败", 0)
			} else {
				results += "=== SSL/TLS证书信息 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "openssl", "", "", "", "SSL/TLS证书信息收集完成", 0)
			}
		}

		// 目录扫描（如果有dirb工具）
		if availableTools["dirb"] {
			utils.InfoPrint("进行目录扫描...")
			logger.Log(PhaseInfoGathering, "dirb", "", "", "", "开始目录扫描", 0)

			output, err := RunCommand("dirb", webTarget, "/usr/share/wordlists/dirb/common.txt", "-S")
			if err != nil {
				utils.WarningPrint("dirb目录扫描失败: %v", err)
				logger.Log(PhaseInfoGathering, "dirb", "", "", err.Error(), "目录扫描失败", 0)
			} else {
				results += "=== 目录扫描结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "dirb", "", "", "", "目录扫描完成", 0)
			}
		}

		// 技术栈识别（如果有whatweb工具）
		if availableTools["whatweb"] {
			utils.InfoPrint("识别网站技术栈...")
			logger.Log(PhaseInfoGathering, "whatweb", "", "", "", "开始技术栈识别", 0)

			output, err := RunCommand("whatweb", webTarget)
			if err != nil {
				utils.WarningPrint("whatweb技术栈识别失败: %v", err)
				logger.Log(PhaseInfoGathering, "whatweb", "", "", err.Error(), "技术栈识别失败", 0)
			} else {
				results += "=== 网站技术栈识别结果 ===\n" + output + "\n\n"
				logger.Log(PhaseInfoGathering, "whatweb", "", "", "", "技术栈识别完成", 0)
			}
		}
	}

	logger.LogPhaseComplete(PhaseInfoGathering, "增强版基础信息收集完成", 0)
	return results, nil
}

// generateSmartReportForAux 为aux命令生成智能报告
func generateSmartReportForAux(target string, logger *PenetrationLogger, startTime time.Time, testResult string, testErr error) {
	endTime := time.Now()
	utils.InfoPrint("\n=== 智能报告生成阶段 ===")

	// 创建AI客户端用于智能报告生成
	cfgPath := config.GetDefaultConfigPath()
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		utils.WarningPrint("加载AI配置失败: %v，将使用基础报告", err)
		generateBasicReportForAux(target, logger, startTime, endTime, testResult, testErr)
		return
	}

	aiClient, err := NewAIClient(*cfg)
	if err != nil {
		utils.WarningPrint("创建AI客户端失败: %v，将使用基础报告", err)
		generateBasicReportForAux(target, logger, startTime, endTime, testResult, testErr)
		return
	}

	// 创建智能报告生成器
	reportGenerator := NewSmartReportGenerator(aiClient, logger, "reports")

	// 生成智能报告
	if err := reportGenerator.GenerateSmartReport(target, FormatHTML, FormatMarkdown); err != nil {
		utils.ErrorPrint("智能报告生成失败: %v，将使用基础报告", err)
		generateBasicReportForAux(target, logger, startTime, endTime, testResult, testErr)
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

// generateBasicReportForAux 为aux命令生成基础报告
func generateBasicReportForAux(target string, logger *PenetrationLogger, startTime, endTime time.Time, testResult string, testErr error) {
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
		TaskID:          "target_info_collection",
		Title:           "AI驱动目标信息收集报告",
		Summary:         summary,
		Findings:        findings,
		RiskAssessment:  types.RiskAssessment{},
		Recommendations: recommendations,
		CreatedAt:       time.Now(),
		Metadata: map[string]string{
			"target":     target,
			"scan_type":  "aux",
			"start_time": startTime.Format("2006-01-02 15:04:05"),
			"end_time":   endTime.Format("2006-01-02 15:04:05"),
			"duration":   endTime.Sub(startTime).String(),
			"logs":       testResult,
		},
	}

	if err := GenerateReport(reportData, "", FormatHTML); err != nil {
		utils.ErrorPrint("生成报告失败: %v", err)
	} else {
		utils.SuccessPrint("基础报告生成成功")
	}
}

// intelligentInformationCollectionWithLoggingAux 带日志记录的智能信息收集（aux版本）
func intelligentInformationCollectionWithLoggingAux(target string, aiClient *AIClient, availableTools map[string]bool, logger *PenetrationLogger) (string, error) {
	// 让AI自主制定专业信息收集策略（基于增强的工具列表）
	strategy, err := aiClient.DecideInfoCollectionStrategy(target, availableTools)
	if err != nil {
		utils.WarningPrint("AI决策失败，使用增强的默认工具: %v", err)
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "AI决策失败", 0)
		return enhancedBasicInfoCollectionWithLogging(target, availableTools, logger)
	}

	// 解析JSON格式的策略
	var aiStrategy struct {
		Strategy string `json:"strategy"`
		Steps    []struct {
			Step    string `json:"step"`
			Tool    string `json:"tool"`
			Command string `json:"command"`
			Reason  string `json:"reason"`
		} `json:"steps"`
	}

	if err := json.Unmarshal([]byte(strategy), &aiStrategy); err != nil {
		utils.WarningPrint("解析AI策略失败，使用增强的默认工具: %v", err)
		logger.Log(PhaseInfoGathering, "", "", "", err.Error(), "解析AI策略失败", 0)
		return enhancedBasicInfoCollectionWithLogging(target, availableTools, logger)
	}

	utils.InfoPrint("AI制定的专业信息收集策略: %s", strategy)
	logger.Log(PhaseInfoGathering, "", "", "", "", fmt.Sprintf("AI制定的专业信息收集策略: %s", aiStrategy.Strategy), 0)

	// 执行AI制定的专业信息收集策略步骤
	utils.InfoPrint("开始执行AI制定的专业信息收集步骤...")
	var results string

	for i, step := range aiStrategy.Steps {
		utils.InfoPrint("执行步骤 %d/%d: %s", i+1, len(aiStrategy.Steps), step.Step)
		utils.InfoPrint("工具: %s, 原因: %s", step.Tool, step.Reason)

		logger.Log(PhaseInfoGathering, step.Tool, "", "", "", fmt.Sprintf("开始执行步骤: %s", step.Step), 0)

		// 检查工具是否可用
		if !availableTools[step.Tool] {
			utils.WarningPrint("工具 %s 不可用，跳过此步骤", step.Tool)
			logger.Log(PhaseInfoGathering, step.Tool, "", "", "", fmt.Sprintf("工具 %s 不可用，跳过步骤", step.Tool), 0)
			continue
		}

		// 执行命令
		stepStart := time.Now()
		output, err := executeAIStep(step.Command)
		stepDuration := time.Since(stepStart)

		if err != nil {
			utils.WarningPrint("执行步骤失败: %v", err)
			logger.Log(PhaseInfoGathering, step.Tool, "", "", err.Error(), fmt.Sprintf("步骤失败: %s", step.Step), stepDuration)
			results += fmt.Sprintf("步骤失败: %s - %v\n", step.Step, err)
		} else {
			utils.SuccessPrint("步骤执行成功")
			logger.Log(PhaseInfoGathering, step.Tool, "", "", "", fmt.Sprintf("步骤完成: %s", step.Step), stepDuration)
			results += fmt.Sprintf("=== %s ===\n", step.Step)
			results += fmt.Sprintf("工具: %s\n", step.Tool)
			results += fmt.Sprintf("命令: %s\n", step.Command)
			results += fmt.Sprintf("结果:\n%s\n\n", output)
		}
	}

	return results, nil
}
