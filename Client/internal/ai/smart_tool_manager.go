package ai

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"
)

// SmartToolManager 智能工具管理器
type SmartToolManager struct {
	ToolManager      *ToolManager
	ToolCache        map[string]*ToolCacheEntry
	CacheMutex       sync.RWMutex
	ExecutionHistory map[string][]*ToolExecutionRecord
	HistoryMutex     sync.RWMutex
	AIClient         AIClientInterface
}

// ToolCacheEntry 工具缓存条目
type ToolCacheEntry struct {
	Tool        ToolInterface
	LastUsed    time.Time
	UsageCount  int
	SuccessRate float64
	IsAvailable bool
}

// ToolExecutionRecord 工具执行记录
type ToolExecutionRecord struct {
	ToolName  string
	Args      []string
	Output    string
	Error     string
	Duration  time.Duration
	Timestamp time.Time
	Success   bool
	Context   string
}

// NewSmartToolManager 创建新的智能工具管理器
func NewSmartToolManager(toolManager *ToolManager, aiClient AIClientInterface) *SmartToolManager {
	return &SmartToolManager{
		ToolManager:      toolManager,
		ToolCache:        make(map[string]*ToolCacheEntry),
		ExecutionHistory: make(map[string][]*ToolExecutionRecord),
		AIClient:         aiClient,
	}
}

// InitializeCache 初始化工具缓存
func (stm *SmartToolManager) InitializeCache() {
	stm.CacheMutex.Lock()
	defer stm.CacheMutex.Unlock()

	for name, tool := range stm.ToolManager.Tools {
		stm.ToolCache[name] = &ToolCacheEntry{
			Tool:        tool,
			LastUsed:    time.Now(),
			UsageCount:  0,
			SuccessRate: 0.0,
			IsAvailable: tool.IsAvailable(),
		}
	}

	utils.InfoPrint("智能工具管理器缓存初始化完成，共缓存 %d 个工具", len(stm.ToolCache))
}

// ExecuteToolWithAI 使用AI辅助执行工具
func (stm *SmartToolManager) ExecuteToolWithAI(toolName string, target string, context string) (string, error) {
	// 检查工具是否可用
	tool, exists := stm.ToolManager.GetTool(toolName)
	if !exists {
		return "", fmt.Errorf("工具 %s 不存在", toolName)
	}

	if !tool.IsAvailable() {
		return "", fmt.Errorf("工具 %s 不可用", toolName)
	}

	// 使用AI生成最佳参数
	optimalArgs, err := stm.generateOptimalArgsWithAI(toolName, target, context)
	if err != nil {
		utils.WarningPrint("AI参数生成失败，使用默认参数: %v", err)
		optimalArgs = stm.getDefaultArgs(toolName, target)
	}

	// 记录执行开始
	startTime := time.Now()

	// 执行工具
	utils.InfoPrint("执行工具: %s %s", toolName, strings.Join(optimalArgs, " "))
	output, err := tool.Run(optimalArgs...)

	// 记录执行结果
	duration := time.Since(startTime)
	success := err == nil

	record := &ToolExecutionRecord{
		ToolName:  toolName,
		Args:      optimalArgs,
		Output:    output,
		Error:     "",
		Duration:  duration,
		Timestamp: startTime,
		Success:   success,
		Context:   context,
	}

	if err != nil {
		record.Error = err.Error()
	}

	stm.recordExecution(toolName, record)
	stm.updateToolCache(toolName, success)

	if err != nil {
		utils.ErrorPrint("工具 %s 执行失败: %v", toolName, err)
		return "", fmt.Errorf("工具 %s 执行失败: %v", toolName, err)
	}

	utils.SuccessPrint("工具 %s 执行成功，耗时: %v", toolName, duration)
	return output, nil
}

// generateOptimalArgsWithAI 使用AI生成最优参数
func (stm *SmartToolManager) generateOptimalArgsWithAI(toolName, target, context string) ([]string, error) {
	if stm.AIClient == nil {
		return stm.getDefaultArgs(toolName, target), nil
	}

	// 获取工具的历史执行记录
	history := stm.getExecutionHistory(toolName)

	// 构建AI提示
	systemPrompt := `你是一名专业的渗透测试工程师。请根据目标信息和上下文，为指定的工具生成最优参数。`

	userContent := fmt.Sprintf(`工具: %s
目标: %s
上下文: %s

历史执行记录:
%s

请生成最适合当前情况的工具参数，返回格式为: "参数1 参数2 参数3"`,
		toolName, target, context, stm.formatHistoryForAI(history))

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

	// 调用AI生成参数
	response, err := stm.AIClient.Chat(messages)
	if err != nil {
		return nil, err
	}

	// 解析AI返回的参数
	args := strings.Fields(response)
	if len(args) == 0 {
		return stm.getDefaultArgs(toolName, target), nil
	}

	utils.InfoPrint("AI生成参数: %s", strings.Join(args, " "))
	return args, nil
}

// getDefaultArgs 获取工具的默认参数
func (stm *SmartToolManager) getDefaultArgs(toolName, target string) []string {
	// 根据工具类型返回默认参数
	switch toolName {
	case "nmap":
		return []string{"-sS", "-sV", "-O", "-T4", target}
	case "sqlmap":
		return []string{"-u", target, "--batch", "--level=3", "--risk=2"}
	case "nikto":
		return []string{"-h", target, "-C", "all"}
	case "wpscan":
		return []string{"--url", target, "--enumerate", "vp"}
	case "dirb":
		return []string{target, "/usr/share/dirb/wordlists/common.txt"}
	default:
		return []string{target}
	}
}

// recordExecution 记录工具执行历史
func (stm *SmartToolManager) recordExecution(toolName string, record *ToolExecutionRecord) {
	stm.HistoryMutex.Lock()
	defer stm.HistoryMutex.Unlock()

	// 限制历史记录数量
	if len(stm.ExecutionHistory[toolName]) >= 100 {
		stm.ExecutionHistory[toolName] = stm.ExecutionHistory[toolName][1:]
	}

	stm.ExecutionHistory[toolName] = append(stm.ExecutionHistory[toolName], record)
}

// getExecutionHistory 获取工具执行历史
func (stm *SmartToolManager) getExecutionHistory(toolName string) []*ToolExecutionRecord {
	stm.HistoryMutex.RLock()
	defer stm.HistoryMutex.RUnlock()

	return stm.ExecutionHistory[toolName]
}

// formatHistoryForAI 格式化历史记录供AI使用
func (stm *SmartToolManager) formatHistoryForAI(history []*ToolExecutionRecord) string {
	if len(history) == 0 {
		return "无历史记录"
	}

	var result strings.Builder
	for i, record := range history {
		if i >= 5 { // 只显示最近5条记录
			break
		}
		status := "失败"
		if record.Success {
			status = "成功"
		}
		result.WriteString(fmt.Sprintf("%d. 参数: %s, 状态: %s, 耗时: %v\n",
			i+1, strings.Join(record.Args, " "), status, record.Duration))
	}

	return result.String()
}

// updateToolCache 更新工具缓存
func (stm *SmartToolManager) updateToolCache(toolName string, success bool) {
	stm.CacheMutex.Lock()
	defer stm.CacheMutex.Unlock()

	if entry, exists := stm.ToolCache[toolName]; exists {
		entry.LastUsed = time.Now()
		entry.UsageCount++

		// 更新成功率
		if success {
			entry.SuccessRate = (entry.SuccessRate*float64(entry.UsageCount-1) + 1.0) / float64(entry.UsageCount)
		} else {
			entry.SuccessRate = (entry.SuccessRate * float64(entry.UsageCount-1)) / float64(entry.UsageCount)
		}
	}
}

// GetToolRecommendations 获取工具推荐
func (stm *SmartToolManager) GetToolRecommendations(targetType, context string) []string {
	stm.CacheMutex.RLock()
	defer stm.CacheMutex.RUnlock()

	var recommendations []string

	// 基于目标类型和上下文推荐工具
	switch targetType {
	case "web_app":
		recommendations = stm.recommendWebAppTools(context)
	case "network":
		recommendations = stm.recommendNetworkTools(context)
	case "api":
		recommendations = stm.recommendAPITools(context)
	default:
		recommendations = stm.recommendGeneralTools()
	}

	return recommendations
}

// recommendWebAppTools 推荐Web应用测试工具
func (stm *SmartToolManager) recommendWebAppTools(context string) []string {
	// 基于成功率和使用频率排序
	webAppTools := []string{"nmap", "nikto", "sqlmap", "dirb", "wpscan"}
	return stm.sortToolsByPerformance(webAppTools)
}

// recommendNetworkTools 推荐网络测试工具
func (stm *SmartToolManager) recommendNetworkTools(context string) []string {
	networkTools := []string{"nmap", "ping", "traceroute", "netcat"}
	return stm.sortToolsByPerformance(networkTools)
}

// recommendAPITools 推荐API测试工具
func (stm *SmartToolManager) recommendAPITools(context string) []string {
	apiTools := []string{"curl", "postman", "burp"}
	return stm.sortToolsByPerformance(apiTools)
}

// recommendGeneralTools 推荐通用工具
func (stm *SmartToolManager) recommendGeneralTools() []string {
	generalTools := []string{"nmap", "curl", "ping", "whois"}
	return stm.sortToolsByPerformance(generalTools)
}

// sortToolsByPerformance 根据性能排序工具
func (stm *SmartToolManager) sortToolsByPerformance(tools []string) []string {
	var availableTools []string

	// 过滤可用的工具
	for _, tool := range tools {
		if entry, exists := stm.ToolCache[tool]; exists && entry.IsAvailable {
			availableTools = append(availableTools, tool)
		}
	}

	// 按成功率和最近使用时间排序
	for i := 0; i < len(availableTools)-1; i++ {
		for j := i + 1; j < len(availableTools); j++ {
			toolI := availableTools[i]
			toolJ := availableTools[j]

			entryI := stm.ToolCache[toolI]
			entryJ := stm.ToolCache[toolJ]

			// 比较成功率
			if entryJ.SuccessRate > entryI.SuccessRate ||
				(entryJ.SuccessRate == entryI.SuccessRate && entryJ.LastUsed.After(entryI.LastUsed)) {
				availableTools[i], availableTools[j] = availableTools[j], availableTools[i]
			}
		}
	}

	return availableTools
}

// GetToolStats 获取工具统计信息
func (stm *SmartToolManager) GetToolStats() map[string]interface{} {
	stm.CacheMutex.RLock()
	defer stm.CacheMutex.RUnlock()

	stats := make(map[string]interface{})
	for name, entry := range stm.ToolCache {
		if entry.IsAvailable {
			stats[name] = map[string]interface{}{
				"usage_count":  entry.UsageCount,
				"success_rate": entry.SuccessRate,
				"last_used":    entry.LastUsed.Format(time.RFC3339),
			}
		}
	}

	return stats
}
