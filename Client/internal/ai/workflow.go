package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// WorkflowEngine 智能渗透测试工作流引擎
type WorkflowEngine struct {
	Target      string
	ToolManager *ToolManager
	AIClient    *AIClient
	Config      config.AIConfig
	Context     context.Context
	CancelFunc  context.CancelFunc
	State       *WorkflowState
	Progress    *WorkflowProgress
}

// WorkflowState 工作流状态
type WorkflowState struct {
	CurrentPhase    WorkflowPhase
	PhaseStatus     map[WorkflowPhase]PhaseStatus
	CollectedData   map[string]interface{}
	Vulnerabilities []types.Vulnerability
	Findings        []types.Finding
	Recommendations []string
	StartTime       time.Time
	LastUpdateTime  time.Time
}

// WorkflowProgress 工作流进度
type WorkflowProgress struct {
	CurrentPhase   WorkflowPhase
	PhaseProgress  map[WorkflowPhase]float64
	TotalProgress  float64
	EstimatedTime  time.Duration
	PhaseStartTime time.Time
	PhaseEndTime   time.Time
}

// WorkflowPhase 工作流阶段（已移至types包）
type WorkflowPhase = types.WorkflowPhase

// PhaseStatus 阶段状态（已移至types包）
type PhaseStatus = types.PhaseStatus

// 阶段状态常量（已移至types包）
const (
	StatusPending    = types.StatusPending    // 待执行
	StatusInProgress = types.StatusInProgress // 执行中
	StatusCompleted  = types.StatusCompleted  // 已完成
	StatusFailed     = types.StatusFailed     // 失败
	StatusSkipped    = types.StatusSkipped    // 跳过
)

// WorkflowConfig 工作流配置
type WorkflowConfig struct {
	MaxExecutionTime time.Duration
	ParallelTasks    int
	RiskLevel        RiskLevel
	TargetType       TargetType
	CustomPhases     []WorkflowPhase
}

// RiskLevel 风险级别（已移至types包）
type RiskLevel = types.RiskLevel

// 风险级别常量（已移至types包）
const (
	RiskLevelLow    = types.RiskLevelLow    // 低风险
	RiskLevelMedium = types.RiskLevelMedium // 中风险
	RiskLevelHigh   = types.RiskLevelHigh   // 高风险
)

// TargetType 目标类型（已移至types包）
type TargetType = types.TargetType

// 目标类型常量（已移至types包）
const (
	TargetTypeWebApp  = types.TargetTypeWebApp  // Web应用
	TargetTypeNetwork = types.TargetTypeNetwork // 网络设备
	TargetTypeAPI     = types.TargetTypeAPI     // API接口
	TargetTypeMobile  = types.TargetTypeMobile  // 移动应用
	TargetTypeIoT     = types.TargetTypeIoT     // 物联网设备
	TargetTypeCloud   = types.TargetTypeCloud   // 云服务
)

// NewWorkflowEngine 创建新的工作流引擎
func NewWorkflowEngine(target string, toolManager *ToolManager, aiClient *AIClient, cfg config.AIConfig) *WorkflowEngine {
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkflowEngine{
		Target:      target,
		ToolManager: toolManager,
		AIClient:    aiClient,
		Config:      cfg,
		Context:     ctx,
		CancelFunc:  cancel,
		State: &WorkflowState{
			CurrentPhase:    types.PhaseTargetAnalysis,
			PhaseStatus:     make(map[WorkflowPhase]PhaseStatus),
			CollectedData:   make(map[string]interface{}),
			Vulnerabilities: []types.Vulnerability{},
			Findings:        []types.Finding{},
			Recommendations: []string{},
			StartTime:       time.Now(),
			LastUpdateTime:  time.Now(),
		},
		Progress: &WorkflowProgress{
			CurrentPhase:   types.PhaseTargetAnalysis,
			PhaseProgress:  make(map[WorkflowPhase]float64),
			TotalProgress:  0.0,
			EstimatedTime:  0,
			PhaseStartTime: time.Now(),
		},
	}
}

// Execute 执行智能渗透测试工作流
func (w *WorkflowEngine) Execute(config WorkflowConfig) error {
	utils.InfoPrint("开始执行智能渗透测试工作流，目标: %s", w.Target)

	// 初始化所有阶段状态
	w.initializePhases(config)

	// 执行工作流阶段
	phases := w.getExecutionPhases(config)

	for _, phase := range phases {
		select {
		case <-w.Context.Done():
			utils.WarningPrint("工作流被取消")
			return fmt.Errorf("工作流执行被取消")
		default:
			if err := w.executePhase(phase, config); err != nil {
				utils.ErrorPrint("阶段 %s 执行失败: %v", phase, err)
				w.updatePhaseStatus(phase, StatusFailed)
				return err
			}
		}
	}

	utils.SuccessPrint("智能渗透测试工作流执行完成")
	return nil
}

// initializePhases 初始化所有阶段状态
func (w *WorkflowEngine) initializePhases(config WorkflowConfig) {
	phases := w.getExecutionPhases(config)

	for _, phase := range phases {
		w.State.PhaseStatus[phase] = StatusPending
		w.Progress.PhaseProgress[phase] = 0.0
	}
}

// getExecutionPhases 获取执行阶段列表
func (w *WorkflowEngine) getExecutionPhases(config WorkflowConfig) []WorkflowPhase {
	basePhases := []WorkflowPhase{
		types.PhaseTargetAnalysis,
		types.PhaseReconnaissance,
		types.PhaseVulnerabilityScan,
		types.PhaseExploitation,
		types.PhasePostExploitation,
		types.PhaseReporting,
	}

	// 如果有自定义阶段，插入到适当位置
	if len(config.CustomPhases) > 0 {
		// 将自定义阶段插入到漏洞扫描之前
		index := 2 // PhaseVulnerabilityScan 的位置
		basePhases = append(basePhases[:index], append(config.CustomPhases, basePhases[index:]...)...)
	}

	return basePhases
}

// executePhase 执行单个阶段
func (w *WorkflowEngine) executePhase(phase WorkflowPhase, config WorkflowConfig) error {
	utils.InfoPrint("开始执行阶段: %s", phase)

	// 更新阶段状态
	w.updatePhaseStatus(phase, StatusInProgress)
	w.Progress.CurrentPhase = phase
	w.Progress.PhaseStartTime = time.Now()

	var err error
	switch phase {
	case types.PhaseTargetAnalysis:
		err = w.executeTargetAnalysis(config)
	case types.PhaseReconnaissance:
		err = w.executeReconnaissance(config)
	case types.PhaseVulnerabilityScan:
		err = w.executeVulnerabilityScan(config)
	case types.PhaseExploitation:
		err = w.executeExploitation(config)
	case types.PhasePostExploitation:
		err = w.executePostExploitation(config)
	case types.PhaseReporting:
		err = w.executeReporting(config)
	default:
		// 处理自定义阶段
		err = w.executeCustomPhase(phase, config)
	}

	if err != nil {
		w.updatePhaseStatus(phase, StatusFailed)
		return err
	}

	w.updatePhaseStatus(phase, StatusCompleted)
	w.Progress.PhaseEndTime = time.Now()
	w.updateProgress()

	utils.SuccessPrint("阶段 %s 执行完成", phase)
	return nil
}

// executeTargetAnalysis 执行目标分析阶段
func (w *WorkflowEngine) executeTargetAnalysis(config WorkflowConfig) error {
	utils.InfoPrint("正在分析目标: %s", w.Target)

	// 使用AI分析目标类型和特征
	targetType, err := w.analyzeTargetType()
	if err != nil {
		return fmt.Errorf("目标类型分析失败: %v", err)
	}

	// 收集目标基本信息
	targetInfo, err := w.collectTargetInfo()
	if err != nil {
		return fmt.Errorf("目标信息收集失败: %v", err)
	}

	// 评估风险级别
	riskLevel := w.assessRiskLevel(targetType, targetInfo)

	// 更新状态
	w.State.CollectedData["target_type"] = targetType
	w.State.CollectedData["target_info"] = targetInfo
	w.State.CollectedData["risk_level"] = riskLevel

	utils.InfoPrint("目标分析完成 - 类型: %s, 风险级别: %s", targetType, riskLevel)
	return nil
}

// analyzeTargetType 分析目标类型
func (w *WorkflowEngine) analyzeTargetType() (TargetType, error) {
	// 使用AI客户端进行目标类型分析
	messages := []Message{
		{
			Role:    "system",
			Content: "你是一个专业的网络安全专家，请分析给定的目标并确定其类型。",
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("分析目标: %s，请确定其类型（Web应用、网络服务、API、移动应用、IoT设备、云服务等）", w.Target),
		},
	}

	response, err := w.AIClient.Chat(messages)
	if err != nil {
		return TargetTypeWebApp, fmt.Errorf("AI分析失败: %v", err)
	}

	// 解析响应，确定目标类型
	if strings.Contains(strings.ToLower(response), "web") {
		return TargetTypeWebApp, nil
	} else if strings.Contains(strings.ToLower(response), "api") {
		return TargetTypeAPI, nil
	} else if strings.Contains(strings.ToLower(response), "network") {
		return TargetTypeNetwork, nil
	} else if strings.Contains(strings.ToLower(response), "mobile") {
		return TargetTypeMobile, nil
	} else if strings.Contains(strings.ToLower(response), "iot") {
		return TargetTypeIoT, nil
	} else if strings.Contains(strings.ToLower(response), "cloud") {
		return TargetTypeCloud, nil
	}

	// 默认返回Web应用类型
	return TargetTypeWebApp, nil
}

// collectTargetInfo 收集目标基本信息
func (w *WorkflowEngine) collectTargetInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})

	// 这里实现目标信息收集逻辑
	// 包括DNS查询、端口扫描、服务识别等

	return info, nil
}

// assessRiskLevel 评估风险级别
func (w *WorkflowEngine) assessRiskLevel(targetType TargetType, targetInfo map[string]interface{}) RiskLevel {
	// 基于目标类型和特征评估风险级别
	switch targetType {
	case TargetTypeWebApp:
		return RiskLevelMedium
	case TargetTypeAPI:
		return RiskLevelHigh
	case TargetTypeNetwork:
		return RiskLevelMedium
	case TargetTypeMobile:
		return RiskLevelLow
	case TargetTypeIoT:
		return RiskLevelHigh
	case TargetTypeCloud:
		return RiskLevelHigh
	default:
		return RiskLevelMedium
	}
}

// executeReconnaissance 执行侦察阶段
func (w *WorkflowEngine) executeReconnaissance(config WorkflowConfig) error {
	utils.InfoPrint("正在执行侦察阶段")

	// 实现侦察逻辑
	// 包括端口扫描、服务识别、目录枚举等

	return nil
}

// executeVulnerabilityScan 执行漏洞扫描阶段
func (w *WorkflowEngine) executeVulnerabilityScan(config WorkflowConfig) error {
	utils.InfoPrint("正在执行漏洞扫描阶段")

	// 实现漏洞扫描逻辑
	// 使用AI驱动的漏洞检测

	return nil
}

// executeExploitation 执行漏洞利用阶段
func (w *WorkflowEngine) executeExploitation(config WorkflowConfig) error {
	utils.InfoPrint("正在执行漏洞利用阶段")

	// 实现漏洞利用逻辑
	// 基于风险级别和配置决定攻击强度

	return nil
}

// executePostExploitation 执行后渗透阶段
func (w *WorkflowEngine) executePostExploitation(config WorkflowConfig) error {
	utils.InfoPrint("正在执行后渗透阶段")

	// 实现后渗透逻辑
	// 包括权限提升、横向移动等

	return nil
}

// executeReporting 执行报告生成阶段
func (w *WorkflowEngine) executeReporting(config WorkflowConfig) error {
	utils.InfoPrint("正在执行报告生成阶段")

	// 生成详细的渗透测试报告

	return nil
}

// executeCustomPhase 执行自定义阶段
func (w *WorkflowEngine) executeCustomPhase(phase WorkflowPhase, config WorkflowConfig) error {
	utils.InfoPrint("正在执行自定义阶段: %s", phase)

	// 实现自定义阶段逻辑

	return nil
}

// updatePhaseStatus 更新阶段状态
func (w *WorkflowEngine) updatePhaseStatus(phase WorkflowPhase, status PhaseStatus) {
	w.State.PhaseStatus[phase] = status
	w.State.LastUpdateTime = time.Now()
}

// updateProgress 更新进度
func (w *WorkflowEngine) updateProgress() {
	totalPhases := len(w.State.PhaseStatus)
	completedPhases := 0

	for _, status := range w.State.PhaseStatus {
		if status == StatusCompleted {
			completedPhases++
		}
	}

	w.Progress.TotalProgress = float64(completedPhases) / float64(totalPhases) * 100
}

// Cancel 取消工作流执行
func (w *WorkflowEngine) Cancel() {
	if w.CancelFunc != nil {
		w.CancelFunc()
	}
}

// GetStatus 获取工作流状态
func (w *WorkflowEngine) GetStatus() *WorkflowState {
	return w.State
}

// GetProgress 获取工作流进度
func (w *WorkflowEngine) GetProgress() *WorkflowProgress {
	return w.Progress
}
