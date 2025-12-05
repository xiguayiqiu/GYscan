package ai

import (
	"context"
	"strings"

	"GYscan/internal/ai/types"
	"GYscan/internal/utils"

	"github.com/looplab/fsm"
)

// PenetrationStateMachine 定义渗透测试状态机
type PenetrationStateMachine struct {
	FSM                         *fsm.FSM
	Target                      string
	ToolManager                 *ToolManager
	ScanResult                  string
	InformationGatheringResults map[string]string
	Findings                    []types.Finding
}

// NewPenetrationStateMachine 创建新的渗透测试状态机
func NewPenetrationStateMachine(target string, toolManager *ToolManager) *PenetrationStateMachine {
	psm := &PenetrationStateMachine{
		Target:                      target,
		ToolManager:                 toolManager,
		InformationGatheringResults: make(map[string]string),
		Findings:                    []types.Finding{},
	}

	// 初始化状态机
	psm.FSM = fsm.NewFSM(
		"init",
		fsm.Events{
			{
				Name: "start",
				Src:  []string{"init"},
				Dst:  "reconnaissance",
			},
			{
				Name: "recon_complete",
				Src:  []string{"reconnaissance"},
				Dst:  "vulnerability_scan",
			},
			{
				Name: "vuln_scan_complete",
				Src:  []string{"vulnerability_scan"},
				Dst:  "exploitation",
			},
			{
				Name: "exploit_complete",
				Src:  []string{"exploitation"},
				Dst:  "lateral_movement",
			},
			{
				Name: "lateral_complete",
				Src:  []string{"lateral_movement"},
				Dst:  "reporting",
			},
			{
				Name: "report_complete",
				Src:  []string{"reporting"},
				Dst:  "done",
			},
			{
				Name: "failed",
				Src:  []string{"reconnaissance", "vulnerability_scan", "exploitation", "lateral_movement", "reporting"},
				Dst:  "failed",
			},
		},
		fsm.Callbacks{
			"enter_state": func(ctx context.Context, e *fsm.Event) {
				utils.InfoPrint("状态转换: %s -> %s", e.Src, e.Dst)
			},
			"enter_reconnaissance": func(ctx context.Context, e *fsm.Event) {
				utils.InfoPrint("=== 开始信息收集阶段 ===")
				// 自动执行信息收集
				if psm.ToolManager != nil {
					results, err := PerformInformationGathering(psm.Target, psm.ToolManager)
					if err != nil {
						utils.ErrorPrint("信息收集失败: %v", err)
						psm.FSM.Event(context.Background(), "failed")
						return
					}
					psm.InformationGatheringResults = results
					// 自动转换到漏洞扫描阶段
					psm.FSM.Event(context.Background(), "recon_complete")
				}
			},
			"enter_vulnerability_scan": func(ctx context.Context, e *fsm.Event) {
				utils.InfoPrint("=== 开始漏洞扫描阶段 ===")
			},
			"enter_exploitation": func(ctx context.Context, e *fsm.Event) {
				utils.InfoPrint("=== 开始漏洞利用阶段 ===")
			},
			"enter_lateral_movement": func(ctx context.Context, e *fsm.Event) {
				utils.InfoPrint("=== 开始横向移动阶段 ===")
			},
			"enter_reporting": func(ctx context.Context, e *fsm.Event) {
				utils.InfoPrint("=== 开始报告生成阶段 ===")
			},
			"enter_done": func(ctx context.Context, e *fsm.Event) {
				utils.SuccessPrint("=== 渗透测试完成 ===")
			},
			"enter_failed": func(ctx context.Context, e *fsm.Event) {
				utils.ErrorPrint("=== 渗透测试失败 ===")
			},
		},
	)

	return psm
}

// Start 开始渗透测试
func (psm *PenetrationStateMachine) Start() error {
	return psm.FSM.Event(context.Background(), "start")
}

// ReconComplete 目标探测完成
func (psm *PenetrationStateMachine) ReconComplete(scanResult string) error {
	psm.ScanResult = scanResult
	return psm.FSM.Event(context.Background(), "recon_complete")
}

// SetInformationGatheringResults 设置信息收集结果
func (psm *PenetrationStateMachine) SetInformationGatheringResults(results map[string]string) {
	psm.InformationGatheringResults = results
}

// GetInformationGatheringResults 获取信息收集结果
func (psm *PenetrationStateMachine) GetInformationGatheringResults() map[string]string {
	return psm.InformationGatheringResults
}

// VulnScanComplete 漏洞扫描完成
func (psm *PenetrationStateMachine) VulnScanComplete(findings []types.Finding) error {
	psm.Findings = findings
	return psm.FSM.Event(context.Background(), "vuln_scan_complete")
}

// ExploitComplete 漏洞利用完成
func (psm *PenetrationStateMachine) ExploitComplete() error {
	return psm.FSM.Event(context.Background(), "exploit_complete")
}

// LateralComplete 横向移动完成
func (psm *PenetrationStateMachine) LateralComplete() error {
	return psm.FSM.Event(context.Background(), "lateral_complete")
}

// ReportComplete 报告生成完成
func (psm *PenetrationStateMachine) ReportComplete() error {
	return psm.FSM.Event(context.Background(), "report_complete")
}

// Failed 渗透测试失败
func (psm *PenetrationStateMachine) Failed() error {
	return psm.FSM.Event(context.Background(), "failed")
}

// CurrentState 获取当前状态
func (psm *PenetrationStateMachine) CurrentState() string {
	return psm.FSM.Current()
}

// IsDone 检查是否完成
func (psm *PenetrationStateMachine) IsDone() bool {
	return psm.FSM.Current() == "done"
}

// IsFailed 检查是否失败
func (psm *PenetrationStateMachine) IsFailed() bool {
	return psm.FSM.Current() == "failed"
}

// StateString 返回状态的友好名称
func (psm *PenetrationStateMachine) StateString() string {
	state := psm.FSM.Current()
	states := map[string]string{
		"init":               "初始化",
		"reconnaissance":     "目标探测",
		"vulnerability_scan": "漏洞扫描",
		"exploitation":       "漏洞利用",
		"lateral_movement":   "横向移动",
		"reporting":          "报告生成",
		"done":               "完成",
		"failed":             "失败",
	}

	if friendlyName, ok := states[state]; ok {
		return friendlyName
	}
	return strings.Title(state)
}
