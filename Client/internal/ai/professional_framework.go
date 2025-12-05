package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"
)

// ProfessionalPenetrationTest 专业渗透测试框架
type ProfessionalPenetrationTest struct {
	Target    string
	AIClient  *AIClient
	Logger    *PenetrationLogger
	Config    *config.AIConfig
	OutputDir string
}

// ExecuteFullWorkflow 执行完整的专业渗透测试工作流程
func (ppt *ProfessionalPenetrationTest) ExecuteFullWorkflow() (string, error) {
	var results strings.Builder
	results.WriteString("=== 专业渗透测试工作流程开始 ===\n")
	results.WriteString(fmt.Sprintf("目标: %s\n", ppt.Target))
	results.WriteString(fmt.Sprintf("开始时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))

	// 创建输出目录
	if err := os.MkdirAll(ppt.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 阶段1: 专业信息收集
	utils.InfoPrint("\n=== 阶段1: 专业信息收集 ===")
	recon := &ProfessionalReconnaissance{
		Target:   ppt.Target,
		AIClient: ppt.AIClient,
		Logger:   ppt.Logger,
	}
	reconResults, err := recon.ExecuteProfessionalReconnaissance()
	if err != nil {
		utils.ErrorPrint("专业信息收集失败: %v", err)
		results.WriteString("专业信息收集失败\n")
	} else {
		results.WriteString("\n=== 专业信息收集结果 ===\n")
		results.WriteString(reconResults)
		// 保存信息收集结果到文件
		reconFile := filepath.Join(ppt.OutputDir, "reconnaissance_results.txt")
		os.WriteFile(reconFile, []byte(reconResults), 0644)
	}

	// 阶段2: 专业漏洞评估
	utils.InfoPrint("\n=== 阶段2: 专业漏洞评估 ===")
	vuln := &ProfessionalVulnerabilityAssessment{
		Target:    ppt.Target,
		AIClient:  ppt.AIClient,
		Logger:    ppt.Logger,
		ReconData: reconResults,
	}
	vulnResults, err := vuln.ExecuteProfessionalVulnerabilityAssessment()
	if err != nil {
		utils.ErrorPrint("专业漏洞评估失败: %v", err)
		results.WriteString("专业漏洞评估失败\n")
	} else {
		results.WriteString("\n=== 专业漏洞评估结果 ===\n")
		results.WriteString(vulnResults)
		// 保存漏洞评估结果到文件
		vulnFile := filepath.Join(ppt.OutputDir, "vulnerability_results.txt")
		os.WriteFile(vulnFile, []byte(vulnResults), 0644)
	}

	// 阶段3: 专业横向移动
	utils.InfoPrint("\n=== 阶段3: 专业横向移动 ===")
	lateral := &ProfessionalLateralMovement{
		Target:      ppt.Target,
		AIClient:    ppt.AIClient,
		Logger:      ppt.Logger,
		Credentials: make(map[string]string),
	}
	lateralResults, err := lateral.ExecuteProfessionalLateralMovement()
	if err != nil {
		utils.ErrorPrint("专业横向移动失败: %v", err)
		results.WriteString("专业横向移动失败\n")
	} else {
		results.WriteString("\n=== 专业横向移动结果 ===\n")
		results.WriteString(lateralResults)
		// 保存横向移动结果到文件
		lateralFile := filepath.Join(ppt.OutputDir, "lateral_movement_results.txt")
		os.WriteFile(lateralFile, []byte(lateralResults), 0644)
	}

	// 阶段4: 专业报告生成
	utils.InfoPrint("\n=== 阶段4: 专业报告生成 ===")
	reportGen := &ProfessionalReportGenerator{
		Target:          ppt.Target,
		ReconResults:    reconResults,
		VulnResults:     vulnResults,
		LateralResults:  lateralResults,
		ReportOutputDir: filepath.Join(ppt.OutputDir, "reports"),
		Logger:          ppt.Logger,
	}
	reportResults, err := reportGen.GenerateProfessionalReport()
	if err != nil {
		utils.ErrorPrint("专业报告生成失败: %v", err)
		results.WriteString("专业报告生成失败\n")
	} else {
		results.WriteString("\n=== 专业报告生成结果 ===\n")
		results.WriteString(reportResults)
	}

	// 阶段5: 结果分析
	utils.InfoPrint("\n=== 阶段5: 结果分析 ===")
	analysisResults, err := reportGen.AnalyzeResults()
	if err != nil {
		utils.ErrorPrint("结果分析失败: %v", err)
		results.WriteString("结果分析失败\n")
	} else {
		results.WriteString("\n=== 结果分析 ===\n")
		results.WriteString(analysisResults)
		// 保存分析结果到文件
		analysisFile := filepath.Join(ppt.OutputDir, "analysis_results.txt")
		os.WriteFile(analysisFile, []byte(analysisResults), 0644)
	}

	results.WriteString("\n=== 专业渗透测试工作流程完成 ===\n")
	results.WriteString(fmt.Sprintf("结束时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))

	// 保存完整结果到文件
	fullResultsFile := filepath.Join(ppt.OutputDir, "full_penetration_results.txt")
	os.WriteFile(fullResultsFile, []byte(results.String()), 0644)

	utils.SuccessPrint("专业渗透测试完成！所有结果已保存到: %s", ppt.OutputDir)

	return results.String(), nil
}
