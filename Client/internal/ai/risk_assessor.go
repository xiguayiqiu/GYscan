package ai

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// RiskAssessor 漏洞评估与风险分析系统
type RiskAssessor struct {
	AIClient *AIClient
	Config   config.AIConfig
}

// VulnerabilityAssessment 漏洞评估结果
type VulnerabilityAssessment struct {
	Vulnerability   types.Vulnerability `json:"vulnerability"`
	RiskScore       float64             `json:"risk_score"`
	ImpactScore     float64             `json:"impact_score"`
	LikelihoodScore float64             `json:"likelihood_score"`
	CVSSScore       float64             `json:"cvss_score"`
	RemediationCost string              `json:"remediation_cost"`
	BusinessImpact  string              `json:"business_impact"`
	Exploitability  string              `json:"exploitability"`
	Recommendations []string            `json:"recommendations"`
	Confidence      float64             `json:"confidence"`
}

// RiskMatrix 风险矩阵配置
type RiskMatrix struct {
	ImpactLevels     []string `json:"impact_levels"`
	LikelihoodLevels []string `json:"likelihood_levels"`
	RiskScores       [][]int  `json:"risk_scores"`
}

// NewRiskAssessor 创建新的风险分析器
func NewRiskAssessor(aiClient *AIClient, cfg config.AIConfig) *RiskAssessor {
	return &RiskAssessor{
		AIClient: aiClient,
		Config:   cfg,
	}
}

// AssessVulnerabilities 评估漏洞集合
func (ra *RiskAssessor) AssessVulnerabilities(vulnerabilities []types.Vulnerability, targetType types.TargetType, environment string) ([]VulnerabilityAssessment, *types.RiskAssessment, error) {
	utils.InfoPrint("开始评估 %d 个漏洞", len(vulnerabilities))

	var assessments []VulnerabilityAssessment

	// 评估每个漏洞
	for _, vuln := range vulnerabilities {
		assessment, err := ra.assessSingleVulnerability(vuln, targetType, environment)
		if err != nil {
			utils.WarningPrint("漏洞 %s 评估失败: %v", vuln.ID, err)
			continue
		}
		assessments = append(assessments, assessment)
	}

	// 按风险分数排序
	sort.Slice(assessments, func(i, j int) bool {
		return assessments[i].RiskScore > assessments[j].RiskScore
	})

	// 生成整体风险评估
	riskAssessment := ra.generateOverallRiskAssessment(assessments, targetType, environment)

	utils.SuccessPrint("漏洞评估完成 - 评估漏洞: %d, 整体风险: %s",
		len(assessments), riskAssessment.OverallRisk)

	return assessments, riskAssessment, nil
}

// assessSingleVulnerability 评估单个漏洞
func (ra *RiskAssessor) assessSingleVulnerability(vuln types.Vulnerability, targetType types.TargetType, environment string) (VulnerabilityAssessment, error) {
	assessment := VulnerabilityAssessment{
		Vulnerability: vuln,
		Confidence:    vuln.Confidence,
	}

	// 1. 计算影响分数
	impactScore, err := ra.calculateImpactScore(vuln, targetType, environment)
	if err != nil {
		return assessment, fmt.Errorf("计算影响分数失败: %v", err)
	}
	assessment.ImpactScore = impactScore

	// 2. 计算可能性分数
	likelihoodScore, err := ra.calculateLikelihoodScore(vuln, targetType, environment)
	if err != nil {
		return assessment, fmt.Errorf("计算可能性分数失败: %v", err)
	}
	assessment.LikelihoodScore = likelihoodScore

	// 3. 计算CVSS分数
	cvssScore, err := ra.calculateCVSSScore(vuln)
	if err != nil {
		return assessment, fmt.Errorf("计算CVSS分数失败: %v", err)
	}
	assessment.CVSSScore = cvssScore

	// 4. 计算风险分数
	assessment.RiskScore = ra.calculateRiskScore(impactScore, likelihoodScore, cvssScore)

	// 5. 评估修复成本
	assessment.RemediationCost = ra.estimateRemediationCost(vuln, targetType)

	// 6. 评估业务影响
	assessment.BusinessImpact = ra.assessBusinessImpact(vuln, targetType)

	// 7. 评估可利用性
	assessment.Exploitability = ra.assessExploitability(vuln)

	// 8. 生成修复建议
	assessment.Recommendations = ra.generateRemediationRecommendations(vuln, targetType)

	return assessment, nil
}

// calculateImpactScore 计算影响分数
func (ra *RiskAssessor) calculateImpactScore(vuln types.Vulnerability, targetType types.TargetType, environment string) (float64, error) {
	baseScore := 0.0

	// 基于严重性计算基础分数
	switch vuln.Severity {
	case "critical":
		baseScore = 9.0
	case "high":
		baseScore = 7.0
	case "medium":
		baseScore = 5.0
	case "low":
		baseScore = 3.0
	default:
		baseScore = 1.0
	}

	// 基于目标类型调整分数
	targetMultiplier := ra.getTargetTypeMultiplier(targetType)

	// 基于环境调整分数
	environmentMultiplier := ra.getEnvironmentMultiplier(environment)

	// 基于漏洞特征调整分数
	vulnMultiplier := ra.getVulnerabilityMultiplier(vuln)

	impactScore := baseScore * targetMultiplier * environmentMultiplier * vulnMultiplier

	// 确保分数在1-10之间
	if impactScore > 10.0 {
		impactScore = 10.0
	} else if impactScore < 1.0 {
		impactScore = 1.0
	}

	return impactScore, nil
}

// calculateLikelihoodScore 计算可能性分数
func (ra *RiskAssessor) calculateLikelihoodScore(vuln types.Vulnerability, targetType types.TargetType, environment string) (float64, error) {
	baseScore := 0.0

	// 基于漏洞类型和特征计算基础分数
	if strings.Contains(strings.ToLower(vuln.Name), "sql") ||
		strings.Contains(strings.ToLower(vuln.Name), "xss") ||
		strings.Contains(strings.ToLower(vuln.Name), "csrf") {
		baseScore = 8.0 // 常见Web漏洞
	} else if strings.Contains(strings.ToLower(vuln.Name), "buffer") ||
		strings.Contains(strings.ToLower(vuln.Name), "overflow") {
		baseScore = 6.0 // 内存相关漏洞
	} else if strings.Contains(strings.ToLower(vuln.Name), "auth") ||
		strings.Contains(strings.ToLower(vuln.Name), "认证") {
		baseScore = 7.0 // 认证相关漏洞
	} else {
		baseScore = 5.0 // 其他漏洞
	}

	// 基于置信度调整分数
	confidenceMultiplier := vuln.Confidence

	// 基于目标暴露程度调整分数
	exposureMultiplier := ra.getExposureMultiplier(targetType, environment)

	likelihoodScore := baseScore * confidenceMultiplier * exposureMultiplier

	// 确保分数在1-10之间
	if likelihoodScore > 10.0 {
		likelihoodScore = 10.0
	} else if likelihoodScore < 1.0 {
		likelihoodScore = 1.0
	}

	return likelihoodScore, nil
}

// calculateCVSSScore 计算CVSS分数
func (ra *RiskAssessor) calculateCVSSScore(vuln types.Vulnerability) (float64, error) {
	// 简化的CVSS分数计算
	// 实际实现中应该使用完整的CVSS计算器

	baseScore := 0.0

	// 基于严重性估算CVSS分数
	switch vuln.Severity {
	case "critical":
		baseScore = 9.0 - 10.0
	case "high":
		baseScore = 7.0 - 8.9
	case "medium":
		baseScore = 4.0 - 6.9
	case "low":
		baseScore = 0.1 - 3.9
	default:
		baseScore = 0.0
	}

	// 添加随机波动以模拟真实CVSS计算
	// 在实际系统中应该使用更精确的计算方法
	cvssScore := baseScore + (vuln.Confidence * 0.5)

	if cvssScore > 10.0 {
		cvssScore = 10.0
	} else if cvssScore < 0.0 {
		cvssScore = 0.0
	}

	return cvssScore, nil
}

// calculateRiskScore 计算风险分数
func (ra *RiskAssessor) calculateRiskScore(impact, likelihood, cvss float64) float64 {
	// 使用加权平均计算风险分数
	riskScore := (impact * 0.4) + (likelihood * 0.3) + (cvss * 0.3)

	// 确保分数在0-10之间
	if riskScore > 10.0 {
		riskScore = 10.0
	} else if riskScore < 0.0 {
		riskScore = 0.0
	}

	return riskScore
}

// estimateRemediationCost 评估修复成本
func (ra *RiskAssessor) estimateRemediationCost(vuln types.Vulnerability, targetType types.TargetType) string {
	// 基于漏洞严重性和目标类型评估修复成本

	switch vuln.Severity {
	case "critical", "high":
		if targetType == types.TargetTypeWebApp || targetType == types.TargetTypeAPI {
			return "高 (需要立即修复，可能涉及代码重构)"
		} else {
			return "中高 (需要系统级修复)"
		}
	case "medium":
		return "中 (需要计划性修复)"
	case "low":
		return "低 (可以批量修复)"
	default:
		return "未知"
	}
}

// assessBusinessImpact 评估业务影响
func (ra *RiskAssessor) assessBusinessImpact(vuln types.Vulnerability, targetType types.TargetType) string {
	// 基于漏洞类型和目标类型评估业务影响

	if strings.Contains(strings.ToLower(vuln.Name), "data") ||
		strings.Contains(strings.ToLower(vuln.Name), "信息") {
		return "高 (可能导致数据泄露)"
	} else if strings.Contains(strings.ToLower(vuln.Name), "auth") ||
		strings.Contains(strings.ToLower(vuln.Name), "认证") {
		return "中高 (可能导致未授权访问)"
	} else if strings.Contains(strings.ToLower(vuln.Name), "dos") ||
		strings.Contains(strings.ToLower(vuln.Name), "拒绝服务") {
		return "中 (可能导致服务中断)"
	} else {
		return "低 (影响有限)"
	}
}

// assessExploitability 评估可利用性
func (ra *RiskAssessor) assessExploitability(vuln types.Vulnerability) string {
	// 基于漏洞特征评估可利用性

	if strings.Contains(strings.ToLower(vuln.Name), "remote") ||
		strings.Contains(strings.ToLower(vuln.Name), "远程") {
		return "高 (可远程利用)"
	} else if strings.Contains(strings.ToLower(vuln.Name), "local") ||
		strings.Contains(strings.ToLower(vuln.Name), "本地") {
		return "中 (需要本地访问权限)"
	} else if strings.Contains(strings.ToLower(vuln.Name), "physical") ||
		strings.Contains(strings.ToLower(vuln.Name), "物理") {
		return "低 (需要物理访问)"
	} else {
		return "未知"
	}
}

// generateRemediationRecommendations 生成修复建议
func (ra *RiskAssessor) generateRemediationRecommendations(vuln types.Vulnerability, targetType types.TargetType) []string {
	recommendations := []string{}

	// 通用修复建议
	recommendations = append(recommendations,
		"及时更新系统和应用程序",
		"实施安全编码最佳实践",
		"加强输入验证和输出编码",
	)

	// 基于漏洞类型的特定建议
	if strings.Contains(strings.ToLower(vuln.Name), "sql") {
		recommendations = append(recommendations,
			"使用参数化查询或预编译语句",
			"实施最小权限原则",
			"使用Web应用防火墙",
		)
	} else if strings.Contains(strings.ToLower(vuln.Name), "xss") {
		recommendations = append(recommendations,
			"实施内容安全策略(CSP)",
			"对所有用户输入进行适当的编码",
			"使用安全的HTML模板引擎",
		)
	} else if strings.Contains(strings.ToLower(vuln.Name), "csrf") {
		recommendations = append(recommendations,
			"实施CSRF令牌验证",
			"检查Referer头",
			"使用SameSite Cookie属性",
		)
	}

	// 基于目标类型的建议
	switch targetType {
	case types.TargetTypeWebApp:
		recommendations = append(recommendations,
			"实施Web应用安全扫描",
			"加强会话管理安全性",
			"配置适当的安全头",
		)
	case types.TargetTypeAPI:
		recommendations = append(recommendations,
			"实施API安全测试",
			"加强认证和授权机制",
			"实施API速率限制",
		)
	case types.TargetTypeNetwork:
		recommendations = append(recommendations,
			"加强网络访问控制",
			"实施网络分段",
			"加强防火墙配置",
		)
	}

	return recommendations
}

// generateOverallRiskAssessment 生成整体风险评估
func (ra *RiskAssessor) generateOverallRiskAssessment(assessments []VulnerabilityAssessment, targetType types.TargetType, environment string) *types.RiskAssessment {
	riskAssessment := &types.RiskAssessment{
		ID:          fmt.Sprintf("risk-%s-%d", targetType, time.Now().Unix()),
		OverallRisk: string(types.RiskLevelLow),
		CreatedAt:   time.Now(),
	}

	// 计算平均风险分数
	totalRiskScore := 0.0
	highRiskCount := 0
	mediumRiskCount := 0
	lowRiskCount := 0

	for _, assessment := range assessments {
		totalRiskScore += assessment.RiskScore

		if assessment.RiskScore >= 7.0 {
			highRiskCount++
		} else if assessment.RiskScore >= 4.0 {
			mediumRiskCount++
		} else {
			lowRiskCount++
		}
	}

	averageRiskScore := 0.0
	if len(assessments) > 0 {
		averageRiskScore = totalRiskScore / float64(len(assessments))
	}

	// 确定整体风险级别
	if averageRiskScore >= 7.0 || highRiskCount > 0 {
		riskAssessment.OverallRisk = string(types.RiskLevelHigh)
	} else if averageRiskScore >= 4.0 || mediumRiskCount > 0 {
		riskAssessment.OverallRisk = string(types.RiskLevelMedium)
	} else {
		riskAssessment.OverallRisk = string(types.RiskLevelLow)
	}

	// 设置风险评分和发现数量
	riskAssessment.RiskScore = averageRiskScore
	riskAssessment.CriticalFindings = 0 // 暂时设为0，需要根据实际漏洞严重程度计算
	riskAssessment.HighFindings = highRiskCount
	riskAssessment.MediumFindings = mediumRiskCount
	riskAssessment.LowFindings = lowRiskCount

	riskAssessment.Recommendations = ra.generateOverallRecommendations(assessments, targetType, environment)

	return riskAssessment
}

// generateOverallRecommendations 生成整体建议
func (ra *RiskAssessor) generateOverallRecommendations(assessments []VulnerabilityAssessment, targetType types.TargetType, environment string) []string {
	recommendations := []string{}

	// 基于风险级别生成建议
	highRiskCount := 0
	for _, assessment := range assessments {
		if assessment.RiskScore >= 7.0 {
			highRiskCount++
		}
	}

	if highRiskCount > 0 {
		recommendations = append(recommendations,
			"立即修复所有高危漏洞",
			"加强安全监控和应急响应",
			"考虑进行深度安全评估",
		)
	}

	if len(assessments) > 0 {
		recommendations = append(recommendations,
			"制定全面的漏洞修复计划",
			"加强安全开发流程",
			"定期进行安全培训和意识提升",
		)
	}

	// 基于环境生成建议
	if environment == "production" {
		recommendations = append(recommendations,
			"加强生产环境的安全监控",
			"实施严格的变更管理流程",
			"定期进行安全审计",
		)
	}

	return recommendations
}

// 辅助函数

// getTargetTypeMultiplier 获取目标类型乘数
func (ra *RiskAssessor) getTargetTypeMultiplier(targetType types.TargetType) float64 {
	switch targetType {
	case types.TargetTypeWebApp, types.TargetTypeAPI:
		return 1.2 // Web应用和API风险较高
	case types.TargetTypeIoT:
		return 1.3 // IoT设备风险高
	case types.TargetTypeCloud:
		return 1.1 // 云服务风险中等
	case types.TargetTypeNetwork:
		return 1.0 // 网络服务风险基础
	case types.TargetTypeMobile:
		return 0.9 // 移动应用风险相对较低
	default:
		return 1.0
	}
}

// getEnvironmentMultiplier 获取环境乘数
func (ra *RiskAssessor) getEnvironmentMultiplier(environment string) float64 {
	switch environment {
	case "production":
		return 1.3 // 生产环境风险高
	case "staging":
		return 1.1 // 预发布环境风险中等
	case "development", "testing":
		return 0.8 // 开发和测试环境风险较低
	default:
		return 1.0
	}
}

// getVulnerabilityMultiplier 获取漏洞特征乘数
func (ra *RiskAssessor) getVulnerabilityMultiplier(vuln types.Vulnerability) float64 {
	multiplier := 1.0

	// 基于漏洞特征调整乘数
	if strings.Contains(strings.ToLower(vuln.Name), "remote") {
		multiplier *= 1.3 // 远程漏洞风险更高
	}

	if strings.Contains(strings.ToLower(vuln.Name), "privilege") ||
		strings.Contains(strings.ToLower(vuln.Name), "权限") {
		multiplier *= 1.2 // 权限相关漏洞风险较高
	}

	return multiplier
}

// getExposureMultiplier 获取暴露程度乘数
func (ra *RiskAssessor) getExposureMultiplier(targetType types.TargetType, environment string) float64 {
	multiplier := 1.0

	// 基于目标类型调整暴露程度
	switch targetType {
	case types.TargetTypeWebApp, types.TargetTypeAPI:
		multiplier *= 1.2 // 面向互联网的服务暴露程度高
	case types.TargetTypeCloud:
		multiplier *= 1.1 // 云服务暴露程度中等
	case types.TargetTypeNetwork, types.TargetTypeIoT:
		multiplier *= 1.0 // 内部网络设备暴露程度较低
	}

	// 基于环境调整暴露程度
	if environment == "production" {
		multiplier *= 1.3 // 生产环境暴露程度高
	}

	return multiplier
}

// GetRiskLevel 根据风险分数获取风险级别
func (ra *RiskAssessor) GetRiskLevel(riskScore float64) types.RiskLevel {
	if riskScore >= 7.0 {
		return types.RiskLevelHigh
	} else if riskScore >= 4.0 {
		return types.RiskLevelMedium
	} else {
		return types.RiskLevelLow
	}
}

// FormatRiskScore 格式化风险分数
func (ra *RiskAssessor) FormatRiskScore(score float64) string {
	return fmt.Sprintf("%.2f/10.0", score)
}
