package security

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// RiskLevel 风险等级
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// String 风险等级字符串表示
func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "低风险"
	case RiskMedium:
		return "中风险"
	case RiskHigh:
		return "高风险"
	case RiskCritical:
		return "严重风险"
	default:
		return "未知风险"
	}
}

// RiskFactor 风险因素
type RiskFactor struct {
	Name        string  `json:"name"`        // 风险因素名称
	Description string  `json:"description"` // 风险描述
	Weight      float64 `json:"weight"`      // 权重 (0-1)
	Score       float64 `json:"score"`       // 评分 (0-1)
}

// RiskAssessment 风险评估
type RiskAssessment struct {
	// 风险因素
	Factors []RiskFactor `json:"factors"`

	// 配置参数
	LowThreshold    float64 `json:"low_threshold"`    // 低风险阈值
	MediumThreshold float64 `json:"medium_threshold"` // 中风险阈值
	HighThreshold   float64 `json:"high_threshold"`   // 高风险阈值
}

// NewRiskAssessment 创建风险评估实例
func NewRiskAssessment() *RiskAssessment {
	return &RiskAssessment{
		Factors: []RiskFactor{
			{
				Name:        "网络暴露度",
				Description: "目标系统在网络中的暴露程度",
				Weight:      0.15,
				Score:       0.0,
			},
			{
				Name:        "系统重要性",
				Description: "目标系统在业务中的重要性",
				Weight:      0.20,
				Score:       0.0,
			},
			{
				Name:        "安全防护",
				Description: "目标系统的安全防护水平",
				Weight:      0.15,
				Score:       0.0,
			},
			{
				Name:        "操作影响",
				Description: "操作对目标系统的影响程度",
				Weight:      0.25,
				Score:       0.0,
			},
			{
				Name:        "法律合规",
				Description: "操作的法律合规性风险",
				Weight:      0.15,
				Score:       0.0,
			},
			{
				Name:        "时间因素",
				Description: "操作时间对风险的影响",
				Weight:      0.10,
				Score:       0.0,
			},
		},
		LowThreshold:    0.3,
		MediumThreshold: 0.6,
		HighThreshold:   0.8,
	}
}

// AssessNetworkExposure 评估网络暴露度
func (r *RiskAssessment) AssessNetworkExposure(isPublic bool, openPorts int, services []string) float64 {
	score := 0.0

	// 公网暴露
	if isPublic {
		score += 0.4
	}

	// 开放端口数量
	if openPorts > 10 {
		score += 0.3
	} else if openPorts > 5 {
		score += 0.2
	} else if openPorts > 0 {
		score += 0.1
	}

	// 高风险服务
	highRiskServices := []string{"ssh", "rdp", "telnet", "ftp", "smb"}
	for _, service := range services {
		for _, hrService := range highRiskServices {
			if strings.Contains(strings.ToLower(service), hrService) {
				score += 0.3
				break
			}
		}
	}

	// 限制在0-1范围内
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// AssessSystemImportance 评估系统重要性
func (r *RiskAssessment) AssessSystemImportance(isCritical bool, userCount int, dataSensitivity string) float64 {
	score := 0.0

	// 关键系统
	if isCritical {
		score += 0.5
	}

	// 用户数量
	if userCount > 1000 {
		score += 0.3
	} else if userCount > 100 {
		score += 0.2
	} else if userCount > 10 {
		score += 0.1
	}

	// 数据敏感性
	switch strings.ToLower(dataSensitivity) {
	case "high":
		score += 0.2
	case "medium":
		score += 0.1
	case "low":
		// 不加分
	}

	return score
}

// AssessSecurityProtection 评估安全防护
func (r *RiskAssessment) AssessSecurityProtection(hasFirewall bool, hasAV bool, hasEDR bool, patchLevel string) float64 {
	score := 0.0

	// 防护措施缺失会增加风险
	if !hasFirewall {
		score += 0.3
	}

	if !hasAV {
		score += 0.2
	}

	if !hasEDR {
		score += 0.2
	}

	// 补丁级别
	switch strings.ToLower(patchLevel) {
	case "outdated":
		score += 0.3
	case "some":
		score += 0.1
	case "current":
		// 不加分
	}

	return score
}

// AssessOperationImpact 评估操作影响
func (r *RiskAssessment) AssessOperationImpact(operationType string, isDestructive bool, downtime int) float64 {
	score := 0.0

	// 操作类型
	switch strings.ToLower(operationType) {
	case "reconnaissance":
		score += 0.1
	case "lateral":
		score += 0.3
	case "privilege":
		score += 0.5
	case "persistence":
		score += 0.7
	}

	// 破坏性操作
	if isDestructive {
		score += 0.3
	}

	// 停机时间
	if downtime > 60 {
		score += 0.2
	} else if downtime > 10 {
		score += 0.1
	}

	return score
}

// AssessLegalCompliance 评估法律合规
func (r *RiskAssessment) AssessLegalCompliance(isAuthorized bool, jurisdiction string, dataClassification string) float64 {
	score := 0.0

	// 授权状态
	if !isAuthorized {
		score += 0.6
	}

	// 管辖区域
	switch strings.ToLower(jurisdiction) {
	case "strict":
		score += 0.3
	case "moderate":
		score += 0.1
	case "lenient":
		// 不加分
	}

	// 数据分类
	switch strings.ToLower(dataClassification) {
	case "sensitive":
		score += 0.1
	case "confidential":
		score += 0.2
	case "secret":
		score += 0.3
	}

	return score
}

// AssessTimeFactor 评估时间因素
func (r *RiskAssessment) AssessTimeFactor(isBusinessHours bool, isHoliday bool, urgency string) float64 {
	score := 0.0

	// 业务时段
	if isBusinessHours {
		score += 0.4
	}

	// 节假日
	if isHoliday {
		score += 0.3
	}

	// 紧急程度
	switch strings.ToLower(urgency) {
	case "high":
		score += 0.3
	case "medium":
		score += 0.1
	case "low":
		// 不加分
	}

	return score
}

// CalculateOverallRisk 计算总体风险
func (r *RiskAssessment) CalculateOverallRisk() (float64, RiskLevel) {
	totalScore := 0.0
	totalWeight := 0.0

	for _, factor := range r.Factors {
		totalScore += factor.Score * factor.Weight
		totalWeight += factor.Weight
	}

	// 归一化到0-1范围
	if totalWeight > 0 {
		totalScore = totalScore / totalWeight
	}

	// 确定风险等级
	var level RiskLevel
	switch {
	case totalScore <= r.LowThreshold:
		level = RiskLow
	case totalScore <= r.MediumThreshold:
		level = RiskMedium
	case totalScore <= r.HighThreshold:
		level = RiskHigh
	default:
		level = RiskCritical
	}

	return totalScore, level
}

// GenerateRiskReport 生成风险评估报告
func (r *RiskAssessment) GenerateRiskReport() map[string]interface{} {
	totalScore, riskLevel := r.CalculateOverallRisk()

	report := make(map[string]interface{})
	report["overall_score"] = totalScore
	report["risk_level"] = riskLevel.String()
	report["risk_factors"] = r.Factors
	report["recommendation"] = r.GetRecommendation(riskLevel)

	return report
}

// GetRecommendation 获取风险建议
func (r *RiskAssessment) GetRecommendation(level RiskLevel) string {
	switch level {
	case RiskLow:
		return "风险较低，可以继续执行操作"
	case RiskMedium:
		return "中等风险，建议采取适当的规避措施"
	case RiskHigh:
		return "高风险，强烈建议采取规避措施，或重新评估操作必要性"
	case RiskCritical:
		return "严重风险，不建议执行操作，请重新评估授权和操作计划"
	default:
		return "未知风险等级，请谨慎操作"
	}
}

// UpdateFactorScore 更新风险因素评分
func (r *RiskAssessment) UpdateFactorScore(factorName string, score float64) error {
	for i := range r.Factors {
		if r.Factors[i].Name == factorName {
			if score < 0 || score > 1 {
				return fmt.Errorf("评分必须在0-1范围内")
			}
			r.Factors[i].Score = score
			logrus.Debugf("[GYscan-Risk] 更新风险因素 '%s' 评分: %.2f", factorName, score)
			return nil
		}
	}

	return fmt.Errorf("未找到风险因素: %s", factorName)
}

// ValidateConfiguration 验证配置有效性
func (r *RiskAssessment) ValidateConfiguration() error {
	// 验证阈值
	if r.LowThreshold <= 0 || r.LowThreshold >= 1 {
		return fmt.Errorf("低风险阈值必须在0-1范围内")
	}

	if r.MediumThreshold <= r.LowThreshold || r.MediumThreshold >= 1 {
		return fmt.Errorf("中风险阈值必须大于低风险阈值且小于1")
	}

	if r.HighThreshold <= r.MediumThreshold || r.HighThreshold >= 1 {
		return fmt.Errorf("高风险阈值必须大于中风险阈值且小于1")
	}

	// 验证权重总和
	totalWeight := 0.0
	for _, factor := range r.Factors {
		if factor.Weight < 0 || factor.Weight > 1 {
			return fmt.Errorf("风险因素权重必须在0-1范围内")
		}
		totalWeight += factor.Weight
	}

	if totalWeight > 1.0 {
		return fmt.Errorf("风险因素权重总和不能超过1")
	}

	return nil
}

// QuickAssessment 快速风险评估
func (r *RiskAssessment) QuickAssessment(target string, operation string) (float64, RiskLevel) {
	// 设置默认评分
	r.UpdateFactorScore("网络暴露度", 0.5)
	r.UpdateFactorScore("系统重要性", 0.3)
	r.UpdateFactorScore("安全防护", 0.4)
	r.UpdateFactorScore("操作影响", 0.6)
	r.UpdateFactorScore("法律合规", 0.2)
	r.UpdateFactorScore("时间因素", 0.3)

	logrus.Infof("[GYscan-Risk] 对目标 '%s' 执行操作 '%s' 进行快速风险评估", target, operation)

	return r.CalculateOverallRisk()
}
