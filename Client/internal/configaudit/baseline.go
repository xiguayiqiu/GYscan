package configaudit

import (
	"fmt"
	"time"
)

type SecurityBaseline struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Version     string             `json:"version"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	Profile     BaselineProfile    `json:"profile"`
	Rules       []BaselineRule     `json:"rules"`
	Categories  []BaselineCategory `json:"categories"`
}

type BaselineProfile string

const (
	ProfileEnterprise   BaselineProfile = "enterprise"
	ProfileHighSecurity BaselineProfile = "high_security"
	ProfilePCIDSS       BaselineProfile = "pci_dss"
	ProfileHIPAA        BaselineProfile = "hipaa"
	ProfileCustom       BaselineProfile = "custom"
)

type BaselineCategory struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Rules       []BaselineRule `json:"rules"`
	Weight      float64        `json:"weight"`
}

type BaselineRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Severity    Severity          `json:"severity"`
	Condition   BaselineCondition `json:"condition"`
	Remediation string            `json:"remediation"`
	Reference   string            `json:"reference"`
	Enabled     bool              `json:"enabled"`
}

type BaselineCondition struct {
	Type      string        `json:"type"`
	Parameter string        `json:"parameter"`
	Operator  string        `json:"operator"`
	Value     interface{}   `json:"value"`
	Values    []interface{} `json:"values"`
	Logic     string        `json:"logic"`
}

type BaselineManager struct {
	baselines map[string]*SecurityBaseline
	active    *SecurityBaseline
}

func NewBaselineManager() *BaselineManager {
	return &BaselineManager{
		baselines: make(map[string]*SecurityBaseline),
	}
}

func (bm *BaselineManager) RegisterBaseline(baseline *SecurityBaseline) {
	bm.baselines[baseline.Name] = baseline
}

func (bm *BaselineManager) SetActiveBaseline(name string) error {
	baseline, exists := bm.baselines[name]
	if !exists {
		return &BaselineNotFoundError{Name: name}
	}
	bm.active = baseline
	return nil
}

func (bm *BaselineManager) GetActiveBaseline() *SecurityBaseline {
	return bm.active
}

func (bm *BaselineManager) GetBaseline(name string) (*SecurityBaseline, error) {
	baseline, exists := bm.baselines[name]
	if !exists {
		return nil, &BaselineNotFoundError{Name: name}
	}
	return baseline, nil
}

func (bm *BaselineManager) CreateCustomBaseline(name string, description string) *SecurityBaseline {
	baseline := &SecurityBaseline{
		Name:        name,
		Description: description,
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Profile:     ProfileCustom,
		Rules:       []BaselineRule{},
		Categories:  []BaselineCategory{},
	}
	bm.baselines[name] = baseline
	return baseline
}

func (bm *BaselineManager) AddRule(baselineName string, rule BaselineRule) error {
	baseline, err := bm.GetBaseline(baselineName)
	if err != nil {
		return err
	}
	rule.Enabled = true
	baseline.Rules = append(baseline.Rules, rule)
	baseline.UpdatedAt = time.Now()
	return nil
}

func (bm *BaselineManager) RemoveRule(baselineName string, ruleID string) error {
	baseline, err := bm.GetBaseline(baselineName)
	if err != nil {
		return err
	}
	for i, rule := range baseline.Rules {
		if rule.ID == ruleID {
			baseline.Rules = append(baseline.Rules[:i], baseline.Rules[i+1:]...)
			baseline.UpdatedAt = time.Now()
			return nil
		}
	}
	return &RuleNotFoundError{RuleID: ruleID}
}

func (bm *BaselineManager) ExportBaseline(name string) (string, error) {
	baseline, err := bm.GetBaseline(name)
	if err != nil {
		return "", err
	}
	return SerializeBaseline(baseline), nil
}

type BaselineNotFoundError struct {
	Name string
}

func (e *BaselineNotFoundError) Error() string {
	return "未找到安全基线: " + e.Name
}

type RuleNotFoundError struct {
	RuleID string
}

func (e *RuleNotFoundError) Error() string {
	return "未找到规则: " + e.RuleID
}

func SerializeBaseline(baseline *SecurityBaseline) string {
	result := ""
	result += fmt.Sprintf("# 安全基线: %s\n", baseline.Name)
	result += fmt.Sprintf("# 描述: %s\n", baseline.Description)
	result += fmt.Sprintf("# 版本: %s\n", baseline.Version)
	result += fmt.Sprintf("# 规则数量: %d\n\n", len(baseline.Rules))

	for _, rule := range baseline.Rules {
		result += fmt.Sprintf("[%s]\n", rule.ID)
		result += fmt.Sprintf("名称: %s\n", rule.Name)
		result += fmt.Sprintf("描述: %s\n", rule.Description)
		result += fmt.Sprintf("类别: %s\n", rule.Category)
		result += fmt.Sprintf("严重程度: %s\n", rule.Severity)
		result += fmt.Sprintf("参考: %s\n", rule.Reference)
		result += fmt.Sprintf("修复建议: %s\n\n", rule.Remediation)
	}

	return result
}

func LoadDefaultBaselines() *BaselineManager {
	bm := NewBaselineManager()

	enterpriseBaseline := &SecurityBaseline{
		Name:        "enterprise",
		Description: "企业级安全基线 - 平衡安全性和可用性",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Profile:     ProfileEnterprise,
		Rules:       []BaselineRule{},
		Categories:  []BaselineCategory{},
	}

	highSecurityBaseline := &SecurityBaseline{
		Name:        "high_security",
		Description: "高安全环境基线 - 适用于敏感系统",
		Version:     "1.0.0",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Profile:     ProfileHighSecurity,
		Rules:       []BaselineRule{},
		Categories:  []BaselineCategory{},
	}

	bm.baselines["enterprise"] = enterpriseBaseline
	bm.baselines["high_security"] = highSecurityBaseline

	return bm
}
