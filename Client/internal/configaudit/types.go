package configaudit

import (
	"fmt"
	"strings"
)

type AuditCategory string

const (
	CATEGORY_OS         AuditCategory = "os"
	CATEGORY_WEB        AuditCategory = "web"
	CATEGORY_SSH        AuditCategory = "ssh"
	CATEGORY_MIDDLEWARE AuditCategory = "middleware"
	CATEGORY_NETWORK   AuditCategory = "network"
)

type AuditType string

const (
	AuditTypeCompliance    AuditType = "compliance"
	AuditTypeSecurity      AuditType = "security"
	AuditTypeOperational   AuditType = "operational"
)

type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "critical"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelLow      RiskLevel = "low"
	RiskLevelInfo     RiskLevel = "info"
)

type CheckStatus string

const (
	CheckStatusPass    CheckStatus = "pass"
	CheckStatusFail    CheckStatus = "fail"
	CheckStatusWarning CheckStatus = "warning"
	CheckStatusError   CheckStatus = "error"
	CheckStatusNA      CheckStatus = "na"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type AuditCheck struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	Category       AuditCategory `json:"category"`
	AuditType      AuditType    `json:"audit_type"`
	Severity       Severity     `json:"severity"`
	BaselineRef    string       `json:"baseline_ref"`
	Reference      string       `json:"reference"`
	Remediation    string       `json:"remediation"`
	Impact         string       `json:"impact"`
	Execute        func(*AuditContext) *CheckResult `json:"-"`
}

type CheckResult struct {
	CheckID        string       `json:"check_id"`
	Status         CheckStatus  `json:"status"`
	ActualValue    interface{}  `json:"actual_value"`
	ExpectedValue  interface{}  `json:"expected_value"`
	Details        string       `json:"details"`
	Evidence       string       `json:"evidence"`
	RiskLevel      RiskLevel    `json:"risk_level"`
	Score          int          `json:"score"`
	ConfigFile     string       `json:"config_file"`
	ConfigKey      string       `json:"config_key"`
	ConfigSection  string       `json:"config_section"`
	RawValue       string       `json:"raw_value"`
}

type AuditContext struct {
	Target      string                 `json:"target"`
	Category    AuditCategory          `json:"category"`
	Config      map[string]interface{} `json:"config"`
	Credentials map[string]string      `json:"credentials"`
	Results     []*CheckResult         `json:"results"`
	Errors      []error                `json:"errors"`
}

func (r *RiskLevel) CalculateScore() int {
	switch *r {
	case RiskLevelCritical:
		return 100
	case RiskLevelHigh:
		return 75
	case RiskLevelMedium:
		return 50
	case RiskLevelLow:
		return 25
	default:
		return 0
	}
}

func (s *Severity) ToRiskLevel() RiskLevel {
	switch *s {
	case SeverityCritical:
		return RiskLevelCritical
	case SeverityHigh:
		return RiskLevelHigh
	case SeverityMedium:
		return RiskLevelMedium
	case SeverityLow:
		return RiskLevelLow
	default:
		return RiskLevelInfo
	}
}

func (c *AuditCheck) Run(ctx *AuditContext) *CheckResult {
	if c.Execute == nil {
		return &CheckResult{
			CheckID:   c.ID,
			Status:    CheckStatusError,
			Details:   "Check implementation missing",
			RiskLevel: RiskLevelMedium,
			Score:     50,
		}
	}
	return c.Execute(ctx)
}

type AuditReport struct {
	Target           string         `json:"target"`
	Timestamp        string         `json:"timestamp"`
	Duration         float64        `json:"duration"`
	Category         AuditCategory  `json:"category"`
	Summary          ReportSummary  `json:"summary"`
	Results          []*CheckResult `json:"results"`
	FailedChecks     []*CheckResult `json:"failed_checks"`
	PassedChecks     []*CheckResult `json:"passed_checks"`
	Warnings         []*CheckResult `json:"warnings"`
	RemediationPlan  []Remediation  `json:"remediation_plan"`
}

type ReportSummary struct {
	TotalChecks     int            `json:"total_checks"`
	PassedChecks    int            `json:"passed_checks"`
	FailedChecks    int            `json:"failed_checks"`
	WarningChecks   int            `json:"warning_checks"`
	ErrorChecks     int            `json:"error_checks"`
	OverallScore    float64        `json:"overall_score"`
	RiskLevel       RiskLevel      `json:"risk_level"`
	ComplianceRate  float64        `json:"compliance_rate"`
}

type Remediation struct {
	CheckID      string   `json:"check_id"`
	Priority     int      `json:"priority"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Steps        []string `json:"steps"`
	Commands     []string `json:"commands"`
	EstimatedTime string  `json:"estimated_time"`
	Risk         string   `json:"risk"`
}

func GenerateRemediation(result *CheckResult, check *AuditCheck) *Remediation {
	if result.Status == CheckStatusPass {
		return nil
	}

	steps := []string{}
	if len(check.Remediation) > 0 {
		steps = append(steps, check.Remediation)
	}

	return &Remediation{
		CheckID:      result.CheckID,
		Priority:     check.Severity.ToPriority(),
		Title:        fmt.Sprintf("修复: %s", check.Name),
		Description:  check.Description,
		Steps:        steps,
		EstimatedTime: "15-30分钟",
		Risk:         check.Impact,
	}
}

func (s *Severity) ToPriority() int {
	switch *s {
	case SeverityCritical:
		return 1
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 4
	default:
		return 5
	}
}

func CalculateOverallScore(results []*CheckResult) (float64, RiskLevel) {
	if len(results) == 0 {
		return 0, RiskLevelInfo
	}

	var totalScore float64
	var weightedScore float64
	weights := map[Severity]float64{
		SeverityCritical: 1.5,
		SeverityHigh:     1.2,
		SeverityMedium:   1.0,
		SeverityLow:      0.8,
		SeverityInfo:     0.5,
	}

	for _, r := range results {
		if r.Score == 0 {
			r.Score = r.RiskLevel.CalculateScore()
		}
		totalScore += float64(r.Score)

		severity := Severity(strings.ToLower(string(r.RiskLevel)))
		weight := weights[severity]
		if weight == 0 {
			weight = 1.0
		}
		weightedScore += float64(r.Score) * weight
	}

	avgScore := weightedScore / float64(len(results))
	return avgScore, ScoreToRiskLevel(avgScore)
}

func ScoreToRiskLevel(score float64) RiskLevel {
	if score >= 80 {
		return RiskLevelCritical
	} else if score >= 60 {
		return RiskLevelHigh
	} else if score >= 40 {
		return RiskLevelMedium
	} else if score >= 20 {
		return RiskLevelLow
	}
	return RiskLevelInfo
}

func (c *AuditCategory) String() string {
	return string(*c)
}
