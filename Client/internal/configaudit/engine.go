package configaudit

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type AuditEngine struct {
	checks     map[AuditCategory][]*AuditCheck
	collectors map[AuditCategory]DataCollector
	baselines  map[string]*SecurityBaseline
	config     *EngineConfig
	resultChan chan *CheckResult
	wg         sync.WaitGroup
	localMode  bool
}

type EngineConfig struct {
	Parallelism     int           `json:"parallelism"`
	Timeout         time.Duration `json:"timeout"`
	RetryCount      int           `json:"retry_count"`
	OutputFormat    string        `json:"output_format"`
	IncludeDetails  bool          `json:"include_details"`
	SkipPassed      bool          `json:"skip_passed"`
	BaselineProfile string        `json:"baseline_profile"`
	CustomRules     []CustomRule  `json:"custom_rules"`
	Baseline        string        `json:"baseline"`
	SkipPrivCheck   bool          `json:"skip_priv_check"`
	PrivMode        string        `json:"priv_mode"`
}

type CustomRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Category    AuditCategory          `json:"category"`
	Condition   string                 `json:"condition"`
	Parameters  map[string]interface{} `json:"parameters"`
	Severity    Severity               `json:"severity"`
	Remediation string                 `json:"remediation"`
}

type DataCollector interface {
	Collect(*CollectionRequest) (*CollectionResult, error)
	Name() string
	SupportedCategories() []AuditCategory
}

type CollectionRequest struct {
	Target      string
	Category    AuditCategory
	Config      map[string]interface{}
	Credentials map[string]string
	Timeout     time.Duration
}

type CollectionResult struct {
	Success  bool
	Data     map[string]interface{}
	Errors   []error
	Duration time.Duration
	Evidence []string
}

func NewAuditEngine(config *EngineConfig) *AuditEngine {
	if config == nil {
		config = &EngineConfig{
			Parallelism:    4,
			Timeout:        5 * time.Minute,
			RetryCount:     2,
			OutputFormat:   "text",
			IncludeDetails: true,
			SkipPassed:     false,
		}
	}

	if config.Parallelism <= 0 {
		config.Parallelism = 4
	}

	return &AuditEngine{
		checks:     make(map[AuditCategory][]*AuditCheck),
		collectors: make(map[AuditCategory]DataCollector),
		baselines:  make(map[string]*SecurityBaseline),
		config:     config,
		resultChan: make(chan *CheckResult, 1000),
	}
}

func (e *AuditEngine) RegisterCheck(check *AuditCheck) {
	e.checks[check.Category] = append(e.checks[check.Category], check)
}

func (e *AuditEngine) RegisterCollector(collector DataCollector) {
	for _, cat := range collector.SupportedCategories() {
		e.collectors[cat] = collector
	}
}

func (e *AuditEngine) RegisterBaseline(baseline *SecurityBaseline) {
	e.baselines[baseline.Name] = baseline
}

func (e *AuditEngine) SetLocalMode() {
	e.localMode = true
}

func (e *AuditEngine) RunAudit(target string, categories []AuditCategory, osType OSType) (*AuditReport, error) {
	startTime := time.Now()

	ctx := &AuditContext{
		Target:      target,
		OSType:      osType,
		Config:      make(map[string]interface{}),
		Credentials: make(map[string]string),
		Results:     []*CheckResult{},
		Errors:      []error{},
	}

	var results []*CheckResult
	var mu sync.Mutex

	if len(categories) == 0 {
		for cat := range e.checks {
			categories = append(categories, cat)
		}
	}

	semaphore := make(chan struct{}, e.config.Parallelism)

	var wg sync.WaitGroup
	wg.Add(len(categories))

	for _, category := range categories {
		go func(cat AuditCategory) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := e.runCategoryAudit(ctx, cat); err != nil {
				log.Printf("审计类别 %s 执行失败: %v", cat, err)
				mu.Lock()
				ctx.Errors = append(ctx.Errors, err)
				mu.Unlock()
			}
		}(category)
	}

	wg.Wait()

	for {
		select {
		case result := <-e.resultChan:
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		default:
			goto done
		}
	}

done:
	report := e.generateReport(target, results, startTime)
	return report, nil
}

func (e *AuditEngine) runCategoryAudit(ctx *AuditContext, category AuditCategory) error {
	checks, exists := e.checks[category]
	if !exists || len(checks) == 0 {
		return fmt.Errorf("未找到类别 %s 的审计检查项", category)
	}

	if collector, exists := e.collectors[category]; exists {
		req := &CollectionRequest{
			Target:   ctx.Target,
			Category: category,
			Config:   ctx.Config,
			Timeout:  e.config.Timeout,
		}

		result, err := collector.Collect(req)
		if err != nil {
			log.Printf("数据采集失败 (%s): %v", category, err)
		} else if result.Success {
			ctx.Mutex.Lock()
			for k, v := range result.Data {
				ctx.Config[k] = v
			}
			ctx.Mutex.Unlock()
		}
	}

	for _, check := range checks {
		if ctx.OSType != OSUnknown && check.OSType != OSUnknown && check.OSType != ctx.OSType {
			continue
		}

		select {
		case <-time.After(e.config.Timeout):
			e.resultChan <- &CheckResult{
				CheckID:   check.ID,
				Status:    CheckStatusError,
				Details:   "检查超时",
				RiskLevel: RiskLevelMedium,
				Score:     50,
			}
			continue
		default:
		}

		result := check.Run(ctx)
		e.resultChan <- result
	}

	return nil
}

func (e *AuditEngine) generateReport(target string, results []*CheckResult, startTime time.Time) *AuditReport {
	var passed, failed, warnings, errors int
	var failedChecks, passedChecks, warningChecks []*CheckResult

	for _, r := range results {
		switch r.Status {
		case CheckStatusPass:
			passed++
			passedChecks = append(passedChecks, r)
		case CheckStatusFail:
			failed++
			failedChecks = append(failedChecks, r)
		case CheckStatusWarning:
			warnings++
			warningChecks = append(warningChecks, r)
		case CheckStatusError:
			errors++
		}
	}

	total := len(results)
	complianceRate := 0.0
	if total > 0 {
		complianceRate = float64(passed) / float64(total) * 100
	}

	score, riskLevel := CalculateOverallScore(results)

	remediationPlan := e.generateRemediationPlan(failedChecks)

	summary := ReportSummary{
		TotalChecks:    total,
		PassedChecks:   passed,
		FailedChecks:   failed,
		WarningChecks:  warnings,
		ErrorChecks:    errors,
		OverallScore:   score,
		RiskLevel:      riskLevel,
		ComplianceRate: complianceRate,
	}

	return &AuditReport{
		Target:          target,
		Timestamp:       startTime.Format("2006-01-02 15:04:05"),
		Duration:        time.Since(startTime).Seconds(),
		Results:         results,
		Summary:         summary,
		FailedChecks:    failedChecks,
		PassedChecks:    passedChecks,
		Warnings:        warningChecks,
		RemediationPlan: remediationPlan,
	}
}

func (e *AuditEngine) generateRemediationPlan(failedChecks []*CheckResult) []Remediation {
	var plan []Remediation
	for _, result := range failedChecks {
		for _, checks := range e.checks {
			for _, check := range checks {
				if check.ID == result.CheckID {
					remediation := GenerateRemediation(result, check)
					if remediation != nil {
						plan = append(plan, *remediation)
					}
				}
			}
		}
	}
	return plan
}

func (e *AuditEngine) GetChecksByCategory(category AuditCategory) []*AuditCheck {
	return e.checks[category]
}

func (e *AuditEngine) GetCheckCount() int {
	total := 0
	for _, checks := range e.checks {
		total += len(checks)
	}
	return total
}

func (e *AuditEngine) ValidateBaseline(profile string) ([]*CheckResult, error) {
	baseline, exists := e.baselines[profile]
	if !exists {
		return nil, fmt.Errorf("未找到基线配置: %s", profile)
	}

	var results []*CheckResult
	for _, rule := range baseline.Rules {
		result := &CheckResult{
			CheckID:   rule.ID,
			Status:    CheckStatusPass,
			RiskLevel: RiskLevelInfo,
			Score:     0,
		}

		if rule.Severity == SeverityCritical || rule.Severity == SeverityHigh {
			result.Status = CheckStatusFail
			result.RiskLevel = RiskLevelHigh
			result.Score = 75
			result.Details = fmt.Sprintf("基线规则未通过: %s", rule.Description)
		}

		results = append(results, result)
	}

	return results, nil
}
