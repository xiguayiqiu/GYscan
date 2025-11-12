package audit

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

// AuditManager 审计管理器
type AuditManager struct {
	config     *Config
	modules    map[string]AuditModule
	systemInfo SystemInfo
}

// NewAuditManager 创建新的审计管理器
func NewAuditManager(config *Config) *AuditManager {
	return &AuditManager{
		config:  config,
		modules: make(map[string]AuditModule),
	}
}

// RegisterModule 注册审计模块
func (am *AuditManager) RegisterModule(module AuditModule) {
	am.modules[module.Name()] = module
}

// GetSystemInfo 获取系统信息
func (am *AuditManager) GetSystemInfo() SystemInfo {
	if am.systemInfo.Hostname == "" {
		am.systemInfo = am.collectSystemInfo()
	}
	return am.systemInfo
}

// collectSystemInfo 收集系统信息
func (am *AuditManager) collectSystemInfo() SystemInfo {
	var info SystemInfo

	// 获取主机名
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// 获取操作系统信息
	info.OS = runtime.GOOS
	info.Architecture = runtime.GOARCH

	// 获取Windows版本信息（简化实现）
	// 在实际实现中，应该使用Windows API获取准确的版本信息
	info.Version = "10.0.19041" // 默认版本号
	info.Build = "19041" // 默认构建号

	// 获取当前用户信息
	if currentUser, err := getCurrentUser(); err == nil {
		info.CurrentUser = currentUser
	}

	// 检查管理员权限
	info.IsAdmin = am.isRunningAsAdmin()

	// 获取域名信息
	if domain, err := getDomainName(); err == nil {
		info.Domain = domain
	}

	return info
}

// isRunningAsAdmin 检查是否以管理员权限运行
func (am *AuditManager) isRunningAsAdmin() bool {
	// 简化实现：检查当前进程是否以管理员权限运行
	// 在实际实现中，应该使用Windows API检查令牌权限
	
	// 这里返回false作为简化实现
	// 在实际使用中，应该根据实际权限返回正确值
	return false
}

// RunAudit 执行审计
func (am *AuditManager) RunAudit() (*AuditReport, error) {
	startTime := time.Now()
	
	// 收集系统信息
	systemInfo := am.GetSystemInfo()
	
	// 检查权限
	if !systemInfo.IsAdmin && am.config.Verbose {
		color.Yellow("警告: 当前未以管理员权限运行，某些审计模块可能无法正常工作")
	}

	// 执行选定的模块
	var allResults []AuditResult
	modulesToRun := am.getModulesToRun()

	if am.config.Verbose {
		color.Cyan("开始Windows安全审计...")
		fmt.Printf("系统信息: %s %s (%s)\n", systemInfo.OS, systemInfo.Version, systemInfo.Architecture)
		fmt.Printf("运行模块: %s\n", strings.Join(modulesToRun, ", "))
	}

	for _, moduleName := range modulesToRun {
		if module, exists := am.modules[moduleName]; exists {
			if am.config.Verbose {
				color.Blue("执行模块: %s", module.Name())
			}

			results, err := module.Run()
			if err != nil {
				log.Printf("模块 %s 执行失败: %v", module.Name(), err)
				allResults = append(allResults, AuditResult{
					ModuleName:    module.Name(),
					Level:         AuditLevelHigh,
					Status:        "error",
					Description:   fmt.Sprintf("模块执行失败: %v", err),
					RiskScore:     100,
					Timestamp:     time.Now(),
				})
				continue
			}

			allResults = append(allResults, results...)
			
			if am.config.Verbose {
				color.Green("模块 %s 完成，生成 %d 个结果", module.Name(), len(results))
			}
		} else {
			log.Printf("警告: 未找到模块 %s", moduleName)
		}
	}

	// 生成摘要
	summary := am.generateSummary(allResults)
	duration := time.Since(startTime)

	report := &AuditReport{
		SystemInfo: systemInfo,
		Results:    allResults,
		Summary:    summary,
		Timestamp:  startTime,
		Duration:   duration,
	}

	return report, nil
}

// getModulesToRun 获取要运行的模块列表
func (am *AuditManager) getModulesToRun() []string {
	if len(am.config.Modules) == 0 {
		// 如果没有指定模块，运行所有模块
		var allModules []string
		for name := range am.modules {
			allModules = append(allModules, name)
		}
		sort.Strings(allModules)
		return allModules
	}

	// 运行指定的模块
	return am.config.Modules
}

// generateSummary 生成审计摘要
func (am *AuditManager) generateSummary(results []AuditResult) AuditSummary {
	var summary AuditSummary
	summary.TotalChecks = len(results)

	// 权重因子：不同级别的检查项有不同的权重
	weightFactors := map[string]float64{
		"fail":  1.5,  // 失败项权重最高
		"error": 2.0,  // 错误项权重最高
		"warning": 1.2, // 警告项权重较高
		"pass":   0.5,  // 通过项权重较低
	}

	totalWeightedScore := 0.0
	totalWeight := 0.0

	for _, result := range results {
		switch result.Status {
		case "pass":
			summary.Passed++
		case "fail":
			summary.Failed++
		case "warning":
			summary.Warnings++
		case "error":
			summary.Errors++
		}

		// 根据检查项状态和风险级别计算加权分数
		weight := weightFactors[result.Status]
		
		// 根据风险级别调整权重
		switch result.Level {
		case AuditLevelHigh:
			weight *= 1.5
		case AuditLevelMedium:
			weight *= 1.2
		case AuditLevelLow:
			weight *= 0.8
		}

		totalWeightedScore += float64(result.RiskScore) * weight
		totalWeight += weight
	}

	// 计算加权平均风险评分
	if totalWeight > 0 {
		summary.RiskScore = int(totalWeightedScore / totalWeight)
	}

	// 根据失败和错误数量调整最终风险评分
	if summary.Failed > 0 || summary.Errors > 0 {
		// 每有一个失败或错误项，增加风险评分
		criticalIssues := summary.Failed + summary.Errors
		if criticalIssues > 0 {
			// 根据严重问题数量调整风险评分
			adjustment := criticalIssues * 5
			if adjustment > 30 {
				adjustment = 30 // 最大调整30分
			}
			summary.RiskScore += adjustment
			if summary.RiskScore > 100 {
				summary.RiskScore = 100
			}
		}
	}

	return summary
}

// PrintSummary 打印审计摘要
func (am *AuditManager) PrintSummary(report *AuditReport) {
	summary := report.Summary
	
	fmt.Println("\n" + strings.Repeat("=", 60))
	color.Cyan("Windows安全审计完成")
	fmt.Println(strings.Repeat("=", 60))
	
	fmt.Printf("系统: %s %s (%s)\n", 
		report.SystemInfo.OS, 
		report.SystemInfo.Version, 
		report.SystemInfo.Architecture)
	fmt.Printf("主机: %s (%s)\n", 
		report.SystemInfo.Hostname, 
		report.SystemInfo.Domain)
	fmt.Printf("用户: %s (管理员: %v)\n", 
		report.SystemInfo.CurrentUser, 
		report.SystemInfo.IsAdmin)
	
	fmt.Println("\n审计结果:")
	fmt.Printf("总检查项: %d\n", summary.TotalChecks)
	color.Green("通过: %d", summary.Passed)
	color.Red("失败: %d", summary.Failed)
	color.Yellow("警告: %d", summary.Warnings)
	color.Red("错误: %d", summary.Errors)
	
	// 计算风险等级
	riskLevel := "低"
	if summary.RiskScore >= 70 {
		riskLevel = "高"
		color.Red("风险评分: %d (%s)", summary.RiskScore, riskLevel)
	} else if summary.RiskScore >= 40 {
		riskLevel = "中"
		color.Yellow("风险评分: %d (%s)", summary.RiskScore, riskLevel)
	} else {
		color.Green("风险评分: %d (%s)", summary.RiskScore, riskLevel)
	}
	
	fmt.Printf("审计耗时: %v\n", report.Duration)
	fmt.Printf("完成时间: %s\n", report.Timestamp.Format("2006-01-02 15:04:05"))
}

// 辅助函数
func getCurrentUser() (string, error) {
	return os.Getenv("USERNAME"), nil
}

func getDomainName() (string, error) {
	return os.Getenv("USERDOMAIN"), nil
}