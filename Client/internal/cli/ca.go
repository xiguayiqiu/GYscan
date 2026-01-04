package cli

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"GYscan/internal/configaudit"
	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	auditTarget        string
	auditCategory      string
	auditOutput        string
	auditFormat        string
	auditVerbose       bool
	auditBaseline      string
	auditParallelism   int
	auditTimeout       int
	auditSkipPrivCheck bool
	auditPrivMode      string
	osType             string
)

var caCmd = &cobra.Command{
	Use:   "ca [target]",
	Short: "配置审计功能 - 检查系统、Web、SSH和中间件配置安全性",
	Long: fmt.Sprintf(`
===============================================
              GYscan 配置审计模块
===============================================
%s

功能说明:
  - 系统审计: 检查操作系统配置、用户权限、服务和内核参数
  - Web审计: 分析Web服务器配置和SSL/TLS设置
  - SSH审计: 评估SSH服务安全配置
  - 中间件审计: 检查数据库和消息队列等中间件配置

使用示例:

  # 全面审计本地系统
  GYscan ca localhost --category all

  # 只审计操作系统配置
  GYscan ca localhost --category os

  # 生成HTML格式报告
  GYscan ca localhost --output security_report.html --format html

  # JSON格式输出（便于程序解析）
  GYscan ca localhost --format json

  # 使用高安全基线
  GYscan ca localhost --baseline high_security

  # 显示详细输出
  GYscan ca localhost --verbose

注意事项:
  - 需要管理员/root权限运行以获得完整检查结果
  - 建议在测试环境中先验证审计规则
  - 审计结果仅作为安全加固的参考依据
%s`,
		color.YellowString("警告: 仅用于授权测试，严禁未授权使用！"),
		color.CyanString("提示: 使用 --category 参数指定审计类别 (os, web, ssh, middleware, all)")),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && auditTarget == "" {
			utils.ErrorPrint("请指定审计目标")
			cmd.Help()
			return
		}

		if len(args) > 0 {
			auditTarget = args[0]
		}

		runConfigAudit()
	},
}

func init() {
	caCmd.Flags().StringVarP(&auditCategory, "category", "c", "all",
		"审计类别 (os, web, ssh, middleware, all)")
	caCmd.Flags().StringVarP(&auditOutput, "output", "o", "",
		"输出文件路径")
	caCmd.Flags().StringVarP(&auditFormat, "format", "f", "text",
		"输出格式 (text, json, html)")
	caCmd.Flags().BoolVarP(&auditVerbose, "verbose", "v", false,
		"显示详细信息")
	caCmd.Flags().StringVar(&auditBaseline, "baseline", "enterprise",
		"安全基线配置 (enterprise, high_security, pci_dss, hipaa)")
	caCmd.Flags().IntVarP(&auditParallelism, "parallel", "p", 4,
		"并行审计数量")
	caCmd.Flags().IntVar(&auditTimeout, "timeout", 300,
		"超时时间 (秒)")
	caCmd.Flags().BoolVar(&auditSkipPrivCheck, "skip-priv-check", false,
		"跳过权限检查（谨慎使用，仅当确认已有所需权限时）")
	caCmd.Flags().StringVar(&auditPrivMode, "priv-mode", "auto",
		"权限提升模式 (auto, sudo, runas, none)")
	caCmd.Flags().StringVar(&osType, "os-type", "auto",
		"目标系统类型 (windows, linux, auto)")

	rootCmd.AddCommand(caCmd)
}

func runConfigAudit() {
	startTime := time.Now()

	utils.BoldInfo("==============================================")
	utils.BoldInfo("              GYscan 配置审计模块")
	utils.BoldInfo("==============================================")
	fmt.Println()

	utils.LogInfo("审计目标: %s", auditTarget)
	utils.LogInfo("审计类别: %s", auditCategory)
	utils.LogInfo("输出格式: %s", auditFormat)

	osTypeEnum := parseOSType(osType)

	if auditTarget == "localhost" || auditTarget == "127.0.0.1" {
		auditTarget = getLocalHostName()
	}

	categories := parseCategories(auditCategory)
	utils.LogInfo("审计类别: %v", categories)

	var report *configaudit.AuditReport
	var err error

	engine := configaudit.NewAuditEngine(&configaudit.EngineConfig{
		Parallelism:   auditParallelism,
		Timeout:       time.Duration(auditTimeout) * time.Second,
		Baseline:      auditBaseline,
		SkipPrivCheck: auditSkipPrivCheck,
		PrivMode:      auditPrivMode,
	})

	currUser, _ := user.Current()
	utils.LogInfo("当前用户: %s", currUser.Username)

	engine.SetLocalMode()
	report, err = engine.RunAudit(auditTarget, categories, osTypeEnum)

	if err != nil {
		utils.ErrorPrint("审计执行失败: %v", err)
		os.Exit(1)
	}

	if auditOutput != "" {
		utils.LogInfo("输出格式: %s", auditFormat)
		utils.LogInfo("输出文件: %s", auditOutput)
	}

	printAuditReport(report)

	duration := time.Since(startTime)
	utils.LogInfo("审计完成，耗时: %.2f秒", duration.Seconds())
}

func parseCategories(categoryStr string) []configaudit.AuditCategory {
	categories := []configaudit.AuditCategory{}
	categoryStr = strings.ToLower(categoryStr)

	categoryMap := map[string]configaudit.AuditCategory{
		"all":        configaudit.CATEGORY_ALL,
		"os":         configaudit.CATEGORY_OS,
		"web":        configaudit.CATEGORY_WEB,
		"ssh":        configaudit.CATEGORY_SSH,
		"middleware": configaudit.CATEGORY_MIDDLEWARE,
		"security":   configaudit.CATEGORY_SECURITY,
		"database":   configaudit.CATEGORY_DATABASE,
		"network":    configaudit.CATEGORY_NETWORK,
	}

	if categoryStr == "all" {
		for _, cat := range []configaudit.AuditCategory{
			configaudit.CATEGORY_OS,
			configaudit.CATEGORY_WEB,
			configaudit.CATEGORY_SSH,
			configaudit.CATEGORY_MIDDLEWARE,
		} {
			categories = append(categories, cat)
		}
		return categories
	}

	parts := strings.Split(categoryStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if cat, ok := categoryMap[part]; ok {
			categories = append(categories, cat)
		}
	}

	if len(categories) == 0 {
		categories = append(categories, configaudit.CATEGORY_OS)
	}

	return categories
}

func parseOSType(osTypeStr string) configaudit.OSType {
	osTypeStr = strings.ToLower(osTypeStr)
	switch osTypeStr {
	case "windows":
		return configaudit.OSWindows
	case "linux":
		return configaudit.OSLinux
	case "macos", "mac os":
		return configaudit.OSMacOS
	default:
		return detectLocalOSType()
	}
}

func detectLocalOSType() configaudit.OSType {
	switch runtime.GOOS {
	case "windows":
		return configaudit.OSWindows
	case "linux":
		return configaudit.OSLinux
	case "darwin":
		return configaudit.OSMacOS
	default:
		return configaudit.OSUnknown
	}
}

func getLocalHostName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}

func printAuditReport(report *configaudit.AuditReport) {
	fmt.Printf("\n===========================================================\n")
	fmt.Printf("                    配置审计报告\n")
	fmt.Printf("===========================================================\n\n")

	fmt.Printf("审计目标: %s\n", report.Target)
	fmt.Printf("审计时间: %s\n", report.Timestamp)
	fmt.Printf("审计类别: %s\n", report.Category)
	fmt.Printf("执行耗时: %.2f 秒\n\n", report.Duration)

	fmt.Printf("---------------------------------------------------------------------\n")
	fmt.Printf("                         审计摘要\n")
	fmt.Printf("---------------------------------------------------------------------\n")
	fmt.Printf("  总检查项:    %d\n", report.Summary.TotalChecks)
	fmt.Printf("  通过:        %d\n", report.Summary.PassedChecks)
	fmt.Printf("  失败:        %d\n", report.Summary.FailedChecks)
	fmt.Printf("  警告:        %d\n", report.Summary.WarningChecks)
	fmt.Printf("  错误:        %d\n\n", report.Summary.ErrorChecks)

	fmt.Printf("  整体评分:    %.1f/100\n", report.Summary.OverallScore)
	fmt.Printf("  风险等级:    %s\n", report.Summary.RiskLevel)

	fmt.Printf("\n===========================================================\n")
	fmt.Printf("                      报告结束\n")
	fmt.Printf("===========================================================\n")
}
