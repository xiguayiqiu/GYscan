package ai

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"GYscan/internal/utils"
)

// ComplianceManager 合规管理器
type ComplianceManager struct {
	ErrorHandler *ErrorHandler
	// 可以添加OPA策略引擎、速率限制器等
}

// NewComplianceManager 创建合规管理器
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		ErrorHandler: NewErrorHandler("", "info"),
	}
}

// CheckTargetAuthorization 检查目标是否授权
func (cm *ComplianceManager) CheckTargetAuthorization(target string, authorizedTargets []string) bool {
	// 简单实现：检查目标是否在授权列表中
	for _, authTarget := range authorizedTargets {
		if target == authTarget {
			return true
		}
	}
	return false
}

// CheckToolAuthorization 检查工具是否授权
func (cm *ComplianceManager) CheckToolAuthorization(toolName string, authorizedTools []string) bool {
	// 简单实现：检查工具是否在授权列表中
	for _, authTool := range authorizedTools {
		if toolName == authTool {
			return true
		}
	}
	return false
}

// LogAction 记录操作日志
func (cm *ComplianceManager) LogAction(action, target, tool, result string) {
	cm.ErrorHandler.Log("info", "ai_mcp_compliance", "操作执行",
		map[string]interface{}{
			"action":      action,
			"target":      target,
			"tool":        tool,
			"result":      result,
			"timestamp":   time.Now().Format(time.RFC3339),
			"compliant":   true,
		})
	utils.InfoPrint("合规日志: 操作=%s, 目标=%s, 工具=%s, 结果=%s", action, target, tool, result)
}

// CheckRateLimit 检查速率限制
func (cm *ComplianceManager) CheckRateLimit(ip string) (bool, error) {
	// 简单实现：返回true，允许所有请求
	// 实际实现中可以添加redis或内存速率限制器
	return true, nil
}

// ValidateCommand 验证命令的合法性
func (cm *ComplianceManager) ValidateCommand(toolName string, args []string) (bool, error) {
	// 简单实现：检查是否是已知的安全工具
	safeTools := map[string]bool{
		"nmap":      true,
		"curl":      true,
		"sqlmap":    true,
		"nikto":     true,
		"gobuster":  true,
		"dirb":      true,
		"wpscan":    true,
		"ffuf":      true,
		"nuclei":    true,
		"dirsearch": true,
		"httpx":     true,
	}

	// 检查工具是否安全
	if !safeTools[toolName] {
		return false, fmt.Errorf("工具 %s 未在安全白名单中", toolName)
	}

	// 检查是否包含危险参数
	dangerousArgs := []string{
		"--os-shell", "--os-pwn", "--os-smbrelay", "--os-bof",
		"--privilege-escalation", "--autopwn", "--exploit",
	}

	for _, arg := range args {
		for _, dangerousArg := range dangerousArgs {
			if arg == dangerousArg {
				return false, fmt.Errorf("命令包含危险参数: %s", arg)
			}
		}
	}

	return true, nil
}

// GetComplianceReport 获取合规报告
func (cm *ComplianceManager) GetComplianceReport(startTime, endTime time.Time) string {
	// 简单实现：返回空报告
	// 实际实现中可以查询日志系统生成完整报告
	return "合规报告生成功能待实现"
}

// ValidateTarget 验证目标的合法性
func (cm *ComplianceManager) ValidateTarget(target string) (bool, error) {
	// 简单实现：检查目标是否是有效的IP或域名或URL
	if utils.IsValidIP(target) {
		return true, nil
	}
	
	// 检查是否是有效的URL
	if _, err := url.ParseRequestURI(target); err == nil {
		return true, nil
	}
	
	// 检查是否是有效的域名
	if strings.Contains(target, ".") {
		// 简单检查：包含点，并且没有空格和特殊字符
		for _, char := range target {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '-') {
				return false, fmt.Errorf("无效的目标格式: %s", target)
			}
		}
		return true, nil
	}
	
	return false, fmt.Errorf("无效的目标格式: %s", target)
}
