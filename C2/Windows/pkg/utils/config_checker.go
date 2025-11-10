package utils

import (
	"fmt"
	"os/exec"
	"strings"
	"GYscan-Win-C2/pkg/types"
)

// ConfigChecker 配置文件检查器
type ConfigChecker struct {
	Verbose bool
}

// SecurityConfig 安全配置信息
type SecurityConfig struct {
	Category    string
	Setting     string
	Value       string
	Recommended string
	Compliant   bool
}

// NewConfigChecker 创建新的配置文件检查器
func NewConfigChecker(verbose bool) *ConfigChecker {
	return &ConfigChecker{
		Verbose: verbose,
	}
}

// CheckSecurityConfigurations 检查安全配置
func (cc *ConfigChecker) CheckSecurityConfigurations() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	if cc.Verbose {
		fmt.Println("开始检查安全配置...")
	}

	// 检查密码策略
	passwordConfigs, passwordVulns := cc.checkPasswordPolicy()
	configs = append(configs, passwordConfigs...)
	vulnerabilities = append(vulnerabilities, passwordVulns...)

	// 检查账户策略
	accountConfigs, accountVulns := cc.checkAccountPolicy()
	configs = append(configs, accountConfigs...)
	vulnerabilities = append(vulnerabilities, accountVulns...)

	// 检查审计策略
	auditConfigs, auditVulns := cc.checkAuditPolicy()
	configs = append(configs, auditConfigs...)
	vulnerabilities = append(vulnerabilities, auditVulns...)

	// 检查防火墙配置
	firewallConfigs, firewallVulns := cc.checkFirewallConfig()
	configs = append(configs, firewallConfigs...)
	vulnerabilities = append(vulnerabilities, firewallVulns...)

	// 检查服务配置
	serviceConfigs, serviceVulns := cc.checkServiceConfig()
	configs = append(configs, serviceConfigs...)
	vulnerabilities = append(vulnerabilities, serviceVulns...)

	// 检查共享配置
	shareConfigs, shareVulns := cc.checkShareConfig()
	configs = append(configs, shareConfigs...)
	vulnerabilities = append(vulnerabilities, shareVulns...)

	if cc.Verbose {
		fmt.Printf("检查安全配置项: %d个\n", len(configs))
		fmt.Printf("发现配置漏洞: %d个\n", len(vulnerabilities))
	}

	return configs, vulnerabilities
}

// checkPasswordPolicy 检查密码策略
func (cc *ConfigChecker) checkPasswordPolicy() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	// 使用PowerShell获取密码策略
	cmd := exec.Command("powershell", "net accounts")
	output, err := cmd.Output()
	if err != nil {
		return configs, vulnerabilities
	}

	result := string(output)
	lines := strings.Split(result, "\n")

	// 解析密码策略设置
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Minimum password age") {
			value := cc.extractValue(line)
			config := SecurityConfig{
				Category:    "密码策略",
				Setting:     "最小密码使用期限",
				Value:       value,
				Recommended: "1天",
				Compliant:   cc.isPasswordAgeCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-PASSWORD-AGE",
					Name:        "弱密码使用期限策略",
					Severity:    "中危",
					Description: "密码使用期限设置过短",
					Solution:    "设置最小密码使用期限为1天",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}

		if strings.Contains(line, "Maximum password age") {
			value := cc.extractValue(line)
			config := SecurityConfig{
				Category:    "密码策略",
				Setting:     "最大密码使用期限",
				Value:       value,
				Recommended: "90天",
				Compliant:   cc.isMaxPasswordAgeCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-MAX-PASSWORD-AGE",
					Name:        "弱最大密码使用期限策略",
					Severity:    "中危",
					Description: "密码使用期限设置过长",
					Solution:    "设置最大密码使用期限为90天",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}

		if strings.Contains(line, "Minimum password length") {
			value := cc.extractValue(line)
			config := SecurityConfig{
				Category:    "密码策略",
				Setting:     "最小密码长度",
				Value:       value,
				Recommended: "8字符",
				Compliant:   cc.isPasswordLengthCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-PASSWORD-LENGTH",
					Name:        "弱密码长度策略",
					Severity:    "高危",
					Description: "密码长度设置过短",
					Solution:    "设置最小密码长度为8字符",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}

		if strings.Contains(line, "Password history") {
			value := cc.extractValue(line)
			config := SecurityConfig{
				Category:    "密码策略",
				Setting:     "密码历史记录",
				Value:       value,
				Recommended: "24个密码",
				Compliant:   cc.isPasswordHistoryCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-PASSWORD-HISTORY",
					Name:        "弱密码历史策略",
					Severity:    "中危",
					Description: "密码历史记录设置过少",
					Solution:    "设置密码历史记录为24个密码",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}
	}

	return configs, vulnerabilities
}

// checkAccountPolicy 检查账户策略
func (cc *ConfigChecker) checkAccountPolicy() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	// 使用PowerShell获取账户策略
	cmd := exec.Command("powershell", "net accounts")
	output, err := cmd.Output()
	if err != nil {
		return configs, vulnerabilities
	}

	result := string(output)
	lines := strings.Split(result, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Lockout threshold") {
			value := cc.extractValue(line)
			config := SecurityConfig{
				Category:    "账户策略",
				Setting:     "账户锁定阈值",
				Value:       value,
				Recommended: "5次",
				Compliant:   cc.isLockoutThresholdCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-LOCKOUT-THRESHOLD",
					Name:        "弱账户锁定阈值",
					Severity:    "中危",
					Description: "账户锁定阈值设置不当",
					Solution:    "设置账户锁定阈值为5次",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}

		if strings.Contains(line, "Lockout duration") {
			value := cc.extractValue(line)
			config := SecurityConfig{
				Category:    "账户策略",
				Setting:     "账户锁定持续时间",
				Value:       value,
				Recommended: "30分钟",
				Compliant:   cc.isLockoutDurationCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-LOCKOUT-DURATION",
					Name:        "弱账户锁定持续时间",
					Severity:    "中危",
					Description: "账户锁定持续时间设置不当",
					Solution:    "设置账户锁定持续时间为30分钟",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}
	}

	return configs, vulnerabilities
}

// checkAuditPolicy 检查审计策略
func (cc *ConfigChecker) checkAuditPolicy() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	// 使用PowerShell获取审计策略
	cmd := exec.Command("powershell", "auditpol /get /category:*")
	output, err := cmd.Output()
	if err != nil {
		return configs, vulnerabilities
	}

	result := string(output)
	lines := strings.Split(result, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "Audit Policy Change") {
			value := cc.extractAuditValue(line)
			config := SecurityConfig{
				Category:    "审计策略",
				Setting:     "审计策略更改",
				Value:       value,
				Recommended: "成功和失败",
				Compliant:   cc.isAuditPolicyCompliant(value),
			}
			configs = append(configs, config)
			
			if !config.Compliant {
				vulnerabilities = append(vulnerabilities, types.Vulnerability{
					ID:          "WEAK-AUDIT-POLICY",
					Name:        "弱审计策略",
					Severity:    "中危",
					Description: "审计策略设置不充分",
					Solution:    "启用关键事件的审计策略",
					CVE:         "",
					Affected:    "所有Windows系统",
				})
			}
		}
	}

	return configs, vulnerabilities
}

// checkFirewallConfig 检查防火墙配置
func (cc *ConfigChecker) checkFirewallConfig() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	// 使用PowerShell检查防火墙状态
	cmd := exec.Command("powershell", "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json")
	output, err := cmd.Output()
	if err != nil {
		return configs, vulnerabilities
	}

	result := string(output)
	
	// 简化的检查逻辑
	if !strings.Contains(result, "\"Enabled\": true") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "FIREWALL-DISABLED",
			Name:        "防火墙未启用",
			Severity:    "高危",
			Description: "Windows防火墙未启用",
			Solution:    "启用Windows防火墙",
			CVE:         "",
			Affected:    "所有Windows系统",
		})
	}

	return configs, vulnerabilities
}

// checkServiceConfig 检查服务配置
func (cc *ConfigChecker) checkServiceConfig() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	// 检查危险服务
	dangerousServices := []string{
		"Telnet",
		"FTP",
		"Remote Registry",
		"Task Scheduler",
	}

	for _, service := range dangerousServices {
		cmd := exec.Command("powershell", fmt.Sprintf("Get-Service -Name '%s' -ErrorAction SilentlyContinue", service))
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "Running") {
			vulnerabilities = append(vulnerabilities, types.Vulnerability{
				ID:          "DANGEROUS-SERVICE-" + service,
				Name:        "危险服务运行中: " + service,
				Severity:    "中危",
				Description: "发现危险服务正在运行",
				Solution:    "禁用或限制危险服务",
				CVE:         "",
				Affected:    "所有Windows系统",
			})
		}
	}

	return configs, vulnerabilities
}

// checkShareConfig 检查共享配置
func (cc *ConfigChecker) checkShareConfig() ([]SecurityConfig, []types.Vulnerability) {
	var configs []SecurityConfig
	var vulnerabilities []types.Vulnerability

	// 检查共享配置
	cmd := exec.Command("powershell", "net share")
	output, err := cmd.Output()
	if err != nil {
		return configs, vulnerabilities
	}

	result := string(output)
	if strings.Contains(result, "C$") || strings.Contains(result, "ADMIN$") {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          "DANGEROUS-SHARE",
			Name:        "危险共享存在",
			Severity:    "高危",
			Description: "发现默认管理共享",
			Solution:    "禁用默认管理共享",
			CVE:         "",
			Affected:    "所有Windows系统",
		})
	}

	return configs, vulnerabilities
}

// 辅助函数
func (cc *ConfigChecker) extractValue(line string) string {
	parts := strings.Split(line, ":")
	if len(parts) > 1 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func (cc *ConfigChecker) extractAuditValue(line string) string {
	parts := strings.Split(line, " ")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return ""
}

func (cc *ConfigChecker) isPasswordAgeCompliant(value string) bool {
	return value != "0" && value != ""
}

func (cc *ConfigChecker) isMaxPasswordAgeCompliant(value string) bool {
	return value != "42" && value != "" && value != "0"
}

func (cc *ConfigChecker) isPasswordLengthCompliant(value string) bool {
	return value >= "8"
}

func (cc *ConfigChecker) isPasswordHistoryCompliant(value string) bool {
	return value >= "24"
}

func (cc *ConfigChecker) isLockoutThresholdCompliant(value string) bool {
	return value != "0" && value != ""
}

func (cc *ConfigChecker) isLockoutDurationCompliant(value string) bool {
	return value != "0" && value != ""
}

func (cc *ConfigChecker) isAuditPolicyCompliant(value string) bool {
	return value == "Success and Failure" || value == "成功和失败"
}