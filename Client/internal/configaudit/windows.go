package configaudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func GetWindowsAuditChecks() []*AuditCheck {
	return []*AuditCheck{
		{
			ID:          "WIN-ACCT-001",
			Name:        "账户权限管控检查",
			Description: "检查系统账户权限配置，确保遵循最小权限原则",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Windows-2020-1.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用或删除不必要的账户，审查管理员组权限",
			Impact:      "过度权限分配可能导致账户滥用和数据泄露",
			Execute:     checkWindowsAccountRights,
		},
		{
			ID:          "WIN-PASS-001",
			Name:        "密码策略强度检查",
			Description: "验证密码策略是否符合安全要求",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeCompliance,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Windows-2020-2.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "通过secpol.msc或GPO设置强密码策略",
			Impact:      "弱密码策略可能导致暴力破解成功",
			Execute:     checkWindowsPasswordPolicy,
		},
		{
			ID:          "WIN-SVC-001",
			Name:        "服务端口开放状态检查",
			Description: "审计系统服务端口配置，识别不必要的开放端口",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Windows-2020-9.2",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用不必要的服务，配置防火墙规则限制访问",
			Impact:      "不必要的开放端口增加攻击面",
			Execute:     checkWindowsServicePorts,
		},
		{
			ID:          "WIN-REG-001",
			Name:        "注册表安全配置检查",
			Description: "检查关键注册表项的安全配置",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Windows-2020-19.6",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "修改注册表配置以增强安全性",
			Impact:      "不安全的注册表设置可能被攻击者利用",
			Execute:     checkWindowsRegistrySecurity,
		},
		{
			ID:          "WIN-AUDIT-001",
			Name:        "审核策略配置检查",
			Description: "验证审核策略是否正确配置以支持安全审计",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Windows-2020-17.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "通过secpol.msc配置适当的审核策略",
			Impact:      "缺乏审核将无法追踪安全事件",
			Execute:     checkWindowsAuditPolicy,
		},
		{
			ID:          "WIN-LSA-001",
			Name:        "LSA安全配置检查",
			Description: "检查本地安全机构(LSA)的安全配置",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Windows-2020-2.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置注册表项以增强LSA安全性",
			Impact:      "LSA配置不当可能导致凭据泄露",
			Execute:     checkWindowsLSASecurity,
		},
		{
			ID:          "WIN-UAC-001",
			Name:        "用户账户控制(UAC)检查",
			Description: "验证UAC是否正确启用",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Windows-2020-2.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "通过控制面板或GPO启用UAC",
			Impact:      "禁用UAC会增加权限提升攻击风险",
			Execute:     checkWindowsUACStatus,
		},
		{
			ID:          "WIN-FW-001",
			Name:        "Windows防火墙状态检查",
			Description: "验证Windows防火墙是否启用",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Windows-2020-9.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "启用Windows防火墙并配置适当规则",
			Impact:      "防火墙禁用将导致系统暴露于网络攻击",
			Execute:     checkWindowsFirewallStatus,
		},
		{
			ID:          "WIN-SMB-001",
			Name:        "SMB协议安全配置检查",
			Description: "检查SMBv1是否已禁用，验证SMB安全设置",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Windows-2020-2.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "通过注册表禁用SMBv1，配置SMB签名",
			Impact:      "SMBv1存在严重安全漏洞，禁用可防止WannaCry等攻击",
			Execute:     checkWindowsSMBSecurity,
		},
		{
			ID:          "WIN-ANON-001",
			Name:        "匿名枚举安全检查",
			Description: "检查是否阻止匿名用户枚举SAM账户",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Windows-2020-2.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置注册表项限制匿名枚举",
			Impact:      "匿名枚举可能泄露系统信息用于后续攻击",
			Execute:     checkWindowsAnonymousRestriction,
		},
	}
}

func checkWindowsAccountRights(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-ACCT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	evidence := []string{}
	issues := []string{}

	admins, ok := ctx.Config["local_admins"].([]string)
	if !ok {
		issues = append(issues, "无法获取本地管理员组成员列表")
		result.Status = CheckStatusWarning
		result.Details = "检查执行过程中出现异常"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "注册表: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
		result.ConfigKey = "本地管理员组"
		result.RawValue = "无法读取"
	} else {
		for _, admin := range admins {
			if strings.Contains(strings.ToLower(admin), "guest") ||
			   strings.Contains(strings.ToLower(admin), "defaultaccount") {
				issues = append(issues, fmt.Sprintf("发现可疑管理员账户: %s", admin))
				evidence = append(evidence, fmt.Sprintf("管理员组包含非标准账户: %s", admin))
			}
		}

		if len(admins) > 5 {
			issues = append(issues, fmt.Sprintf("管理员组成员数量较多: %d", len(admins)))
			result.Status = CheckStatusWarning
			result.ConfigFile = "本地用户和组 (lusrmgr.msc)"
			result.ConfigKey = "Administrators组成员数"
			result.RawValue = fmt.Sprintf("%d", len(admins))
			result.Evidence = fmt.Sprintf("当前管理员数: %d\n建议: <= 5人", len(admins))
		}

		if len(issues) > 0 {
			result.Status = CheckStatusFail
			result.RiskLevel = RiskLevelHigh
			result.Score = 75
			result.Details = fmt.Sprintf("发现%d个账户权限问题: %s", len(issues), strings.Join(issues, "; "))
			result.Evidence = strings.Join(evidence, "\n")
		} else {
			result.Details = "管理员账户配置符合安全要求"
			result.Evidence = fmt.Sprintf("管理员组成员: %v", admins)
		}
	}

	return result
}

func checkWindowsPasswordPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-PASS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	minLength := 14
	maxAge := 60

	policy, ok := ctx.Config["password_policy"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取密码策略信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "安全策略: secpol.msc"
		result.ConfigKey = "密码策略"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemDetails := []string{}

	if policy["min_length"] != nil {
		ml, _ := strconv.Atoi(fmt.Sprintf("%v", policy["min_length"]))
		if ml < minLength {
			issue := fmt.Sprintf("最小密码长度不足: 当前%d, 要求%d", ml, minLength)
			issues = append(issues, issue)
			problemDetails = append(problemDetails, fmt.Sprintf("策略: 密码长度\n当前值: %d\n要求值: >= %d\n位置: secpol.msc -> 账户策略 -> 密码策略", ml, minLength))
			result.ConfigFile = "安全策略: secpol.msc"
			result.ConfigKey = "密码最小长度"
			result.RawValue = fmt.Sprintf("%d", ml)
		}
	}

	if policy["complexity"] != nil {
		comp := fmt.Sprintf("%v", policy["complexity"])
		if !strings.Contains(strings.ToLower(comp), "enabled") && comp != "1" {
			issue := "密码复杂性要求未启用"
			issues = append(issues, issue)
			problemDetails = append(problemDetails, fmt.Sprintf("策略: 密码必须符合复杂性要求\n当前值: %s\n要求值: 已启用\n位置: secpol.msc -> 账户策略 -> 密码策略", comp))
			if result.ConfigKey == "" {
				result.ConfigFile = "安全策略: secpol.msc"
				result.ConfigKey = "密码必须符合复杂性要求"
				result.RawValue = comp
			}
		}
	}

	if policy["max_age"] != nil {
		ma, _ := strconv.Atoi(fmt.Sprintf("%v", policy["max_age"]))
		if ma > maxAge {
			issue := fmt.Sprintf("密码最长使用期限过长: 当前%d天, 要求%d天", ma, maxAge)
			issues = append(issues, issue)
			problemDetails = append(problemDetails, fmt.Sprintf("策略: 密码最长期限\n当前值: %d天\n要求值: <= %d天\n位置: secpol.msc -> 账户策略 -> 密码策略", ma, maxAge))
			if result.ConfigKey == "" {
				result.ConfigFile = "安全策略: secpol.msc"
				result.ConfigKey = "密码最长期限"
				result.RawValue = fmt.Sprintf("%d", ma)
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("密码策略不合规: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置位置: 安全策略 (secpol.msc)\n\n%s", strings.Join(problemDetails, "\n\n"))
		result.ActualValue = policy
		result.ExpectedValue = fmt.Sprintf("最小长度>=%d, 复杂性要求=启用, 最长期限<=%d天", minLength, maxAge)
	} else {
		result.Details = "密码策略配置符合安全要求"
		result.ActualValue = policy
	}

	return result
}

func checkWindowsServicePorts(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-SVC-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	dangerousPorts := map[int]string{
		21:   "FTP",
		23:   "Telnet",
		445:  "SMB",
		135:  "RPC",
		139:  "NetBIOS",
		3389: "RDP",
		5900: "VNC",
	}

	openPorts, ok := ctx.Config["listening_ports"].([]int)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取端口信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "netsh advfirewall firewall show rule name=all"
		result.ConfigKey = "监听端口"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	evidence := []string{}

	for _, port := range openPorts {
		if name, exists := dangerousPorts[port]; exists {
			issue := fmt.Sprintf("发现危险端口开放: %d (%s)", port, name)
			issues = append(issues, issue)
			evidence = append(evidence, fmt.Sprintf("端口: %d\n服务: %s\n风险: 高\n建议: 检查并关闭该端口或限制访问", port, name))
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("发现%d个需要审查的端口: %s", len(issues), strings.Join(issues, "; "))
		result.ConfigFile = "netstat -ano | findstr LISTENING"
		result.ConfigKey = "危险开放端口"
		result.RawValue = fmt.Sprintf("%v", openPorts)
		result.Evidence = fmt.Sprintf("检测到的危险端口:\n\n%s", strings.Join(evidence, "\n\n"))
		result.ActualValue = openPorts
	} else {
		result.Details = "未发现明显危险端口开放"
		result.ActualValue = openPorts
	}

	return result
}

func checkWindowsRegistrySecurity(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-REG-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	criticalKeys := []struct {
		Path       string
		ValueName  string
		SafeValue  string
		Setting    string
	}{
		{`HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "RestrictAnonymous", "1", "限制匿名访问"},
		{`HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "RestrictAnonymousSam", "1", "限制SAM匿名访问"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "AutoShareServer", "0", "禁用默认共享"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "EnableICMPRedirect", "0", "禁用ICMP重定向"},
	}

	registry, ok := ctx.Config["registry_settings"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取注册表配置信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "注册表编辑器 (regedit)"
		result.ConfigKey = "安全配置"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	evidence := []string{}

	for _, key := range criticalKeys {
		currentValue := ""
		if v, exists := registry[key.Path]; exists {
			currentValue = fmt.Sprintf("%v", v)
		}

		if currentValue != key.SafeValue {
			issue := fmt.Sprintf("%s 设置不正确 (当前:%s, 要求:%s)", key.Setting, currentValue, key.SafeValue)
			issues = append(issues, issue)
			evidence = append(evidence, fmt.Sprintf("注册表项: %s\\%s\n当前值: %s\n要求值: %s\n修复命令: reg add \"%s\" /v %s /t REG_SZ /d %s /f", key.Path, key.ValueName, currentValue, key.SafeValue, key.Path, key.ValueName, key.SafeValue))
			if result.ConfigFile == "" {
				result.ConfigFile = key.Path
				result.ConfigKey = key.ValueName
				result.RawValue = currentValue
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("发现%d个注册表安全配置问题", len(issues))
		result.Evidence = fmt.Sprintf("需要修复的注册表项:\n\n%s", strings.Join(evidence, "\n\n"))
	} else {
		result.Details = "关键注册表安全配置正确"
	}

	return result
}

func checkWindowsAuditPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-AUDIT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	requiredAudits := map[string]string{
		"AuditLogonEvents":            "成功,失败",
		"AuditAccountLogon":           "成功,失败",
		"AuditDirectoryServiceAccess": "失败",
		"AuditObjectAccess":           "失败",
		"AuditPolicyChange":           "成功,失败",
		"AuditPrivilegeUse":           "失败",
		"AuditProcessTracking":        "失败",
		"AuditSystemEvents":           "成功,失败",
	}

	auditPolicy, ok := ctx.Config["audit_policy"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取审核策略信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "安全策略: secpol.msc -> 本地策略 -> 审核策略"
		result.ConfigKey = "审核策略"
		result.RawValue = "无法读取"
		return result
	}

	missingAudits := []string{}
	problemAudits := []string{}

	for auditType, expected := range requiredAudits {
		current, exists := auditPolicy[auditType]
		if !exists {
			missingAudits = append(missingAudits, auditType)
			problemAudits = append(problemAudits, fmt.Sprintf("策略: %s\n当前状态: 未配置\n要求状态: %s\n位置: secpol.msc -> 本地策略 -> 审核策略", auditType, expected))
			if result.ConfigFile == "" {
				result.ConfigFile = "安全策略: secpol.msc"
				result.ConfigKey = auditType
				result.RawValue = "未配置"
			}
		} else if !strings.Contains(expected, fmt.Sprintf("%v", current)) {
			missingAudits = append(missingAudits, fmt.Sprintf("%s(当前:%s, 要求:%s)", auditType, current, expected))
			problemAudits = append(problemAudits, fmt.Sprintf("策略: %s\n当前状态: %s\n要求状态: %s", auditType, current, expected))
			if result.ConfigFile == "" {
				result.ConfigFile = "安全策略: secpol.msc"
				result.ConfigKey = auditType
				result.RawValue = fmt.Sprintf("%v", current)
			}
		}
	}

	if len(missingAudits) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("发现%d个审核策略配置不完整", len(missingAudits))
		result.Evidence = fmt.Sprintf("配置位置: secpol.msc -> 本地策略 -> 审核策略\n\n%s", strings.Join(problemAudits, "\n\n"))
	} else {
		result.Details = "审核策略配置符合要求"
	}

	return result
}

func checkWindowsLSASecurity(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-LSA-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	lsaSettings, ok := ctx.Config["lsa_settings"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取LSA配置信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "注册表: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA"
		result.ConfigKey = "LSA配置"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemLSA := []string{}

	restrictAnonymous := lsaSettings["RestrictAnonymous"]
	if restrictAnonymous != nil {
		cv := fmt.Sprintf("%v", restrictAnonymous)
		if cv == "0" {
			issue := "未限制匿名访问"
			issues = append(issues, issue)
			problemLSA = append(problemLSA, fmt.Sprintf("注册表项: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymous\n当前值: %s\n要求值: 1\n修复命令: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v RestrictAnonymous /t REG_DWORD /d 1 /f", cv))
			result.ConfigFile = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA"
			result.ConfigKey = "RestrictAnonymous"
			result.RawValue = cv
		}
	}

	disableDomainCreds := lsaSettings["DisableDomainCreds"]
	if disableDomainCreds != nil {
		cv := fmt.Sprintf("%v", disableDomainCreds)
		if cv == "0" {
			issue := "未禁用域凭据的存储"
			issues = append(issues, issue)
			problemLSA = append(problemLSA, fmt.Sprintf("注册表项: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\DisableDomainCreds\n当前值: %s\n要求值: 1", cv))
			if result.ConfigKey == "" {
				result.ConfigFile = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA"
				result.ConfigKey = "DisableDomainCreds"
				result.RawValue = cv
			}
		}
	}

	restrictRemoteSamAccount := lsaSettings["RestrictRemoteSamAccount"]
	if restrictRemoteSamAccount != nil {
		cv := fmt.Sprintf("%v", restrictRemoteSamAccount)
		if cv == "0" {
			issue := "未限制远程SAM账户访问"
			issues = append(issues, issue)
			problemLSA = append(problemLSA, fmt.Sprintf("注册表项: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictRemoteSamAccount\n当前值: %s\n要求值: 1", cv))
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("LSA安全配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置位置: 注册表编辑器 (regedit)\n\nLSA安全配置问题:\n\n%s", strings.Join(problemLSA, "\n\n"))
	} else {
		result.Details = "LSA安全配置正确"
	}

	return result
}

func checkWindowsUACStatus(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-UAC-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	uacLevel, ok := ctx.Config["uac_level"].(string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取UAC状态"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "注册表: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
		result.ConfigKey = "ConsentPromptBehaviorAdmin"
		result.RawValue = "无法读取"
		return result
	}

	level, err := strconv.Atoi(uacLevel)
	if err != nil {
		level = 0
	}

	if level < 2 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = "UAC未正确配置 (建议等级2-4)"
		result.ConfigFile = "注册表: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
		result.ConfigKey = "ConsentPromptBehaviorAdmin"
		result.RawValue = fmt.Sprintf("%d (等级: %d)", level, level)
		result.Evidence = fmt.Sprintf("UAC等级说明:\n- 0: 从不通知\n- 1: 仅在程序尝试更改时通知(不降低桌面亮度)\n- 2: 仅在程序尝试更改时通知(降低桌面亮度)- 默认等级\n- 3: 始终通知\n- 4: 始终通知(需要安全桌面)\n\n当前等级: %d\n建议等级: 2-4\n修复方法: 控制面板 -> 用户账户 -> 更改用户账户控制设置", level)
		result.ActualValue = level
		result.ExpectedValue = ">=2"
	} else {
		result.Details = fmt.Sprintf("UAC配置正确 (等级: %d)", level)
		result.ActualValue = level
	}

	return result
}

func checkWindowsFirewallStatus(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-FW-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	firewallStatus, ok := ctx.Config["firewall_status"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取防火墙状态"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "netsh advfirewall firewall show allprofiles"
		result.ConfigKey = "防火墙状态"
		result.RawValue = "无法读取"
		return result
	}

	domainEnabled := false
	privateEnabled := false
	publicEnabled := false

	if v, ok := firewallStatus["domain_enabled"].(bool); ok {
		domainEnabled = v
	}
	if v, ok := firewallStatus["private_enabled"].(bool); ok {
		privateEnabled = v
	}
	if v, ok := firewallStatus["public_enabled"].(bool); ok {
		publicEnabled = v
	}

	disabledProfiles := []string{}
	if !domainEnabled {
		disabledProfiles = append(disabledProfiles, "域")
	}
	if !privateEnabled {
		disabledProfiles = append(disabledProfiles, "专用")
	}
	if !publicEnabled {
		disabledProfiles = append(disabledProfiles, "公用")
	}

	if len(disabledProfiles) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 100
		result.Details = "Windows防火墙未在所有网络类型上启用"
		result.ConfigFile = "Windows Defender 防火墙 (wf.msc)"
		result.ConfigKey = "未启用的配置文件"
		result.RawValue = strings.Join(disabledProfiles, ", ")
		result.Evidence = fmt.Sprintf("未启用的防火墙配置文件: %s\n\n建议操作:\n1. 打开 Windows Defender 防火墙 (wf.msc)\n2. 点击左侧'Windows Defender 防火墙属性'\n3. 为每个配置文件(域、专用、公用)将'防火墙状态'设置为'启用'\n4. 点击确定保存", strings.Join(disabledProfiles, ", "))
		result.ActualValue = firewallStatus
		result.ExpectedValue = map[string]interface{}{
			"domain_enabled":  true,
			"private_enabled": true,
			"public_enabled":  true,
		}
	} else {
		result.Details = "Windows防火墙已正确启用"
		result.ActualValue = firewallStatus
	}

	return result
}

func checkWindowsSMBSecurity(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-SMB-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	smbSettings, ok := ctx.Config["smb_settings"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SMB配置信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "注册表: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
		result.ConfigKey = "SMB配置"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemSMB := []string{}

	smbv1Enabled := smbSettings["smbv1_enabled"]
	if smbv1Enabled != nil {
		if smbv1Enabled.(bool) {
			issue := "SMBv1协议已启用 (存在严重安全漏洞)"
			issues = append(issues, issue)
			problemSMB = append(problemSMB, "问题: SMBv1已启用\n风险: 极易受到WannaCry等勒索软件攻击\n修复方法: \n1. 运行: sc.exe config lanmanworks depend= RxNDRxSMBv2\n2. 或在注册表中设置: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> SMBv1 = 0\n3. 重启系统")
			result.ConfigFile = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
			result.ConfigKey = "SMBv1"
			result.RawValue = "已启用"
		}
	} else {
		smbv1Str := fmt.Sprintf("%v", smbv1Enabled)
		if strings.Contains(strings.ToLower(smbv1Str), "true") || smbv1Str == "1" {
			issue := "SMBv1协议可能已启用"
			issues = append(issues, issue)
			problemSMB = append(problemSMB, "SMBv1协议可能已启用，请检查注册表设置")
		}
	}

	requireSMB2 := smbSettings["require_smb2"]
	if requireSMB2 != nil {
		requireStr := fmt.Sprintf("%v", requireSMB2)
		if strings.Contains(strings.ToLower(requireStr), "false") || requireStr == "0" {
			issue := "未要求SMBv2/3签名"
			issues = append(issues, issue)
			problemSMB = append(problemSMB, "问题: 未要求SMBv2/3签名\n修复方法: 设置注册表项: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> RequireSecuritySignature = 1")
			if result.ConfigKey == "" {
				result.ConfigFile = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
				result.ConfigKey = "RequireSecuritySignature"
				result.RawValue = "未设置"
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelCritical
		result.Score = 100
		result.Details = fmt.Sprintf("SMB安全配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置位置: 注册表编辑器 (regedit)\n\n%s", strings.Join(problemSMB, "\n\n"))
		result.Evidence = strings.Join(issues, "\n")
	} else {
		result.Details = "SMB安全配置符合要求"
	}

	return result
}

func checkWindowsAnonymousRestriction(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WIN-ANON-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	restrictSettings, ok := ctx.Config["anonymous_restrictions"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取匿名限制配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "注册表: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA"
		result.ConfigKey = "匿名限制"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemAnon := []string{}

	restrictAnonymous, exists := restrictSettings["restrict_anonymous"]
	if !exists || fmt.Sprintf("%v", restrictAnonymous) != "1" {
		issues = append(issues, "未限制匿名访问")
		problemAnon = append(problemAnon, "注册表项: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymous\n当前值: 未配置\n要求值: 1\n修复: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v RestrictAnonymous /t REG_DWORD /d 1 /f")
		if result.ConfigFile == "" {
			result.ConfigFile = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA"
			result.ConfigKey = "RestrictAnonymous"
			result.RawValue = "未配置"
		}
	}

	restrictAnonymousSam, exists := restrictSettings["restrict_anonymous_sam"]
	if !exists || fmt.Sprintf("%v", restrictAnonymousSam) != "1" {
		issues = append(issues, "未限制SAM账户匿名枚举")
		problemAnon = append(problemAnon, "注册表项: HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymousSam\n当前值: 未配置\n要求值: 1\n修复: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v RestrictAnonymousSam /t REG_DWORD /d 1 /f")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("匿名访问限制配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置位置: 注册表编辑器 (regedit)\n\n需要修复的设置:\n\n%s", strings.Join(problemAnon, "\n\n"))
	} else {
		result.Details = "匿名访问限制已正确配置"
	}

	return result
}

func init() {
	for _, check := range GetWindowsAuditChecks() {
		RegisterCheck(check)
	}
}

var windowsChecksRegistered bool = false

func RegisterCheck(check *AuditCheck) {
}

func LoadWindowsChecks(engine *AuditEngine) {
	if !windowsChecksRegistered {
		checks := GetWindowsAuditChecks()
		for _, check := range checks {
			engine.RegisterCheck(check)
		}
		windowsChecksRegistered = true
	}
}

func ValidateWindowsCheckID(id string) bool {
	matched, _ := regexp.MatchString(`^WIN-[A-Z]+-\d{3}$`, id)
	return matched
}
