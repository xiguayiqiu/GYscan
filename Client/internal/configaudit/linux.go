package configaudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func GetLinuxAuditChecks() []*AuditCheck {
	return []*AuditCheck{
		{
			ID:          "LIN-ACCT-001",
			Name:        "Linux账户权限检查",
			Description: "检查Linux系统账户配置，验证root账户访问控制和用户权限",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Debian-11-1.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "限制sudo权限，禁用root SSH登录，配置PAM模块",
			Impact:      "不正确的账户权限可能导致未授权访问",
			Execute:     checkLinuxAccountRights,
		},
		{
			ID:          "LIN-PASS-001",
			Name:        "Linux密码策略检查",
			Description: "验证PAM密码策略配置是否符合安全要求",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeCompliance,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Debian-11-5.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置/etc/security/pwquality.conf和PAM模块",
			Impact:      "弱密码策略使系统容易受到暴力破解攻击",
			Execute:     checkLinuxPasswordPolicy,
		},
		{
			ID:          "LIN-SVC-001",
			Name:        "Linux服务状态检查",
			Description: "审计系统服务配置，禁用不必要的服务",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Debian-11-2.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "使用systemctl禁用不必要的服务",
			Impact:      "不必要的服务增加攻击面",
			Execute:     checkLinuxServices,
		},
		{
			ID:          "LIN-KRN-001",
			Name:        "Linux内核安全参数检查",
			Description: "验证内核参数配置是否符合安全最佳实践",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Debian-11-3.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "修改/etc/sysctl.conf配置参数",
			Impact:      "不安全的内核参数可能导致权限提升或信息泄露",
			Execute:     checkLinuxKernelParameters,
		},
		{
			ID:          "LIN-PERM-001",
			Name:        "Linux文件系统权限检查",
			Description: "检查关键文件和目录的权限配置",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Debian-11-6.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "使用chmod和chown修改文件权限",
			Impact:      "不正确的文件权限可能导致敏感信息泄露",
			Execute:     checkLinuxFilePermissions,
		},
		{
			ID:          "LIN-SSH-001",
			Name:        "SSH服务安全配置检查",
			Description: "验证SSH服务安全配置，包括协议版本和认证设置",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Debian-11-6.2",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "修改/etc/ssh/sshd_config配置",
			Impact:      "SSH配置不当可能导致未授权访问",
			Execute:     checkLinuxSSHConfig,
		},
		{
			ID:          "LIN-AUDIT-001",
			Name:        "Linux审计配置检查",
			Description: "验证审计服务(auditd)是否正确配置",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Debian-11-4.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "安装并配置auditd服务",
			Impact:      "缺乏审计将无法追踪安全事件",
			Execute:     checkLinuxAuditConfig,
		},
		{
			ID:          "LIN-FIREWALL-001",
			Name:        "Linux防火墙配置检查",
			Description: "验证iptables或firewalld配置是否符合安全要求",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Debian-11-3.5",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置防火墙规则限制入站连接",
			Impact:      "防火墙配置不当增加网络攻击风险",
			Execute:     checkLinuxFirewallConfig,
		},
		{
			ID:          "LIN-LOG-001",
			Name:        "系统日志配置检查",
			Description: "验证rsyslog或syslog-ng配置是否正确记录日志",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Debian-11-4.2",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置日志轮转和远程日志记录",
			Impact:      "日志配置不当可能丢失重要安全信息",
			Execute:     checkLinuxLogConfig,
		},
		{
			ID:          "LIN-UPDATE-001",
			Name:        "系统更新状态检查",
			Description: "检查系统安全更新是否及时安装",
			Category:    CATEGORY_OS,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Debian-11-1.2",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "运行系统更新命令安装安全补丁",
			Impact:      "未安装的安全补丁可能被利用进行攻击",
			Execute:     checkLinuxUpdateStatus,
		},
	}
}

func checkLinuxAccountRights(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-ACCT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	issues := []string{}
	evidence := []string{}

	sudoersRaw, _ := ctx.GetConfig("sudoers_users")
	sudoers, ok := sudoersRaw.([]string)
	if ok && len(sudoers) > 3 {
		issue := fmt.Sprintf("sudo用户数量过多: %d", len(sudoers))
		issues = append(issues, issue)
		evidence = append(evidence, fmt.Sprintf("配置文件: /etc/sudoers\nsudoers用户列表: %v", sudoers))
		result.ConfigFile = "/etc/sudoers"
		result.ConfigKey = "用户列表"
		result.RawValue = fmt.Sprintf("%v", sudoers)
	}

	rootLoginRaw, _ := ctx.GetConfig("root_ssh_login")
	rootLogin, ok := rootLoginRaw.(bool)
	if ok && rootLogin {
		issues = append(issues, "root账户可通过SSH直接登录")
		if len(evidence) == 0 {
			evidence = append(evidence, fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n%s", "PermitRootLogin: yes"))
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "PermitRootLogin"
			result.RawValue = "yes"
		}
	}

	passwordAuthRaw, _ := ctx.GetConfig("password_auth")
	passwordAuth, ok := passwordAuthRaw.(bool)
	if ok && passwordAuth {
		issues = append(issues, "允许使用密码进行SSH认证")
		if len(evidence) == 0 {
			evidence = append(evidence, fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n%s", "PasswordAuthentication: yes"))
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "PasswordAuthentication"
			result.RawValue = "yes"
		}
	}

	emptyPasswordsRaw, _ := ctx.GetConfig("empty_password_accounts")
	emptyPasswords, ok := emptyPasswordsRaw.([]string)
	if ok && len(emptyPasswords) > 0 {
		issues = append(issues, fmt.Sprintf("发现%d个空密码账户", len(emptyPasswords)))
		evidence = append(evidence, fmt.Sprintf("配置文件: /etc/shadow\n空密码账户: %v", emptyPasswords))
		if result.ConfigFile == "" {
			result.ConfigFile = "/etc/shadow"
			result.ConfigKey = "空密码账户"
			result.RawValue = fmt.Sprintf("%v", emptyPasswords)
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("发现%d个账户权限问题", len(issues))
		result.Evidence = strings.Join(evidence, "\n")
	} else {
		result.Details = "账户权限配置符合安全要求"
	}

	return result
}

func checkLinuxPasswordPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-PASS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	minLength := 12
	minClass := 4

	policyRaw, ok := ctx.GetConfig("password_policy")
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取密码策略信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/security/pwquality.conf"
		result.ConfigKey = "策略配置"
		result.RawValue = "无法读取配置"
		return result
	}

	policy, ok := policyRaw.(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "密码策略格式错误"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/security/pwquality.conf"
		result.ConfigKey = "策略配置"
		result.RawValue = "格式错误"
		return result
	}

	issues := []string{}
	problemDetails := []string{}

	if policy["min_length"] != nil {
		ml, _ := strconv.Atoi(fmt.Sprintf("%v", policy["min_length"]))
		if ml < minLength {
			issue := fmt.Sprintf("最小密码长度不足: %d (要求>=%d)", ml, minLength)
			issues = append(issues, issue)
			problemDetails = append(problemDetails, fmt.Sprintf("配置项: minlen = %d\n要求值: >= %d", ml, minLength))
			result.ConfigFile = "/etc/security/pwquality.conf"
			result.ConfigKey = "minlen"
			result.RawValue = fmt.Sprintf("%d", ml)
		}
	}

	if policy["min_class"] != nil {
		mc, _ := strconv.Atoi(fmt.Sprintf("%v", policy["min_class"]))
		if mc < minClass {
			issue := fmt.Sprintf("密码字符类别不足: %d (要求>=%d)", mc, minClass)
			issues = append(issues, issue)
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/security/pwquality.conf"
				result.ConfigKey = "minclass"
				result.RawValue = fmt.Sprintf("%d", mc)
			}
			problemDetails = append(problemDetails, fmt.Sprintf("配置项: minclass = %d\n要求值: >= %d", mc, minClass))
		}
	}

	if policy["retry"] != nil {
		retry, _ := strconv.Atoi(fmt.Sprintf("%v", policy["retry"]))
		if retry > 3 {
			issue := fmt.Sprintf("密码重试次数过多: %d (要求<=3)", retry)
			issues = append(issues, issue)
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/pam.d/common-auth"
				result.ConfigKey = "retry"
				result.RawValue = fmt.Sprintf("%d", retry)
			}
			problemDetails = append(problemDetails, fmt.Sprintf("配置项: retry = %d\n要求值: <= 3", retry))
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("密码策略不合规: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置文件: /etc/security/pwquality.conf\n\n%s", strings.Join(problemDetails, "\n"))
	} else {
		result.Details = "密码策略配置符合安全要求"
	}

	return result
}

func checkLinuxServices(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-SVC-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	dangerousServices := []string{
		"telnet", "rsh", "rlogin", "ypbind", "tftp",
		"chargen", "echo", "discard", "daytime", "time",
	}

	servicesRaw, ok := ctx.GetConfig("enabled_services")
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取服务列表"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/systemd/system"
		result.ConfigKey = "服务列表"
		result.RawValue = "无法读取"
		return result
	}

	services, ok := servicesRaw.([]string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "服务列表格式错误"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/systemd/system"
		result.ConfigKey = "服务列表"
		result.RawValue = "格式错误"
		return result
	}

	issues := []string{}
	problemServices := []string{}

	for _, service := range services {
		for _, dangerous := range dangerousServices {
			if strings.Contains(strings.ToLower(service), dangerous) {
				issues = append(issues, fmt.Sprintf("危险服务已启用: %s", service))
				problemServices = append(problemServices, service)
				break
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("发现%d个危险服务: %s", len(issues), strings.Join(issues, "; "))
		result.ConfigFile = "/etc/systemd/system"
		result.ConfigKey = "已启用的危险服务"
		result.RawValue = strings.Join(problemServices, ", ")
		result.Evidence = fmt.Sprintf("检测到的危险服务:\n%s", strings.Join(problemServices, "\n"))
	} else {
		result.Details = "服务配置符合安全要求"
	}

	return result
}

func checkLinuxKernelParameters(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-KRN-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	kernelParamsRaw, ok := ctx.GetConfig("kernel_params")
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取内核参数"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/proc/sys"
		result.ConfigKey = "内核参数"
		result.RawValue = "无法读取"
		return result
	}

	kernelParams, ok := kernelParamsRaw.(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "内核参数格式错误"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/proc/sys"
		result.ConfigKey = "内核参数"
		result.RawValue = "格式错误"
		return result
	}

	issues := []string{}
	problemParams := []string{}

	checkParam := func(paramName string, currentValue interface{}, safeValue string, description string) {
		cvStr := fmt.Sprintf("%v", currentValue)
		if cvStr != safeValue {
			issue := fmt.Sprintf("%s: 当前=%s, 安全值=%s", description, cvStr, safeValue)
			issues = append(issues, issue)
			problemParams = append(problemParams, fmt.Sprintf("文件: /proc/sys/%s\n当前值: %s\n要求值: %s", paramName, cvStr, safeValue))
			if result.ConfigFile == "" {
				result.ConfigFile = fmt.Sprintf("/proc/sys/%s", paramName)
				result.ConfigKey = paramName
				result.RawValue = cvStr
			}
		}
	}

	checkParam("net/ipv4/ip_forward", kernelParams["net.ipv4.ip_forward"], "0", "IP转发")
	checkParam("net/ipv4.icmp_echo_ignore_broadcasts", kernelParams["net.ipv4.icmp_echo_ignore_broadcasts"], "1", "ICMP广播")
	checkParam("net/ipv4.conf.all.rp_filter", kernelParams["net.ipv4.conf.all.rp_filter"], "1", "反向路径过滤")
	checkParam("net.ipv4.conf.all.send_redirects", kernelParams["net.ipv4.conf.all.send_redirects"], "0", "ICMP重定向")

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("发现%d个内核参数需要优化", len(issues))
		result.Evidence = fmt.Sprintf("需要修复的内核参数:\n\n%s", strings.Join(problemParams, "\n\n"))
	} else {
		result.Details = "内核参数配置符合安全要求"
	}

	return result
}

func checkLinuxFilePermissions(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-PERM-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sensitiveFiles := []struct {
		Path     string
		SafeMode string
		Desc     string
	}{
		{"/etc/passwd", "644", "用户账户文件"},
		{"/etc/shadow", "640", "用户密码文件"},
		{"/etc/group", "644", "用户组文件"},
		{"/etc/gshadow", "640", "用户组密码文件"},
		{"/etc/sudoers", "440", "sudoers配置文件"},
		{"/root/.ssh/authorized_keys", "600", "SSH授权密钥"},
	}

	filePermsRaw, ok := ctx.GetConfig("file_permissions")
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取文件权限信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		return result
	}

	filePerms, ok := filePermsRaw.(map[string]string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "文件权限信息格式错误"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		return result
	}

	issues := []string{}
	problemFiles := []string{}

	for _, file := range sensitiveFiles {
		currentPerm, exists := filePerms[file.Path]
		if !exists {
			issues = append(issues, fmt.Sprintf("文件不存在或无法访问: %s", file.Path))
		} else if currentPerm != file.SafeMode {
			issues = append(issues, fmt.Sprintf("%s 权限不当: 当前=%s, 要求=%s", file.Desc, currentPerm, file.SafeMode))
			problemFiles = append(problemFiles, fmt.Sprintf("文件: %s\n当前权限: %s\n要求权限: %s\n命令: chmod %s %s", file.Path, currentPerm, file.SafeMode, file.SafeMode, file.Path))
			if result.ConfigFile == "" {
				result.ConfigFile = file.Path
				result.ConfigKey = "权限"
				result.RawValue = currentPerm
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("发现%d个文件权限问题", len(issues))
		result.Evidence = fmt.Sprintf("权限不当的文件:\n\n%s", strings.Join(problemFiles, "\n\n"))
	} else {
		result.Details = "关键文件权限配置正确"
	}

	return result
}

func checkLinuxSSHConfig(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-SSH-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfigRaw, ok := ctx.GetConfig("ssh_config")
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "配置读取"
		result.RawValue = "无法读取"
		return result
	}

	sshConfig, ok := sshConfigRaw.(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "SSH配置格式错误"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "配置读取"
		result.RawValue = "格式错误"
		return result
	}

	issues := []string{}
	problemConfigs := []string{}

	protocol := sshConfig["protocol"]
	if protocol != nil && protocol.(string) == "1" {
		issues = append(issues, "SSH协议版本1已启用 (存在安全漏洞)")
		problemConfigs = append(problemConfigs, "Protocol = 1 (应改为 2)")
		if result.ConfigFile == "" {
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "Protocol"
			result.RawValue = "1"
		}
	}

	permitRootLogin := sshConfig["permit_root_login"]
	if permitRootLogin != nil && (permitRootLogin.(string) == "yes" || permitRootLogin.(string) == "without-password") {
		issues = append(issues, "允许root用户登录SSH")
		problemConfigs = append(problemConfigs, fmt.Sprintf("PermitRootLogin = %s (应改为 no)", permitRootLogin.(string)))
		if result.ConfigFile == "" {
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "PermitRootLogin"
			result.RawValue = permitRootLogin.(string)
		}
	}

	passwordAuth := sshConfig["password_authentication"]
	if passwordAuth != nil && passwordAuth.(string) == "yes" {
		issues = append(issues, "允许密码认证 (建议使用密钥认证)")
		problemConfigs = append(problemConfigs, "PasswordAuthentication = yes (应改为 no)")
		if result.ConfigFile == "" {
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "PasswordAuthentication"
			result.RawValue = "yes"
		}
	}

	permitEmptyPasswords := sshConfig["permit_empty_passwords"]
	if permitEmptyPasswords != nil && permitEmptyPasswords.(string) == "yes" {
		issues = append(issues, "允许空密码登录")
		problemConfigs = append(problemConfigs, "PermitEmptyPasswords = yes (应改为 no)")
		if result.ConfigFile == "" {
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "PermitEmptyPasswords"
			result.RawValue = "yes"
		}
	}

	x11Forwarding := sshConfig["x11_forwarding"]
	if x11Forwarding != nil && x11Forwarding.(string) == "yes" {
		issues = append(issues, "X11转发已启用 (存在安全风险)")
		problemConfigs = append(problemConfigs, "X11Forwarding = yes (应改为 no)")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("SSH配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n\n需要修复的配置项:\n%s", strings.Join(problemConfigs, "\n"))
	} else {
		result.Details = "SSH服务配置符合安全要求"
	}

	return result
}

func checkLinuxAuditConfig(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-AUDIT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	auditStatusRaw, _ := ctx.GetConfig("auditd_status")
	auditStatus, ok := auditStatusRaw.(string)
	if !ok || auditStatus != "running" {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = "审计服务(auditd)未运行"
		result.ConfigFile = "/etc/audit/auditd.conf"
		result.ConfigKey = "status"
		result.RawValue = auditStatus
		result.Evidence = fmt.Sprintf("服务状态: %s\n建议操作: systemctl start auditd", auditStatus)
		return result
	}

	auditRulesRaw, _ := ctx.GetConfig("audit_rules")
	auditRules, ok := auditRulesRaw.([]string)
	if ok {
		if len(auditRules) < 10 {
			result.Status = CheckStatusWarning
			result.RiskLevel = RiskLevelMedium
			result.Score = 50
			result.Details = "审计规则数量不足"
			result.ConfigFile = "/etc/audit/rules.d"
			result.ConfigKey = "规则数量"
			result.RawValue = fmt.Sprintf("%d", len(auditRules))
			result.Evidence = fmt.Sprintf("当前规则数: %d\n建议规则数: >= 10", len(auditRules))
		} else {
			result.Details = "审计服务配置正确"
		}
	} else {
		result.Details = "审计服务已运行，但无法检查规则"
	}

	return result
}

func checkLinuxFirewallConfig(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-FIREWALL-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	firewallStatusRaw, _ := ctx.GetConfig("firewall_status")
	firewallStatus, ok := firewallStatusRaw.(string)
	if !ok || (firewallStatus != "active" && firewallStatus != "iptables") {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = "防火墙状态未知或未激活"
		result.ConfigFile = "/etc/firewalld/firewalld.conf"
		result.ConfigKey = "DefaultZone"
		result.RawValue = firewallStatus
		result.Evidence = fmt.Sprintf("检测到的防火墙状态: %s\n建议操作: systemctl start firewalld", firewallStatus)
		return result
	}

	rulesCountRaw, _ := ctx.GetConfig("firewall_rules_count")
	rulesCount, ok := rulesCountRaw.(int)
	if !ok || rulesCount < 5 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = "防火墙规则可能不足"
		result.ConfigFile = "/etc/firewalld/zones"
		result.ConfigKey = "规则数量"
		if ok {
			result.RawValue = fmt.Sprintf("%d", rulesCount)
		} else {
			result.RawValue = "无法获取"
		}
		result.Evidence = fmt.Sprintf("当前规则数: %d\n建议规则数: >= 5", rulesCount)
	} else {
		result.Details = "防火墙配置符合要求"
	}

	return result
}

func checkLinuxLogConfig(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-LOG-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	logConfigRaw, ok := ctx.GetConfig("log_config")
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取日志配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/rsyslog.conf"
		result.ConfigKey = "配置读取"
		result.RawValue = "无法读取"
		return result
	}

	logConfig, ok := logConfigRaw.(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "日志配置格式错误"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/rsyslog.conf"
		result.ConfigKey = "配置读取"
		result.RawValue = "格式错误"
		return result
	}

	issues := []string{}
	problemLogs := []string{}

	rsyslogStatus := logConfig["rsyslog_status"]
	if rsyslogStatus != nil && rsyslogStatus.(string) != "running" {
		issues = append(issues, "rsyslog服务未运行")
		problemLogs = append(problemLogs, "服务状态: rsyslog未运行\n命令: systemctl start rsyslog")
		if result.ConfigFile == "" {
			result.ConfigFile = "/lib/systemd/system/rsyslog.service"
			result.ConfigKey = "ActiveState"
			result.RawValue = rsyslogStatus.(string)
		}
	}

	logRotation := logConfig["log_rotation"]
	if logRotation != nil && logRotation.(bool) == false {
		issues = append(issues, "日志轮转未配置")
		problemLogs = append(problemLogs, "配置: logrotate未配置\n检查: /etc/logrotate.conf")
		if result.ConfigFile == "" {
			result.ConfigFile = "/etc/logrotate.conf"
			result.ConfigKey = "配置状态"
			result.RawValue = "未配置"
		}
	}

	remoteLogging := logConfig["remote_logging"]
	if remoteLogging != nil && remoteLogging.(bool) == false {
		issues = append(issues, "未配置远程日志记录")
		problemLogs = append(problemLogs, "配置: 未配置远程日志\n建议: 在/etc/rsyslog.conf添加*.* @远程日志服务器")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = fmt.Sprintf("日志配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("日志配置问题详情:\n\n%s", strings.Join(problemLogs, "\n\n"))
	} else {
		result.Details = "日志配置符合要求"
	}

	return result
}

func checkLinuxUpdateStatus(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "LIN-UPDATE-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	pendingUpdates, ok := ctx.Config["pending_updates"].(int)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法检查更新状态"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/var/lib/dpkg"
		result.ConfigKey = "pending-updates"
		result.RawValue = "无法获取"
		return result
	}

	securityUpdates, _ := ctx.Config["security_updates"].(int)

	if pendingUpdates > 50 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelCritical
		result.Score = 100
		result.Details = fmt.Sprintf("存在大量待安装更新: %d个 (安全更新: %d个)", pendingUpdates, securityUpdates)
		result.ConfigFile = "/var/lib/apt"
		result.ConfigKey = "pending-updates"
		result.RawValue = fmt.Sprintf("%d", pendingUpdates)
		result.Evidence = fmt.Sprintf("待安装更新: %d个\n安全更新: %d个\n建议操作: apt-get update && apt-get upgrade", pendingUpdates, securityUpdates)
	} else if pendingUpdates > 10 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("存在%d个待安装更新", pendingUpdates)
		result.ConfigFile = "/var/lib/apt"
		result.ConfigKey = "pending-updates"
		result.RawValue = fmt.Sprintf("%d", pendingUpdates)
		result.Evidence = fmt.Sprintf("待安装更新: %d个\n建议操作: apt-get upgrade", pendingUpdates)
	} else if securityUpdates > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("存在%d个安全更新待安装", securityUpdates)
		result.ConfigFile = "/var/lib/apt"
		result.ConfigKey = "security-updates"
		result.RawValue = fmt.Sprintf("%d", securityUpdates)
		result.Evidence = fmt.Sprintf("安全更新: %d个\n建议操作: apt-get upgrade -security", securityUpdates)
	} else {
		result.Details = "系统已更新到最新版本"
	}

	return result
}

func init() {
	checks := GetLinuxAuditChecks()
	for _, check := range checks {
		if check != nil {
			check.OSType = OSLinux
		}
		RegisterLinuxCheck(check)
		RegisterCheckForReport(check)
	}
}

var linuxChecksRegistered bool = false

func RegisterLinuxCheck(check *AuditCheck) {
	if check != nil {
		check.OSType = OSLinux
		if globalCheckStore != nil {
			globalCheckStore.checks[check.ID] = check
		}
	}
}

func LoadLinuxChecks(engine *AuditEngine) {
	if !linuxChecksRegistered {
		checks := GetLinuxAuditChecks()
		for _, check := range checks {
			if check != nil {
				check.OSType = OSLinux
			}
			engine.RegisterCheck(check)
		}
		linuxChecksRegistered = true
	}
}

func ValidateLinuxCheckID(id string) bool {
	matched, _ := regexp.MatchString(`^LIN-[A-Z]+-\d{3}$`, id)
	return matched
}
