package configaudit

import (
	"fmt"
	"strings"
)

type SecurityIssueDisplay struct {
	Category    string
	CheckType   string
	ConfigKey   string
	ConfigValue string
	Description string
	RiskLevel   RiskLevel
	Advice      string
	Evidence    string
}

func NewSecurityIssueDisplay() *SecurityIssueDisplay {
	return &SecurityIssueDisplay{}
}

func (s *SecurityIssueDisplay) FormatIssue() string {
	riskIndicator := s.getRiskIndicator()
	border := strings.Repeat("-", 60)

	var builder strings.Builder
	builder.WriteString("\n")
	builder.WriteString(border + "\n")
	builder.WriteString(riskIndicator + " " + s.Category + "\n")
	builder.WriteString(border + "\n")
	
	if s.CheckType != "" {
		builder.WriteString(fmt.Sprintf("  配置项: %s\n", s.CheckType))
	}
	if s.ConfigKey != "" && s.ConfigValue != "" {
		builder.WriteString(fmt.Sprintf("  当前值: %s = %s\n", s.ConfigKey, s.ConfigValue))
	} else if s.ConfigKey != "" {
		builder.WriteString(fmt.Sprintf("  配置项: %s\n", s.ConfigKey))
	}
	if s.Description != "" {
		builder.WriteString(fmt.Sprintf("  问题: %s\n", s.Description))
	}
	if s.Advice != "" {
		builder.WriteString(fmt.Sprintf("  建议: %s\n", s.Advice))
	}
	if s.Evidence != "" {
		builder.WriteString("\n  证据:\n")
		builder.WriteString(fmt.Sprintf("    %s\n", s.Evidence))
	}
	builder.WriteString(border + "\n")
	
	return builder.String()
}

func (s *SecurityIssueDisplay) getRiskIndicator() string {
	switch s.RiskLevel {
	case RiskLevelCritical:
		return "[严重]"
	case RiskLevelHigh:
		return "[高危]"
	case RiskLevelMedium:
		return "[中危]"
	case RiskLevelLow:
		return "[低危]"
	default:
		return "[信息]"
	}
}

type SecurityCheckFormatter struct {
	issueDisplays []SecurityIssueDisplay
}

func NewSecurityCheckFormatter() *SecurityCheckFormatter {
	return &SecurityCheckFormatter{
		issueDisplays: []SecurityIssueDisplay{},
	}
}

func (f *SecurityCheckFormatter) AddIssue(issue SecurityIssueDisplay) {
	f.issueDisplays = append(f.issueDisplays, issue)
}

func (f *SecurityCheckFormatter) FormatAll() string {
	if len(f.issueDisplays) == 0 {
		return ""
	}

	var builder strings.Builder
	for _, issue := range f.issueDisplays {
		builder.WriteString(issue.FormatIssue())
	}
	return builder.String()
}

func (f *SecurityCheckFormatter) GetIssueCount() int {
	return len(f.issueDisplays)
}

func FormatSecurityIssue(category string, checkType string, configKey string, configValue string, description string, advice string, riskLevel RiskLevel, evidence string) string {
	display := SecurityIssueDisplay{
		Category:    category,
		CheckType:   checkType,
		ConfigKey:   configKey,
		ConfigValue: configValue,
		Description: description,
		RiskLevel:   riskLevel,
		Advice:      advice,
		Evidence:    evidence,
	}
	return display.FormatIssue()
}

func FormatSSHIssue(configKey string, configValue string, riskLevel RiskLevel) string {
	return FormatSecurityIssue(
		"OpenSSH配置不当",
		"SSH配置",
		configKey,
		configValue,
		fmt.Sprintf("SSH配置项 %s 的值为 %s", configKey, configValue),
		getSSHAdvice(configKey, configValue),
		riskLevel,
		"",
	)
}

func FormatLinuxIssue(category string, configKey string, configValue string, description string, advice string, riskLevel RiskLevel) string {
	return FormatSecurityIssue(
		category,
		"Linux系统配置",
		configKey,
		configValue,
		description,
		advice,
		riskLevel,
		"",
	)
}

func FormatWindowsIssue(category string, configKey string, configValue string, description string, advice string, riskLevel RiskLevel) string {
	return FormatSecurityIssue(
		category,
		"Windows安全配置",
		configKey,
		configValue,
		description,
		advice,
		riskLevel,
		"",
	)
}

func FormatMiddlewareIssue(middleware string, configKey string, configValue string, description string, advice string, riskLevel RiskLevel) string {
	return FormatSecurityIssue(
		fmt.Sprintf("%s配置不当", middleware),
		fmt.Sprintf("%s配置", middleware),
		configKey,
		configValue,
		description,
		advice,
		riskLevel,
		"",
	)
}

func getSSHAdvice(configKey string, configValue string) string {
	adviceMap := map[string]string{
		"PermitRootLogin":           "建议设置为 prohibit-password 或 no，禁止root直接登录",
		"PasswordAuthentication":    "建议设置为 no，禁用密码登录，使用密钥认证",
		"PermitEmptyPasswords":      "建议设置为 no，禁止空密码登录",
		"Protocol":                  "建议使用 Protocol 2，禁用不安全的Protocol 1",
		"X11Forwarding":             "如无必要建议设置为 no，减少攻击面",
		"AllowTcpForwarding":        "如无必要建议设置为 no，限制端口转发",
		"MaxAuthTries":              "建议设置较低的值，如 3 或 4",
		"MaxSessions":               "建议限制最大会话数",
		"ClientAliveInterval":       "建议设置合理的超时时间",
		"StrictModes":               "建议设置为 yes，检查文件权限",
		"IgnoreRhosts":              "建议设置为 yes，忽略.rhosts文件",
		"HostbasedAuthentication":   "建议设置为 no，禁用基于主机的认证",
		"PubkeyAuthentication":      "建议启用公钥认证并禁用密码认证",
		"AuthorizedKeysFile":        "确认授权密钥文件路径正确",
		"PermitUserEnvironment":     "建议设置为 no，禁止用户环境变量",
		"UseDNS":                    "建议设置为 no，加速连接并防止DNS欺骗",
		"AllowAgentForwarding":      "如无必要建议设置为 no",
		"GatewayPorts":              "建议设置为 no，禁止网关端口",
		"PermitTunnel":              "建议设置为 no，禁用隧道功能",
	}
	
	if advice, exists := adviceMap[configKey]; exists {
		return advice
	}
	return "建议检查此配置项是否符合安全要求"
}

func getLinuxAdvice(configKey string, configValue string) string {
	adviceMap := map[string]string{
		"net.ipv4.ip_forward":           "如非路由服务器，建议设置为 0，禁用IP转发",
		"net.ipv4.conf.all.accept_source_route": "建议设置为 0，禁用源路由",
		"net.ipv4.conf.default.accept_source_route": "建议设置为 0，禁用源路由",
		"net.ipv4.icmp_echo_ignore_broadcasts": "建议设置为 1，忽略ICMP广播",
		"net.ipv4.icmp_ignore_bogus_error_responses": "建议设置为 1，忽略错误ICMP",
		"net.ipv4.conf.all.rp_filter": "建议设置为 1，启用反向路径过滤",
		"net.ipv4.conf.default.rp_filter": "建议设置为 1，启用反向路径过滤",
		"kernel.randomize_va_space": "建议设置为 2，启用地址空间随机化",
		"fs.suid_dumpable": "建议设置为 0，禁止SUID程序core dump",
		"kernel.sysrq": "建议设置为 0，禁用SysReq",
		"fs.file-max": "根据系统资源调整文件描述符限制",
		"vm.swappiness": "建议设置为较低值，减少swap使用",
	}
	
	if advice, exists := adviceMap[configKey]; exists {
		return advice
	}
	return "建议检查此配置项是否符合安全基线要求"
}

func FormatCheckResultAsSecurityIssue(result *CheckResult, check *AuditCheck) string {
	if result.Status == CheckStatusPass {
		return ""
	}
	
	category := string(check.Category)
	configKey := result.ConfigKey
	configValue := result.RawValue
	
	var checkType string
	var description string
	var advice string
	
	switch check.Category {
	case CATEGORY_SSH:
		checkType = "SSH配置"
		description = fmt.Sprintf("SSH配置项 %s 的值为 %s", configKey, configValue)
		advice = getSSHAdvice(configKey, configValue)
	case CATEGORY_OS:
		if strings.Contains(strings.ToLower(check.ID), "linux") {
			checkType = "Linux系统配置"
			description = fmt.Sprintf("Linux配置项 %s 的值为 %s", configKey, configValue)
			advice = getLinuxAdvice(configKey, configValue)
		} else if strings.Contains(strings.ToLower(check.ID), "windows") {
			checkType = "Windows安全配置"
			description = fmt.Sprintf("Windows安全策略 %s 的值为 %s", configKey, configValue)
			advice = check.Remediation
		}
	case CATEGORY_MIDDLEWARE:
		checkType = "中间件配置"
		middlewareName := inferMiddlewareName(check.ID)
		description = fmt.Sprintf("%s 配置项 %s 的值为 %s", middlewareName, configKey, configValue)
		advice = check.Remediation
	case CATEGORY_WEB:
		checkType = "Web安全配置"
		description = fmt.Sprintf("Web安全配置 %s 的值为 %s", configKey, configValue)
		advice = check.Remediation
	default:
		checkType = "安全配置"
		description = result.Details
		advice = check.Remediation
	}
	
	return FormatSecurityIssue(
		category+"配置不当",
		checkType,
		configKey,
		configValue,
		description,
		advice,
		result.RiskLevel,
		result.Evidence,
	)
}

func inferMiddlewareName(checkID string) string {
	checkIDLower := strings.ToLower(checkID)
	if strings.Contains(checkIDLower, "mysql") || strings.Contains(checkIDLower, "mariadb") {
		return "MySQL"
	} else if strings.Contains(checkIDLower, "redis") {
		return "Redis"
	} else if strings.Contains(checkIDLower, "apache") {
		return "Apache"
	} else if strings.Contains(checkIDLower, "nginx") {
		return "Nginx"
	} else if strings.Contains(checkIDLower, "postgresql") {
		return "PostgreSQL"
	} else if strings.Contains(checkIDLower, "mongodb") {
		return "MongoDB"
	} else if strings.Contains(checkIDLower, "rabbitmq") {
		return "RabbitMQ"
	} else if strings.Contains(checkIDLower, "kafka") {
		return "Kafka"
	} else if strings.Contains(checkIDLower, "elasticsearch") {
		return "Elasticsearch"
	} else if strings.Contains(checkIDLower, "tomcat") {
		return "Tomcat"
	} else if strings.Contains(checkIDLower, "jdk") || strings.Contains(checkIDLower, "java") {
		return "Java"
	}
	return "中间件"
}
