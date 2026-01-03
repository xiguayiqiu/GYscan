package configaudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func GetSSHAuditChecks() []*AuditCheck {
	return []*AuditCheck{
		{
			ID:          "SSH-PROT-001",
			Name:        "SSH协议版本检查",
			Description: "验证SSH服务仅接受协议版本2连接",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityCritical,
			BaselineRef: "CIS-Linux-7-6.2.1",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "在sshd_config中设置: Protocol 2",
			Impact:      "SSH协议版本1存在多个严重安全漏洞",
			Execute:     checkSSHProtocolVersion,
		},
		{
			ID:          "SSH-AUTH-001",
			Name:        "SSH认证方式检查",
			Description: "验证SSH认证配置，禁用不安全的认证方式",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Linux-7-6.2.2",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用密码认证，强制使用公钥认证: PasswordAuthentication no",
			Impact:      "密码认证容易受到暴力破解攻击",
			Execute:     checkSSHAuthentication,
		},
		{
			ID:          "SSH-ROOT-001",
			Name:        "root用户SSH登录检查",
			Description: "验证是否禁止root用户直接SSH登录",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Linux-7-6.2.3",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: PermitRootLogin no 或 PermitRootLogin prohibit-password",
			Impact:      "允许root登录增加暴力破解和凭据泄露风险",
			Execute:     checkSSHRootLogin,
		},
		{
			ID:          "SSH-PERM-001",
			Name:        "SSH权限检查",
			Description: "验证SSH关键文件和目录的权限配置",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.4",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置sshd_config权限为0600，ssh目录权限为0700",
			Impact:      "不正确的权限可能允许未授权访问私钥",
			Execute:     checkSSHFilePermissions,
		},
		{
			ID:          "SSH-TMOUT-001",
			Name:        "SSH会话超时检查",
			Description: "验证SSH空闲会话超时配置",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.5",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: ClientAliveInterval 300, ClientAliveCountMax 2",
			Impact:      "未配置超时可能导致 abandoned会话被利用",
			Execute:     checkSSHTimeout,
		},
		{
			ID:          "SSH-X11-001",
			Name:        "SSH X11转发检查",
			Description: "验证是否禁用不必要的X11转发",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.6",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: X11Forwarding no",
			Impact:      "X11转发可能泄露显示内容或被利用",
			Execute:     checkSSHX11Forwarding,
		},
		{
			ID:          "SSH-FWD-001",
			Name:        "SSH端口转发检查",
			Description: "验证SSH端口转发配置是否安全",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.7",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "根据需要设置: AllowTcpForwarding yes/no, AllowAgentForwarding yes/no",
			Impact:      "不安全的端口转发可能绕过防火墙",
			Execute:     checkSSHPortForwarding,
		},
		{
			ID:          "SSH-HOSTKEY-001",
			Name:        "SSH主机密钥算法检查",
			Description: "验证SSH主机密钥算法配置是否安全",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Linux-7-6.2.8",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用dsa和ecdsa-sha2-nistp256，使用ed25519或rsa-sha2-512",
			Impact:      "弱主机密钥算法容易被攻破",
			Execute:     checkSSHHostKeyAlgorithms,
		},
		{
			ID:          "SSH-CIPHER-001",
			Name:        "SSH加密算法检查",
			Description: "验证SSH支持的加密算法是否安全",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Linux-7-6.2.9",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用3des-cbc, aes128-cbc等弱加密算法",
			Impact:      "弱加密算法可能被密码分析攻击",
			Execute:     checkSSHCiphers,
		},
		{
			ID:          "SSH-MAC-001",
			Name:        "SSH MAC算法检查",
			Description: "验证SSH消息认证码算法是否安全",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.10",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用hmac-md5, hmac-sha1等弱MAC算法",
			Impact:      "弱MAC算法可能允许消息篡改",
			Execute:     checkSSHMACs,
		},
		{
			ID:          "SSH-KEX-001",
			Name:        "SSH密钥交换算法检查",
			Description: "验证SSH密钥交换算法是否安全",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.11",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用diffie-hellman-group1-sha1等弱KEX算法",
			Impact:      "弱密钥交换算法可能泄露会话密钥",
			Execute:     checkSSHKeyExchange,
		},
		{
			ID:          "SSH-BANNER-001",
			Name:        "SSH登录警告横幅检查",
			Description: "验证SSH登录警告横幅是否配置",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityLow,
			BaselineRef: "CIS-Linux-7-6.2.12",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: Banner /etc/issue.net",
			Impact:      "缺少警告横幅可能影响法律追责",
			Execute:     checkSSHBanner,
		},
		{
			ID:          "SSH-MAXAUTH-001",
			Name:        "SSH认证尝试限制检查",
			Description: "验证SSH最大认证尝试次数配置",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.13",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: MaxAuthTries 4",
			Impact:      "无限制的认证尝试增加暴力破解风险",
			Execute:     checkSSHMaxAuthTries,
		},
		{
			ID:          "SSH-MAXSESS-001",
			Name:        "SSH最大会话数检查",
			Description: "验证SSH最大并发会话数配置",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityLow,
			BaselineRef: "CIS-Linux-7-6.2.14",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: MaxSessions 10",
			Impact:      "过多会话可能耗尽系统资源",
			Execute:     checkSSHMaxSessions,
		},
		{
			ID:          "SSH-LOGLEVEL-001",
			Name:        "SSH日志级别检查",
			Description: "验证SSH日志级别是否设置为INFO或以上",
			Category:    CATEGORY_SSH,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Linux-7-6.2.15",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "设置: LogLevel INFO",
			Impact:      "日志级别过低可能丢失安全事件记录",
			Execute:     checkSSHLogLevel,
		},
	}
}

func checkSSHProtocolVersion(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-PROT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "Protocol"
		result.RawValue = "无法读取"
		return result
	}

	protocol := sshConfig["Protocol"]
	if protocol == nil {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelCritical
		result.Score = 100
		result.Details = "未明确指定SSH协议版本，可能接受协议1"
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "Protocol"
		result.RawValue = "未设置"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n问题: Protocol指令未设置\n风险: SSH可能同时接受协议1和协议2\n建议: 添加配置 Protocol 2"
	} else {
		protocolStr := fmt.Sprintf("%v", protocol)
		result.RawValue = protocolStr
		if protocolStr == "2" {
			result.Details = "SSH协议版本配置正确(仅接受v2)"
		} else if protocolStr == "1" {
			result.Status = CheckStatusFail
			result.RiskLevel = RiskLevelCritical
			result.Score = 100
			result.Details = "SSH协议版本1已启用，存在严重安全漏洞"
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "Protocol"
			result.RawValue = "1"
			result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置值: Protocol 1\n风险: SSHv1存在多个严重漏洞(CVE-1999-0161等)\n建议: 立即修改为 Protocol 2"
		} else if protocolStr == "2,1" || protocolStr == "1,2" {
			result.Status = CheckStatusFail
			result.RiskLevel = RiskLevelCritical
			result.Score = 100
			result.Details = "SSH接受协议1和2，应仅使用协议2"
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "Protocol"
			result.RawValue = protocolStr
			result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置值: Protocol %s\n风险: 同时接受不安全的协议1\n建议: 修改为 Protocol 2", protocolStr)
		}
	}

	return result
}

func checkSSHAuthentication(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-AUTH-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "认证配置"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemAuth := []string{}

	passwordAuth := sshConfig["PasswordAuthentication"]
	if passwordAuth != nil {
		passwordStr := fmt.Sprintf("%v", passwordAuth)
		if passwordStr == "yes" || passwordStr == "true" {
			issues = append(issues, "允许密码认证")
			problemAuth = append(problemAuth, "配置项: PasswordAuthentication\n当前值: yes\n风险: 容易受到暴力破解攻击\n建议: 设置为 PasswordAuthentication no\n配置: PasswordAuthentication no")
			if result.ConfigFile == "" {
				result.ConfigFile = "/etc/ssh/sshd_config"
				result.ConfigKey = "PasswordAuthentication"
				result.RawValue = passwordStr
			}
		}
	}

	challengeResponseAuth := sshConfig["ChallengeResponseAuthentication"]
	if challengeResponseAuth != nil {
		chalStr := fmt.Sprintf("%v", challengeResponseAuth)
		if chalStr == "yes" || chalStr == "true" {
			issues = append(issues, "允许Challenge-Response认证")
			problemAuth = append(problemAuth, "配置项: ChallengeResponseAuthentication\n当前值: yes\n建议: 设置为 ChallengeResponseAuthentication no")
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/ssh/sshd_config"
				result.ConfigKey = "ChallengeResponseAuthentication"
				result.RawValue = chalStr
			}
		}
	}

	pubkeyAuth := sshConfig["PubkeyAuthentication"]
	if pubkeyAuth != nil {
		pubkeyStr := fmt.Sprintf("%v", pubkeyAuth)
		if pubkeyStr == "no" || pubkeyStr == "false" {
			issues = append(issues, "公钥认证已禁用")
			problemAuth = append(problemAuth, "配置项: PubkeyAuthentication\n当前值: no\n建议: 设置为 PubkeyAuthentication yes")
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/ssh/sshd_config"
				result.ConfigKey = "PubkeyAuthentication"
				result.RawValue = pubkeyStr
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("认证配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n\n认证配置问题:\n%s", strings.Join(problemAuth, "\n"))
	} else {
		result.Details = "SSH认证配置符合安全要求"
	}

	return result
}

func checkSSHRootLogin(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-ROOT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "PermitRootLogin"
		result.RawValue = "无法读取"
		return result
	}

	permitRootLogin := sshConfig["PermitRootLogin"]
	if permitRootLogin == nil {
		result.Status = CheckStatusWarning
		result.Details = "PermitRootLogin未设置，可能默认为yes"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "PermitRootLogin"
		result.RawValue = "未设置(默认yes)"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n问题: PermitRootLogin指令未设置\n默认行为: 可能允许root登录\n建议: 添加配置 PermitRootLogin no"
		return result
	}

	permitRootStr := fmt.Sprintf("%v", permitRootLogin)
	result.RawValue = permitRootStr
	result.ConfigKey = "PermitRootLogin"

	if permitRootStr == "yes" {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = "允许root用户SSH登录"
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置项: PermitRootLogin\n当前值: yes\n风险: root账户容易成为暴力破解目标\n建议: 设置为 PermitRootLogin no\n或: PermitRootLogin prohibit-password"
	} else if permitRootStr == "without-password" || permitRootStr == "prohibit-password" {
		result.Details = "root用户可登录但需要公钥认证"
	} else if permitRootStr == "no" {
		result.Details = "root用户SSH登录已禁用"
	}

	return result
}

func checkSSHFilePermissions(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-PERM-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	filePerms, ok := ctx.Config["ssh_file_permissions"].(map[string]string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH文件权限信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/"
		result.ConfigKey = "文件权限"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemPerms := []string{}

	requiredPerms := map[string]string{
		"/etc/ssh/sshd_config":           "0600",
		"/etc/ssh/ssh_host_rsa_key":      "0600",
		"/etc/ssh/ssh_host_ed25519_key":  "0600",
		"/root/.ssh":                     "0700",
		"/root/.ssh/authorized_keys":     "0600",
	}

	for path, requiredPerm := range requiredPerms {
		currentPerm, exists := filePerms[path]
		if !exists {
			issues = append(issues, fmt.Sprintf("文件不存在: %s", path))
			problemPerms = append(problemPerms, fmt.Sprintf("文件: %s\n状态: 文件不存在\n建议: 确保SSH正确安装", path))
		} else if currentPerm != requiredPerm {
			issues = append(issues, fmt.Sprintf("%s 权限不当: 当前=%s, 要求=%s", path, currentPerm, requiredPerm))
			problemPerms = append(problemPerms, fmt.Sprintf("文件: %s\n当前权限: %s\n要求权限: %s\n修复命令: chmod %s %s", path, currentPerm, requiredPerm, requiredPerm, path))
			if result.ConfigFile == "" {
				result.ConfigFile = path
				result.ConfigKey = "权限"
				result.RawValue = currentPerm
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("SSH文件权限问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("需要修复的文件权限:\n\n%s", strings.Join(problemPerms, "\n\n"))
	} else {
		result.Details = "SSH文件权限配置正确"
	}

	return result
}

func checkSSHTimeout(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-TMOUT-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "会话超时"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemTimeout := []string{}

	clientAliveInterval := sshConfig["ClientAliveInterval"]
	if clientAliveInterval == nil {
		issues = append(issues, "未配置ClientAliveInterval")
		problemTimeout = append(problemTimeout, "配置项: ClientAliveInterval\n当前值: 未设置\n建议值: 300\n配置: ClientAliveInterval 300")
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "ClientAliveInterval"
		result.RawValue = "未设置"
	} else {
		intervalStr := fmt.Sprintf("%v", clientAliveInterval)
		interval := 0
		fmt.Sscanf(intervalStr, "%d", &interval)
		result.RawValue = intervalStr
		if interval == 0 || interval > 300 {
			issue := fmt.Sprintf("ClientAliveInterval设置不当: %s", intervalStr)
			issues = append(issues, issue)
			problemTimeout = append(problemTimeout, fmt.Sprintf("配置项: ClientAliveInterval\n当前值: %s\n建议值: 300\n配置: ClientAliveInterval 300", intervalStr))
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/ssh/sshd_config"
				result.ConfigKey = "ClientAliveInterval"
			}
		}
	}

	clientAliveCountMax := sshConfig["ClientAliveCountMax"]
	if clientAliveCountMax == nil {
		issues = append(issues, "未配置ClientAliveCountMax")
		problemTimeout = append(problemTimeout, "配置项: ClientAliveCountMax\n当前值: 未设置\n建议值: 2\n配置: ClientAliveCountMax 2")
		if result.ConfigKey == "" {
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "ClientAliveCountMax"
			result.RawValue = "未设置"
		}
	} else {
		countStr := fmt.Sprintf("%v", clientAliveCountMax)
		count := 0
		fmt.Sscanf(countStr, "%d", &count)
		if count > 3 {
			issue := fmt.Sprintf("ClientAliveCountMax过高: %s", countStr)
			issues = append(issues, issue)
			problemTimeout = append(problemTimeout, fmt.Sprintf("配置项: ClientAliveCountMax\n当前值: %s\n建议值: <=3\n配置: ClientAliveCountMax 2", countStr))
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/ssh/sshd_config"
				result.ConfigKey = "ClientAliveCountMax"
				result.RawValue = countStr
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("会话超时配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n\n会话超时配置建议:\n%s", strings.Join(problemTimeout, "\n"))
	} else {
		result.Details = "SSH会话超时配置正确"
	}

	return result
}

func checkSSHX11Forwarding(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-X11-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "X11Forwarding"
		result.RawValue = "无法读取"
		return result
	}

	x11Forwarding := sshConfig["X11Forwarding"]
	if x11Forwarding != nil {
		x11Str := fmt.Sprintf("%v", x11Forwarding)
		result.RawValue = x11Str
		result.ConfigKey = "X11Forwarding"
		if x11Str == "yes" {
			result.Status = CheckStatusWarning
			result.RiskLevel = RiskLevelMedium
			result.Score = 50
			result.Details = "X11转发已启用，存在安全风险"
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置项: X11Forwarding\n当前值: yes\n风险: 可能泄露显示内容或被利用进行攻击\n建议: 设置为 X11Forwarding no"
		} else {
			result.Details = "X11转发已禁用"
		}
	} else {
		result.Details = "X11Forwarding未设置，可能默认为yes"
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "X11Forwarding"
		result.RawValue = "未设置"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置项: X11Forwarding\n当前值: 未设置(默认yes)\n建议: 显式设置为 X11Forwarding no"
	}

	return result
}

func checkSSHPortForwarding(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-FWD-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "端口转发"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemFwd := []string{}

	allowTcpForwarding := sshConfig["AllowTcpForwarding"]
	if allowTcpForwarding != nil {
		tcpStr := fmt.Sprintf("%v", allowTcpForwarding)
		result.RawValue = tcpStr
		if tcpStr == "yes" {
			issues = append(issues, "TCP端口转发已启用")
			problemFwd = append(problemFwd, "配置项: AllowTcpForwarding\n当前值: yes\n风险: 可能绕过防火墙限制\n建议: 根据需要设置为 no\n配置: AllowTcpForwarding no")
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.ConfigKey = "AllowTcpForwarding"
		}
	}

	allowAgentForwarding := sshConfig["AllowAgentForwarding"]
	if allowAgentForwarding != nil {
		agentStr := fmt.Sprintf("%v", allowAgentForwarding)
		if agentStr == "yes" {
			issues = append(issues, "Agent转发已启用")
			problemFwd = append(problemFwd, "配置项: AllowAgentForwarding\n当前值: yes\n风险: 可能被用于权限提升\n建议: 设置为 AllowAgentForwarding no")
			if result.ConfigKey == "" {
				result.ConfigFile = "/etc/ssh/sshd_config"
				result.ConfigKey = "AllowAgentForwarding"
				result.RawValue = agentStr
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = fmt.Sprintf("端口转发配置: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n\n端口转发配置建议:\n%s", strings.Join(problemFwd, "\n"))
	} else {
		result.Details = "SSH端口转发配置符合要求"
	}

	return result
}

func checkSSHHostKeyAlgorithms(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-HOSTKEY-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "HostKeyAlgorithms"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemHostKey := []string{}

	hostKeyAlgorithms := sshConfig["HostKeyAlgorithms"]
	if hostKeyAlgorithms != nil {
		algorithms := fmt.Sprintf("%v", hostKeyAlgorithms)
		result.RawValue = algorithms
		result.ConfigKey = "HostKeyAlgorithms"
		if strings.Contains(algorithms, "ssh-dss") || strings.Contains(algorithms, "ssh-rsa") {
			issues = append(issues, "使用了较弱的HostKey算法")
			problemHostKey = append(problemHostKey, "配置项: HostKeyAlgorithms\n当前值包含: ssh-dss 或 ssh-rsa\n风险: 这些算法可能不够安全\n建议: 优先使用 ed25519\n配置: HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519")
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = strings.Join(issues, "; ")
		result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n\n主机密钥算法建议:\n%s", strings.Join(problemHostKey, "\n"))
	} else {
		result.Details = "SSH主机密钥算法配置符合要求"
	}

	return result
}

func checkSSHCiphers(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-CIPHER-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "Ciphers"
		result.RawValue = "无法读取"
		return result
	}

	weakCiphers := []string{"3des", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish"}

	ciphers := sshConfig["Ciphers"]
	if ciphers != nil {
		cipherStr := fmt.Sprintf("%v", ciphers)
		result.RawValue = cipherStr
		result.ConfigKey = "Ciphers"
		for _, weak := range weakCiphers {
			if strings.Contains(cipherStr, weak) {
				result.Status = CheckStatusWarning
				result.RiskLevel = RiskLevelMedium
				result.Score = 50
				result.Details = fmt.Sprintf("使用了弱加密算法: %s", weak)
				result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置项: Ciphers\n当前值: %s\n弱算法: %s\n建议: 禁用弱算法\n推荐: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com", cipherStr, weak)
				return result
			}
		}
	}

	result.Details = "SSH加密算法配置符合要求"
	return result
}

func checkSSHMACs(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-MAC-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "MACs"
		result.RawValue = "无法读取"
		return result
	}

	weakMACs := []string{"hmac-md5", "hmac-sha1", "hmac-ripemd160"}

	macs := sshConfig["MACs"]
	if macs != nil {
		macStr := fmt.Sprintf("%v", macs)
		result.RawValue = macStr
		result.ConfigKey = "MACs"
		for _, weak := range weakMACs {
			if strings.Contains(macStr, weak) {
				result.Status = CheckStatusWarning
				result.RiskLevel = RiskLevelLow
				result.Score = 25
				result.Details = fmt.Sprintf("使用了弱MAC算法: %s", weak)
				result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置项: MACs\n当前值: %s\n弱算法: %s\n建议: 禁用弱算法\n推荐: hmac-sha2-512,hmac-sha2-256", macStr, weak)
				return result
			}
		}
	}

	result.Details = "SSH MAC算法配置符合要求"
	return result
}

func checkSSHKeyExchange(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-KEX-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "KexAlgorithms"
		result.RawValue = "无法读取"
		return result
	}

	weakKEX := []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}

	kexAlgorithms := sshConfig["KexAlgorithms"]
	if kexAlgorithms != nil {
		kexStr := fmt.Sprintf("%v", kexAlgorithms)
		result.RawValue = kexStr
		result.ConfigKey = "KexAlgorithms"
		for _, weak := range weakKEX {
			if strings.Contains(kexStr, weak) {
				result.Status = CheckStatusWarning
				result.RiskLevel = RiskLevelLow
				result.Score = 25
				result.Details = fmt.Sprintf("使用了弱密钥交换算法: %s", weak)
				result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置项: KexAlgorithms\n当前值: %s\n弱算法: %s\n建议: 禁用弱算法\n推荐: curve25519-sha256,ecdh-sha2-nistp521", kexStr, weak)
				return result
			}
		}
	}

	result.Details = "SSH密钥交换算法配置符合要求"
	return result
}

func checkSSHBanner(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-BANNER-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "Banner"
		result.RawValue = "无法读取"
		return result
	}

	banner := sshConfig["Banner"]
	if banner == nil || fmt.Sprintf("%v", banner) == "" {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = "未配置SSH登录警告横幅"
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "Banner"
		result.RawValue = "未设置"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置项: Banner\n当前值: 未设置\n建议: 添加警告横幅\n配置: Banner /etc/issue.net\n\n示例横幅内容: /etc/issue.net\n-------------------------------------------\n警告: 此系统仅限授权用户访问。\n所有活动可能被监控和记录。\n-------------------------------------------\n"
	} else {
		result.Details = "SSH登录警告横幅已配置"
		result.RawValue = fmt.Sprintf("%v", banner)
	}

	return result
}

func checkSSHMaxAuthTries(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-MAXAUTH-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "MaxAuthTries"
		result.RawValue = "无法读取"
		return result
	}

	maxAuthTries := sshConfig["MaxAuthTries"]
	if maxAuthTries == nil {
		result.Status = CheckStatusWarning
		result.Details = "MaxAuthTries未设置，默认值可能过高"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "MaxAuthTries"
		result.RawValue = "未设置(默认6)"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置项: MaxAuthTries\n当前值: 未设置(默认6)\n建议: 设置为更低的值\n配置: MaxAuthTries 4"
	} else {
		maxStr := fmt.Sprintf("%v", maxAuthTries)
		maxVal := 6
		fmt.Sscanf(maxStr, "%d", &maxVal)
		result.RawValue = maxStr
		result.ConfigKey = "MaxAuthTries"
		if maxVal > 4 {
			result.Status = CheckStatusWarning
			result.RiskLevel = RiskLevelMedium
			result.Score = 50
			result.Details = fmt.Sprintf("MaxAuthTries过高: %d (建议<=4)", maxVal)
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置项: MaxAuthTries\n当前值: %d\n建议值: <=4\n配置: MaxAuthTries 4", maxVal)
		} else {
			result.Details = "MaxAuthTries配置正确"
		}
	}

	return result
}

func checkSSHMaxSessions(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-MAXSESS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "MaxSessions"
		result.RawValue = "无法读取"
		return result
	}

	maxSessions := sshConfig["MaxSessions"]
	if maxSessions == nil {
		result.Details = "MaxSessions未设置，使用默认值"
	} else {
		maxStr := fmt.Sprintf("%v", maxSessions)
		maxVal := 10
		fmt.Sscanf(maxStr, "%d", &maxVal)
		result.RawValue = maxStr
		result.ConfigKey = "MaxSessions"
		if maxVal > 10 {
			result.Status = CheckStatusWarning
			result.RiskLevel = RiskLevelLow
			result.Score = 25
			result.Details = fmt.Sprintf("MaxSessions过高: %d", maxVal)
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置项: MaxSessions\n当前值: %d\n建议值: <=10\n配置: MaxSessions 10", maxVal)
		} else {
			result.Details = "MaxSessions配置正确"
		}
	}

	return result
}

func checkSSHLogLevel(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "SSH-LOGLEVEL-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sshConfig, ok := ctx.Config["ssh_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSH配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "LogLevel"
		result.RawValue = "无法读取"
		return result
	}

	logLevel := sshConfig["LogLevel"]
	if logLevel == nil {
		result.Status = CheckStatusWarning
		result.Details = "LogLevel未设置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "/etc/ssh/sshd_config"
		result.ConfigKey = "LogLevel"
		result.RawValue = "未设置"
		result.Evidence = "配置文件: /etc/ssh/sshd_config\n配置项: LogLevel\n当前值: 未设置\n建议: 设置为 INFO 或 VERBOSE\n配置: LogLevel INFO"
	} else {
		levelStr := strings.ToLower(fmt.Sprintf("%v", logLevel))
		result.RawValue = levelStr
		result.ConfigKey = "LogLevel"
		if levelStr == "quiet" || levelStr == "error" {
			result.Status = CheckStatusFail
			result.RiskLevel = RiskLevelMedium
			result.Score = 50
			result.Details = "LogLevel设置过低，可能丢失重要日志"
			result.ConfigFile = "/etc/ssh/sshd_config"
			result.Evidence = fmt.Sprintf("配置文件: /etc/ssh/sshd_config\n配置项: LogLevel\n当前值: %s\n建议值: INFO 或 VERBOSE\n配置: LogLevel INFO", levelStr)
		} else {
			result.Details = "LogLevel配置正确"
		}
	}

	return result
}

func init() {
	for _, check := range GetSSHAuditChecks() {
		RegisterSSHCheck(check)
	}
}

var sshChecksRegistered bool = false

func RegisterSSHCheck(check *AuditCheck) {
}

func LoadSSHChecks(engine *AuditEngine) {
	if !sshChecksRegistered {
		checks := GetSSHAuditChecks()
		for _, check := range checks {
			engine.RegisterCheck(check)
		}
		sshChecksRegistered = true
	}
}

func ValidateSSHCheckID(id string) bool {
	matched, _ := regexp.MatchString(`^SSH-[A-Z]+-\d{3}$`, id)
	return matched
}

func convertToInt(val interface{}) int {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}
