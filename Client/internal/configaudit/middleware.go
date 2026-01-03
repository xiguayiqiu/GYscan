package configaudit

import (
	"fmt"
	"regexp"
	"strings"
)

func GetMiddlewareAuditChecks() []*AuditCheck {
	return []*AuditCheck{
		{
			ID:          "MW-DB-001",
			Name:        "数据库账户权限检查",
			Description: "检查数据库用户权限配置是否遵循最小权限原则",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Database-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "移除不必要的数据库权限，禁用匿名账户",
			Impact:      "过度权限可能导致数据泄露或未授权访问",
			Execute:     checkDatabaseAccountRights,
		},
		{
			ID:          "MW-DB-002",
			Name:        "数据库网络访问控制检查",
			Description: "验证数据库是否限制非必要的网络访问",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Database-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置防火墙规则，仅允许可信IP访问数据库端口",
			Impact:      "公开暴露的数据库容易受到攻击",
			Execute:     checkDatabaseNetworkAccess,
		},
		{
			ID:          "MW-DB-003",
			Name:        "数据库加密配置检查",
			Description: "验证数据库传输层和存储层加密配置",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Database-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "启用SSL/TLS连接，配置透明数据加密(TDE)",
			Impact:      "未加密的通信可能被中间人攻击",
			Execute:     checkDatabaseEncryption,
		},
		{
			ID:          "MW-DB-004",
			Name:        "数据库审计日志检查",
			Description: "验证数据库审计功能是否正确配置",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Database-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "启用数据库审计功能，记录关键操作",
			Impact:      "缺乏审计无法追踪数据访问和变更",
			Execute:     checkDatabaseAuditLogging,
		},
		{
			ID:          "MW-DB-005",
			Name:        "数据库密码策略检查",
			Description: "验证数据库用户密码策略是否安全",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeCompliance,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Database-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置强密码策略，设置最小长度和复杂度要求",
			Impact:      "弱密码可能导致数据库被暴力破解",
			Execute:     checkDatabasePasswordPolicy,
		},
		{
			ID:          "MW-APP-001",
			Name:        "应用服务器管理接口检查",
			Description: "检查应用服务器管理控制台的安全性",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-AppServer-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用或保护管理接口，使用强认证",
			Impact:      "暴露的管理接口可能导致完全控制权丢失",
			Execute:     checkAppServerManagement,
		},
		{
			ID:          "MW-APP-002",
			Name:        "应用服务器安全配置检查",
			Description: "验证应用服务器安全配置是否正确",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-AppServer-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用危险功能，配置安全的会话管理",
			Impact:      "不安全的应用服务器配置可能被利用",
			Execute:     checkAppServerSecurity,
		},
		{
			ID:          "MW-CACHE-001",
			Name:        "缓存服务器安全配置检查",
			Description: "验证Redis/Memcached等缓存服务器安全配置",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "CIS-Cache-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "启用认证，禁用危险命令，限制网络访问",
			Impact:      "不安全的缓存服务器可能导致数据泄露",
			Execute:     checkCacheServerSecurity,
		},
		{
			ID:          "MW-MQ-001",
			Name:        "消息队列安全配置检查",
			Description: "验证RabbitMQ/Kafka等消息队列安全配置",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-MQ-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "启用认证，配置ACL，启用TLS加密",
			Impact:      "不安全的消息队列可能被未授权访问",
			Execute:     checkMessageQueueSecurity,
		},
		{
			ID:          "MW-LOG-001",
			Name:        "中间件日志配置检查",
			Description: "验证中间件日志记录是否完整",
			Category:    CATEGORY_MIDDLEWARE,
			AuditType:   AuditTypeOperational,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Middleware-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "配置详细日志，设置日志轮转和归档",
			Impact:      "不完整的日志影响故障排查和安全分析",
			Execute:     checkMiddlewareLogging,
		},
	}
}

func checkDatabaseAccountRights(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-DB-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	dbConfig, ok := ctx.Config["database_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取数据库配置"
		result.ConfigFile = "database_config"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: database_config\n\n无法获取数据库配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	anonUsers := dbConfig["anonymous_users"]
	if anonUsers != nil && anonUsers.(bool) {
		issues = append(issues, "存在匿名数据库用户")
		evidenceDetails = append(evidenceDetails, "配置项: anonymous_users\n当前值: true\n风险: 匿名用户可无需认证访问数据库\n建议: 设置为 anonymous_users = false")
	}

	rootAccessUsers := dbConfig["root_access_users"]
	if rootAccessUsers != nil {
		users := rootAccessUsers.([]string)
		if len(users) > 1 {
			issues = append(issues, fmt.Sprintf("拥有root权限的用户过多: %d个", len(users)))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: root_access_users\n当前值: %v\n风险: 过多用户拥有root权限增加误用风险\n建议: 仅保留必要的root账户", users))
		}
	}

	emptyPasswordUsers := dbConfig["empty_password_users"]
	if emptyPasswordUsers != nil {
		users := emptyPasswordUsers.([]string)
		if len(users) > 0 {
			issues = append(issues, fmt.Sprintf("发现%d个空密码用户", len(users)))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: empty_password_users\n当前值: %v\n风险: 空密码用户可被直接登录\n建议: 为所有用户设置强密码", users))
		}
	}

	publicSchemas := dbConfig["public_schema_access"]
	if publicSchemas != nil && publicSchemas.(bool) {
		issues = append(issues, "public模式可被任意用户访问")
		evidenceDetails = append(evidenceDetails, "配置项: public_schema_access\n当前值: true\n风险: public模式暴露可能导致数据泄露\n建议: 限制public模式的访问权限")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("数据库权限问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "database_config"
		result.ConfigKey = "anonymous_users, root_access_users, empty_password_users, public_schema_access"
		result.RawValue = fmt.Sprintf("anon=%v, root_users=%v, empty_pwd=%v, public=%v",
			anonUsers, rootAccessUsers, emptyPasswordUsers, publicSchemas)
		result.Evidence = fmt.Sprintf("配置文件: database_config (数据库配置)\n\n%s\n\n修复建议:\n1. 禁用匿名用户访问\n2. 限制root权限用户数量\n3. 为所有用户设置强密码\n4. 限制public模式访问", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "数据库权限配置符合安全要求"
		result.ConfigFile = "database_config"
		result.ConfigKey = "所有权限配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: database_config\n\n数据库权限配置符合安全要求:\n- 无匿名用户\n- root权限用户数量合理\n- 无空密码用户\n- public模式访问已限制"
	}

	return result
}

func checkDatabaseNetworkAccess(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-DB-002",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	netConfig, ok := ctx.Config["database_network"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取数据库网络配置"
		result.ConfigFile = "database_network"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: database_network\n\n无法获取数据库网络配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	bindAddress := netConfig["bind_address"]
	if bindAddress != nil {
		addr := fmt.Sprintf("%v", bindAddress)
		if addr == "0.0.0.0" || addr == "::" {
			issues = append(issues, "数据库绑定到所有网络接口")
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: bind_address\n当前值: %s\n风险: 数据库监听所有网络接口，可被公网访问\n建议: 设置为127.0.0.1或特定内网IP", addr))
		}
	}

	publicAccess := netConfig["public_access"]
	if publicAccess != nil && publicAccess.(bool) {
		issues = append(issues, "数据库可从公网访问")
		evidenceDetails = append(evidenceDetails, "配置项: public_access\n当前值: true\n风险: 公网可直接访问数据库，容易被攻击\n建议: 设置为false并通过VPN或堡垒机访问")
	}

	skipNetTables := netConfig["skip_networking"]
	if skipNetTables != nil && skipNetTables.(bool) == false {
		issues = append(issues, "网络连接已启用")
		evidenceDetails = append(evidenceDetails, "配置项: skip_networking\n当前值: false (网络连接启用)\n风险: 允许网络连接增加了攻击面\n建议: 如无需远程访问，设置为true")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("数据库网络访问问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "database_network"
		result.ConfigKey = "bind_address, public_access, skip_networking"
		result.RawValue = fmt.Sprintf("bind=%v, public=%v, skip_net=%v", bindAddress, publicAccess, skipNetTables)
		result.Evidence = fmt.Sprintf("配置文件: database_network (数据库网络配置)\n\n%s\n\n修复建议:\n1. 将bind_address设置为127.0.0.1或特定内网IP\n2. 禁用公网访问(public_access=false)\n3. 如无需远程访问，启用skip_networking", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "数据库网络访问控制符合要求"
		result.ConfigFile = "database_network"
		result.ConfigKey = "所有网络配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: database_network\n\n数据库网络访问控制符合安全要求:\n- 未绑定到所有网络接口\n- 公网访问已禁用\n- 网络连接已适当配置"
	}

	return result
}

func checkDatabaseEncryption(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-DB-003",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	encConfig, ok := ctx.Config["database_encryption"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取数据库加密配置"
		result.ConfigFile = "database_encryption"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: database_encryption\n\n无法获取数据库加密配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	sslRequired := encConfig["require_ssl"]
	if sslRequired != nil && sslRequired.(bool) == false {
		issues = append(issues, "未强制要求SSL连接")
		evidenceDetails = append(evidenceDetails, "配置项: require_ssl\n当前值: false\n风险: 允许非SSL连接，数据传输可能被窃听\n建议: 设置为require_ssl = true")
	}

	sslMode := encConfig["ssl_mode"]
	if sslMode != nil {
		mode := fmt.Sprintf("%v", sslMode)
		if mode == "disable" || mode == "allow" {
			issues = append(issues, fmt.Sprintf("SSL模式不安全: %s", mode))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: ssl_mode\n当前值: %s\n风险: SSL模式不安全，允许未加密连接\n建议: 设置为ssl_mode = verify-full或verify-ca", mode))
		}
	}

	tdeEnabled := encConfig["tde_enabled"]
	if tdeEnabled != nil && tdeEnabled.(bool) == false {
		issues = append(issues, "未启用透明数据加密(TDE)")
		evidenceDetails = append(evidenceDetails, "配置项: tde_enabled\n当前值: false\n风险: 存储数据未加密，磁盘被窃取可能导致数据泄露\n建议: 启用TDE加密存储数据")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("数据库加密配置问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "database_encryption"
		result.ConfigKey = "require_ssl, ssl_mode, tde_enabled"
		result.RawValue = fmt.Sprintf("ssl_req=%v, ssl_mode=%v, tde=%v", sslRequired, sslMode, tdeEnabled)
		result.Evidence = fmt.Sprintf("配置文件: database_encryption (数据库加密配置)\n\n%s\n\n修复建议:\n1. 强制要求SSL连接(require_ssl=true)\n2. 设置SSL模式为verify-full或verify-ca\n3. 启用透明数据加密(TDE)", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "数据库加密配置符合要求"
		result.ConfigFile = "database_encryption"
		result.ConfigKey = "所有加密配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: database_encryption\n\n数据库加密配置符合安全要求:\n- 已强制要求SSL连接\n- SSL模式配置安全\n- 已启用TDE加密"
	}

	return result
}

func checkDatabaseAuditLogging(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-DB-004",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	auditConfig, ok := ctx.Config["database_audit"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取数据库审计配置"
		result.ConfigFile = "database_audit"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: database_audit\n\n无法获取数据库审计配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	auditEnabled := auditConfig["audit_enabled"]
	if auditEnabled != nil && auditEnabled.(bool) == false {
		issues = append(issues, "数据库审计未启用")
		evidenceDetails = append(evidenceDetails, "配置项: audit_enabled\n当前值: false\n风险: 无法审计和追踪数据库操作，安全事件无法溯源\n建议: 设置为audit_enabled = true")
	}

	logConnections := auditConfig["log_connections"]
	if logConnections != nil && logConnections.(bool) == false {
		issues = append(issues, "未记录连接日志")
		evidenceDetails = append(evidenceDetails, "配置项: log_connections\n当前值: false\n风险: 无法追踪谁连接了数据库\n建议: 设置为log_connections = true")
	}

	logStatements := auditConfig["log_statements"]
	if logStatements != nil && logStatements.(bool) == false {
		issues = append(issues, "未记录语句执行日志")
		evidenceDetails = append(evidenceDetails, "配置项: log_statements\n当前值: false\n风险: 无法追踪执行的SQL语句\n建议: 设置为log_statements = true")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("数据库审计问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "database_audit"
		result.ConfigKey = "audit_enabled, log_connections, log_statements"
		result.RawValue = fmt.Sprintf("audit=%v, conn=%v, stmt=%v", auditEnabled, logConnections, logStatements)
		result.Evidence = fmt.Sprintf("配置文件: database_audit (数据库审计配置)\n\n%s\n\n修复建议:\n1. 启用数据库审计功能(audit_enabled=true)\n2. 启用连接日志记录(log_connections=true)\n3. 启用语句执行日志(log_statements=true)", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "数据库审计配置符合要求"
		result.ConfigFile = "database_audit"
		result.ConfigKey = "所有审计配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: database_audit\n\n数据库审计配置符合安全要求:\n- 审计功能已启用\n- 连接日志已记录\n- 语句执行日志已记录"
	}

	return result
}

func checkDatabasePasswordPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-DB-005",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	policyConfig, ok := ctx.Config["database_password_policy"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取密码策略配置"
		result.ConfigFile = "database_password_policy"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: database_password_policy\n\n无法获取数据库密码策略配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	minLength := policyConfig["min_length"]
	if minLength != nil {
		length := minLength.(int)
		if length < 12 {
			issues = append(issues, fmt.Sprintf("最小密码长度不足: %d (要求>=12)", length))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: min_length\n当前值: %d\n风险: 短密码容易被暴力破解\n建议: 设置为min_length = 12或更长", length))
		}
	}

	passwordExpiry := policyConfig["password_expiry"]
	if passwordExpiry != nil {
		expiry := passwordExpiry.(int)
		if expiry > 90 {
			issues = append(issues, fmt.Sprintf("密码过期时间过长: %d天 (要求<=90)", expiry))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: password_expiry\n当前值: %d天\n风险: 长期不更换密码增加泄露风险\n建议: 设置为password_expiry = 90或更短", expiry))
		}
	}

	reuseCount := policyConfig["password_reuse_count"]
	if reuseCount != nil {
		reuse := reuseCount.(int)
		if reuse > 5 {
			issues = append(issues, fmt.Sprintf("允许重用密码次数过多: %d (要求<=5)", reuse))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: password_reuse_count\n当前值: %d\n风险: 允许重用密码降低了密码历史策略的有效性\n建议: 设置为password_reuse_count = 5或更少", reuse))
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("数据库密码策略问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "database_password_policy"
		result.ConfigKey = "min_length, password_expiry, password_reuse_count"
		result.RawValue = fmt.Sprintf("minlen=%d, expiry=%d天, reuse=%d", getIntOrDefault(minLength, 0), getIntOrDefault(passwordExpiry, 0), getIntOrDefault(reuseCount, 0))
		result.Evidence = fmt.Sprintf("配置文件: database_password_policy (数据库密码策略配置)\n\n%s\n\n修复建议:\n1. 设置最小密码长度为12位以上\n2. 设置密码过期时间为90天以内\n3. 限制密码重用次数为5次以内", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "数据库密码策略符合要求"
		result.ConfigFile = "database_password_policy"
		result.ConfigKey = "所有密码策略配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: database_password_policy\n\n数据库密码策略符合安全要求:\n- 最小密码长度符合要求\n- 密码过期时间合理\n- 密码重用限制有效"
	}

	return result
}

func checkAppServerManagement(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-APP-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	appConfig, ok := ctx.Config["app_server_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取应用服务器配置"
		result.ConfigFile = "app_server_config"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: app_server_config\n\n无法获取应用服务器配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	managementEnabled := appConfig["management_interface"]
	if managementEnabled != nil && managementEnabled.(bool) {
		issues = append(issues, "管理接口已启用")

		managementAuth := appConfig["management_auth"]
		if managementAuth == nil || managementAuth.(bool) == false {
			issues = append(issues, "管理接口未启用认证")
			evidenceDetails = append(evidenceDetails, "配置项: management_interface = true, management_auth = false\n当前值: 管理接口已启用但未启用认证\n风险: 未认证的管理接口可被任意访问\n建议: 设置为management_auth = true或禁用管理接口")
		} else {
			evidenceDetails = append(evidenceDetails, "配置项: management_interface = true, management_auth = true\n当前值: 管理接口已启用且已配置认证")
		}
	} else {
		evidenceDetails = append(evidenceDetails, "配置项: management_interface = false\n当前值: 管理接口已禁用\n状态: 安全")
	}

	defaultCredentials := appConfig["default_credentials"]
	if defaultCredentials != nil && defaultCredentials.(bool) {
		issues = append(issues, "可能使用默认凭据")
		evidenceDetails = append(evidenceDetails, "配置项: default_credentials\n当前值: true\n风险: 默认凭据是常见攻击目标\n建议: 更换所有默认用户名和密码")
	}

	managementPort := appConfig["management_port"]
	if managementPort != nil {
		port := managementPort.(int)
		if port < 1024 {
			issues = append(issues, "管理端口号异常")
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: management_port\n当前值: %d\n风险: 低端口可能需要root权限运行\n建议: 使用1024以上端口", port))
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("应用服务器管理问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "app_server_config"
		result.ConfigKey = "management_interface, management_auth, default_credentials, management_port"
		result.RawValue = fmt.Sprintf("enabled=%v, auth=%v, default_cred=%v, port=%v",
			managementEnabled, appConfig["management_auth"], defaultCredentials, managementPort)
		result.Evidence = fmt.Sprintf("配置文件: app_server_config (应用服务器配置)\n\n%s\n\n修复建议:\n1. 如不需要，禁用管理接口\n2. 必须启用管理接口认证\n3. 更换所有默认凭据\n4. 使用非特权端口(>1024)", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "应用服务器管理配置符合要求"
		result.ConfigFile = "app_server_config"
		result.ConfigKey = "所有管理配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: app_server_config\n\n应用服务器管理配置符合安全要求:\n- 管理接口已适当配置\n- 认证已启用\n- 无默认凭据\n- 端口配置正常"
	}

	return result
}

func checkAppServerSecurity(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-APP-002",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	secConfig, ok := ctx.Config["app_server_security"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取应用服务器安全配置"
		result.ConfigFile = "app_server_security"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: app_server_security\n\n无法获取应用服务器安全配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	sessionTimeout := secConfig["session_timeout"]
	if sessionTimeout != nil {
		timeout := sessionTimeout.(int)
		if timeout > 1800 {
			issues = append(issues, fmt.Sprintf("会话超时过长: %d秒", timeout))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: session_timeout\n当前值: %d秒\n风险: 长会话超时增加会话劫持风险\n建议: 设置为session_timeout = 1800或更短", timeout))
		} else {
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: session_timeout\n当前值: %d秒\n状态: 符合要求", timeout))
		}
	}

	debugMode := secConfig["debug_mode"]
	if debugMode != nil && debugMode.(bool) {
		issues = append(issues, "服务器处于调试模式")
		evidenceDetails = append(evidenceDetails, "配置项: debug_mode\n当前值: true\n风险: 调试模式可能泄露敏感信息\n建议: 设置为debug_mode = false")
	}

	sampleApps := secConfig["sample_applications"]
	if sampleApps != nil && sampleApps.(bool) {
		issues = append(issues, "示例应用未移除")
		evidenceDetails = append(evidenceDetails, "配置项: sample_applications\n当前值: true\n风险: 示例应用可能存在已知漏洞\n建议: 移除所有示例应用和测试页面")
	}

	hotDeployment := secConfig["hot_deployment"]
	if hotDeployment != nil && hotDeployment.(bool) {
		issues = append(issues, "热部署功能已启用")
		evidenceDetails = append(evidenceDetails, "配置项: hot_deployment\n当前值: true\n风险: 热部署可能绕过安全检查\n建议: 生产环境禁用热部署功能")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("应用服务器安全问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "app_server_security"
		result.ConfigKey = "session_timeout, debug_mode, sample_applications, hot_deployment"
		result.RawValue = fmt.Sprintf("timeout=%d, debug=%v, samples=%v, hot_deploy=%v",
			getIntOrDefault(sessionTimeout, 0), debugMode, sampleApps, hotDeployment)
		result.Evidence = fmt.Sprintf("配置文件: app_server_security (应用服务器安全配置)\n\n%s\n\n修复建议:\n1. 将会话超时设置为30分钟以内\n2. 生产环境禁用调试模式\n3. 移除所有示例应用\n4. 生产环境禁用热部署", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "应用服务器安全配置符合要求"
		result.ConfigFile = "app_server_security"
		result.ConfigKey = "所有安全配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: app_server_security\n\n应用服务器安全配置符合安全要求:\n- 会话超时设置合理\n- 调试模式已禁用\n- 无示例应用\n- 热部署功能已适当配置"
	}

	return result
}

func checkCacheServerSecurity(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-CACHE-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	cacheConfig, ok := ctx.Config["cache_server_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取缓存服务器配置"
		result.ConfigFile = "cache_server_config"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: cache_server_config\n\n无法获取缓存服务器配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	noAuth := cacheConfig["no_password_required"]
	if noAuth != nil && noAuth.(bool) {
		issues = append(issues, "未配置密码认证")
		evidenceDetails = append(evidenceDetails, "配置项: no_password_required\n当前值: true\n风险: 任何人都可访问缓存数据\n建议: 设置为requirepass <your_password>")
	}

	bindAll := cacheConfig["bind_all_interfaces"]
	if bindAll != nil && bindAll.(bool) {
		issues = append(issues, "缓存服务器绑定到所有网络接口")
		evidenceDetails = append(evidenceDetails, "配置项: bind_all_interfaces\n当前值: true\n风险: 缓存服务器可被公网访问\n建议: 设置为仅监听127.0.0.1或特定内网IP")
	}

	flushCommand := cacheConfig["flush_command_protected"]
	if flushCommand != nil && flushCommand.(bool) == false {
		issues = append(issues, "危险命令(FLUSHALL)未受保护")
		evidenceDetails = append(evidenceDetails, "配置项: flush_command_protected\n当前值: false\n风险: FLUSHALL命令可清空所有数据\n建议: 使用rename-command FLUSHALL <new_command>重命名危险命令")
	}

	persistData := cacheConfig["persistence_enabled"]
	if persistData != nil && persistData.(bool) == false {
		issues = append(issues, "未启用持久化")
		evidenceDetails = append(evidenceDetails, "配置项: persistence_enabled\n当前值: false\n风险: 服务重启后数据丢失\n建议: 根据业务需求启用RDB或AOF持久化")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("缓存服务器安全问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "cache_server_config"
		result.ConfigKey = "no_password_required, bind_all_interfaces, flush_command_protected, persistence_enabled"
		result.RawValue = fmt.Sprintf("no_auth=%v, bind_all=%v, flush_protected=%v, persist=%v",
			noAuth, bindAll, flushCommand, persistData)
		result.Evidence = fmt.Sprintf("配置文件: cache_server_config (缓存服务器配置)\n\n%s\n\n修复建议:\n1. 配置强密码认证(requirepass)\n2. 绑定到内网接口\n3. 保护或禁用危险命令\n4. 根据需求启用持久化", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "缓存服务器安全配置符合要求"
		result.ConfigFile = "cache_server_config"
		result.ConfigKey = "所有安全配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: cache_server_config\n\n缓存服务器安全配置符合安全要求:\n- 密码认证已启用\n- 网络接口配置安全\n- 危险命令已保护\n- 持久化已适当配置"
	}

	return result
}

func checkMessageQueueSecurity(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-MQ-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	mqConfig, ok := ctx.Config["message_queue_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取消息队列配置"
		result.ConfigFile = "message_queue_config"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Evidence = "配置数据源: message_queue_config\n\n无法获取消息队列配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	authEnabled := mqConfig["authentication_enabled"]
	if authEnabled != nil && authEnabled.(bool) == false {
		issues = append(issues, "消息队列认证未启用")
		evidenceDetails = append(evidenceDetails, "配置项: authentication_enabled\n当前值: false\n风险: 任何人都可连接消息队列\n建议: 启用认证并设置强密码")
	}

	tlsEnabled := mqConfig["tls_enabled"]
	if tlsEnabled != nil && tlsEnabled.(bool) == false {
		issues = append(issues, "消息队列TLS加密未启用")
		evidenceDetails = append(evidenceDetails, "配置项: tls_enabled\n当前值: false\n风险: 消息传输未加密，可能被窃听\n建议: 启用TLS加密通信")
	}

	aclEnabled := mqConfig["acl_enabled"]
	if aclEnabled != nil && aclEnabled.(bool) == false {
		issues = append(issues, "访问控制列表(ACL)未配置")
		evidenceDetails = append(evidenceDetails, "配置项: acl_enabled\n当前值: false\n风险: 无法限制用户访问特定队列\n建议: 配置ACL规则限制用户权限")
	}

	guestUser := mqConfig["guest_user_enabled"]
	if guestUser != nil && guestUser.(bool) {
		issues = append(issues, "存在guest/guest默认账户")
		evidenceDetails = append(evidenceDetails, "配置项: guest_user_enabled\n当前值: true\n风险: 默认账户是常见攻击目标\n建议: 禁用guest账户或设置强密码")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("消息队列安全问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "message_queue_config"
		result.ConfigKey = "authentication_enabled, tls_enabled, acl_enabled, guest_user_enabled"
		result.RawValue = fmt.Sprintf("auth=%v, tls=%v, acl=%v, guest=%v",
			authEnabled, tlsEnabled, aclEnabled, guestUser)
		result.Evidence = fmt.Sprintf("配置文件: message_queue_config (消息队列配置)\n\n%s\n\n修复建议:\n1. 启用消息队列认证\n2. 启用TLS加密\n3. 配置访问控制列表\n4. 禁用或保护默认guest账户", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "消息队列安全配置符合要求"
		result.ConfigFile = "message_queue_config"
		result.ConfigKey = "所有安全配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: message_queue_config\n\n消息队列安全配置符合安全要求:\n- 认证已启用\n- TLS加密已启用\n- ACL已配置\n- 无默认弱账户"
	}

	return result
}

func checkMiddlewareLogging(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "MW-LOG-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	logConfig, ok := ctx.Config["middleware_logging"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取日志配置"
		result.ConfigFile = "middleware_logging"
		result.ConfigKey = "无法获取"
		result.RawValue = "配置不存在"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Evidence = "配置数据源: middleware_logging\n\n无法获取中间件日志配置信息，请检查配置文件是否正确加载。"
		return result
	}

	issues := []string{}
	evidenceDetails := []string{}

	logLevel := logConfig["log_level"]
	if logLevel != nil {
		level := fmt.Sprintf("%v", logLevel)
		if level == "DEBUG" || level == "INFO" {
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: log_level\n当前值: %s\n状态: 日志级别适当", level))
		} else if level == "ERROR" || level == "WARN" {
			issues = append(issues, fmt.Sprintf("日志级别可能过于简单: %s", level))
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: log_level\n当前值: %s\n风险: 日志信息不足可能影响故障排查\n建议: 生产环境设置为INFO或DEBUG", level))
		} else {
			evidenceDetails = append(evidenceDetails, fmt.Sprintf("配置项: log_level\n当前值: %s\n状态: 未知日志级别", level))
		}
	}

	logRotation := logConfig["log_rotation"]
	if logRotation != nil && logRotation.(bool) == false {
		issues = append(issues, "未配置日志轮转")
		evidenceDetails = append(evidenceDetails, "配置项: log_rotation\n当前值: false\n风险: 日志文件无限增长占用磁盘空间\n建议: 启用日志轮转，设置保留策略")
	} else {
		evidenceDetails = append(evidenceDetails, "配置项: log_rotation\n当前值: true\n状态: 日志轮转已启用")
	}

	auditLogEnabled := logConfig["audit_log_enabled"]
	if auditLogEnabled != nil && auditLogEnabled.(bool) == false {
		issues = append(issues, "审计日志未启用")
		evidenceDetails = append(evidenceDetails, "配置项: audit_log_enabled\n当前值: false\n风险: 无法追踪安全相关操作\n建议: 启用审计日志记录关键操作")
	} else {
		evidenceDetails = append(evidenceDetails, "配置项: audit_log_enabled\n当前值: true\n状态: 审计日志已启用")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = fmt.Sprintf("中间件日志配置问题: %s", strings.Join(issues, "; "))
		result.ConfigFile = "middleware_logging"
		result.ConfigKey = "log_level, log_rotation, audit_log_enabled"
		result.RawValue = fmt.Sprintf("level=%v, rotation=%v, audit=%v", logLevel, logRotation, auditLogEnabled)
		result.Evidence = fmt.Sprintf("配置文件: middleware_logging (中间件日志配置)\n\n%s\n\n修复建议:\n1. 设置适当的日志级别(生产环境INFO)\n2. 启用日志轮转\n3. 启用审计日志", strings.Join(evidenceDetails, "\n\n"))
	} else {
		result.Details = "中间件日志配置符合要求"
		result.ConfigFile = "middleware_logging"
		result.ConfigKey = "所有日志配置项"
		result.RawValue = "符合安全基线"
		result.Evidence = "配置文件: middleware_logging\n\n中间件日志配置符合安全要求:\n- 日志级别适当\n- 日志轮转已配置\n- 审计日志已启用"
	}

	return result
}

func init() {
	for _, check := range GetMiddlewareAuditChecks() {
		RegisterMiddlewareCheck(check)
	}
}

var middlewareChecksRegistered bool = false

func RegisterMiddlewareCheck(check *AuditCheck) {
}

func LoadMiddlewareChecks(engine *AuditEngine) {
	if !middlewareChecksRegistered {
		checks := GetMiddlewareAuditChecks()
		for _, check := range checks {
			engine.RegisterCheck(check)
		}
		middlewareChecksRegistered = true
	}
}

func ValidateMiddlewareCheckID(id string) bool {
	matched, _ := regexp.MatchString(`^MW-[A-Z]+-\d{3}$`, id)
	return matched
}

func getIntOrDefault(v interface{}, defaultVal int) int {
	if v == nil {
		return defaultVal
	}
	if i, ok := v.(int); ok {
		return i
	}
	return defaultVal
}
