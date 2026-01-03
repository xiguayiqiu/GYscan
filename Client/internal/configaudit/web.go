package configaudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func GetWebAuditChecks() []*AuditCheck {
	return []*AuditCheck{
		{
			ID:          "WEB-HDR-001",
			Name:        "安全Headers配置检查",
			Description: "检查Web服务器安全响应头配置",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "OWASP-CSRF-2021",
			Reference:   "https://owasp.org/www-project-secure-headers/",
			Remediation: "配置服务器响应头：Strict-Transport-Security, X-Content-Type-Options等",
			Impact:      "缺少安全响应头使应用容易受到多种攻击",
			Execute:     checkSecurityHeaders,
		},
		{
			ID:          "WEB-CORS-001",
			Name:        "CORS策略合规性检查",
			Description: "验证跨域资源共享(CORS)策略是否安全配置",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "OWASP-CORS-2021",
			Reference:   "https://owasp.org/www-project-web-security-testing-guide/",
			Remediation: "限制允许的来源域名，不使用通配符*",
			Impact:      "宽松的CORS策略可能导致数据泄露",
			Execute:     checkCORSPolicy,
		},
		{
			ID:          "WEB-SSL-001",
			Name:        "SSL/TLS配置安全检查",
			Description: "检查Web服务器SSL/TLS配置和证书安全",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityCritical,
			BaselineRef: "CIS-Web-Server-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用SSLv2/SSLv3，启用TLS 1.2+，配置强加密套件",
			Impact:      "弱SSL/TLS配置允许中间人攻击",
			Execute:     checkSSLTLSConfig,
		},
		{
			ID:          "WEB-HTTPS-001",
			Name:        "HTTPS强制使用检查",
			Description: "验证是否强制使用HTTPS访问",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "OWASP-HTTPS-2021",
			Reference:   "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
			Remediation: "配置HTTP到HTTPS重定向，启用HSTS",
			Impact:      "允许HTTP访问可能导致传输层数据泄露",
			Execute:     checkHTTPSEnforcement,
		},
		{
			ID:          "WEB-SESS-001",
			Name:        "会话管理安全检查",
			Description: "验证会话管理机制的安全性",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "OWASP-Session-2021",
			Reference:   "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
			Remediation: "使用安全的会话Cookie，设置HttpOnly和Secure标志",
			Impact:      "不安全的会话管理可能导致会话劫持",
			Execute:     checkSessionManagement,
		},
		{
			ID:          "WEB-XSS-001",
			Name:        "XSS防护机制检查",
			Description: "检查Web应用XSS防护措施",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "OWASP-XSS-2021",
			Reference:   "https://owasp.org/www-community/attacks/xss/",
			Remediation: "实施内容安全策略(CSP)，输出编码",
			Impact:      "XSS漏洞允许攻击者注入恶意脚本",
			Execute:     checkXSSProtection,
		},
		{
			ID:          "WEB-CSRF-001",
			Name:        "CSRF防护机制检查",
			Description: "验证CSRF防护机制是否正确配置",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "OWASP-CSRF-2021",
			Reference:   "https://owasp.org/www-project-csrf/",
			Remediation: "实施Anti-CSRF Token，验证Origin/Referer头",
			Impact:      "CSRF漏洞允许攻击者执行未授权操作",
			Execute:     checkCSRFProtection,
		},
		{
			ID:          "WEB-INFO-001",
			Name:        "敏感信息泄露检查",
			Description: "检查Web应用是否泄露敏感信息",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "OWASP-Info-2021",
			Reference:   "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
			Remediation: "禁用详细错误信息，移除服务器版本信息",
			Impact:      "敏感信息泄露辅助攻击者制定攻击计划",
			Execute:     checkInformationDisclosure,
		},
		{
			ID:          "WEB-DIR-001",
			Name:        "目录遍历防护检查",
			Description: "验证目录遍历攻击的防护措施",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityHigh,
			BaselineRef: "OWASP-Path-2021",
			Reference:   "https://owasp.org/www-community/attacks/Path_Traversal",
			Remediation: "验证和清理用户输入的文件路径",
			Impact:      "目录遍历允许访问系统敏感文件",
			Execute:     checkDirectoryTraversal,
		},
		{
			ID:          "WEB-HTTPMETH-001",
			Name:        "HTTP方法安全检查",
			Description: "验证是否限制不安全的HTTP方法",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "CIS-Web-Server-1.0",
			Reference:   "https://www.cisecurity.org/cis-benchmarks/",
			Remediation: "禁用TRACE/TRACK方法，限制其他危险方法",
			Impact:      "危险HTTP方法可能被用于XST攻击",
			Execute:     checkHTTPMethods,
		},
		{
			ID:          "WEB-CLICKJACK-001",
			Name:        "点击劫持防护检查",
			Description: "验证X-Frame-Options或CSP配置",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityMedium,
			BaselineRef: "OWASP-Clickjack-2021",
			Reference:   "https://owasp.org/www-community/attacks/Clickjacking",
			Remediation: "配置X-Frame-Options: DENY或SAMEORIGIN",
			Impact:      "点击劫持允许攻击者诱导用户点击恶意内容",
			Execute:     checkClickjackingProtection,
		},
		{
			ID:          "WEB-REF-001",
			Name:        "Referrer策略检查",
			Description: "验证Referrer策略是否正确配置",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityLow,
			BaselineRef: "OWASP-Referrer-2021",
			Reference:   "https://www.w3.org/TR/referrer-policy/",
			Remediation: "配置严格的Referrer策略如strict-origin-when-cross-origin",
			Impact:      "不当的Referrer策略可能泄露敏感URL信息",
			Execute:     checkReferrerPolicy,
		},
		{
			ID:          "WEB-PERM-001",
			Name:        "HTTP权限策略检查",
			Description: "验证Permissions-Policy配置",
			Category:    CATEGORY_WEB,
			AuditType:   AuditTypeSecurity,
			Severity:    SeverityLow,
			BaselineRef: "W3C-Permissions-2021",
			Reference:   "https://www.w3.org/TR/permissions-policy-1/",
			Remediation: "配置Permissions-Policy限制敏感API访问",
			Impact:      "缺少策略限制可能允许滥用浏览器API",
			Execute:     checkPermissionsPolicy,
		},
	}
}

func checkSecurityHeaders(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-HDR-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	headers, ok := ctx.Config["security_headers"].(map[string]string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取响应头信息"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "安全响应头"
		result.RawValue = "无法读取"
		return result
	}

	requiredHeaders := map[string]string{
		"Strict-Transport-Security": "至少31536000秒",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY/SAMEORIGIN",
		"X-XSS-Protection":          "1; mode=block",
		"Content-Security-Policy":   "应配置",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "应配置",
	}

	missingHeaders := []string{}
	missingDetails := []string{}

	for header, expected := range requiredHeaders {
		if _, exists := headers[header]; !exists {
			missingHeaders = append(missingHeaders, fmt.Sprintf("%s (期望: %s)", header, expected))
			missingDetails = append(missingDetails, fmt.Sprintf("响应头: %s\n当前状态: 未配置\n建议值: %s\n配置位置: 服务器配置或代码中设置", header, expected))
		}
	}

	if len(missingHeaders) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("缺少%d个安全响应头", len(missingHeaders))
		result.ConfigFile = "HTTP响应头配置"
		result.ConfigKey = "缺失的响应头"
		result.RawValue = strings.Join(missingHeaders, ", ")
		result.Evidence = fmt.Sprintf("需要配置的安全响应头:\n\n%s", strings.Join(missingDetails, "\n\n"))
		result.ExpectedValue = fmt.Sprintf("必需: %v", requiredHeaders)
	} else {
		result.Details = "安全响应头配置完整"
		result.ActualValue = headers
	}

	return result
}

func checkCORSPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-CORS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	corsConfig, ok := ctx.Config["cors_policy"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取CORS配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "HTTP响应头: Access-Control-Allow-Origin"
		result.ConfigKey = "CORS策略"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemCors := []string{}

	allowOrigin := corsConfig["Access-Control-Allow-Origin"]
	if allowOrigin != nil {
		originStr := fmt.Sprintf("%v", allowOrigin)
		if originStr == "*" {
			issue := "Access-Control-Allow-Origin设置为通配符*"
			issues = append(issues, issue)
			problemCors = append(problemCors, "响应头: Access-Control-Allow-Origin\n当前值: *\n风险: 允许任何来源访问\n建议: 限制为特定域名\n示例: Access-Control-Allow-Origin: https://trusted.example.com")
			result.ConfigFile = "HTTP响应头"
			result.ConfigKey = "Access-Control-Allow-Origin"
			result.RawValue = "*"
		}
	}

	allowCredentials := corsConfig["Access-Control-Allow-Credentials"]
	if allowCredentials != nil {
		credStr := fmt.Sprintf("%v", allowCredentials)
		if credStr == "true" && allowOrigin != nil {
			originStr := fmt.Sprintf("%v", allowOrigin)
			if originStr == "*" {
				issue := "允许凭据时不能使用通配符Origin"
				issues = append(issues, issue)
				problemCors = append(problemCors, "当Access-Control-Allow-Credentials为true时，Access-Control-Allow-Origin不能使用*")
			}
		}
	}

	allowMethods := corsConfig["Access-Control-Allow-Methods"]
	if allowMethods != nil {
		methodsStr := fmt.Sprintf("%v", allowMethods)
		if strings.Contains(methodsStr, "PUT") || strings.Contains(methodsStr, "DELETE") || strings.Contains(methodsStr, "PATCH") {
			if !strings.Contains(methodsStr, "OPTIONS") {
				issue := "CORS允许了危险的HTTP方法"
				issues = append(issues, issue)
				problemCors = append(problemCors, fmt.Sprintf("允许的方法: %s\n建议: 仅允许GET, POST, OPTIONS等必要方法", methodsStr))
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("CORS配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("CORS配置问题详情:\n\n%s", strings.Join(problemCors, "\n\n"))
	} else {
		result.Details = "CORS策略配置符合安全要求"
	}

	return result
}

func checkSSLTLSConfig(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-SSL-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sslConfig, ok := ctx.Config["ssl_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取SSL/TLS配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "服务器SSL/TLS配置"
		result.ConfigKey = "协议版本"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemSSL := []string{}

	protocolVersions, _ := sslConfig["protocol_versions"].([]string)
	hasSSLV2 := false
	hasSSLV3 := false
	hasTLS10 := false

	for _, v := range protocolVersions {
		vLower := strings.ToLower(v)
		if vLower == "sslv2" {
			hasSSLV2 = true
		}
		if vLower == "sslv3" {
			hasSSLV3 = true
		}
		if vLower == "tlsv1.0" || vLower == "tlsv1" {
			hasTLS10 = true
		}
	}

	if hasSSLV2 {
		issues = append(issues, "SSLv2协议已启用 (存在严重漏洞)")
		problemSSL = append(problemSSL, "协议: SSLv2\n风险: 严重漏洞(CVE-2016-0800等)\n建议: 立即禁用SSLv2\n配置: ssl_protocols TLSv1.2 TLSv1.3;")
		result.ConfigFile = "服务器SSL配置"
		result.ConfigKey = "SSLv2"
		result.RawValue = "已启用"
	}
	if hasSSLV3 {
		issues = append(issues, "SSLv3协议已启用 (存在POODLE漏洞)")
		problemSSL = append(problemSSL, "协议: SSLv3\n风险: POODLE攻击(CVE-2014-3566)\n建议: 立即禁用SSLv3\n配置: ssl_protocols TLSv1.2 TLSv1.3;")
		if result.ConfigKey == "" {
			result.ConfigFile = "服务器SSL配置"
			result.ConfigKey = "SSLv3"
			result.RawValue = "已启用"
		}
	}
	if hasTLS10 {
		issues = append(issues, "TLSv1.0协议已启用 (存在安全风险)")
		problemSSL = append(problemSSL, "协议: TLSv1.0\n风险: BEAST攻击等\n建议: 禁用TLSv1.0\n配置: ssl_protocols TLSv1.2 TLSv1.3;")
		if result.ConfigKey == "" {
			result.ConfigFile = "服务器SSL配置"
			result.ConfigKey = "TLSv1.0"
			result.RawValue = "已启用"
		}
	}

	cipherSuites, _ := sslConfig["cipher_suites"].([]string)
	weakCiphers := []string{
		"null", "export", "RC4", "DES", "3DES", "MD5", "SHA1",
	}
	hasWeakCipher := false
	weakFound := []string{}
	for _, cipher := range cipherSuites {
		cipherLower := strings.ToLower(cipher)
		for _, weak := range weakCiphers {
			if strings.Contains(cipherLower, weak) {
				hasWeakCipher = true
				weakFound = append(weakFound, cipher)
				break
			}
		}
	}

	if hasWeakCipher {
		issues = append(issues, fmt.Sprintf("使用了弱加密套件: %s", strings.Join(weakFound, ", ")))
		problemSSL = append(problemSSL, fmt.Sprintf("弱加密套件: %s\n建议: 使用强加密套件\n推荐: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256", strings.Join(weakFound, ", ")))
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelCritical
		result.Score = 100
		result.Details = fmt.Sprintf("SSL/TLS配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("SSL/TLS配置问题详情:\n\n%s", strings.Join(problemSSL, "\n\n"))
	} else {
		result.Details = "SSL/TLS配置符合安全要求"
	}

	return result
}

func checkHTTPSEnforcement(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-HTTPS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	httpsConfig, ok := ctx.Config["https_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取HTTPS配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "服务器HTTPS配置"
		result.ConfigKey = "HTTPS配置"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemHTTPS := []string{}

	httpRedirect := httpsConfig["http_redirect"]
	if httpRedirect == nil || httpRedirect.(bool) == false {
		issue := "未配置HTTP到HTTPS重定向"
		issues = append(issues, issue)
		problemHTTPS = append(problemHTTPS, "问题: 未配置HTTP到HTTPS重定向\n建议: 配置永久重定向(301)\nNginx配置: return 301 https://$host$request_uri;")
		result.ConfigFile = "服务器重定向配置"
		result.ConfigKey = "HTTP重定向"
		result.RawValue = "未配置"
	}

	hstsHeader := httpsConfig["hsts_header"]
	if hstsHeader == nil {
		issue := "未配置HSTS响应头"
		issues = append(issues, issue)
		problemHTTPS = append(problemHTTPS, "问题: 未配置HSTS (Strict-Transport-Security)\n建议: 添加响应头\n配置: Strict-Transport-Security: max-age=31536000; includeSubDomains")
		if result.ConfigKey == "" {
			result.ConfigFile = "HTTP响应头"
			result.ConfigKey = "Strict-Transport-Security"
			result.RawValue = "未配置"
		}
	} else {
		hstsMaxAge := httpsConfig["hsts_max_age"]
		if hstsMaxAge != nil {
			maxAge, _ := strconv.Atoi(fmt.Sprintf("%v", hstsMaxAge))
			if maxAge < 31536000 {
				issue := fmt.Sprintf("HSTS max-age不足: %d秒 (建议>=31536000)", maxAge)
				issues = append(issues, issue)
				problemHTTPS = append(problemHTTPS, fmt.Sprintf("问题: HSTS max-age过小\n当前值: %d秒\n建议值: 至少31536000秒(1年)\n配置: Strict-Transport-Security: max-age=31536000", maxAge))
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("HTTPS强制问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("HTTPS配置问题详情:\n\n%s", strings.Join(problemHTTPS, "\n\n"))
	} else {
		result.Details = "HTTPS强制访问配置正确"
	}

	return result
}

func checkSessionManagement(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-SESS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	sessionConfig, ok := ctx.Config["session_config"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取会话配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "会话Cookie配置"
		result.ConfigKey = "会话管理"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemSession := []string{}

	cookieSecure := sessionConfig["cookie_secure"]
	if cookieSecure == nil || cookieSecure.(bool) == false {
		issue := "会话Cookie未设置Secure标志"
		issues = append(issues, issue)
		problemSession = append(problemSession, "Cookie: Secure标志\n当前: 未设置\n建议: 设置Secure标志确保仅HTTPS传输\n配置: Set-Cookie: session=xxx; Secure; HttpOnly")
		result.ConfigFile = "会话Cookie配置"
		result.ConfigKey = "Secure"
		result.RawValue = "未设置"
	}

	cookieHttpOnly := sessionConfig["cookie_httponly"]
	if cookieHttpOnly == nil || cookieHttpOnly.(bool) == false {
		issue := "会话Cookie未设置HttpOnly标志"
		issues = append(issues, issue)
		problemSession = append(problemSession, "Cookie: HttpOnly标志\n当前: 未设置\n建议: 设置HttpOnly防止JavaScript访问\n配置: Set-Cookie: session=xxx; Secure; HttpOnly")
		if result.ConfigKey == "" {
			result.ConfigFile = "会话Cookie配置"
			result.ConfigKey = "HttpOnly"
			result.RawValue = "未设置"
		}
	}

	cookieSameSite := sessionConfig["cookie_samesite"]
	if cookieSameSite == nil {
		issue := "会话Cookie未设置SameSite标志"
		issues = append(issues, issue)
		problemSession = append(problemSession, "Cookie: SameSite标志\n当前: 未设置\n建议: 设置SameSite=Strict或Lax\n配置: Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict")
	}

	sessionTimeout := sessionConfig["session_timeout"]
	if sessionTimeout != nil {
		timeout, _ := strconv.Atoi(fmt.Sprintf("%v", sessionTimeout))
		if timeout > 1800 {
			issue := fmt.Sprintf("会话超时时间过长: %d秒 (建议<=1800)", timeout)
			issues = append(issues, issue)
			problemSession = append(problemSession, fmt.Sprintf("会话超时: %d秒\n建议: 最多30分钟(1800秒)\n建议配置: session.timeout = 1800", timeout))
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("会话管理问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("会话管理问题详情:\n\n%s", strings.Join(problemSession, "\n\n"))
	} else {
		result.Details = "会话管理配置符合安全要求"
	}

	return result
}

func checkXSSProtection(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-XSS-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	xssConfig, ok := ctx.Config["xss_protection"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取XSS防护配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "XSS防护"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemXSS := []string{}

	cspHeader := xssConfig["Content-Security-Policy"]
	if cspHeader == nil || fmt.Sprintf("%v", cspHeader) == "" {
		issue := "未配置Content-Security-Policy"
		issues = append(issues, issue)
		problemXSS = append(problemXSS, "响应头: Content-Security-Policy\n当前: 未配置\n建议: 配置严格的CSP\n示例: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "Content-Security-Policy"
		result.RawValue = "未配置"
	} else {
		cspStr := fmt.Sprintf("%v", cspHeader)
		if strings.Contains(cspStr, "unsafe-inline") || strings.Contains(cspStr, "unsafe-eval") {
			issue := "CSP配置包含unsafe-inline或unsafe-eval"
			issues = append(issues, issue)
			problemXSS = append(problemXSS, fmt.Sprintf("CSP包含不安全的指令:\n当前: %s\n风险: 可能允许XSS攻击\n建议: 尽量避免使用unsafe-inline和unsafe-eval", cspStr))
		}
	}

	xXSSProtection := xssConfig["X-XSS-Protection"]
	if xXSSProtection == nil || fmt.Sprintf("%v", xXSSProtection) == "" {
		issue := "未配置X-XSS-Protection响应头"
		issues = append(issues, issue)
		problemXSS = append(problemXSS, "响应头: X-XSS-Protection\n当前: 未配置\n建议: 设置为1; mode=block\n配置: X-XSS-Protection: 1; mode=block")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("XSS防护问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("XSS防护问题详情:\n\n%s", strings.Join(problemXSS, "\n\n"))
	} else {
		result.Details = "XSS防护配置符合要求"
	}

	return result
}

func checkCSRFProtection(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-CSRF-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	csrfConfig, ok := ctx.Config["csrf_protection"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取CSRF防护配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "CSRF防护配置"
		result.ConfigKey = "CSRF Token"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemCSRF := []string{}

	csrfToken := csrfConfig["csrf_token_enabled"]
	if csrfToken == nil || csrfToken.(bool) == false {
		issue := "未启用Anti-CSRF Token"
		issues = append(issues, issue)
		problemCSRF = append(problemCSRF, "防护: Anti-CSRF Token\n当前: 未启用\n建议: 在表单中添加CSRF Token\n示例: <input type=\"hidden\" name=\"csrf_token\" value=\"xxx\">")
		result.ConfigFile = "表单/CSRF防护"
		result.ConfigKey = "csrf_token_enabled"
		result.RawValue = "false"
	}

	originCheck := csrfConfig["origin_check"]
	if originCheck == nil || originCheck.(bool) == false {
		issue := "未启用Origin/Referer检查"
		issues = append(issues, issue)
		problemCSRF = append(problemCSRF, "防护: Origin/Referer检查\n当前: 未启用\n建议: 在服务端验证Origin和Referer头\n示例: if req.Header.Get(\"Origin\") != \"https://trusted.example.com\" { reject }")
	}

	sameSiteCookie := csrfConfig["same_site_cookie"]
	if sameSiteCookie == nil || fmt.Sprintf("%v", sameSiteCookie) == "" {
		issue := "Cookie未设置SameSite=Lax或Strict"
		issues = append(issues, issue)
		problemCSRF = append(problemCSRF, "Cookie: SameSite属性\n当前: 未设置\n建议: 设置SameSite=Lax或Strict\n配置: Set-Cookie: session=xxx; SameSite=Strict")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusFail
		result.RiskLevel = RiskLevelHigh
		result.Score = 75
		result.Details = fmt.Sprintf("CSRF防护问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("CSRF防护问题详情:\n\n%s", strings.Join(problemCSRF, "\n\n"))
	} else {
		result.Details = "CSRF防护配置符合要求"
	}

	return result
}

func checkInformationDisclosure(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-INFO-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	infoConfig, ok := ctx.Config["information_disclosure"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取信息泄露配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "服务器响应头"
		result.ConfigKey = "信息泄露检查"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemInfo := []string{}

	serverHeader := infoConfig["Server"]
	if serverHeader != nil && serverHeader.(string) != "" {
		serverStr := fmt.Sprintf("%v", serverHeader)
		if len(serverStr) > 0 {
			issue := fmt.Sprintf("Server头泄露信息: %s", serverStr)
			issues = append(issues, issue)
			problemInfo = append(problemInfo, fmt.Sprintf("响应头: Server\n当前值: %s\n建议: 隐藏或修改Server头\nNginx配置: server_tokens off;\nApache配置: ServerTokens Prod", serverStr))
			result.ConfigFile = "服务器配置"
			result.ConfigKey = "Server"
			result.RawValue = serverStr
		}
	}

	xPoweredBy := infoConfig["X-Powered-By"]
	if xPoweredBy != nil && fmt.Sprintf("%v", xPoweredBy) != "" {
		issue := fmt.Sprintf("X-Powered-By头泄露信息: %v", xPoweredBy)
		issues = append(issues, issue)
		problemInfo = append(problemInfo, fmt.Sprintf("响应头: X-Powered-By\n当前值: %v\n建议: 移除此响应头\nPHP配置: expose_php = Off", xPoweredBy))
		if result.ConfigKey == "" {
			result.ConfigFile = "服务器/PHP配置"
			result.ConfigKey = "X-Powered-By"
			result.RawValue = fmt.Sprintf("%v", xPoweredBy)
		}
	}

	detailedErrors := infoConfig["detailed_errors"]
	if detailedErrors != nil && detailedErrors.(bool) == true {
		issue := "详细错误信息可能泄露系统内部结构"
		issues = append(issues, issue)
		problemInfo = append(problemInfo, "问题: 详细错误信息已启用\n建议: 生产环境关闭详细错误\n配置: debug=false, display_errors=Off")
	}

	debugMode := infoConfig["debug_mode"]
	if debugMode != nil && debugMode.(bool) == true {
		issue := "应用程序处于调试模式"
		issues = append(issues, issue)
		problemInfo = append(problemInfo, "问题: 应用程序调试模式已启用\n建议: 生产环境关闭调试模式\n影响: 可能泄露敏感信息")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = fmt.Sprintf("信息泄露问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("信息泄露问题详情:\n\n%s", strings.Join(problemInfo, "\n\n"))
	} else {
		result.Details = "未发现明显信息泄露"
	}

	return result
}

func checkDirectoryTraversal(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-DIR-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	traversalConfig, ok := ctx.Config["directory_traversal"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取目录遍历防护配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "应用程序输入验证"
		result.ConfigKey = "目录遍历防护"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemTraversal := []string{}

	inputValidation := traversalConfig["input_validation"]
	if inputValidation == nil || inputValidation.(bool) == false {
		issue := "未实施输入验证"
		issues = append(issues, issue)
		problemTraversal = append(problemTraversal, "防护: 输入验证\n当前: 未实施\n建议: 对用户输入的文件路径进行验证\n示例: 使用正则验证路径格式")
		result.ConfigFile = "应用程序代码"
		result.ConfigKey = "input_validation"
		result.RawValue = "false"
	}

	pathSanitization := traversalConfig["path_sanitization"]
	if pathSanitization == nil || pathSanitization.(bool) == false {
		issue := "未实施路径清理"
		issues = append(issues, issue)
		problemTraversal = append(problemTraversal, "防护: 路径清理\n当前: 未实施\n建议: 使用realpath()和basename()清理路径")
	}

	allowList := traversalConfig["allow_list_validation"]
	if allowList == nil || allowList.(bool) == false {
		issue := "未实施文件路径白名单验证"
		issues = append(issues, issue)
		problemTraversal = append(problemTraversal, "防护: 白名单验证\n当前: 未实施\n建议: 限制可访问的目录范围")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("目录遍历防护问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("目录遍历防护问题详情:\n\n%s", strings.Join(problemTraversal, "\n\n"))
	} else {
		result.Details = "目录遍历防护配置符合要求"
	}

	return result
}

func checkHTTPMethods(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-HTTPMETH-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	methodsConfig, ok := ctx.Config["http_methods"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取HTTP方法配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "服务器HTTP方法限制"
		result.ConfigKey = "允许的方法"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemMethods := []string{}

	allowedMethods, _ := methodsConfig["allowed_methods"].([]string)
	dangerousMethods := []string{"TRACE", "TRACK", "CONNECT"}

	for _, method := range dangerousMethods {
		for _, allowed := range allowedMethods {
			if strings.EqualFold(allowed, method) {
				issue := fmt.Sprintf("危险HTTP方法已启用: %s", method)
				issues = append(issues, issue)
				problemMethods = append(problemMethods, fmt.Sprintf("HTTP方法: %s\n状态: 已启用\n风险: 可用于XST攻击\n建议: 禁用此方法\nNginx配置: if ($request_method !~ ^(GET|POST|HEAD|OPTIONS)$ ) { return 405; }", method))
				if result.ConfigKey == "" {
					result.ConfigFile = "服务器方法限制"
					result.ConfigKey = method
					result.RawValue = "已启用"
				}
				break
			}
		}
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("HTTP方法配置问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("HTTP方法配置问题详情:\n\n%s", strings.Join(problemMethods, "\n\n"))
	} else {
		result.Details = "HTTP方法配置符合要求"
	}

	return result
}

func checkClickjackingProtection(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-CLICKJACK-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	clickjackConfig, ok := ctx.Config["clickjacking_protection"].(map[string]interface{})
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取点击劫持防护配置"
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "点击劫持防护"
		result.RawValue = "无法读取"
		return result
	}

	issues := []string{}
	problemClickjack := []string{}

	xFrameOptions := clickjackConfig["X-Frame-Options"]
	if xFrameOptions == nil || fmt.Sprintf("%v", xFrameOptions) == "" {
		issue := "未配置X-Frame-Options"
		issues = append(issues, issue)
		problemClickjack = append(problemClickjack, "响应头: X-Frame-Options\n当前: 未配置\n建议: 设置为DENY或SAMEORIGIN\n配置: X-Frame-Options: SAMEORIGIN")
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "X-Frame-Options"
		result.RawValue = "未配置"
	}

	cspFrameAncestors := clickjackConfig["frame-ancestors"]
	if cspFrameAncestors == nil || fmt.Sprintf("%v", cspFrameAncestors) == "" {
		issue := "CSP中未配置frame-ancestors"
		issues = append(issues, issue)
		problemClickjack = append(problemClickjack, "CSP指令: frame-ancestors\n当前: 未配置\n建议: 在CSP中添加frame-ancestors\n配置: Content-Security-Policy: frame-ancestors 'self';")
	}

	if len(issues) > 0 {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelMedium
		result.Score = 50
		result.Details = fmt.Sprintf("点击劫持防护问题: %s", strings.Join(issues, "; "))
		result.Evidence = fmt.Sprintf("点击劫持防护问题详情:\n\n%s", strings.Join(problemClickjack, "\n\n"))
	} else {
		result.Details = "点击劫持防护配置符合要求"
	}

	return result
}

func checkReferrerPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-REF-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	referrerConfig, ok := ctx.Config["referrer_policy"].(string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取Referrer策略配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "Referrer-Policy"
		result.RawValue = "无法读取"
		return result
	}

	unsafePolicies := []string{
		"no-referrer",
		"unsafe-url",
		"no-referrer-when-downgrade",
	}

	for _, unsafe := range unsafePolicies {
		if strings.EqualFold(referrerConfig, unsafe) {
			result.Status = CheckStatusWarning
			result.RiskLevel = RiskLevelLow
			result.Score = 25
			result.Details = fmt.Sprintf("Referrer策略不安全: %s", referrerConfig)
			result.ConfigFile = "HTTP响应头"
			result.ConfigKey = "Referrer-Policy"
			result.RawValue = referrerConfig
			result.Evidence = fmt.Sprintf("Referrer-Policy: %s\n不安全原因: 可能泄露敏感URL信息\n建议值: strict-origin-when-cross-origin\n配置: Referrer-Policy: strict-origin-when-cross-origin", referrerConfig)
			return result
		}
	}

	result.Details = "Referrer策略配置符合要求"
	return result
}

func checkPermissionsPolicy(ctx *AuditContext) *CheckResult {
	result := &CheckResult{
		CheckID:   "WEB-PERM-001",
		Status:    CheckStatusPass,
		RiskLevel: RiskLevelLow,
		Score:     0,
	}

	permissionsConfig, ok := ctx.Config["permissions_policy"].(string)
	if !ok {
		result.Status = CheckStatusWarning
		result.Details = "无法获取Permissions-Policy配置"
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "Permissions-Policy"
		result.RawValue = "无法读取"
		return result
	}

	if permissionsConfig == "" {
		result.Status = CheckStatusWarning
		result.RiskLevel = RiskLevelLow
		result.Score = 25
		result.Details = "未配置Permissions-Policy"
		result.ConfigFile = "HTTP响应头"
		result.ConfigKey = "Permissions-Policy"
		result.RawValue = "未配置"
		result.Evidence = "建议配置Permissions-Policy限制敏感浏览器API\n示例: Permissions-Policy: geolocation=(), microphone=(), camera=()"
		return result
	}

	result.Details = "Permissions-Policy配置符合要求"
	return result
}

func init() {
	for _, check := range GetWebAuditChecks() {
		RegisterWebCheck(check)
	}
}

var webChecksRegistered bool = false

func RegisterWebCheck(check *AuditCheck) {
}

func LoadWebChecks(engine *AuditEngine) {
	if !webChecksRegistered {
		checks := GetWebAuditChecks()
		for _, check := range checks {
			engine.RegisterCheck(check)
		}
		webChecksRegistered = true
	}
}

func ValidateWebCheckID(id string) bool {
	matched, _ := regexp.MatchString(`^WEB-[A-Z]+-\d{3}$`, id)
	return matched
}
