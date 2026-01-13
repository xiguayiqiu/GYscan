package adcs

import (
	"encoding/json"
	"fmt"
	"strings"
)

func containsEKU(ekus []string, oid string) bool {
	for _, eku := range ekus {
		if strings.EqualFold(eku, oid) {
			return true
		}
	}
	return false
}

func hasClientAuthEKU(ekus []string) bool {
	clientAuthOIDs := []string{
		EKUClientAuth,
		EKUSmartCardLogon,
		EKUPKINITClient,
	}
	for _, oid := range clientAuthOIDs {
		if containsEKU(ekus, oid) {
			return true
		}
	}
	return false
}

func hasElevatedEKUs(ekus []string) bool {
	elevatedOIDs := []string{
		"1.3.6.1.4.1.311.21.19", // Directory Email
		"1.3.6.1.5.5.7.3.1",     // Server Authentication
	}
	for _, oid := range elevatedOIDs {
		if containsEKU(ekus, oid) {
			return true
		}
	}
	return false
}

func CheckVulnerabilities(cas []CertificateAuthority, templates []CertificateTemplate, filters []string) []Vulnerability {
	vulns := make([]Vulnerability, 0)

	filterMap := make(map[string]bool)
	for _, f := range filters {
		normalized := strings.ToUpper(strings.TrimSpace(f))
		if normalized != "" {
			filterMap[normalized] = true
		}
	}

	shouldCheck := func(vulnType string) bool {
		if len(filters) == 0 {
			return true
		}
		return filterMap[strings.ToUpper(vulnType)]
	}

	for _, ca := range cas {
		if shouldCheck(VulnESC6) {
			if vuln := checkESC6(ca); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
		if shouldCheck(VulnESC7) {
			if vuln := checkESC7(ca); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
		if shouldCheck(VulnESC8) {
			if vuln := checkESC8(ca); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
	}

	for _, template := range templates {
		if shouldCheck(VulnESC1) {
			if vuln := checkESC1(template); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
		if shouldCheck(VulnESC2) {
			if vuln := checkESC2(template); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
		if shouldCheck(VulnESC3) {
			if vuln := checkESC3(template); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
		if shouldCheck(VulnESC4) {
			if vuln := checkESC4(template); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
	}

	return vulns
}

func checkESC1(template CertificateTemplate) *Vulnerability {
	hasEnrolleeSubject := (template.CertificateNameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0
	if !hasEnrolleeSubject {
		return nil
	}

	hasClientAuth := hasClientAuthEKU(template.EKUs)
	if !hasClientAuth {
		return nil
	}

	requiresApproval := (template.EnrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) != 0
	if requiresApproval {
		return nil
	}

	if template.RASignature > 0 {
		return nil
	}

	details := map[string]interface{}{
		"certificate_name_flag": template.CertificateNameFlag,
		"enrollment_flag":       template.EnrollmentFlag,
		"ekus":                  template.EKUs,
		"schema_version":        template.SchemaVersion,
		"display_name":          template.DisplayName,
	}

	if template.SchemaVersion >= 2 {
		details["requires_manager_approval"] = false
		details["requires_signature"] = template.RASignature
	}

	return &Vulnerability{
		Type:        VulnESC1,
		Target:      template.Name,
		Severity:    SeverityHigh,
		Description: "证书模板允许请求者提供主题名称并支持客户端身份验证，可用于伪造任意用户证书实现权限提升",
		Remediation: "禁用 CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT 标志或移除客户端身份验证 EKU，或启用管理员批准",
		Details:     details,
	}
}

func checkESC2(template CertificateTemplate) *Vulnerability {
	hasAnyPurpose := containsEKU(template.EKUs, EKUAnyPurpose)
	hasNoEKU := len(template.EKUs) == 0

	if !hasAnyPurpose && !hasNoEKU {
		return nil
	}

	details := map[string]interface{}{
		"has_any_purpose": hasAnyPurpose,
		"has_no_eku":      hasNoEKU,
		"ekus":            template.EKUs,
		"display_name":    template.DisplayName,
	}

	return &Vulnerability{
		Type:        VulnESC2,
		Target:      template.Name,
		Severity:    SeverityHigh,
		Description: "证书模板配置了 Any Purpose EKU 或未定义任何 EKU，此类证书可用于任何目的包括身份验证",
		Remediation: "移除 Any Purpose EKU 或添加适当的 EKU 限制（如仅允许服务器身份验证）",
		Details:     details,
	}
}

func checkESC3(template CertificateTemplate) *Vulnerability {
	hasCRA := containsEKU(template.EKUs, EKUCertRequestAgent)

	if !hasCRA {
		for _, eku := range template.EKUs {
			if strings.EqualFold(eku, EKUAnyPurpose) {
				hasCRA = true
				break
			}
		}
	}

	if !hasCRA {
		return nil
	}

	details := map[string]interface{}{
		"ekus":                    template.EKUs,
		"display_name":            template.DisplayName,
		"ra_signature":            template.RASignature,
		"ra_application_policies": template.RAApplicationPolicies,
		"certificate_name_flag":   template.CertificateNameFlag,
	}

	if template.RASignature == 0 {
		return &Vulnerability{
			Type:        "ESC3-1",
			Target:      template.Name,
			Severity:    SeverityHigh,
			Description: "证书模板包含 Certificate Request Agent EKU 且不需要签名，可代表其他用户请求证书",
			Remediation: "设置 msPKI-RA-Signature >= 1 或移除 Certificate Request Agent EKU",
			Details:     details,
		}
	}

	if template.RASignature == 1 {
		for _, policy := range template.RAApplicationPolicies {
			if strings.EqualFold(policy, EKUCertRequestAgent) {
				return &Vulnerability{
					Type:        "ESC3-2",
					Target:      template.Name,
					Severity:    SeverityMedium,
					Description: "证书模板包含 Certificate Request Agent EKU 且签名策略为 Application Policy，攻击者可通过签名获取高权限证书",
					Remediation: "修改签名策略或移除 Certificate Request Agent EKU",
					Details:     details,
				}
			}
		}
	}

	return nil
}

func checkESC4(template CertificateTemplate) *Vulnerability {
	if template.SecurityDescriptor == "" {
		return nil
	}

	sd := strings.ToLower(template.SecurityDescriptor)
	hasWriteOwner := strings.Contains(sd, "writeowner")
	hasWriteDacl := strings.Contains(sd, "writedacl")
	hasGenericWrite := strings.Contains(sd, "genericwrite")
	hasAllControl := strings.Contains(sd, "generic_all")

	if !hasWriteOwner && !hasWriteDacl && !hasGenericWrite && !hasAllControl {
		return nil
	}

	permissions := make([]string, 0)
	if hasWriteOwner {
		permissions = append(permissions, "WriteOwner")
	}
	if hasWriteDacl {
		permissions = append(permissions, "WriteDacl")
	}
	if hasGenericWrite {
		permissions = append(permissions, "GenericWrite")
	}
	if hasAllControl {
		permissions = append(permissions, "GenericAll")
	}

	return &Vulnerability{
		Type:        VulnESC4,
		Target:      template.Name,
		Severity:    SeverityHigh,
		Description: "证书模板的 ACL 配置过于宽松，允许低权限用户修改模板配置，进而可利用 ESC1 等漏洞",
		Remediation: "限制证书模板的修改权限，仅允许 Domain Admins 或管理员组修改",
		Details: map[string]interface{}{
			"permissions":  permissions,
			"display_name": template.DisplayName,
		},
	}
}

func checkESC6(ca CertificateAuthority) *Vulnerability {
	hasESC6 := (ca.EditFlags & EDITF_ATTRIBUTESUBJECTALTNAME2) != 0

	if !hasESC6 {
		return nil
	}

	return &Vulnerability{
		Type:        VulnESC6,
		Target:      ca.Name,
		Severity:    SeverityHigh,
		Description: "CA 服务器配置了 EDITF_ATTRIBUTESUBJECTALTNAME2 标志，允许在任何证书请求中指定 SAN，可伪造任意用户证书",
		Remediation: "运行 'certutil -config - -editflags EDITF_ATTRIBUTESUBJECTALTNAME2' 清除该标志",
		Details: map[string]interface{}{
			"edit_flags":   ca.EditFlags,
			"dns_hostname": ca.DNSHostname,
			"templates":    ca.Templates,
		},
	}
}

func checkESC7(ca CertificateAuthority) *Vulnerability {
	if ca.EditFlags == 0 {
		return nil
	}

	hasManageCA := (ca.EditFlags & 0x2) != 0
	hasManageCerts := (ca.EditFlags & 0x4) != 0

	if !hasManageCA && !hasManageCerts {
		return nil
	}

	permissions := make([]string, 0)
	if hasManageCA {
		permissions = append(permissions, "ManageCA")
	}
	if hasManageCerts {
		permissions = append(permissions, "ManageCertificates")
	}

	return &Vulnerability{
		Type:        VulnESC7,
		Target:      ca.Name,
		Severity:    SeverityMedium,
		Description: "CA 服务器配置了 ManageCA 或 ManageCertificates 权限，攻击者可利用这些权限启用 ESC6 或批准恶意证书请求",
		Remediation: "审查并限制 CA 的权限配置，确保只有可信管理员具有这些权限",
		Details: map[string]interface{}{
			"edit_flags":   ca.EditFlags,
			"permissions":  permissions,
			"dns_hostname": ca.DNSHostname,
		},
	}
}

func checkESC8(ca CertificateAuthority) *Vulnerability {
	if ca.DNSHostname == "" {
		return nil
	}

	httpEndpoints := []string{
		fmt.Sprintf("http://%s/certsrv/", ca.DNSHostname),
		fmt.Sprintf("https://%s/certsrv/", ca.DNSHostname),
	}

	return &Vulnerability{
		Type:        VulnESC8,
		Target:      ca.Name,
		Severity:    SeverityMedium,
		Description: "AD CS Web Enrollment 端点存在 NTLM 中继风险，攻击者可通过强制认证获取用户证书",
		Remediation: "启用 HTTPS 绑定、禁用 NTLM 身份验证或启用 EPA（扩展保护身份验证）",
		Details: map[string]interface{}{
			"dns_hostname":   ca.DNSHostname,
			"http_endpoints": httpEndpoints,
			"attack_vector":  "强制目标向攻击者发起 NTLM 认证，然后中继到 AD CS HTTP 端点获取证书",
		},
	}
}

func FormatVulnerabilitiesJSON(vulns []Vulnerability) (string, error) {
	data, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON 格式化失败: %v", err)
	}
	return string(data), nil
}

func GetVulnerabilityCount(vulns []Vulnerability) map[string]int {
	count := make(map[string]int)
	for _, vuln := range vulns {
		count[vuln.Severity]++
		count["total"]++
	}
	return count
}
