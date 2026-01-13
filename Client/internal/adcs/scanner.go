package adcs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapScopeBaseObject = 0
	ldapScopeOneLevel   = 1
	ldapScopeSubtree    = 2
	ldapDerefNever      = 0
	ldapDerefSearching  = 1
	ldapDerefFinding    = 2
	ldapDerefAlways     = 3

	defaultLDAPPort  = 389
	defaultLDAPSPort = 636
	defaultTimeout   = 30 * time.Second
)

type Scanner struct {
	conn   *ldap.Conn
	config Config
}

func NewScanner(config Config) *Scanner {
	return &Scanner{
		config: config,
	}
}

func (s *Scanner) Connect() error {
	addr := fmt.Sprintf("%s:%d", s.config.Target, s.config.Port)

	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("无法连接到 LDAP 服务器: %v", err)
	}

	conn.SetTimeout(defaultTimeout)

	if err := conn.Bind(s.config.Username, s.config.Password); err != nil {
		conn.Close()
		return fmt.Errorf("身份验证失败: %v", err)
	}

	s.conn = conn
	return nil
}

func (s *Scanner) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *Scanner) GetConfigNC() (string, error) {
	if s.conn == nil {
		return "", fmt.Errorf("未建立 LDAP 连接")
	}

	searchRequest := ldap.NewSearchRequest(
		"",
		ldapScopeBaseObject,
		ldapDerefNever,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"configurationNamingContext"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("获取配置命名上下文失败: %v", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("未找到根 DSE 对象")
	}

	return result.Entries[0].GetAttributeValue("configurationNamingContext"), nil
}

func (s *Scanner) GetBaseDN() (string, error) {
	if s.conn == nil {
		return "", fmt.Errorf("未建立 LDAP 连接")
	}

	searchRequest := ldap.NewSearchRequest(
		"",
		ldapScopeBaseObject,
		ldapDerefNever,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("获取默认命名上下文失败: %v", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("未找到根 DSE 对象")
	}

	return result.Entries[0].GetAttributeValue("defaultNamingContext"), nil
}

func (s *Scanner) GetCAs(configNC string) ([]CertificateAuthority, error) {
	if s.conn == nil {
		return nil, fmt.Errorf("未建立 LDAP 连接")
	}

	enrollmentPath := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configNC)

	searchRequest := ldap.NewSearchRequest(
		enrollmentPath,
		ldapScopeOneLevel,
		ldapDerefNever,
		0,
		0,
		false,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "certificateTemplates", "EditFlags", "objectGUID"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("搜索证书颁发机构失败: %v", err)
	}

	if len(result.Entries) == 0 {
		utils.WarningPrint("[!] 未找到任何证书颁发机构")
		return []CertificateAuthority{}, nil
	}

	cas := make([]CertificateAuthority, 0, len(result.Entries))

	for _, entry := range result.Entries {
		editFlags := parseUint32(entry.GetAttributeValue("EditFlags"))

		ca := CertificateAuthority{
			Name:        entry.GetAttributeValue("cn"),
			DNSHostname: entry.GetAttributeValue("dNSHostName"),
			Templates:   entry.GetAttributeValues("certificateTemplates"),
			EditFlags:   editFlags,
			ObjectGUID:  entry.GetAttributeValue("objectGUID"),
		}
		cas = append(cas, ca)

		if s.config.Verbose {
			utils.DebugPrint("  发现 CA: %s (%s)", ca.Name, ca.DNSHostname)
		}
	}

	return cas, nil
}

func (s *Scanner) GetTemplates(configNC string) ([]CertificateTemplate, error) {
	if s.conn == nil {
		return nil, fmt.Errorf("未建立 LDAP 连接")
	}

	templatesPath := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configNC)

	searchRequest := ldap.NewSearchRequest(
		templatesPath,
		ldapScopeOneLevel,
		ldapDerefNever,
		0,
		0,
		false,
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"name",
			"displayName",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Application-Policy",
			"msPKI-RA-Signature",
			"msPKI-RA-Application-Policies",
			"msPKI-Template-Schema-Version",
			"nTSecurityDescriptor",
			"objectGUID",
		},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("搜索证书模板失败: %v", err)
	}

	if len(result.Entries) == 0 {
		utils.WarningPrint("[!] 未找到任何证书模板")
		return []CertificateTemplate{}, nil
	}

	templates := make([]CertificateTemplate, 0, len(result.Entries))

	for _, entry := range result.Entries {
		template := CertificateTemplate{
			Name:                  entry.GetAttributeValue("name"),
			DisplayName:           entry.GetAttributeValue("displayName"),
			CertificateNameFlag:   parseUint32(entry.GetAttributeValue("msPKI-Certificate-Name-Flag")),
			EnrollmentFlag:        parseUint32(entry.GetAttributeValue("msPKI-Enrollment-Flag")),
			EKUs:                  entry.GetAttributeValues("pKIExtendedKeyUsage"),
			ApplicationPolicies:   entry.GetAttributeValues("msPKI-Certificate-Application-Policy"),
			RASignature:           parseUint32(entry.GetAttributeValue("msPKI-RA-Signature")),
			RAApplicationPolicies: entry.GetAttributeValues("msPKI-RA-Application-Policies"),
			SchemaVersion:         parseInt(entry.GetAttributeValue("msPKI-Template-Schema-Version")),
			SecurityDescriptor:    entry.GetAttributeValue("nTSecurityDescriptor"),
			ObjectGUID:            entry.GetAttributeValue("objectGUID"),
		}
		templates = append(templates, template)
	}

	return templates, nil
}

func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Timestamp:              time.Now(),
		Server:                 s.config.Target,
		Port:                   s.config.Port,
		Domain:                 s.config.Domain,
		BaseDN:                 s.config.BaseDN,
		CertificateAuthorities: make([]CertificateAuthority, 0),
		CertificateTemplates:   make([]CertificateTemplate, 0),
		Vulnerabilities:        make([]Vulnerability, 0),
		Summary: ScanSummary{
			SeverityCounts: make(map[string]int),
		},
	}

	if err := s.Connect(); err != nil {
		return nil, err
	}
	defer s.Close()

	utils.InfoPrint("[*] 正在连接 LDAP: %s:%d", s.config.Target, s.config.Port)

	baseDN, err := s.GetBaseDN()
	if err != nil {
		utils.WarningPrint("[!] 无法获取基础 DN: %v", err)
	} else {
		result.BaseDN = baseDN
	}

	configNC, err := s.GetConfigNC()
	if err != nil {
		return nil, fmt.Errorf("获取配置命名上下文失败: %v", err)
	}
	utils.InfoPrint("[*] 获取配置命名上下文成功")

	cas, err := s.GetCAs(configNC)
	if err != nil {
		return nil, err
	}
	result.CertificateAuthorities = cas
	utils.InfoPrint("[*] 发现 %d 个证书颁发机构", len(cas))

	templates, err := s.GetTemplates(configNC)
	if err != nil {
		return nil, err
	}
	result.CertificateTemplates = templates
	utils.InfoPrint("[*] 发现 %d 个证书模板", len(templates))

	utils.InfoPrint("[*] 开始漏洞检测...")

	vulns := CheckVulnerabilities(cas, templates, s.config.Filters)
	result.Vulnerabilities = vulns

	for _, vuln := range vulns {
		result.Summary.SeverityCounts[vuln.Severity]++
	}

	result.Summary.TotalCA = len(cas)
	result.Summary.TotalTemplates = len(templates)
	result.Summary.TotalVulnerabilities = len(vulns)

	utils.SuccessPrint("[+] 扫描完成，共发现 %d 个漏洞", len(vulns))

	return result, nil
}

func (s *Scanner) PrintResult(result *ScanResult) {
	fmt.Println()
	utils.TitlePrint("AD CS 漏洞扫描报告")
	fmt.Println()

	utils.InfoPrint("目标服务器: %s:%d", result.Server, result.Port)
	utils.InfoPrint("扫描时间: %s", result.Timestamp.Format("2006-01-02 15:04:05"))
	utils.InfoPrint("证书颁发机构: %d", result.Summary.TotalCA)
	utils.InfoPrint("证书模板: %d", result.Summary.TotalTemplates)
	if result.BaseDN != "" {
		utils.InfoPrint("基础 DN: %s", result.BaseDN)
	}
	fmt.Println()

	utils.BoldInfo("漏洞统计:")
	fmt.Printf("  总计: %d", result.Summary.TotalVulnerabilities)
	if count, ok := result.Summary.SeverityCounts[SeverityHigh]; ok && count > 0 {
		fmt.Printf(" | 高危: %d", count)
	}
	if count, ok := result.Summary.SeverityCounts[SeverityMedium]; ok && count > 0 {
		fmt.Printf(" | 中危: %d", count)
	}
	if count, ok := result.Summary.SeverityCounts[SeverityLow]; ok && count > 0 {
		fmt.Printf(" | 低危: %d", count)
	}
	fmt.Println()
	fmt.Println()

	if len(result.Vulnerabilities) == 0 {
		utils.SuccessPrint("[✓] 未发现 AD CS 漏洞")
		fmt.Println()
		utils.InfoPrint("证书颁发机构详情:")
		for _, ca := range result.CertificateAuthorities {
			fmt.Printf("  - %s (%s)\n", ca.Name, ca.DNSHostname)
			if len(ca.Templates) > 0 && s.config.Verbose {
				fmt.Printf("    启用的模板数量: %d\n", len(ca.Templates))
			}
		}
		return
	}

	severityOrder := []string{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

	for _, severity := range severityOrder {
		vulnsBySeverity := make([]Vulnerability, 0)
		for _, v := range result.Vulnerabilities {
			if v.Severity == severity {
				vulnsBySeverity = append(vulnsBySeverity, v)
			}
		}

		if len(vulnsBySeverity) == 0 {
			continue
		}

		color := utils.Warning
		if severity == SeverityHigh {
			color = utils.Error
		}

		fmt.Printf("==== %s (%d) ====\n", severity, len(vulnsBySeverity))
		fmt.Println()

		for _, vuln := range vulnsBySeverity {
			fmt.Printf("  [!] %s [%s]\n", vuln.Type, vuln.Target)
			color("      描述: %s\n", vuln.Description)
			if vuln.Remediation != "" {
				utils.Info("      修复: %s\n", vuln.Remediation)
			}

			if s.config.Verbose && vuln.Details != nil {
				fmt.Println("      详细信息:")
				if nameFlag, ok := vuln.Details["certificate_name_flag"]; ok {
					fmt.Printf("        证书名称标志: 0x%08x\n", nameFlag)
				}
				if ekuList, ok := vuln.Details["ekus"]; ok {
					if ekus, ok := ekuList.([]string); ok && len(ekus) > 0 {
						fmt.Printf("        EKU: %s\n", strings.Join(ekus, ", "))
					}
				}
				if raSig, ok := vuln.Details["ra_signature"]; ok {
					fmt.Printf("        RA 签名要求: %d\n", raSig)
				}
			}
			fmt.Println()
		}
	}

	fmt.Println()
	utils.InfoPrint("证书颁发机构详情:")
	for _, ca := range result.CertificateAuthorities {
		fmt.Printf("  - %s (%s)\n", ca.Name, ca.DNSHostname)
		if len(ca.Templates) > 0 {
			fmt.Printf("    启用的模板数量: %d\n", len(ca.Templates))
		}
		if ca.EditFlags != 0 && s.config.Verbose {
			fmt.Printf("    EditFlags: 0x%08x\n", ca.EditFlags)
		}
	}
}

func (s *Scanner) ExportJSON(result *ScanResult) error {
	var data []byte
	var err error

	if s.config.JSONIndent > 0 {
		data, err = json.MarshalIndent(result, "", strings.Repeat(" ", s.config.JSONIndent))
	} else {
		data, err = json.MarshalIndent(result, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %v", err)
	}

	if s.config.OutputFile != "" {
		return writeFile(s.config.OutputFile, data)
	}

	fmt.Println(string(data))
	return nil
}

func writeFile(path string, data []byte) error {
	dir := getDirectoryPath(path)

	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %v", err)
		}
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	utils.SuccessPrint("[+] 结果已保存到: %s", path)
	return nil
}

func getDirectoryPath(filePath string) string {
	lastSlash := strings.LastIndex(filePath, "/")
	if lastSlash > 0 {
		return filePath[:lastSlash]
	}
	return ""
}

func parseUint32(s string) uint32 {
	if s == "" {
		return 0
	}
	var result uint32
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		return 0
	}
	return result
}

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		return 0
	}
	return result
}

func parseUint64(s string) uint64 {
	if s == "" {
		return 0
	}
	var result uint64
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		return 0
	}
	return result
}
