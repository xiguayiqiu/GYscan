package adcs

import "time"

type Config struct {
	Target       string
	Port         int
	Username     string
	Password     string
	Domain       string
	BaseDN       string
	OutputFile   string
	OutputFormat string
	Verbose      bool
	JSONIndent   int
	Filters      []string
}

type CertificateTemplate struct {
	Name                  string
	DisplayName           string
	SchemaVersion         int
	CertificateNameFlag   uint32
	EnrollmentFlag        uint32
	EKUs                  []string
	ApplicationPolicies   []string
	RASignature           uint32
	RAApplicationPolicies []string
	SecurityDescriptor    string
	ObjectGUID            string
}

type CertificateAuthority struct {
	Name        string
	DNSHostname string
	Templates   []string
	EditFlags   uint32
	ObjectGUID  string
}

type Vulnerability struct {
	Type        string                 `json:"type"`
	Target      string                 `json:"target"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

type ScanResult struct {
	Timestamp              time.Time              `json:"timestamp"`
	Server                 string                 `json:"server"`
	Port                   int                    `json:"port"`
	Domain                 string                 `json:"domain"`
	BaseDN                 string                 `json:"base_dn"`
	CertificateAuthorities []CertificateAuthority `json:"certificate_authorities"`
	CertificateTemplates   []CertificateTemplate  `json:"certificate_templates"`
	Vulnerabilities        []Vulnerability        `json:"vulnerabilities"`
	Summary                ScanSummary            `json:"summary"`
}

type ScanSummary struct {
	TotalCA              int            `json:"total_ca"`
	TotalTemplates       int            `json:"total_templates"`
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	SeverityCounts       map[string]int `json:"severity_counts"`
}

const (
	SeverityHigh   = "High"
	SeverityMedium = "Medium"
	SeverityLow    = "Low"
	SeverityInfo   = "Info"
)

const (
	VulnESC1 = "ESC1"
	VulnESC2 = "ESC2"
	VulnESC3 = "ESC3"
	VulnESC4 = "ESC4"
	VulnESC6 = "ESC6"
	VulnESC7 = "ESC7"
	VulnESC8 = "ESC8"
)

const (
	CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT          uint32 = 0x00000001
	CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME uint32 = 0x00010000
	CT_FLAG_PEND_ALL_REQUESTS                  uint32 = 0x00000100
	EDITF_ATTRIBUTESUBJECTALTNAME2             uint32 = 0x40000
)

const (
	EKUClientAuth       = "1.3.6.1.5.5.7.3.2"
	EKUCodeSigning      = "1.3.6.1.5.5.7.3.3"
	EKUEmailProtection  = "1.3.6.1.5.5.7.3.4"
	EKUServerAuth       = "1.3.6.1.5.5.7.3.1"
	EKUSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	EKUPKINITClient     = "1.3.6.1.5.2.3.4"
	EKUAnyPurpose       = "2.5.29.37.0"
	EKUCertRequestAgent = "1.3.6.1.4.1.311.20.2.1"
)
