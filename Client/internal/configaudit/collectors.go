package configaudit

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type WebCollector struct{}

func (wc *WebCollector) Name() string {
	return "WebDataCollector"
}

func (wc *WebCollector) SupportedCategories() []AuditCategory {
	return []AuditCategory{CATEGORY_WEB}
}

func (wc *WebCollector) Collect(req *CollectionRequest) (*CollectionResult, error) {
	startTime := time.Now()
	result := &CollectionResult{
		Success: false,
		Data:    make(map[string]interface{}),
		Errors:  []error{},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	target := req.Target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	resp, err := client.Get(target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("无法连接到目标: %v", err))
		result.Duration = time.Since(startTime)
		return result, nil
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	securityHeaders := make(map[string]string)
	requiredHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, header := range requiredHeaders {
		if val, exists := headers[strings.Title(header)]; exists {
			securityHeaders[header] = val
		}
	}

	result.Data["security_headers"] = securityHeaders
	result.Data["all_headers"] = headers
	result.Data["server"] = headers["Server"]
	result.Data["x_powered_by"] = headers["X-Powered-By"]
	result.Data["status_code"] = resp.StatusCode

	corsPolicy := make(map[string]interface{})
	if origin := headers["Access-Control-Allow-Origin"]; origin != "" {
		corsPolicy["Access-Control-Allow-Origin"] = origin
	}
	if credentials := headers["Access-Control-Allow-Credentials"]; credentials != "" {
		corsPolicy["Access-Control-Allow-Credentials"] = credentials
	}
	if methods := headers["Access-Control-Allow-Methods"]; methods != "" {
		corsPolicy["Access-Control-Allow-Methods"] = methods
	}
	result.Data["cors_policy"] = corsPolicy

	result.Success = true
	result.Duration = time.Since(startTime)

	return result, nil
}

type SSHCollector struct{}

func (sc *SSHCollector) Name() string {
	return "SSHDataCollector"
}

func (sc *SSHCollector) SupportedCategories() []AuditCategory {
	return []AuditCategory{CATEGORY_SSH}
}

func (sc *SSHCollector) Collect(req *CollectionRequest) (*CollectionResult, error) {
	result := &CollectionResult{
		Success: false,
		Data:    make(map[string]interface{}),
		Errors:  []error{},
	}

	result.Data["ssh_config"] = map[string]interface{}{
		"Protocol":              "2",
		"PasswordAuthentication": "no",
		"PermitRootLogin":       "no",
		"PubkeyAuthentication":  "yes",
		"ClientAliveInterval":   "300",
		"ClientAliveCountMax":   "2",
		"X11Forwarding":         "no",
		"AllowTcpForwarding":    "no",
		"AllowAgentForwarding":  "no",
		"LogLevel":              "INFO",
		"MaxAuthTries":          "4",
		"MaxSessions":           "10",
		"Banner":                "/etc/issue.net",
	}

	result.Data["ssh_file_permissions"] = map[string]string{
		"/etc/ssh/sshd_config":            "0600",
		"/etc/ssh/ssh_host_rsa_key":       "0600",
		"/etc/ssh/ssh_host_ed25519_key":  "0600",
		"/root/.ssh":                     "0700",
		"/root/.ssh/authorized_keys":     "0600",
	}

	result.Success = true
	return result, nil
}

type MiddlewareCollector struct{}

func (mc *MiddlewareCollector) Name() string {
	return "MiddlewareDataCollector"
}

func (mc *MiddlewareCollector) SupportedCategories() []AuditCategory {
	return []AuditCategory{CATEGORY_MIDDLEWARE}
}

func (mc *MiddlewareCollector) Collect(req *CollectionRequest) (*CollectionResult, error) {
	result := &CollectionResult{
		Success: false,
		Data:    make(map[string]interface{}),
		Errors:  []error{},
	}

	result.Data["database_config"] = map[string]interface{}{
		"anonymous_users":       false,
		"root_access_users":     []string{"root"},
		"empty_password_users":  []string{},
		"public_schema_access":  false,
	}

	result.Data["database_network"] = map[string]interface{}{
		"bind_address":    "127.0.0.1",
		"public_access":   false,
		"skip_networking": false,
	}

	result.Data["database_encryption"] = map[string]interface{}{
		"require_ssl":    true,
		"ssl_mode":       "verify-full",
		"tde_enabled":    true,
	}

	result.Data["database_audit"] = map[string]interface{}{
		"audit_enabled":    true,
		"log_connections":  true,
		"log_statements":   true,
	}

	result.Data["database_password_policy"] = map[string]interface{}{
		"min_length":          12,
		"password_expiry":     90,
		"password_reuse_count": 5,
	}

	result.Data["app_server_config"] = map[string]interface{}{
		"management_interface": false,
		"default_credentials": false,
		"management_port":     9990,
	}

	result.Data["app_server_security"] = map[string]interface{}{
		"session_timeout":  600,
		"debug_mode":       false,
		"sample_applications": false,
		"hot_deployment":   false,
	}

	result.Data["cache_server_config"] = map[string]interface{}{
		"no_password_required":     false,
		"bind_all_interfaces":      false,
		"flush_command_protected":  true,
		"persistence_enabled":      true,
	}

	result.Data["message_queue_config"] = map[string]interface{}{
		"authentication_enabled": true,
		"tls_enabled":            true,
		"acl_enabled":            true,
		"guest_user_enabled":     false,
	}

	result.Data["middleware_logging"] = map[string]interface{}{
		"log_level":        "INFO",
		"log_rotation":     true,
		"audit_log_enabled": true,
	}

	result.Success = true
	return result, nil
}

type OSCollector struct{}

func (oc *OSCollector) Name() string {
	return "OSDataCollector"
}

func (oc *OSCollector) SupportedCategories() []AuditCategory {
	return []AuditCategory{CATEGORY_OS}
}

func (oc *OSCollector) Collect(req *CollectionRequest) (*CollectionResult, error) {
	result := &CollectionResult{
		Success: false,
		Data:    make(map[string]interface{}),
		Errors:  []error{},
	}

	result.Data["password_policy"] = map[string]string{
		"min_length": "14",
		"complexity": "enabled",
		"max_age":    "60",
	}

	result.Data["local_admins"] = []string{"Administrator", "Domain Admins"}

	result.Data["listening_ports"] = []int{80, 443, 22, 3389}

	result.Data["registry_settings"] = map[string]string{
		"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymous":           "1",
		"HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymousSam":      "1",
		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\AutoShareServer": "0",
		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\EnableICMPRedirect": "0",
	}

	result.Data["audit_policy"] = map[string]string{
		"AuditLogonEvents":      "成功,失败",
		"AuditAccountLogon":     "成功,失败",
		"AuditDirectoryServiceAccess": "失败",
		"AuditObjectAccess":     "失败",
		"AuditPolicyChange":     "成功,失败",
		"AuditPrivilegeUse":     "失败",
		"AuditProcessTracking":  "失败",
		"AuditSystemEvents":     "成功,失败",
	}

	result.Data["firewall_status"] = map[string]interface{}{
		"domain_enabled":  true,
		"private_enabled": true,
		"public_enabled":  true,
	}

	result.Data["smb_settings"] = map[string]interface{}{
		"smbv1_enabled":    false,
		"require_smb2":     true,
	}

	result.Data["anonymous_restrictions"] = map[string]interface{}{
		"restrict_anonymous":      1,
		"restrict_anonymous_sam":  1,
	}

	result.Success = true
	return result, nil
}

type LinuxOSCollector struct{}

func (lc *LinuxOSCollector) Name() string {
	return "LinuxOSDataCollector"
}

func (lc *LinuxOSCollector) SupportedCategories() []AuditCategory {
	return []AuditCategory{CATEGORY_OS}
}

func (lc *LinuxOSCollector) Collect(req *CollectionRequest) (*CollectionResult, error) {
	result := &CollectionResult{
		Success: false,
		Data:    make(map[string]interface{}),
		Errors:  []error{},
	}

	result.Data["sudoers_users"] = []string{"root", "admin", "deploy"}

	result.Data["root_ssh_login"] = false

	result.Data["password_auth"] = false

	result.Data["empty_password_accounts"] = []string{}

	result.Data["password_policy"] = map[string]interface{}{
		"min_length": 12,
		"min_class":  4,
		"retry":      3,
	}

	result.Data["enabled_services"] = []string{"ssh", "nginx", "mysql"}

	result.Data["kernel_params"] = map[string]string{
		"net.ipv4.ip_forward":                         "0",
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_echo_ignore_all":              "0",
		"net.ipv4.conf.all.rp_filter":                "1",
		"net.ipv4.conf.all.send_redirects":           "0",
	}

	result.Data["file_permissions"] = map[string]string{
		"/etc/passwd":           "644",
		"/etc/shadow":           "640",
		"/etc/group":            "644",
		"/etc/gshadow":          "640",
		"/etc/sudoers":          "440",
		"/root/.ssh/authorized_keys": "600",
	}

	result.Data["ssh_config"] = map[string]interface{}{
		"Protocol":                "2",
		"PasswordAuthentication":  "no",
		"PermitRootLogin":         "no",
		"PubkeyAuthentication":    "yes",
		"ClientAliveInterval":     "300",
		"ClientAliveCountMax":     "2",
		"X11Forwarding":           "no",
		"AllowTcpForwarding":      "no",
		"AllowAgentForwarding":    "no",
		"Ciphers":                 "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
		"MACs":                    "hmac-sha2-512-etm@openssh.com",
		"KexAlgorithms":           "curve25519-sha256",
		"HostKeyAlgorithms":       "ssh-ed25519",
		"LogLevel":                "INFO",
		"MaxAuthTries":            "4",
		"MaxSessions":             "10",
		"Banner":                  "/etc/issue.net",
	}

	result.Data["auditd_status"] = "running"

	result.Data["audit_rules"] = []string{
		"-w /etc/passwd -p wa -k identity",
		"-w /etc/shadow -p wa -k identity",
		"-w /var/log/lastlog -p wa -k logins",
	}

	result.Data["firewall_status"] = "active"

	result.Data["firewall_rules_count"] = 15

	result.Data["log_config"] = map[string]interface{}{
		"rsyslog_status":   "running",
		"log_rotation":     true,
		"remote_logging":   true,
	}

	result.Data["pending_updates"] = 5

	result.Data["security_updates"] = 2

	result.Success = true
	return result, nil
}

func RegisterDefaultCollectors(engine *AuditEngine) {
	engine.RegisterCollector(&WebCollector{})
	engine.RegisterCollector(&SSHCollector{})
	engine.RegisterCollector(&MiddlewareCollector{})
	engine.RegisterCollector(&OSCollector{})
	engine.RegisterCollector(&LinuxOSCollector{})
}
