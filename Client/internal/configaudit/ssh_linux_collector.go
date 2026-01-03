package configaudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type SSHRemoteConfigCollector struct {
	client *SSHClient
}

func NewSSHRemoteConfigCollector(client *SSHClient) *SSHRemoteConfigCollector {
	return &SSHRemoteConfigCollector{
		client: client,
	}
}

func (c *SSHRemoteConfigCollector) CollectAllConfig() map[string]interface{} {
	return c.CollectLinuxConfig()
}

func (c *SSHRemoteConfigCollector) CollectLinuxConfig() map[string]interface{} {
	config := make(map[string]interface{})

	var wg sync.WaitGroup
	var mu sync.Mutex

	collectors := []struct {
		name string
		fn   func() map[string]interface{}
	}{
		{"account", c.collectAccountConfig},
		{"password_policy", c.collectPasswordPolicyConfig},
		{"ssh_config", c.collectSSHConfig},
		{"services", c.collectServiceConfig},
		{"kernel_params", c.collectKernelParams},
		{"file_permissions", c.collectFilePermissions},
		{"firewall", c.collectFirewallConfig},
		{"audit", c.collectAuditConfig},
		{"log_config", c.collectLogConfig},
		{"updates", c.collectUpdateStatus},
	}

	wg.Add(len(collectors))

	for _, coll := range collectors {
		go func(coll struct {
			name string
			fn   func() map[string]interface{}
		}) {
			defer wg.Done()
			data := coll.fn()
			mu.Lock()
			config[coll.name] = data
			mu.Unlock()
		}(coll)
	}

	wg.Wait()

	return config
}

func (c *SSHRemoteConfigCollector) collectAccountConfig() map[string]interface{} {
	data := make(map[string]interface{})

	output, _ := c.client.ExecuteCommand("grep '^root:' /etc/shadow 2>/dev/null")
	data["root_ssh_login"] = strings.Contains(output, ":") && !strings.Contains(output, "lock")

	output, _ = c.client.ExecuteCommand("awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>/dev/null")
	var emptyPasswordUsers []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			emptyPasswordUsers = append(emptyPasswordUsers, line)
		}
	}
	data["empty_password_users"] = emptyPasswordUsers
	data["has_empty_password_users"] = len(emptyPasswordUsers) > 0

	output, _ = c.client.ExecuteCommand("grep -E '^[^#]*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'")
	if output == "" {
		data["root_login_enabled"] = true
	} else {
		data["root_login_enabled"] = strings.ToLower(output) == "yes"
	}

	output, _ = c.client.ExecuteCommand("grep -E '^[^#]*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'")
	if output == "" {
		data["password_auth_enabled"] = true
	} else {
		data["password_auth_enabled"] = strings.ToLower(output) == "yes"
	}

	sudoersUsers := c.client.GetSudoersUsers()
	data["sudo_users"] = sudoersUsers
	data["has_sudo_users"] = len(sudoersUsers) > 0

	return data
}

func (c *SSHRemoteConfigCollector) collectPasswordPolicyConfig() map[string]interface{} {
	data := make(map[string]interface{})

	output, _ := c.client.ExecuteCommand("cat /etc/pam.d/common-auth 2>/dev/null | grep -E 'pam_cracklib|pam_pwquality' | head -1")
	data["pam_cracklib"] = strings.Contains(output, "cracklib") || strings.Contains(output, "pwquality")

	minlenOutput, _ := c.client.ExecuteCommand("grep '^minlen' /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}'")
	if minlenOutput == "" {
		minlenOutput, _ = c.client.ExecuteCommand("grep -E '^password.*pam_pwquality.*minlen' /etc/pam.d/common-password 2>/dev/null | grep -o 'minlen=[0-9]*' | cut -d= -f2")
	}
	minlen, _ := strconv.Atoi(strings.TrimSpace(minlenOutput))
	data["min_password_length"] = minlen

	minclassOutput, _ := c.client.ExecuteCommand("grep '^minclass' /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}'")
	minclass, _ := strconv.Atoi(strings.TrimSpace(minclassOutput))
	data["min_password_classes"] = minclass

	retryOutput, _ := c.client.ExecuteCommand("grep 'retry=' /etc/pam.d/common-auth 2>/dev/null | head -1 | awk -F'retry=' '{print $2}' | awk '{print $1}'")
	retry, _ := strconv.Atoi(strings.TrimSpace(retryOutput))
	data["password_retry"] = retry

	diffOutput, _ := c.client.ExecuteCommand("grep '^difok' /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}'")
	diff, _ := strconv.Atoi(strings.TrimSpace(diffOutput))
	data["different_chars"] = diff

	maxlenOutput, _ := c.client.ExecuteCommand("grep '^maxlen' /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}'")
	maxlen, _ := strconv.Atoi(strings.TrimSpace(maxlenOutput))
	data["max_password_length"] = maxlen

	expireOutput, _ := c.client.ExecuteCommand("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'")
	if expireOutput == "" {
		expireOutput = "99999"
	}
	expireDays, _ := strconv.Atoi(strings.TrimSpace(expireOutput))
	data["max_password_age"] = expireDays

	mindaysOutput, _ := c.client.ExecuteCommand("grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'")
	if mindaysOutput == "" {
		mindaysOutput = "0"
	}
	minDays, _ := strconv.Atoi(strings.TrimSpace(mindaysOutput))
	data["min_password_age"] = minDays

	warndaysOutput, _ := c.client.ExecuteCommand("grep '^PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}'")
	if warndaysOutput == "" {
		warndaysOutput = "7"
	}
	warnDays, _ := strconv.Atoi(strings.TrimSpace(warndaysOutput))
	data["password_warn_age"] = warnDays

	return data
}

func (c *SSHRemoteConfigCollector) collectSSHConfig() map[string]interface{} {
	data := make(map[string]interface{})

	sshdConfig := c.client.ReadFileContent("/etc/ssh/sshd_config")

	protocolMatch := regexp.MustCompile(`(?i)Protocol\s+(\d+)`)
	if matches := protocolMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		data["protocol_version"] = matches[1]
	}

	permRootMatch := regexp.MustCompile(`(?i)PermitRootLogin\s+(\w+)`)
	if matches := permRootMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		data["permit_root_login"] = strings.ToLower(matches[1])
	}

	pubkeyMatch := regexp.MustCompile(`(?i)PubkeyAuthentication\s+(\w+)`)
	if matches := pubkeyMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		data["pubkey_auth"] = strings.ToLower(matches[1]) == "yes"
	}

	pwdAuthMatch := regexp.MustCompile(`(?i)PasswordAuthentication\s+(\w+)`)
	if matches := pwdAuthMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		data["password_auth"] = strings.ToLower(matches[1]) == "yes"
	}

	emptyPassMatch := regexp.MustCompile(`(?i)PermitEmptyPasswords\s+(\w+)`)
	if matches := emptyPassMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		data["permit_empty_passwords"] = strings.ToLower(matches[1]) == "yes"
	}

	ciphersMatch := regexp.MustCompile(`(?i)Ciphers\s+(.+)`)
	if matches := ciphersMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		ciphers := strings.Split(matches[1], ",")
		var weakCiphers []string
		for _, c := range ciphers {
			c = strings.TrimSpace(c)
			if strings.HasPrefix(strings.ToLower(c), "3des") ||
				strings.HasPrefix(strings.ToLower(c), "aes128-cbc") ||
				strings.HasPrefix(strings.ToLower(c), "aes192-cbc") ||
				strings.HasPrefix(strings.ToLower(c), "aes256-cbc") ||
				strings.HasPrefix(strings.ToLower(c), "blowfish") {
				weakCiphers = append(weakCiphers, c)
			}
		}
		data["weak_ciphers"] = weakCiphers
		data["has_weak_ciphers"] = len(weakCiphers) > 0
	}

	loginGraceMatch := regexp.MustCompile(`(?i)LoginGraceTime\s+(\d+)`)
	if matches := loginGraceMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		graceTime, _ := strconv.Atoi(matches[1])
		data["login_grace_time"] = graceTime
		data["weak_grace_time"] = graceTime > 120
	}

	maxAuthMatch := regexp.MustCompile(`(?i)MaxAuthTries\s+(\d+)`)
	if matches := maxAuthMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		maxAuth, _ := strconv.Atoi(matches[1])
		data["max_auth_tries"] = maxAuth
		data["weak_max_auth"] = maxAuth > 6
	}

	maxSessionsMatch := regexp.MustCompile(`(?i)MaxSessions\s+(\d+)`)
	if matches := maxSessionsMatch.FindStringSubmatch(sshdConfig); len(matches) > 1 {
		maxSessions, _ := strconv.Atoi(matches[1])
		data["max_sessions"] = maxSessions
	}

	return data
}

func (c *SSHRemoteConfigCollector) collectServiceConfig() map[string]interface{} {
	data := make(map[string]interface{})

	cronStatus, _ := c.client.ExecuteCommand("systemctl is-enabled cron 2>/dev/null || echo 'unknown'")
	data["cron_enabled"] = strings.TrimSpace(cronStatus)

	sshStatus, _ := c.client.ExecuteCommand("systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null || echo 'unknown'")
	data["ssh_enabled"] = strings.TrimSpace(sshStatus)

	runningServices := c.client.GetRunningServices()
	data["running_services"] = runningServices

	enabledServices := c.client.GetEnabledServices()
	data["enabled_services"] = enabledServices

	return data
}

func (c *SSHRemoteConfigCollector) collectKernelParams() map[string]interface{} {
	data := make(map[string]interface{})
	kernelParams := make(map[string]string)

	params := map[string]string{
		"net.ipv4.ip_forward":          "/proc/sys/net/ipv4/ip_forward",
		"net.ipv4.conf.default.accept_redirects": "/proc/sys/net/ipv4/conf/default/accept_redirects",
		"net.ipv4.conf.default.secure_redirects": "/proc/sys/net/ipv4/conf/default/secure_redirects",
		"net.ipv4.conf.all.accept_source_route": "/proc/sys/net/ipv4/conf/all/accept_source_route",
		"net.ipv4.conf.default.accept_source_route": "/proc/sys/net/ipv4/conf/default/accept_source_route",
		"kernel.randomize_va_space":            "/proc/sys/kernel/randomize_va_space",
		"kernel.exec_shield":                   "/proc/sys/kernel/exec_shield",
		"net.ipv6.conf.all.disable_ipv6":       "/proc/sys/net/ipv6/conf/all/disable_ipv6",
	}

	for param, path := range params {
		value, _ := c.client.ExecuteCommand(fmt.Sprintf("cat %s 2>/dev/null", path))
		value = strings.TrimSpace(value)
		if value != "" {
			kernelParams[param] = value
		}
	}

	data["kernel_params"] = kernelParams

	return data
}

func (c *SSHRemoteConfigCollector) collectFilePermissions() map[string]interface{} {
	data := make(map[string]interface{})

	filePerms := make(map[string]string)

	sensitiveFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/gshadow",
		"/etc/sudoers",
		"/root/.ssh/authorized_keys",
	}

	for _, file := range sensitiveFiles {
		if c.client.FileExists(file) {
			perms := c.client.GetFilePermissions(file)
			owner := c.client.GetFileOwner(file)
			filePerms[file] = fmt.Sprintf("%s (owner: %s)", perms, owner)
		}
	}

	data["sensitive_files"] = filePerms

	worldWritableCount, _ := c.client.ExecuteCommand("find /etc -type f -perm -002 2>/dev/null | wc -l")
	count, _ := strconv.Atoi(strings.TrimSpace(worldWritableCount))
	data["world_writable_count"] = count
	data["has_world_writable"] = count > 0

	suidCount, _ := c.client.ExecuteCommand("find /usr/bin /bin -type f -perm -4000 2>/dev/null | wc -l")
	count, _ = strconv.Atoi(strings.TrimSpace(suidCount))
	data["suid_binaries_count"] = count

	return data
}

func (c *SSHRemoteConfigCollector) collectFirewallConfig() map[string]interface{} {
	data := make(map[string]interface{})

	firewallStatus := "none"
	if c.client.FileExists("/usr/bin/firewalld") || c.client.FileExists("/sbin/firewalld") {
		firewallStatus = "firewalld"
		status, _ := c.client.ExecuteCommand("systemctl is-active firewalld 2>/dev/null")
		if strings.TrimSpace(status) == "active" {
			data["firewalld_active"] = true
		} else {
			data["firewalld_active"] = false
		}
	} else if c.client.FileExists("/usr/sbin/iptables") {
		firewallStatus = "iptables"
		rules, _ := c.client.ExecuteCommand("iptables -L -n 2>/dev/null | grep -c ' Chain '")
		if _, err := strconv.Atoi(strings.TrimSpace(rules)); err == nil {
			data["iptables_rules_count"] = rules
		}
	} else if c.client.FileExists("/usr/sbin/ufw") {
		firewallStatus = "ufw"
		status, _ := c.client.ExecuteCommand("ufw status 2>/dev/null | grep -i 'status: active'")
		data["ufw_active"] = strings.Contains(status, "active")
	}

	data["firewall_type"] = firewallStatus

	if firewallStatus == "iptables" {
		count, _ := c.client.ExecuteCommand("iptables -L OUTPUT 2>/dev/null | grep -c ' Chain OUTPUT'")
		if c, err := strconv.Atoi(strings.TrimSpace(count)); err == nil {
			data["iptables_output_rules"] = c
		}
	} else if firewallStatus == "firewalld" {
		count, _ := c.client.ExecuteCommand("firewall-cmd --list-all 2>/dev/null | grep -c 'services:'")
		if c, err := strconv.Atoi(strings.TrimSpace(count)); err == nil {
			data["firewalld_services_count"] = c
		}
	}

	return data
}

func (c *SSHRemoteConfigCollector) collectAuditConfig() map[string]interface{} {
	data := make(map[string]interface{})

	if c.client.FileExists("/usr/sbin/auditd") || c.client.FileExists("/sbin/auditd") {
		status, _ := c.client.ExecuteCommand("systemctl is-active auditd 2>/dev/null")
		data["auditd_active"] = strings.TrimSpace(status) == "active"
	} else {
		data["auditd_active"] = false
	}

	rulesOutput, _ := c.client.ExecuteCommand("cat /etc/audit/rules.d/*.rules 2>/dev/null | grep -v '^#' | grep -v '^$' | wc -l")
	rulesCount, _ := strconv.Atoi(strings.TrimSpace(rulesOutput))
	data["audit_rules_count"] = rulesCount

	auditRules := []string{}
	rulesContent, _ := c.client.ExecuteCommand("cat /etc/audit/rules.d/*.rules 2>/dev/null | grep -v '^#' | grep -v '^$'")
	for _, line := range strings.Split(rulesContent, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			auditRules = append(auditRules, line)
		}
	}
	data["audit_rules"] = auditRules

	return data
}

func (c *SSHRemoteConfigCollector) collectLogConfig() map[string]interface{} {
	data := make(map[string]interface{})

	logConfig := make(map[string]interface{})

	rsyslogStatus := "not_found"
	if c.client.FileExists("/usr/sbin/rsyslogd") || c.client.FileExists("/sbin/rsyslogd") {
		status, _ := c.client.ExecuteCommand("systemctl is-active rsyslog 2>/dev/null")
		if strings.TrimSpace(status) == "active" {
			rsyslogStatus = "running"
		} else {
			rsyslogStatus = "installed"
		}
	}
	logConfig["rsyslog_status"] = rsyslogStatus

	logRotation := false
	if c.client.FileExists("/etc/logrotate.conf") {
		logRotation = true
	}
	logConfig["log_rotation"] = logRotation

	remoteLogging := false
	rsyslogConf := c.client.ReadFileContent("/etc/rsyslog.conf")
	if strings.Contains(rsyslogConf, "*.* @") || strings.Contains(rsyslogConf, "UDP") {
		remoteLogging = true
	}
	logConfig["remote_logging"] = remoteLogging

	journaldStatus := "unknown"
	if c.client.FileExists("/usr/lib/systemd/systemd-journald") {
		status, _ := c.client.ExecuteCommand("systemctl is-active systemd-journald 2>/dev/null")
		if strings.TrimSpace(status) == "active" {
			journaldStatus = "running"
		}
	}
	logConfig["journald_status"] = journaldStatus

	data["log_config"] = logConfig

	return data
}

func (c *SSHRemoteConfigCollector) collectUpdateStatus() map[string]interface{} {
	data := make(map[string]interface{})

	osInfo, _ := c.client.ExecuteCommand("cat /etc/os-release 2>/dev/null | grep '^ID=' | cut -d= -f2 | tr -d '\"'")
	data["os_id"] = strings.TrimSpace(osInfo)

	updateCount := 0
	securityCount := 0

	if strings.Contains(osInfo, "ubuntu") || strings.Contains(osInfo, "debian") {
		updateCheck, _ := c.client.ExecuteCommand("apt list --upgradable 2>/dev/null | grep -c '/.*'")
		updateCount, _ = strconv.Atoi(strings.TrimSpace(updateCheck))

		securityCheck, _ := c.client.ExecuteCommand("apt-get -s upgrade 2>/dev/null | grep -c 'Security upgrade'")
		securityCount, _ = strconv.Atoi(strings.TrimSpace(securityCheck))
	} else if strings.Contains(osInfo, "centos") || strings.Contains(osInfo, "rhel") || strings.Contains(osInfo, "fedora") {
		updateCheck, _ := c.client.ExecuteCommand("yum check-update 2>&1 | grep -c '^[a-zA-Z]'")
		updateCount, _ = strconv.Atoi(strings.TrimSpace(updateCheck))

		securityCheck, _ := c.client.ExecuteCommand("yum check-update --security 2>&1 | grep -c '^[a-zA-Z]'")
		securityCount, _ = strconv.Atoi(strings.TrimSpace(securityCheck))
	} else if strings.Contains(osInfo, "arch") {
		updateCheck, _ := c.client.ExecuteCommand("checkupdates 2>/dev/null | wc -l")
		updateCount, _ = strconv.Atoi(strings.TrimSpace(updateCheck))
	}

	data["updates_available"] = updateCount
	data["security_updates"] = securityCount
	data["has_updates"] = updateCount > 0
	data["has_security_updates"] = securityCount > 0

	return data
}

func (c *SSHRemoteConfigCollector) CollectWebConfig() map[string]interface{} {
	data := make(map[string]interface{})

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(2)

	go func() {
		defer wg.Done()
		nginxData := c.collectNginxConfig()
		mu.Lock()
		data["nginx"] = nginxData
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		apacheData := c.collectApacheConfig()
		mu.Lock()
		data["apache"] = apacheData
		mu.Unlock()
	}()

	wg.Wait()

	return data
}

func (c *SSHRemoteConfigCollector) collectNginxConfig() map[string]interface{} {
	data := make(map[string]interface{})

	configFiles := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
	}

	var configContent string
	for _, path := range configFiles {
		if c.client.FileExists(path) {
			content := c.client.ReadFileContent(path)
			configContent += content + "\n"
		}
	}

	data["config_content"] = configContent

	serverTokensMatch := regexp.MustCompile(`(?i)server_tokens\s+(on|off)`)
	if serverTokensMatch.MatchString(configContent) {
		data["server_tokens"] = "off"
	} else {
		data["server_tokens"] = "on"
	}

	autoindexMatch := regexp.MustCompile(`(?i)autoindex\s+(on|off)`)
	data["autoindex_enabled"] = autoindexMatch.MatchString(configContent)

	sslProtocolsMatch := regexp.MustCompile(`(?i)ssl_protocols\s+([^\s;]+)`)
	if matches := sslProtocolsMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["ssl_protocols"] = matches[1]
		hasSSLv2 := strings.Contains(matches[1], "SSLv2")
		hasSSLv3 := strings.Contains(matches[1], "SSLv3")
		data["has_insecure_ssl_protocols"] = hasSSLv2 || hasSSLv3
	}

	headersSecurity := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
	}

	var missingHeaders []string
	for _, header := range headersSecurity {
		if !strings.Contains(configContent, header) {
			missingHeaders = append(missingHeaders, header)
		}
	}

	data["missing_security_headers"] = missingHeaders
	data["has_all_security_headers"] = len(missingHeaders) == 0

	return data
}

func (c *SSHRemoteConfigCollector) collectApacheConfig() map[string]interface{} {
	data := make(map[string]interface{})

	configFiles := []string{
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
	}

	var configContent string
	for _, path := range configFiles {
		if c.client.FileExists(path) {
			content := c.client.ReadFileContent(path)
			configContent += content + "\n"
		}
	}

	data["config_content"] = configContent

	serverTokensMatch := regexp.MustCompile(`(?i)ServerTokens\s+(\w+)`)
	if matches := serverTokensMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["server_tokens"] = matches[1]
	}

	serverSignatureMatch := regexp.MustCompile(`(?i)ServerSignature\s+(\w+)`)
	if matches := serverSignatureMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["server_signature"] = matches[1]
	}

	traceEnableMatch := regexp.MustCompile(`(?i)TraceEnable\s+(\w+)`)
	if matches := traceEnableMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["trace_enable"] = strings.ToLower(matches[1])
		data["trace_enabled"] = strings.ToLower(matches[1]) == "on"
	}

	sslProtocolsMatch := regexp.MustCompile(`(?i)SSLProtocol\s+([^\s]+)`)
	if matches := sslProtocolsMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["ssl_protocols"] = matches[1]
	}

	return data
}

func (c *SSHRemoteConfigCollector) CollectMiddlewareConfig() map[string]interface{} {
	data := make(map[string]interface{})

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(4)

	go func() {
		defer wg.Done()
		mysqlData := c.collectMySQLConfig()
		mu.Lock()
		data["mysql"] = mysqlData
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		postgresData := c.collectPostgreSQLConfig()
		mu.Lock()
		data["postgresql"] = postgresData
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		redisData := c.collectRedisConfig()
		mu.Lock()
		data["redis"] = redisData
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		mongoData := c.collectMongoDBConfig()
		mu.Lock()
		data["mongodb"] = mongoData
		mu.Unlock()
	}()

	wg.Wait()

	return data
}

func (c *SSHRemoteConfigCollector) collectMySQLConfig() map[string]interface{} {
	data := make(map[string]interface{})

	configFiles := []string{
		"/etc/mysql/my.cnf",
		"/etc/my.cnf",
		"/etc/mysql/mariadb.conf.d/*.cnf",
	}

	var configContent string
	for _, path := range configFiles {
		if c.client.FileExists(path) {
			content := c.client.ReadFileContent(path)
			configContent += content + "\n"
		}
	}

	data["config_content"] = configContent

	bindAddressMatch := regexp.MustCompile(`(?i)bind-address\s*=\s*([^\s]+)`)
	if matches := bindAddressMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["bind_address"] = matches[1]
	} else {
		data["bind_address"] = "127.0.0.1"
	}

	skipNetNetworkingMatch := regexp.MustCompile(`(?i)skip-networking\s*`)
	data["skip_networking"] = skipNetNetworkingMatch.MatchString(configContent)

	data["user_exists"] = func() string {
		output, _ := c.client.ExecuteCommand("mysql -V 2>/dev/null | grep -q 'mysql' && echo 'yes' || echo 'no'")
		return strings.TrimSpace(output)
	}()

	return data
}

func (c *SSHRemoteConfigCollector) collectPostgreSQLConfig() map[string]interface{} {
	data := make(map[string]interface{})

	configFiles := []string{
		"/etc/postgresql/*/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
	}

	var configContent string
	for _, path := range configFiles {
		if c.client.FileExists(path) {
			content := c.client.ReadFileContent(path)
			configContent += content + "\n"
		}
	}

	data["config_content"] = configContent

	listenAddressesMatch := regexp.MustCompile(`(?i)listen_addresses\s*=\s*'([^']+)'`)
	if matches := listenAddressesMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["listen_addresses"] = matches[1]
	} else {
		data["listen_addresses"] = "localhost"
	}

	passwordEncryptionMatch := regexp.MustCompile(`(?i)password_encryption\s*=\s*(\w+)`)
	if matches := passwordEncryptionMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["password_encryption"] = matches[1]
	}

	data["user_exists"] = func() string {
		output, _ := c.client.ExecuteCommand("psql --version 2>/dev/null | grep -q 'postgres' && echo 'yes' || echo 'no'")
		return strings.TrimSpace(output)
	}()

	return data
}

func (c *SSHRemoteConfigCollector) collectRedisConfig() map[string]interface{} {
	data := make(map[string]interface{})

	configFiles := []string{
		"/etc/redis/redis.conf",
		"/etc/redis.conf",
		"/usr/local/etc/redis.conf",
	}

	var configContent string
	for _, path := range configFiles {
		if c.client.FileExists(path) {
			content := c.client.ReadFileContent(path)
			configContent += content + "\n"
		}
	}

	data["config_content"] = configContent

	protectedModeMatch := regexp.MustCompile(`(?i)protected-mode\s+(\w+)`)
	if matches := protectedModeMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["protected_mode"] = strings.ToLower(matches[1]) == "yes"
	} else {
		data["protected_mode"] = true
	}

	bindMatch := regexp.MustCompile(`(?i)bind\s+([^\n]+)`)
	if matches := bindMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["bind_addresses"] = strings.TrimSpace(matches[1])
	}

	portMatch := regexp.MustCompile(`(?i)port\s+(\d+)`)
	if matches := portMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		data["port"] = port
		data["non_default_port"] = port != 6379
	}

	data["user_exists"] = func() string {
		output, _ := c.client.ExecuteCommand("redis-server --version 2>/dev/null | grep -q 'redis' && echo 'yes' || echo 'no'")
		return strings.TrimSpace(output)
	}()

	return data
}

func (c *SSHRemoteConfigCollector) collectMongoDBConfig() map[string]interface{} {
	data := make(map[string]interface{})

	configFiles := []string{
		"/etc/mongod.conf",
		"/etc/mongodb.conf",
		"/etc/mongo.conf",
	}

	var configContent string
	for _, path := range configFiles {
		if c.client.FileExists(path) {
			content := c.client.ReadFileContent(path)
			configContent += content + "\n"
		}
	}

	data["config_content"] = configContent

	netPortMatch := regexp.MustCompile(`(?i)net:\s*port:\s*(\d+)`)
	if matches := netPortMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		port, _ := strconv.Atoi(matches[1])
		data["port"] = port
	}

	netBindIPMatch := regexp.MustCompile(`(?i)net:\s*bindIp:\s*([^\s]+)`)
	if matches := netBindIPMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["bind_ip"] = matches[1]
	}

	securityAuthMatch := regexp.MustCompile(`(?i)security:\s*authorization:\s*(\w+)`)
	if matches := securityAuthMatch.FindStringSubmatch(configContent); len(matches) > 1 {
		data["authorization"] = matches[1]
		data["auth_enabled"] = strings.ToLower(matches[1]) == "enabled"
	}

	data["user_exists"] = func() string {
		output, _ := c.client.ExecuteCommand("mongod --version 2>/dev/null | grep -q 'mongodb' && echo 'yes' || echo 'no'")
		return strings.TrimSpace(output)
	}()

	return data
}
