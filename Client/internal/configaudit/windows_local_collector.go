package configaudit

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type WindowsLocalCollector struct{}

func (wc *WindowsLocalCollector) Name() string {
	return "WindowsLocalDataCollector"
}

func (wc *WindowsLocalCollector) SupportedCategories() []AuditCategory {
	return []AuditCategory{CATEGORY_OS, CATEGORY_WEB}
}

func (wc *WindowsLocalCollector) Collect(req *CollectionRequest) (*CollectionResult, error) {
	startTime := time.Now()
	result := &CollectionResult{
		Success: false,
		Data:    make(map[string]interface{}),
		Errors:  []error{},
	}

	result.Data["os_type"] = "windows"
	result.Data["os"] = runtime.GOOS
	result.Data["arch"] = runtime.GOARCH

	passwordPolicy := wc.getPasswordPolicy()
	result.Data["password_policy"] = passwordPolicy

	registrySettings := wc.getRegistrySettings()
	result.Data["registry_settings"] = registrySettings

	auditPolicy := wc.getAuditPolicy()
	result.Data["audit_policy"] = auditPolicy

	lsaSettings := wc.getLSASettings()
	result.Data["lsa_settings"] = lsaSettings

	uacLevel := wc.getUACLevel()
	result.Data["uac_level"] = uacLevel

	firewallStatus := wc.getFirewallStatus()
	result.Data["firewall_status"] = firewallStatus

	anonymousRestrictions := wc.getAnonymousRestrictions()
	result.Data["anonymous_restrictions"] = anonymousRestrictions

	localAdmins := wc.getLocalAdmins()
	result.Data["local_admins"] = localAdmins

	listeningPorts := wc.getListeningPorts()
	result.Data["listening_ports"] = listeningPorts

	smbSettings := wc.getSMBSettings()
	result.Data["smb_settings"] = smbSettings

	result.Success = true
	result.Duration = time.Since(startTime)
	return result, nil
}

func (wc *WindowsLocalCollector) runCommand(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (wc *WindowsLocalCollector) getPasswordPolicy() map[string]interface{} {
	policy := make(map[string]interface{})

	output := wc.runCommand("net", "accounts")
	if output == "" {
		policy["min_length"] = "无法读取"
		policy["max_age"] = "无法读取"
		policy["complexity"] = "无法读取"
		return policy
	}

	re := regexp.MustCompile(`(?i)(Minimum password length|Maximum password age|Password must meet complexity requirements):\s*(\S+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			key := strings.ToLower(match[1])
			value := match[2]
			switch key {
			case "minimum password length":
				policy["min_length"] = value
			case "maximum password age":
				policy["max_age"] = value
			case "password must meet complexity requirements":
				policy["complexity"] = value
			}
		}
	}

	if policy["min_length"] == "" {
		policy["min_length"] = "未配置"
	}
	if policy["max_age"] == "" {
		policy["max_age"] = "未配置"
	}
	if policy["complexity"] == "" {
		policy["complexity"] = "未配置"
	}

	return policy
}

func (wc *WindowsLocalCollector) getRegistrySettings() map[string]interface{} {
	settings := make(map[string]interface{})

	registryKeys := []struct {
		Path      string
		ValueName string
		Key       string
	}{
		{`HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "RestrictAnonymous", "RestrictAnonymous"},
		{`HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "RestrictAnonymousSam", "RestrictAnonymousSam"},
		{`HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "DisableDomainCreds", "DisableDomainCreds"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "AutoShareServer", "AutoShareServer"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "EnableICMPRedirect", "EnableICMPRedirect"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", "EnableLUA"},
		{`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`, "ClearPageFileAtShutdown", "ClearPageFileAtShutdown"},
		{`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`, "SafeDllSearchMode", "SafeDllSearchMode"},
	}

	for _, key := range registryKeys {
		output := wc.runCommand("reg", "query", key.Path, "/v", key.ValueName)
		if output == "" {
			settings[key.Key] = ""
			continue
		}

		re := regexp.MustCompile(key.ValueName + `\s+REG_\w+\s+(\S+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			settings[key.Key] = matches[1]
		} else {
			settings[key.Key] = ""
		}
	}

	return settings
}

func (wc *WindowsLocalCollector) getAuditPolicy() map[string]interface{} {
	policy := make(map[string]interface{})

	policy["AuditPrivilegeUse"] = ""
	policy["AuditProcessTracking"] = ""
	policy["AuditSystemEvents"] = ""
	policy["AuditLogonEvents"] = ""
	policy["AuditAccountLogon"] = ""
	policy["AuditDirectoryServiceAccess"] = ""
	policy["AuditObjectAccess"] = ""
	policy["AuditPolicyChange"] = ""
	policy["AuditAccountManagement"] = ""

	output := wc.runCommand("auditpol", "/get", "/category:*")
	if output != "" {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			re := regexp.MustCompile(`(?i)^(.+?)\s+(Success and Failure|Success|Failure|No Auditing)$`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 3 {
				category := strings.TrimSpace(matches[1])
				status := matches[2]
				policy[category] = status
			}
		}
	}

	return policy
}

func (wc *WindowsLocalCollector) getLSASettings() map[string]interface{} {
	settings := make(map[string]interface{})

	lsaKeys := []struct {
		ValueName string
		Key       string
	}{
		{"RestrictAnonymous", "RestrictAnonymous"},
		{"RestrictAnonymousSam", "RestrictAnonymousSam"},
		{"DisableDomainCreds", "DisableDomainCreds"},
		{"LmCompatibilityLevel", "LmCompatibilityLevel"},
	}

	for _, key := range lsaKeys {
		output := wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "/v", key.ValueName)
		if output == "" {
			settings[key.Key] = ""
			continue
		}

		re := regexp.MustCompile(key.ValueName + `\s+REG_\w+\s+(\S+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			settings[key.Key] = matches[1]
		} else {
			settings[key.Key] = ""
		}
	}

	return settings
}

func (wc *WindowsLocalCollector) getUACLevel() string {
	output := wc.runCommand("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "ConsentPromptBehaviorAdmin")
	if output == "" {
		return "无法读取"
	}

	re := regexp.MustCompile(`ConsentPromptBehaviorAdmin\s+REG_DWORD\s+(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) >= 2 {
		level := matches[1]
		switch level {
		case "0":
			return "0 (从不通知)"
		case "1":
			return "1 (仅在程序尝试更改时通知)"
		case "2":
			return "2 (仅在程序尝试更改时通知) - 默认"
		case "3":
			return "3 (始终通知)"
		case "4":
			return "4 (始终通知，需要安全桌面)"
		default:
			return level + " (未知等级)"
		}
	}

	return "无法读取"
}

func (wc *WindowsLocalCollector) getFirewallStatus() map[string]interface{} {
	status := make(map[string]interface{})

	status["domain_enabled"] = false
	status["private_enabled"] = false
	status["public_enabled"] = false

	output := wc.runCommand("netsh", "advfirewall", "show", "currentprofile")
	if output != "" {
		if strings.Contains(output, "State                                 ON") {
			status["domain_enabled"] = true
			status["private_enabled"] = true
			status["public_enabled"] = true
		}
	}

	return status
}

func (wc *WindowsLocalCollector) getAnonymousRestrictions() map[string]interface{} {
	restrictions := make(map[string]interface{})

	output := wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "/v", "RestrictAnonymous")
	if output == "" {
		restrictions["restrict_anonymous"] = "无法读取"
	} else {
		re := regexp.MustCompile(`RestrictAnonymous\s+REG_\w+\s+(\d+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			restrictions["restrict_anonymous"] = matches[1]
		} else {
			restrictions["restrict_anonymous"] = "未配置"
		}
	}

	output = wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Control\LSA`, "/v", "RestrictAnonymousSam")
	if output == "" {
		restrictions["restrict_anonymous_sam"] = "无法读取"
	} else {
		re := regexp.MustCompile(`RestrictAnonymousSam\s+REG_\w+\s+(\d+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			restrictions["restrict_anonymous_sam"] = matches[1]
		} else {
			restrictions["restrict_anonymous_sam"] = "未配置"
		}
	}

	return restrictions
}

func (wc *WindowsLocalCollector) getLocalAdmins() []string {
	admins := []string{"Administrator"}

	output := wc.runCommand("net", "localgroup", "Administrators")
	if output != "" {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "---") && !strings.Contains(line, "成员") && !strings.Contains(line, "command") {
				if line != "Administrator" {
					admins = append(admins, line)
				}
			}
		}
	}

	return admins
}

func (wc *WindowsLocalCollector) getListeningPorts() []int {
	ports := []int{}

	output := wc.runCommand("netstat", "-ano")
	if output == "" {
		return ports
	}

	re := regexp.MustCompile(`(?i)TCP\s+[\d.]+:(\d+)\s+[\d.]+:(\d+)\s+LISTENING`)
	matches := re.FindAllStringSubmatch(output, -1)
	portSet := make(map[int]bool)
	for _, match := range matches {
		if len(match) >= 2 {
			var port int
			_, err := fmt.Sscanf(match[1], "%d", &port)
			if err == nil && port > 0 {
				portSet[port] = true
			}
		}
	}

	for port := range portSet {
		ports = append(ports, port)
	}

	return ports
}

func (wc *WindowsLocalCollector) getSMBSettings() map[string]interface{} {
	settings := make(map[string]interface{})

	output := wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "/v", "SMB1")

	if output == "" || strings.Contains(output, "ERROR") {
		settings["smbv1_enabled"] = false
		settings["smbv1_status"] = "未安装或已禁用 (默认)"
	} else {
		re := regexp.MustCompile(`(?i)SMB1\s+REG_\w+\s+(\d+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			smbv1Val := matches[1]
			settings["smbv1_enabled"] = smbv1Val != "0"
			if smbv1Val == "0" {
				settings["smbv1_status"] = "已禁用"
			} else if smbv1Val == "1" {
				settings["smbv1_status"] = "已启用"
			} else {
				settings["smbv1_status"] = "未知值: " + smbv1Val
			}
		} else {
			settings["smbv1_enabled"] = false
			settings["smbv1_status"] = "配置不存在 (视为禁用)"
		}
	}

	output = wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "/v", "RequireSecuritySignature")
	if output == "" || strings.Contains(output, "ERROR") {
		settings["require_smb_signing"] = false
		settings["smb_signing_status"] = "未配置"
	} else {
		re := regexp.MustCompile(`(?i)RequireSecuritySignature\s+REG_\w+\s+(\d+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			signingVal := matches[1]
			settings["require_smb_signing"] = signingVal == "1"
			if signingVal == "1" {
				settings["smb_signing_status"] = "已要求"
			} else {
				settings["smb_signing_status"] = "未要求"
			}
		} else {
			settings["require_smb_signing"] = false
			settings["smb_signing_status"] = "未配置"
		}
	}

	output = wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "/v", "AutoShareServer")
	if output == "" || strings.Contains(output, "ERROR") {
		settings["autoshare_server"] = ""
	} else {
		re := regexp.MustCompile(`(?i)AutoShareServer\s+REG_\w+\s+(\S+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			settings["autoshare_server"] = matches[1]
		} else {
			settings["autoshare_server"] = ""
		}
	}

	output = wc.runCommand("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "/v", "AutoShareWks")
	if output == "" || strings.Contains(output, "ERROR") {
		settings["autoshare_wks"] = ""
	} else {
		re := regexp.MustCompile(`(?i)AutoShareWks\s+REG_\w+\s+(\S+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) >= 2 {
			settings["autoshare_wks"] = matches[1]
		} else {
			settings["autoshare_wks"] = ""
		}
	}

	return settings
}
