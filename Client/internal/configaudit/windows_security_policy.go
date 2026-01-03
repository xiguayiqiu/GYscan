package configaudit

import (
	"fmt"
	"regexp"
	"strings"
)

type WindowsSecurityPolicyCollector struct {
	client *WMIClient
}

func NewWindowsSecurityPolicyCollector(client *WMIClient) *WindowsSecurityPolicyCollector {
	return &WindowsSecurityPolicyCollector{
		client: client,
	}
}

func (c *WindowsSecurityPolicyCollector) CollectSecurityPolicy() map[string]interface{} {
	policy := make(map[string]interface{})

	passwordPolicy := make(map[string]interface{})
	passwordPolicy["min_password_length"] = c.getPolicyValue("PasswordHistorySize")
	passwordPolicy["max_password_age"] = c.getPolicyValue("MaxPasswordAge")
	passwordPolicy["min_password_age"] = c.getPolicyValue("MinPasswordAge")
	passwordPolicy["complexity_enabled"] = c.getPolicyValue("PasswordComplexity")
	policy["password_policy"] = passwordPolicy

	lockoutPolicy := make(map[string]interface{})
	lockoutPolicy["lockout_bad_count"] = c.getPolicyValue("LockoutBadCount")
	lockoutPolicy["reset_lockout_count"] = c.getPolicyValue("ResetLockoutCount")
	lockoutPolicy["lockout_duration"] = c.getPolicyValue("LockoutDuration")
	policy["lockout_policy"] = lockoutPolicy

	auditPolicy := make(map[string]interface{})
	auditCategories := []string{
		"AuditAccountLogon", "AuditAccountManagement", "AuditDirectoryServiceAccess",
		"AuditLogonEvents", "AuditObjectAccess", "AuditPolicyChange",
		"AuditPrivilegeUse", "AuditProcessTracking", "AuditSystemEvents",
	}
	for _, policyName := range auditCategories {
		value := c.getPolicyValue(policyName)
		auditPolicy[policyName] = value
	}
	policy["audit_policy"] = auditPolicy

	localPolicy := make(map[string]interface{})
	localPolicy["enable_admin_account"] = c.getPolicyValue("EnableAdminAccount")
	localPolicy["enable_guest_account"] = c.getPolicyValue("EnableGuestAccount")
	policy["local_policy"] = localPolicy

	userRights := make(map[string]interface{})
	userRightsAssignments := map[string]string{
		"SeBackupPrivilege":             "备份文件和目录",
		"SeRestorePrivilege":            "还原文件和目录",
		"SeShutdownPrivilege":           "关闭系统",
		"SeDebugPrivilege":              "调试程序",
		"SeSecurityPrivilege":           "管理审计和安全日志",
		"SeInteractiveLogonRight":       "本地登录",
		"SeNetworkLogonRight":           "从网络访问此计算机",
		"SeRemoteInteractiveLogonRight": "通过远程桌面服务登录",
	}
	for privilege, description := range userRightsAssignments {
		value := c.getUserRightsAssignment(privilege)
		if value != "" {
			userRights[privilege] = map[string]interface{}{
				"description": description,
				"accounts":    value,
			}
		}
	}
	policy["user_rights"] = userRights

	return policy
}

func (c *WindowsSecurityPolicyCollector) getPolicyValue(policyName string) string {
	query := fmt.Sprintf("SELECT Value FROM SecurityPolicy WHERE KeyName='%s'", policyName)
	result, err := c.client.ExecuteWMIQuery(query)
	if err != nil {
		return ""
	}

	if len(result.Data) > 0 {
		if val, ok := result.Data[0]["Value"]; ok {
			return val
		}
	}

	return ""
}

func (c *WindowsSecurityPolicyCollector) getUserRightsAssignment(privilege string) string {
	query := fmt.Sprintf("SELECT Account FROM UserRight WHERE UserRight='%s'", privilege)
	result, err := c.client.ExecuteWMIQuery(query)
	if err != nil {
		return ""
	}

	var accounts []string
	for _, row := range result.Data {
		if account, ok := row["Account"]; ok {
			accounts = append(accounts, account)
		}
	}

	return strings.Join(accounts, ", ")
}

func parseInt(s string) int {
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(s)
	if match == "" {
		return 0
	}
	var result int
	fmt.Sscanf(match, "%d", &result)
	return result
}
