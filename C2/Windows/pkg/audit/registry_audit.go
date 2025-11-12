package audit

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// RegistryAudit 注册表审计模块
type RegistryAudit struct {
	config *Config
}

// NewRegistryAudit 创建注册表审计模块
func NewRegistryAudit(config *Config) *RegistryAudit {
	return &RegistryAudit{
		config: config,
	}
}

// Name 返回模块名称
func (ra *RegistryAudit) Name() string {
	return "registry"
}

// Description 返回模块描述
func (ra *RegistryAudit) Description() string {
	return "Windows注册表安全审计，包括启动项检查、权限设置、恶意注册表项检测"
}

// RequiredPermissions 返回所需权限
func (ra *RegistryAudit) RequiredPermissions() []string {
	return []string{"SeBackupPrivilege"}
}

// Run 执行注册表审计
func (ra *RegistryAudit) Run() ([]AuditResult, error) {
	var results []AuditResult

	// 1. 检查启动项
	results = append(results, ra.auditStartupEntries()...)
	
	// 2. 检查服务配置
	results = append(results, ra.auditServiceConfigurations()...)
	
	// 3. 检查安全策略
	results = append(results, ra.auditSecurityPolicies()...)
	
	// 4. 检查恶意注册表项
	results = append(results, ra.auditMaliciousEntries()...)

	return results, nil
}

// auditStartupEntries 审计启动项
func (ra *RegistryAudit) auditStartupEntries() []AuditResult {
	var results []AuditResult

	// 常见的启动项注册表路径
	startupPaths := []struct {
		path        string
		description string
	}{
		{
			path:        `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`,
			description: "系统启动项",
		},
		{
			path:        `HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`,
			description: "用户启动项",
		},
		{
			path:        `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce`,
			description: "一次性系统启动项",
		},
		{
			path:        `HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce`,
			description: "一次性用户启动项",
		},
		{
			path:        `HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run`,
			description: "32位系统启动项",
		},
	}

	for _, startupPath := range startupPaths {
		entries, err := ra.getRegistryEntries(startupPath.path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// 检查启动项是否可疑
			if ra.isSuspiciousStartupEntry(entry) {
				results = append(results, AuditResult{
					ModuleName:    ra.Name(),
					Level:         AuditLevelHigh,
					Status:        "fail",
					Description:   fmt.Sprintf("可疑启动项: %s", entry.Name),
					Details:       fmt.Sprintf("路径: %s, 值: %v", startupPath.path, entry.Value),
					RiskScore:     80,
					Recommendation: "调查此启动项的合法性",
					Timestamp:     time.Now(),
				})
			}
		}
	}

	return results
}

// getRegistryEntries 获取注册表项
func (ra *RegistryAudit) getRegistryEntries(path string) ([]RegistryEntry, error) {
	var entries []RegistryEntry

	// 解析注册表路径
	hive, subkey, err := ra.parseRegistryPath(path)
	if err != nil {
		return nil, err
	}

	// 打开注册表项
	key, err := registry.OpenKey(hive, subkey, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	// 枚举值
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	for _, valueName := range valueNames {
		value, valueType, err := key.GetValue(valueName, nil)
		if err != nil {
			continue
		}

		entry := RegistryEntry{
			Path:  path,
			Name:  valueName,
			Type:  ra.getRegistryTypeName(valueType),
			Value: value,
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// parseRegistryPath 解析注册表路径
func (ra *RegistryAudit) parseRegistryPath(path string) (registry.Key, string, error) {
	parts := strings.SplitN(path, "\\\\", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("无效的注册表路径: %s", path)
	}

	var hive registry.Key
	switch parts[0] {
	case "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKEY_USERS":
		hive = registry.USERS
	case "HKEY_CURRENT_CONFIG":
		hive = registry.CURRENT_CONFIG
	default:
		return 0, "", fmt.Errorf("未知的注册表根键: %s", parts[0])
	}

	return hive, parts[1], nil
}

// getRegistryTypeName 获取注册表类型名称
func (ra *RegistryAudit) getRegistryTypeName(valueType uint32) string {
	switch valueType {
	case registry.SZ:
		return "REG_SZ"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.QWORD:
		return "REG_QWORD"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	default:
		return "UNKNOWN"
	}
}

// isSuspiciousStartupEntry 检查是否为可疑启动项
func (ra *RegistryAudit) isSuspiciousStartupEntry(entry RegistryEntry) bool {
	// 可疑的启动项特征
	suspiciousPatterns := []string{
		"temp",
		"appdata",
		"users",
		".exe",
		"powershell",
		"cmd",
		"wscript",
		"cscript",
		"rundll32",
		"regsvr32",
	}

	valueStr := fmt.Sprintf("%v", entry.Value)
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(valueStr), strings.ToLower(pattern)) {
			// 检查是否为已知的合法启动项
			if !ra.isKnownLegitimateStartup(entry) {
				return true
			}
		}
	}

	return false
}

// isKnownLegitimateStartup 检查是否为已知的合法启动项
func (ra *RegistryAudit) isKnownLegitimateStartup(entry RegistryEntry) bool {
	// 已知的合法启动项列表
	legitimateStartups := []string{
		"SecurityHealth",
		"Windows Defender",
		"OneDrive",
		"Microsoft Edge",
		"Windows Explorer",
	}

	valueStr := fmt.Sprintf("%v", entry.Value)
	
	for _, legitimate := range legitimateStartups {
		if strings.Contains(strings.ToLower(valueStr), strings.ToLower(legitimate)) {
			return true
		}
	}

	return false
}

// auditServiceConfigurations 审计服务配置
func (ra *RegistryAudit) auditServiceConfigurations() []AuditResult {
	var results []AuditResult

	// 服务配置注册表路径
	servicePaths := []struct {
		path        string
		description string
	}{
		{
			path:        `HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services`,
			description: "系统服务配置",
		},
	}

	for _, servicePath := range servicePaths {
		// 获取服务列表
		services, err := ra.getRegistrySubkeys(servicePath.path)
		if err != nil {
			continue
		}

		for _, service := range services {
			// 检查服务配置
			if ra.isSuspiciousService(servicePath.path + "\\\\" + service) {
				results = append(results, AuditResult{
					ModuleName:    ra.Name(),
					Level:         AuditLevelHigh,
					Status:        "fail",
					Description:   fmt.Sprintf("可疑服务配置: %s", service),
					Details:       servicePath.description,
					RiskScore:     75,
					Recommendation: "调查此服务的配置",
					Timestamp:     time.Now(),
				})
			}
		}
	}

	return results
}

// getRegistrySubkeys 获取注册表子项
func (ra *RegistryAudit) getRegistrySubkeys(path string) ([]string, error) {
	// 简化实现：返回空列表
	// 在实际实现中，应该使用Windows注册表API
	return []string{}, nil
}

// isSuspiciousService 检查是否为可疑服务
func (ra *RegistryAudit) isSuspiciousService(servicePath string) bool {
	// 检查服务配置
	imagePath, err := ra.getRegistryValue(servicePath + "\\\\ImagePath")
	if err != nil {
		return false
	}

	// 可疑的服务特征
	suspiciousPatterns := []string{
		"temp",
		"appdata",
		"users",
		".exe",
		"powershell",
	}

	imagePathStr := fmt.Sprintf("%v", imagePath)
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(imagePathStr), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// getRegistryValue 获取注册表值
func (ra *RegistryAudit) getRegistryValue(path string) (interface{}, error) {
	// 简化实现：返回默认值
	// 在实际实现中，应该使用Windows注册表API
	return uint32(1), nil
}

// auditSecurityPolicies 审计安全策略
func (ra *RegistryAudit) auditSecurityPolicies() []AuditResult {
	var results []AuditResult

	// 安全策略注册表路径
	policyPaths := []struct {
		path        string
		name        string
		expected    interface{}
		description string
	}{
		{
			path:        `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA`,
			name:        "用户账户控制",
			expected:    uint32(1),
			description: "UAC应启用",
		},
		{
			path:        `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin`,
			name:        "UAC管理员提示行为",
			expected:    uint32(2),
			description: "UAC管理员提示应设置为提示凭据",
		},
	}

	for _, policy := range policyPaths {
		actual, err := ra.getRegistryValue(policy.path)
		if err != nil {
			results = append(results, AuditResult{
				ModuleName:    ra.Name(),
				Level:         AuditLevelMedium,
				Status:        "warning",
				Description:   fmt.Sprintf("安全策略未配置: %s", policy.name),
				Details:       policy.description,
				RiskScore:     60,
				Recommendation: "配置此安全策略",
				Timestamp:     time.Now(),
			})
			continue
		}

		if actual != policy.expected {
			results = append(results, AuditResult{
				ModuleName:    ra.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   fmt.Sprintf("安全策略配置错误: %s", policy.name),
				Details:       fmt.Sprintf("期望: %v, 实际: %v", policy.expected, actual),
				RiskScore:     70,
				Recommendation: "修复此安全策略配置",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// auditMaliciousEntries 审计恶意注册表项
func (ra *RegistryAudit) auditMaliciousEntries() []AuditResult {
	var results []AuditResult

	// 已知的恶意注册表模式
	maliciousPatterns := []struct {
		path        string
		description string
		riskScore   int
	}{
		{
			path:        `HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware`,
			description: "已知恶意启动项",
			riskScore:   90,
		},
		{
			path:        `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options`,
			description: "映像劫持位置",
			riskScore:   85,
		},
	}

	for _, pattern := range maliciousPatterns {
		// 检查恶意注册表项是否存在
		if ra.registryKeyExists(pattern.path) {
			results = append(results, AuditResult{
				ModuleName:    ra.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   fmt.Sprintf("检测到恶意注册表项: %s", pattern.path),
				Details:       pattern.description,
				RiskScore:     pattern.riskScore,
				Recommendation: "立即删除此注册表项",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// registryKeyExists 检查注册表项是否存在
func (ra *RegistryAudit) registryKeyExists(path string) bool {
	// 简化实现：返回false
	// 在实际实现中，应该使用Windows注册表API
	return false
}