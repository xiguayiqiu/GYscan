package ldap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig 存储LDAP连接和查询配置
type LDAPConfig struct {
	Server      string
	Port        int
	Domain      string
	Username    string
	Password    string
	BaseDN      string
	Protocol    string // "ldap", "ldaps"
	Timeout     time.Duration
	Verbose     bool
	OutputFile  string
	SearchScope int
}

// LDAPResult 存储LDAP查询结果
type LDAPResult struct {
	Success   bool
	Entries   []LDAPEntry
	Error     error
	Count     int
	ExecutionTime time.Duration
}

// LDAPEntry 存储单个LDAP条目
type LDAPEntry struct {
	DN          string            `json:"dn"`
	Attributes  map[string][]string `json:"attributes"`
}

// LDAPClient 提供LDAP枚举功能
type LDAPClient struct {
	Config *LDAPConfig
	conn   *ldap.Conn
}

// NewLDAPClient 创建新的LDAP客户端实例
func NewLDAPClient(config *LDAPConfig) *LDAPClient {
	return &LDAPClient{
		Config: config,
	}
}

// Connect 建立LDAP连接
func (c *LDAPClient) Connect() error {
	if c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("正在连接到LDAP服务器: %s:%d", c.Config.Server, c.Config.Port))
	}
	
	// 根据协议选择连接方式
	address := fmt.Sprintf("%s:%d", c.Config.Server, c.Config.Port)
	var err error
	
	if c.Config.Protocol == "ldaps" {
		c.conn, err = ldap.DialTLS("tcp", address, nil)
	} else {
		c.conn, err = ldap.Dial("tcp", address)
	}
	
	if err != nil {
		return fmt.Errorf("LDAP连接失败: %v", err)
	}
	
	if c.Config.Verbose {
		utils.SuccessPrint("LDAP连接成功")
	}
	
	return nil
}

// Bind 执行LDAP绑定操作
func (c *LDAPClient) Bind() error {
	if c.conn == nil {
		return fmt.Errorf("LDAP连接未建立")
	}
	
	// 构建绑定用户名
	bindUsername := c.Config.Username
	if c.Config.Domain != "" && !strings.Contains(bindUsername, "@") && !strings.Contains(bindUsername, "\\") {
		// 如果提供了域名，但用户名不是UPN或域\用户名格式，则添加域名
		bindUsername = fmt.Sprintf("%s@%s", bindUsername, strings.ToLower(c.Config.Domain))
	}
	
	if c.Config.Verbose {
		utils.WarningPrint(fmt.Sprintf("执行LDAP绑定，用户名: %s", bindUsername))
	}
	
	err := c.conn.Bind(bindUsername, c.Config.Password)
	if err != nil {
		return fmt.Errorf("LDAP绑定失败: %v", err)
	}
	
	if c.Config.Verbose {
		utils.SuccessPrint("LDAP绑定成功")
	}
	
	return nil
}

// Close 关闭LDAP连接
func (c *LDAPClient) Close() {
	if c.conn != nil {
		c.conn.Close()
		if c.Config.Verbose {
			utils.SuccessPrint("LDAP连接已关闭")
		}
	}
}

// DiscoverBaseDN 自动发现BaseDN
func (c *LDAPClient) DiscoverBaseDN() (string, error) {
	if c.Config.Verbose {
		utils.SuccessPrint("尝试自动发现BaseDN")
	}
	
	// 基于域名构建BaseDN
	if c.Config.Domain != "" {
		parts := strings.Split(c.Config.Domain, ".")
		var baseDNParts []string
		for _, part := range parts {
			baseDNParts = append(baseDNParts, "DC="+part)
		}
		baseDN := strings.Join(baseDNParts, ",")
		
		if c.Config.Verbose {
			utils.SuccessPrint(fmt.Sprintf("自动构建BaseDN: %s", baseDN))
		}
		return baseDN, nil
	}
	
	return "", fmt.Errorf("无法自动发现BaseDN，请提供域名或手动指定BaseDN")
}

// EnumUsers 枚举域用户
func (c *LDAPClient) EnumUsers(filter string) *LDAPResult {
	if filter == "" {
		filter = "(&(objectClass=user)(objectCategory=person))"
	}
	
	return c.Search(filter, []string{"sAMAccountName", "userPrincipalName", "displayName", "description", "memberOf", "lastLogonTimestamp", "accountExpires", "userAccountControl"})
}

// EnumGroups 枚举域组
func (c *LDAPClient) EnumGroups(filter string) *LDAPResult {
	if filter == "" {
		filter = "(&(objectClass=group))"
	}
	
	return c.Search(filter, []string{"sAMAccountName", "displayName", "description", "member", "memberOf"})
}

// EnumComputers 枚举域计算机
func (c *LDAPClient) EnumComputers(filter string) *LDAPResult {
	if filter == "" {
		filter = "(&(objectClass=computer))"
	}
	
	return c.Search(filter, []string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "description", "lastLogonTimestamp"})
}

// EnumOUs 枚举组织单位
func (c *LDAPClient) EnumOUs(filter string) *LDAPResult {
	if filter == "" {
		filter = "(&(objectClass=organizationalUnit))"
	}
	
	return c.Search(filter, []string{"name", "description"})
}

// EnumDomainPolicy 枚举域策略信息
func (c *LDAPClient) EnumDomainPolicy() *LDAPResult {
	// 搜索域策略信息
	filter := "(&(objectClass=domainDNS))"
	return c.Search(filter, []string{"unicodePwdHistory", "lockoutDuration", "lockOutObservationWindow", "maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength", "pwdProperties", "pwdLastSet"})
}

// EnumTrusts 枚举域信任关系
func (c *LDAPClient) EnumTrusts() *LDAPResult {
	filter := "(&(objectClass=trustedDomain))"
	return c.Search(filter, []string{"flatName", "trustDirection", "trustPartner", "trustType", "securityIdentifier"})
}

// FindSPNs 查找配置了SPN的账户（可能用于Kerberoasting）
func (c *LDAPClient) FindSPNs() *LDAPResult {
	filter := "(&(objectClass=user)(servicePrincipalName=*))"
	return c.Search(filter, []string{"sAMAccountName", "servicePrincipalName", "description"})
}

// FindASREPPrincipal 查找无需预认证的账户（可用于AS-REP Roasting）
func (c *LDAPClient) FindASREPPrincipal() *LDAPResult {
	filter := "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	return c.Search(filter, []string{"sAMAccountName", "userPrincipalName", "displayName"})
}

// Search 执行自定义LDAP搜索
func (c *LDAPClient) Search(filter string, attributes []string) *LDAPResult {
	startTime := time.Now()
	
	if c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("执行LDAP搜索，过滤器: %s", filter))
	}
	
	// 确保BaseDN已设置
	baseDN := c.Config.BaseDN
	if baseDN == "" {
		discoveredBaseDN, err := c.DiscoverBaseDN()
		if err != nil {
			return &LDAPResult{
				Success: false,
				Error:   err,
				Count:   0,
			}
		}
		baseDN = discoveredBaseDN
	}
	
	// 构建搜索请求
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		int(c.Config.Timeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	)
	
	// 执行搜索
	searchResult, err := c.conn.Search(searchRequest)
	if err != nil {
		return &LDAPResult{
			Success: false,
			Error:   fmt.Errorf("LDAP搜索失败: %v", err),
			Count:   0,
		}
	}
	
	// 转换结果
	entries := make([]LDAPEntry, 0, len(searchResult.Entries))
	for _, entry := range searchResult.Entries {
		attrMap := make(map[string][]string)
		for _, attr := range entry.Attributes {
			attrMap[attr.Name] = attr.Values
		}
		
		entries = append(entries, LDAPEntry{
			DN:         entry.DN,
			Attributes: attrMap,
		})
	}
	
	executionTime := time.Since(startTime)
	
	result := &LDAPResult{
		Success:       true,
		Entries:       entries,
		Error:         nil,
		Count:         len(entries),
		ExecutionTime: executionTime,
	}
	
	// 如果指定了输出文件，保存结果
	if result.Success && c.Config.OutputFile != "" {
		c.saveResultToFile(result)
	}
	
	if c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("LDAP搜索完成，找到 %d 个条目，耗时 %v", result.Count, result.ExecutionTime))
	}
	
	return result
}

// saveResultToFile 将结果保存到文件
func (c *LDAPClient) saveResultToFile(result *LDAPResult) {
	content, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		if c.Config.Verbose {
			utils.ErrorPrint(fmt.Sprintf("序列化结果失败: %v", err))
		}
		return
	}
	
	err = os.WriteFile(c.Config.OutputFile, content, 0644)
	if err != nil {
		if c.Config.Verbose {
			utils.ErrorPrint(fmt.Sprintf("保存结果到文件失败: %v", err))
		}
		return
	}
	
	if c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("结果已保存到: %s", c.Config.OutputFile))
	}
}

// FormatResult 格式化结果为可读文本
func (c *LDAPClient) FormatResult(result *LDAPResult) string {
	var builder strings.Builder
	
	builder.WriteString(fmt.Sprintf("搜索结果: %d 个条目\n", result.Count))
	builder.WriteString(fmt.Sprintf("执行时间: %v\n\n", result.ExecutionTime))
	
	for i, entry := range result.Entries {
		builder.WriteString(fmt.Sprintf("--- 条目 %d ---\n", i+1))
		builder.WriteString(fmt.Sprintf("DN: %s\n", entry.DN))
		builder.WriteString("属性:\n")
		
		for attrName, values := range entry.Attributes {
			builder.WriteString(fmt.Sprintf("  %s:", attrName))
			
			if len(values) == 1 {
				builder.WriteString(fmt.Sprintf(" %s\n", values[0]))
			} else {
				builder.WriteString("\n")
				for _, value := range values {
					builder.WriteString(fmt.Sprintf("    - %s\n", value))
				}
			}
		}
		
		builder.WriteString("\n")
	}
	
	return builder.String()
}

// IsLDAPSChannel 检查LDAP连接是否使用SSL/TLS
func (c *LDAPClient) IsLDAPSChannel() bool {
	// 简单检查连接是否为LDAPS
	return c.Config.Protocol == "ldaps"
}