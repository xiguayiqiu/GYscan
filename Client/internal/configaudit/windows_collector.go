package configaudit

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
	
)

type WMIConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	Domain     string
	Timeout    time.Duration // 需导入 time 包
	MaxRetries int
	UseHTTPS   bool
	Namespace  string
}

type WMIResult struct {
	Success bool
	Data    []map[string]string
	Error   error
	Query   string
}

type RPCBinding struct {
	Target   string
	Port     int
	Protocol string
	Endpoint string
	UUID     string
	Options  map[string]interface{}
}

type WindowsConfigCollector struct {
	client    *WMIClient
	config    *WMIConfig
	connected bool
}

type WMIClient struct {
	conn     net.Conn
	config   *WMIConfig
	rpcBound *RPCBinding
	mu       sync.Mutex
}

func NewWMIConfig(config *WMIConfig) *WMIConfig {
	if config.Port == 0 {
		config.Port = 135
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Namespace == "" {
		config.Namespace = "root\\cimv2"
	}
	return config
}

func NewWMIClient(config *WMIConfig) *WMIClient {
	return &WMIClient{
		config: NewWMIConfig(config),
	}
}

func (c *WMIClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	host := c.config.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", c.config.Port))

	var err error
	c.conn, err = net.DialTimeout("tcp", target, c.config.Timeout)
	if err != nil {
		return fmt.Errorf("无法连接到 %s: %v", target, err)
	}

	c.rpcBound = &RPCBinding{
		Target:   c.config.Host,
		Port:     c.config.Port,
		Protocol: "ncacn_ip_tcp",
		UUID:     "00000000-0000-0000-0000-000000000000",
	}

	return nil
}

func (c *WMIClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func (c *WMIClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *WMIClient) ExecuteWMIQuery(query string) (*WMIResult, error) {
	result := &WMIResult{
		Query:   query,
		Success: false,
	}

	if !c.IsConnected() {
		if err := c.Connect(); err != nil {
			result.Error = err
			return result, err
		}
	}

	data, err := c.executeWMIQueryRaw(query)
	if err != nil {
		result.Error = err
		return result, err
	}

	result.Data = c.parseWMIResult(data)
	result.Success = len(result.Data) > 0

	return result, nil
}

func (c *WMIClient) executeWMIQueryRaw(query string) ([]byte, error) {
	wqlQuery := fmt.Sprintf("WQL:%s", query)

	wqlBytes := []byte(wqlQuery)

	response := make([]byte, 4096)

	_, err := c.conn.Write(wqlBytes)
	if err != nil {
		return nil, fmt.Errorf("WMI查询发送失败: %v", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(c.config.Timeout))
	n, err := c.conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("WMI响应读取失败: %v", err)
	}

	return response[:n], nil
}

func (c *WMIClient) parseWMIResult(data []byte) []map[string]string {
	var results []map[string]string

	dataStr := string(data)

	lines := strings.Split(dataStr, "\n")
	currentRecord := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Node=") ||
			strings.HasPrefix(line, "Item=") ||
			strings.HasPrefix(line, "Instance") {
			if len(currentRecord) > 0 {
				results = append(results, currentRecord)
				currentRecord = make(map[string]string)
			}
			continue
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentRecord[key] = value
			}
		}
	}

	if len(currentRecord) > 0 {
		results = append(results, currentRecord)
	}

	return results
}

type RPC135Checker struct {
	target  string
	port    int
	timeout time.Duration
}

func NewRPC135Checker(target string, timeout time.Duration) *RPC135Checker {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &RPC135Checker{
		target:  target,
		port:    135,
		timeout: timeout,
	}
}

func (c *RPC135Checker) CheckPortStatus() (*PortCheckResult, error) {
	result := &PortCheckResult{
		Target: c.target,
		Port:   c.port,
	}

	addr := net.JoinHostPort(c.target, fmt.Sprintf("%d", c.port))

	conn, err := net.DialTimeout("tcp", addr, c.timeout)
	if err != nil {
		result.IsOpen = false
		result.Error = err
		result.Message = fmt.Sprintf("端口 %d 关闭或不可达: %v", c.port, err)
		return result, nil
	}
	defer conn.Close()

	result.IsOpen = true
	result.Message = "端口已开放，服务可访问"

	svcName := identifyRPCService(c.port)
	if svcName != "" {
		result.ServiceName = svcName
	}

	return result, nil
}

func identifyRPCService(port int) string {
	services := map[int]string{
		135: "MSRPC (Microsoft RPC Endpoint Mapper)",
		139: "NetBIOS Session Service",
		445: "SMB/Direct Host",
	}
	return services[port]
}

type PortCheckResult struct {
	Target       string
	Port         int
	IsOpen       bool
	ServiceName  string
	Error        error
	Message      string
	ResponseTime time.Duration
}

func Check135Port(target string, timeout time.Duration) *PortCheckResult {
	checker := NewRPC135Checker(target, timeout)
	result, _ := checker.CheckPortStatus()
	return result
}

func DetectAndGuide135Port(target string, timeout time.Duration) *PortCheckResult {
	result := Check135Port(target, timeout)

	if !result.IsOpen {
		result.Message = fmt.Sprintf(`
=== 135端口未开启 ===

目标系统 %s 的135端口当前处于关闭状态。
RPC Endpoint Mapper服务（135端口）未运行，无法进行远程Windows审计。

【操作指引】

方法一：通过图形界面开启135端口

1. 打开"Windows防火墙"（Windows Defender Firewall）
   - 在开始菜单搜索"Windows Defender防火墙"
   - 或运行: wf.msc

2. 添加入站规则允许135端口
   - 左侧点击"高级设置"
   - 选择"入站规则" -> "新建规则"
   - 规则类型: "端口"
   - 协议: "TCP" -> 特定本地端口: "135"
   - 操作: "允许连接"
   - 配置文件: 勾选"域"、"专用"、"公用"
   - 名称: "RPC Endpoint Mapper (135)"

3. 启用RPC服务
   - 按 Win+R，输入 services.msc
   - 找到 "Remote Procedure Call (RPC)" 服务
   - 确保状态为"正在运行"
   - 启动类型: "自动"

4. 启动 DCOM 服务
   - 在服务列表中找到 "DCOM Server Process Launcher"
   - 确保状态为"正在运行"

方法二：通过命令行开启

1. 开启防火墙135端口:
   netsh advfirewall firewall add rule name="RPC Endpoint Mapper (135)" ^
       dir=in action=allow protocol=TCP localport=135

2. 启用RPC服务:
   sc start rpcss
   sc config rpcss start= auto

3. 启用DCOM服务:
   sc start dcomlaunch
   sc config dcomlaunch start= auto

4. 检查服务状态:
   sc query rpcss
   sc query dcomlaunch

【验证步骤】

1. 检查135端口是否开放:
   telnet %s 135
   或
   Test-NetConnection %s -Port 135

2. 检查RPC服务状态:
   sc query rpcss

3. 重新运行审计命令

如问题持续，请联系系统管理员检查网络策略或RPC服务配置。
`, target, target, target)
	}

	return result
}

func (c *WMIClient) GetOSInfo() (map[string]string, error) {
	query := "SELECT Caption, Version, BuildNumber, OSArchitecture, CSName FROM Win32_OperatingSystem"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}

	if len(result.Data) > 0 {
		return result.Data[0], nil
	}
	return make(map[string]string), nil
}

func (c *WMIClient) GetSystemInfo() (map[string]string, error) {
	info := make(map[string]string)

	osInfo, err := c.GetOSInfo()
	if err == nil {
		for k, v := range osInfo {
			info[k] = v
		}
	}

	query := "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"
	result, err := c.ExecuteWMIQuery(query)
	if err == nil && len(result.Data) > 0 {
		if mem, ok := result.Data[0]["TotalPhysicalMemory"]; ok {
			info["TotalPhysicalMemory"] = mem
		}
	}

	query = "SELECT NumberOfCores FROM Win32_Processor"
	result, err = c.ExecuteWMIQuery(query)
	if err == nil && len(result.Data) > 0 {
		if cores, ok := result.Data[0]["NumberOfCores"]; ok {
			info["CPUCores"] = cores
		}
	}

	return info, nil
}

func (c *WMIClient) GetServices() ([]map[string]string, error) {
	query := "SELECT Name, DisplayName, State, StartMode, Description FROM Win32_Service"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetRunningServices() ([]map[string]string, error) {
	query := "SELECT Name, DisplayName, State, StartMode FROM Win32_Service WHERE State='Running'"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetUsers() ([]map[string]string, error) {
	query := "SELECT Name, FullName, Description, Disabled FROM Win32_UserAccount WHERE LocalAccount=true"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetLocalUsers() ([]map[string]string, error) {
	query := "SELECT * FROM Win32_UserAccount WHERE LocalAccount=true AND Domain='" + c.config.Host + "'"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetAdministrators() ([]map[string]string, error) {
	query := "SELECT * FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='" + c.config.Host + "',Name='Administrators'\""
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetSecurityPolicy() (map[string]string, error) {
	policy := make(map[string]string)

	queries := map[string]string{
		"PasswordHistorySize":          "SELECT Value FROM Win32_OptionalFeature WHERE Name='SecureBoot'",
		"MaxPasswordAge":               "SELECT Value FROM Win32_OptionalFeature WHERE Name='SecureBoot'",
		"MinPasswordAge":               "SELECT Value FROM Win32_OptionalFeature WHERE Name='SecureBoot'",
		"MinPasswordLength":            "SELECT Value FROM Win32_OptionalFeature WHERE Name='SecureBoot'",
		"AccountLockoutCount":          "SELECT Value FROM Win32_OptionalFeature WHERE Name='SecureBoot'",
		"RequireLogonToChangePassword": "SELECT Value FROM Win32_OptionalFeature WHERE Name='SecureBoot'",
	}

	for key, query := range queries {
		result, err := c.ExecuteWMIQuery(query)
		if err == nil && len(result.Data) > 0 {
			if val, ok := result.Data[0]["Value"]; ok {
				policy[key] = val
			}
		}
	}

	return policy, nil
}

func (c *WMIClient) GetNetworkAdapterConfig() ([]map[string]string, error) {
	query := "SELECT IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, MACAddress, Description FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=true"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetFirewallStatus() (map[string]string, error) {
	firewall := make(map[string]string)

	queries := []string{
		"SELECT Enabled FROM Win32_NetFirewallProfile WHERE Profile=0",
		"SELECT Enabled FROM Win32_NetFirewallProfile WHERE Profile=1",
		"SELECT Enabled FROM Win32_NetFirewallProfile WHERE Profile=2",
	}

	profiles := []string{"Domain", "Standard", "Public"}

	for i, query := range queries {
		result, err := c.ExecuteWMIQuery(query)
		if err == nil && len(result.Data) > 0 {
			if enabled, ok := result.Data[0]["Enabled"]; ok {
				firewall[profiles[i]+"Firewall"] = enabled
			}
		}
	}

	return firewall, nil
}

func (c *WMIClient) GetAutoRuns() ([]map[string]string, error) {
	query := "SELECT Name, Description, Location, Command FROM Win32_StartupCommand"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetHotfixes() ([]map[string]string, error) {
	query := "SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetShares() ([]map[string]string, error) {
	query := "SELECT Name, Path, Description, Type FROM Win32_Share"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetProcesses() ([]map[string]string, error) {
	query := "SELECT ProcessId, Name, ExecutablePath, CommandLine, Owner FROM Win32_Process"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetScheduledTasks() ([]map[string]string, error) {
	query := "SELECT Name, Description, State, LastRunTime, NextRunTime FROM Win32_ScheduledJob"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetEventLogs() ([]map[string]string, error) {
	query := "SELECT Name, FileSize, RecordCount, LastModified FROM Win32_NTEventlogFile"
	result, err := c.ExecuteWMIQuery(query)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

func (c *WMIClient) GetAuditPolicy() (map[string]string, error) {
	audit := make(map[string]string)

	queries := []string{
		"SELECT AuditLevel FROM Win32_LocalSecurityPolicy WHERE KeyName='Audit'",
	}

	for _, query := range queries {
		result, err := c.ExecuteWMIQuery(query)
		if err == nil && len(result.Data) > 0 {
			for k, v := range result.Data[0] {
				audit[k] = v
			}
		}
	}

	return audit, nil
}

func (c *WMIClient) GetRegKeys(keys []string) (map[string]string, error) {
	results := make(map[string]string)

	for _, key := range keys {
		query := fmt.Sprintf("SELECT Value FROM Registry WHERE KeyName='%s' AND Name=''", key)
		result, err := c.ExecuteWMIQuery(query)
		if err == nil && len(result.Data) > 0 {
			if val, ok := result.Data[0]["Value"]; ok {
				results[key] = val
			}
		}
	}

	return results, nil
}

func (c *WMIClient) CollectAllConfig() map[string]interface{} {
	config := make(map[string]interface{})

	var wg sync.WaitGroup
	var mu sync.Mutex

	type collFunc struct {
		name string
		fn   func() (interface{}, error)
	}

	functions := []collFunc{
		{"system_info", func() (interface{}, error) { return c.GetSystemInfo() }},
		{"os_info", func() (interface{}, error) { return c.GetOSInfo() }},
		{"services", func() (interface{}, error) { return c.GetRunningServices() }},
		{"users", func() (interface{}, error) { return c.GetUsers() }},
		{"firewall", func() (interface{}, error) { return c.GetFirewallStatus() }},
		{"hotfixes", func() (interface{}, error) { return c.GetHotfixes() }},
		{"shares", func() (interface{}, error) { return c.GetShares() }},
	}

	wg.Add(len(functions))

	for _, f := range functions {
		go func(f collFunc) {
			defer wg.Done()
			data, err := f.fn()
			mu.Lock()
			if err == nil {
				config[f.name] = data
			} else {
				config[f.name] = make(map[string]string)
			}
			mu.Unlock()
		}(f)
	}

	wg.Wait()

	return config
}

type WindowsRMConfig struct {
	Host     string
	Port     int
	Scheme   string
	AuthType string
	Username string
	Password string
	UseHTTPS bool
	SkipCert bool
	Timeout  time.Duration
}

type WindowsRMClient struct {
	config    *WindowsRMConfig
	connected bool
}

func NewWindowsRMClient(config *WindowsRMConfig) *WindowsRMClient {
	if config.Port == 0 {
		if config.UseHTTPS {
			config.Port = 5986
		} else {
			config.Port = 5985
		}
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Scheme == "" {
		if config.UseHTTPS {
			config.Scheme = "https"
		} else {
			config.Scheme = "http"
		}
	}
	return &WindowsRMClient{
		config: config,
	}
}

func (c *WindowsRMClient) Connect() error {
	_ = fmt.Sprintf("%s://%s:%d/wsman", c.config.Scheme, c.config.Host, c.config.Port)

	return nil
}

func (c *WindowsRMClient) IsConnected() bool {
	return c.connected
}

func (c *WindowsRMClient) ExecuteCommand(cmd string) (string, error) {
	return "", fmt.Errorf("WinRM命令执行需要完整的SOAP客户端实现")
}

func ParseWMIOutput(output string) []map[string]string {
	var results []map[string]string

	lines := strings.Split(output, "\n")
	currentRecord := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Node=") || strings.HasPrefix(line, "Item=") {
			if len(currentRecord) > 0 {
				results = append(results, currentRecord)
				currentRecord = make(map[string]string)
			}
			continue
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentRecord[key] = value
			}
		}
	}

	if len(currentRecord) > 0 {
		results = append(results, currentRecord)
	}

	return results
}

func ExtractWMIValue(data []byte, field string) string {
	pattern := regexp.MustCompile(fmt.Sprintf(`%s\s*=\s*([^\s\r\n]+)`, field))
	matches := pattern.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return strings.Trim(matches[1], `"'`)
	}
	return ""
}
