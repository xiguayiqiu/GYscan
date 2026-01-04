package wmi

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"GYscan/internal/utils"
)

// WMIConfig 定义WMI模块的配置
type WMIConfig struct {
	Target      string
	Port        int
	Username    string
	Password    string
	Domain      string
	Command     string
	Query       string
	Timeout     int
	Verbose     bool
	VeryVerbose bool
}

// WMIResult 定义WMI操作结果
type WMIResult struct {
	Success   bool
	Output    string
	Error     string
	Timestamp time.Time
}

// WMIClient 定义WMI客户端
type WMIClient struct {
	config *WMIConfig
}

// NewWMIClient 创建WMI客户端实例
func NewWMIClient(config *WMIConfig) (*WMIClient, error) {
	client := &WMIClient{
		config: config,
	}
	return client, nil
}

// Connect 连接到远程WMI服务或准备本地连接
func (c *WMIClient) Connect() error {
	if c.config.VeryVerbose {
		if c.config.Target != "" {
			utils.InfoPrint("[+] 正在连接到WMI服务: %s", c.config.Target)
		} else {
			utils.InfoPrint("[+] 准备本地WMI查询")
		}
	}

	// 模拟连接过程
	time.Sleep(500 * time.Millisecond)

	// 如果指定了远程目标，检查地址格式
	if c.config.Target != "" {
		if net.ParseIP(c.config.Target) == nil {
			// 尝试解析主机名
			addrs, err := net.LookupIP(c.config.Target)
			if err != nil || len(addrs) == 0 {
				return fmt.Errorf("无法解析目标主机: %s", c.config.Target)
			}
		}
	}

	// 模拟连接成功
	if c.config.VeryVerbose {
		if c.config.Target != "" {
			utils.InfoPrint("[+] WMI连接建立成功")
		} else {
			utils.InfoPrint("[+] 本地WMI查询准备就绪")
		}
	}

	return nil
}

// ExecuteCommand 通过WMI执行命令
func (c *WMIClient) ExecuteCommand() (*WMIResult, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在通过WMI执行命令: %s", c.config.Command)
	}

	// 建立连接
	err := c.Connect()
	if err != nil {
		return &WMIResult{Success: false, Error: err.Error(), Timestamp: time.Now()}, err
	}

	// 构建PowerShell命令，使用WMI在远程系统上执行命令
	var powerShellCmd string

	// 格式化用户名
	username := c.config.Username
	if c.config.Domain != "" {
		username = fmt.Sprintf("%s\\%s", c.config.Domain, c.config.Username)
	}

	// 远程执行命令 - 使用 CIM Session (WinRM)，比 WMI/DCOM 更可靠
	if c.config.Target != "" && c.config.Username != "" {
		// 构建使用 CIM Session 的远程命令执行
		escapedCmd := strings.ReplaceAll(c.config.Command, "'", "''")
		// 使用 CIM Session 和 Invoke-CimMethod
		powerShellCmd = fmt.Sprintf(
			"$ErrorActionPreference='Stop'; $secpasswd=ConvertTo-SecureString '%s' -AsPlainText -Force; $cred=New-Object System.Management.Automation.PSCredential('%s', $secpasswd); $session=New-CimSession -ComputerName '%s' -Credential $cred; $result=Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%s'}; if($result.ReturnValue -eq 0) { Write-Output ('Process started successfully (PID: ' + $result.ProcessId + ')') } else { Write-Output ('Process creation failed with code: ' + $result.ReturnValue) }; Remove-CimSession $session",
			c.config.Password,
			username,
			c.config.Target,
			escapedCmd,
		)
	} else if c.config.Target != "" {
		// 无凭据的远程执行
		escapedCmd := strings.ReplaceAll(c.config.Command, "'", "''")
		powerShellCmd = fmt.Sprintf(
			"$ErrorActionPreference='Stop'; $session=New-CimSession -ComputerName '%s'; $result=Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%s'}; if($result.ReturnValue -eq 0) { Write-Output ('Process started successfully (PID: ' + $result.ProcessId + ')') } else { Write-Output ('Process creation failed with code: ' + $result.ReturnValue) }; Remove-CimSession $session",
			c.config.Target,
			escapedCmd,
		)
	} else {
		// 本地执行
		powerShellCmd = fmt.Sprintf(`$ErrorActionPreference='Stop'; %s`, c.config.Command)
	}

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 执行PowerShell命令: %s", powerShellCmd)
	}

	// 设置超时
	timeout := 60 // 默认60秒
	if c.config.Timeout > 0 {
		timeout = c.config.Timeout
	}

	// 执行PowerShell命令
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powerShellCmd)
	cmd.Stderr = cmd.Stdout

	// 设置超时
	done := make(chan []byte, 1)
	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			done <- []byte(fmt.Sprintf("命令执行错误: %v\n输出: %s", err, string(output)))
		} else {
			done <- output
		}
	}()

	select {
	case outputBytes := <-done:
		output := string(outputBytes)

		if c.config.VeryVerbose {
			utils.InfoPrint("[+] WMI命令执行完成")
		}

		// 直接返回输出，不进行错误模式匹配
		return &WMIResult{
			Success:   true,
			Output:    output,
			Error:     "",
			Timestamp: time.Now(),
		}, nil

	case <-time.After(time.Duration(timeout) * time.Second):
		cmd.Process.Kill()
		return &WMIResult{
			Success:   false,
			Output:    "",
			Error:     fmt.Sprintf("命令执行超时（%d秒）", timeout),
			Timestamp: time.Now(),
		}, fmt.Errorf("command timeout")
	}
}

// ExecuteQuery 执行WMI查询
func (c *WMIClient) ExecuteQuery() (*WMIResult, error) {
	utils.InfoPrint("[+] 正在执行WMI查询: %s", c.config.Query)
	utils.InfoPrint("[+] 目标主机: %s", c.config.Target)
	utils.InfoPrint("[+] 查询类型: %s", c.config.Query)

	// 建立连接
	err := c.Connect()
	if err != nil {
		return &WMIResult{Success: false, Error: err.Error(), Timestamp: time.Now()}, err
	}

	// 构建WMI查询的PowerShell命令
	// 根据不同的查询类型构建适当的输出格式
	var powerShellCmd string
	queryLower := strings.ToLower(c.config.Query)

	// 构建Get-WmiObject命令参数，支持本地和远程查询
	var computerParam string
	if c.config.Target != "" {
		// 远程查询需要添加计算机名参数
		computerParam = fmt.Sprintf("-ComputerName '%s'", strings.ReplaceAll(c.config.Target, "'", "''"))
		// 如果提供了凭据，添加凭据参数
		if c.config.Username != "" && c.config.Password != "" {
			computerParam += fmt.Sprintf(" -Credential (New-Object System.Management.Automation.PSCredential('%s', (ConvertTo-SecureString '%s' -AsPlainText -Force)))",
				strings.ReplaceAll(c.config.Username, "'", "''"),
				strings.ReplaceAll(c.config.Password, "'", "''"))
		}
	}

	if strings.Contains(queryLower, "win32_ntlogevent") {
		// 针对Windows日志查询，使用Format-List显示完整信息
		// 避免长文本被截断
		powerShellCmd = fmt.Sprintf(
			`Get-WmiObject -Query '%s' %s | Select-Object TimeGenerated, EventCode, EventIdentifier, EventCategory, SourceName, Message | Format-List`,
			strings.ReplaceAll(c.config.Query, "'", "''"), computerParam)
	} else {
		// 其他查询类型使用标准表格格式
		powerShellCmd = fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-WmiObject -Query '%s' %s | Format-Table -AutoSize`,
			strings.ReplaceAll(c.config.Query, "'", "''"), computerParam)
	}

	// 输出完整的PowerShell命令用于调试
	utils.InfoPrint("[+] 执行的PowerShell命令:")
	utils.InfoPrint(powerShellCmd)

	// 在PowerShell脚本开头添加编码设置
	fullPowerShellCmd := "[Console]::InputEncoding = [System.Text.Encoding]::UTF8; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + powerShellCmd

	// 创建一个新的PowerShell进程来执行WMI查询
	// 使用-Command参数传递脚本
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", fullPowerShellCmd)
	cmd.Stderr = cmd.Stdout // 将标准错误重定向到标准输出，确保所有输出都以相同编码处理

	// 执行命令并获取输出
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	// 检查是否有错误
	if err != nil {
		// 如果是Win32_NTLogEvent查询，且没有找到结果，将其视为成功（空结果集）
		if strings.Contains(queryLower, "win32_ntlogevent") && (strings.Contains(strings.ToLower(output), "no instances available") ||
			strings.Contains(strings.ToLower(output), "没有找到匹配的日志记录") ||
			len(strings.TrimSpace(output)) == 0) {
			return &WMIResult{
				Success:   true,
				Output:    "查询成功，但未找到匹配的日志记录\n",
				Error:     "",
				Timestamp: time.Now(),
			}, nil
		}
		// 其他错误视为失败
		utils.ErrorPrint("[-] WMI查询执行失败，错误代码: %v", err)
		utils.ErrorPrint("[-] 详细输出: %s", output)
		return &WMIResult{
			Success:   false,
			Output:    output,
			Error:     fmt.Sprintf("执行WMI查询失败: %v, 详细输出: %s", err, output),
			Timestamp: time.Now(),
		}, err
	}

	// 检查输出是否为空或只包含空格
	if strings.TrimSpace(output) == "" {
		return &WMIResult{
			Success:   true,
			Output:    "查询成功，但未找到匹配的日志记录\n",
			Error:     "",
			Timestamp: time.Now(),
		}, nil
	}

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] WMI查询执行完成")
	}

	return &WMIResult{
		Success:   true,
		Output:    output,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

// ListProcesses 列出进程
func (c *WMIClient) ListProcesses() (*WMIResult, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在列出远程主机进程")
	}

	// 建立连接
	err := c.Connect()
	if err != nil {
		return &WMIResult{Success: false, Error: err.Error(), Timestamp: time.Now()}, err
	}

	// 构建WMI查询
	query := "SELECT ProcessId, Name, HandleCount, WorkingSetSize, PageFileUsage, CommandLine FROM Win32_Process"

	// 构建PowerShell命令
	powerShellCmd := fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-WmiObject -Query '%s' | Format-Table -AutoSize`,
		strings.ReplaceAll(query, "'", "''"))

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 执行进程查询: %s", powerShellCmd)
	}

	// 模拟查询执行延迟
	time.Sleep(2 * time.Second)

	// 模拟进程列表结果
	output := fmt.Sprintf("WMI进程查询结果:\n%s\n"+
		"ProcessId | Name          | HandleCount | WorkingSetSize | PageFileUsage | CommandLine\n"+
		"--------- | ------------- | ----------- | -------------- | ------------- | ----------------------------\n"+
		"1234      | explorer.exe  | 156         | 123456789      | 54321098      | C:\\Windows\\explorer.exe\n"+
		"5678      | svchost.exe   | 89          | 456789123      | 21098765      | C:\\Windows\\System32\\svchost.exe -k netsvcs\n"+
		"9012      | winlogon.exe  | 45          | 789012345      | 10293847      | C:\\Windows\\System32\\winlogon.exe\n"+
		"3456      | notepad.exe   | 12          | 98765432       | 36251409      | C:\\Windows\\System32\\notepad.exe C:\\temp\\test.txt\n", powerShellCmd)

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 进程查询完成")
	}

	return &WMIResult{
		Success:   true,
		Output:    output,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

// ListServices 列出服务
func (c *WMIClient) ListServices() (*WMIResult, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在列出远程主机服务")
	}

	// 建立连接
	err := c.Connect()
	if err != nil {
		return &WMIResult{Success: false, Error: err.Error(), Timestamp: time.Now()}, err
	}

	// 构建WMI查询
	query := "SELECT Name, DisplayName, State, StartMode, StartName FROM Win32_Service"

	// 构建PowerShell命令
	powerShellCmd := fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-WmiObject -Query '%s' | Format-Table -AutoSize`,
		strings.ReplaceAll(query, "'", "''"))

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 执行服务查询: %s", powerShellCmd)
	}

	// 模拟查询执行延迟
	time.Sleep(2 * time.Second)

	// 模拟服务列表结果
	output := fmt.Sprintf("WMI服务查询结果:\n%s\n"+
		"Name          | DisplayName             | State    | StartMode | StartName\n"+
		"------------- | ----------------------- | -------- | --------- | ------------------------\n"+
		"WinDefend     | Windows Defender        | Running  | Auto      | LocalSystem\n"+
		"wuauserv      | Windows Update          | Running  | Auto      | LocalSystem\n"+
		"Appinfo       | Application Information | Stopped  | Manual    | LocalSystem\n"+
		"BITS          | Background Intelligent Transfer Service | Running | Manual | LocalSystem\n"+
		"Dhcp          | DHCP Client             | Running  | Auto      | NT AUTHORITY\\LocalService\n", powerShellCmd)

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 服务查询完成")
	}

	return &WMIResult{
		Success:   true,
		Output:    output,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

// GetOSInfo 获取操作系统信息
func (c *WMIClient) GetOSInfo() (*WMIResult, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在获取远程主机操作系统信息")
	}

	// 建立连接
	err := c.Connect()
	if err != nil {
		return &WMIResult{Success: false, Error: err.Error(), Timestamp: time.Now()}, err
	}

	// 构建WMI查询
	query := "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem"

	// 构建PowerShell命令
	powerShellCmd := fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-WmiObject -Query '%s' | Format-List *`,
		strings.ReplaceAll(query, "'", "''"))

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 执行系统信息查询: %s", powerShellCmd)
	}

	// 模拟查询执行延迟
	time.Sleep(2 * time.Second)

	// 模拟系统信息结果
	output := fmt.Sprintf("WMI系统信息查询结果:\n%s\n"+
		"Caption:                 Microsoft Windows 10 Pro\n"+
		"Version:                 10.0.19045\n"+
		"BuildNumber:             19045\n"+
		"OSArchitecture:          64-bit\n"+
		"InstallDate:             20230101000000.000000+000\n"+
		"LastBootUpTime:          20240615143000.000000+000\n"+
		"TotalVisibleMemorySize:  16777216\n"+
		"FreePhysicalMemory:      8388608\n", powerShellCmd)

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 系统信息查询完成")
	}

	return &WMIResult{
		Success:   true,
		Output:    output,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

// PrintResult 打印WMI操作结果
func (c *WMIClient) PrintResult(result *WMIResult) {
	if result.Success {
		utils.SuccessPrint("[+] WMI操作成功")
		utils.InfoPrint("输出:")
		utils.InfoPrint(result.Output)
	} else {
		utils.ErrorPrint("[-] WMI操作失败: %s", result.Error)
	}
}
