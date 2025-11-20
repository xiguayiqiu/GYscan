package dcom

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"GYscan/internal/utils"
)

// DCOMConfig 存储DCOM连接配置
type DCOMConfig struct {
	Target      string
	Username    string
	Password    string
	Domain      string
	Command     string
	UseSSL      bool
	Timeout     time.Duration
	Verbose     bool
	Method      string // "mmc20", "shellwindows", "wmiexecute"
}

// DCOMResult 存储DCOM执行结果
type DCOMResult struct {
	Success bool
	Output  string
	Error   error
}

// DCOMClient 提供DCOM远程操作功能
type DCOMClient struct {
	Config *DCOMConfig
}

// NewDCOMClient 创建新的DCOM客户端实例
func NewDCOMClient(config *DCOMConfig) *DCOMClient {
	return &DCOMClient{
		Config: config,
	}
}

// Connect 测试DCOM连接可达性
func (c *DCOMClient) Connect() bool {
	if c.Config.Verbose {
		utils.WarningPrint(fmt.Sprintf("Testing DCOM connectivity to %s", c.Config.Target))
	}
	
	// 简单的端口检测
	cmd := exec.Command("powershell", "Test-NetConnection", c.Config.Target, "-Port", "135")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if c.Config.Verbose {
			utils.ErrorPrint(fmt.Sprintf("DCOM connectivity test failed: %v", err))
		}
		return false
	}
	
	result := strings.Contains(string(output), "TcpTestSucceeded : True")
	if result && c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("DCOM connectivity test successful to %s", c.Config.Target))
	}
	
	return result
}

// ExecuteCommand 通过DCOM执行远程命令
func (c *DCOMClient) ExecuteCommand() *DCOMResult {
	if c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("Executing DCOM command on %s using method: %s", c.Config.Target, c.Config.Method))
	}
	
	// 根据不同的DCOM方法构建PowerShell命令
	var psCommand string
	switch c.Config.Method {
	case "mmc20":
		psCommand = c.buildMMC20Command()
	case "shellwindows":
		psCommand = c.buildShellWindowsCommand()
	case "wmiexecute":
		psCommand = c.buildWMICExecuteCommand()
	default:
		return &DCOMResult{
			Success: false,
			Error:   fmt.Errorf("unsupported DCOM method: %s", c.Config.Method),
		}
	}
	
	// 构建完整的PowerShell命令
	fullCommand := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'; $secpasswd = ConvertTo-SecureString '%s' -AsPlainText -Force; "+ 
		"$cred = New-Object System.Management.Automation.PSCredential('%s', $secpasswd); "+ 
		"Invoke-Command -ComputerName %s -Credential $cred -ScriptBlock {%s}",
		c.Config.Password,
		c.formatUsername(),
		c.Config.Target,
		psCommand,
	)
	
	if c.Config.Verbose {
		utils.WarningPrint(fmt.Sprintf("Running PowerShell command: %s", fullCommand))
	}
	
	// 执行命令
	cmd := exec.Command("powershell", "-Command", fullCommand)
	output, err := cmd.CombinedOutput()
	
	result := &DCOMResult{
		Success: err == nil,
		Output:  string(output),
		Error:   err,
	}
	
	if result.Success && c.Config.Verbose {
		utils.SuccessPrint("DCOM command executed successfully")
	} else if !result.Success && c.Config.Verbose {
		utils.ErrorPrint(fmt.Sprintf("DCOM command failed: %v", result.Error))
	}
	
	return result
}

// 构建MMC20.Application方法的命令
func (c *DCOMClient) buildMMC20Command() string {
	return fmt.Sprintf(
		"$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application', '%s', $true)); "+
		"$doc = $com.Document; "+
		"$doc.ActiveView.ExecuteShellCommand('cmd.exe', '', '/c %s', '7'); "+
		"Start-Sleep -Seconds 1; "+
		"$com.Quit()",
		c.Config.Target,
		c.Config.Command,
	)
}

// 构建ShellWindows方法的命令
func (c *DCOMClient) buildShellWindowsCommand() string {
	return fmt.Sprintf(
		"try { $shell = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('ShellWindows', '%s', $true)); } catch { }; "+
		"if ($shell) { $shellItem = $shell.Item(); $shellItem.Document.Application.ShellExecute('cmd.exe', '/c %s', '', 'open', 7); }",
		c.Config.Target,
		c.Config.Command,
	)
}

// 构建WMIExecute方法的命令
func (c *DCOMClient) buildWMICExecuteCommand() string {
	return fmt.Sprintf("cmd.exe /c %s", c.Config.Command)
}

// 格式化用户名（添加域名前缀）
func (c *DCOMClient) formatUsername() string {
	if c.Config.Domain != "" {
		return c.Config.Domain + "\\" + c.Config.Username
	}
	return c.Config.Username
}

// ListDCOMObjects 列出远程主机上的DCOM对象
func (c *DCOMClient) ListDCOMObjects() *DCOMResult {
	// 这里返回一个空结果作为示例，实际实现需要执行命令
	return &DCOMResult{
		Success: false,
		Output:  "ListDCOMObjects方法暂未实现",
		Error:   nil,
	}
}