package powershell

import (
	"bytes"
	"fmt"
	"time"

	"github.com/masterzen/winrm"
)

// PowerShellConfig 配置信息
type PowerShellConfig struct {
	Target   string
	Port     int
	User     string
	Password string
	Domain   string
	Timeout  int
	Verbose  bool
	HTTPS    bool
}

// PowerShellResult 执行结果
type PowerShellResult struct {
	Success       bool
	Output        string
	Error         string
	ExecutionTime time.Duration
}

// Client PowerShell客户端
type Client struct {
	config *PowerShellConfig
	client *winrm.Client
}

// NewClient 创建新的PowerShell客户端
func NewClient(config *PowerShellConfig) (*Client, error) {
	c := &Client{
		config: config,
	}

	// 创建WinRM连接参数
	params := &winrm.Parameters{}

	// 创建WinRM客户端
	endpoint := winrm.NewEndpoint(
		config.Target,
		config.Port,
		config.HTTPS,  // HTTPS
		false,  // 验证证书
		nil,    // 客户端证书
		nil,    // 证书哈希
		nil,    // 连接池
		time.Duration(config.Timeout) * time.Second, // 超时时间
	)

	// 创建客户端
	client, err := winrm.NewClientWithParameters(
		endpoint,
		config.User,
		config.Password,
		params,
	)
	if err != nil {
		return nil, fmt.Errorf("创建WinRM客户端失败: %v", err)
	}
	c.client = client

	return c, nil
}

// Connect 连接到目标主机
func (c *Client) Connect() error {
	// WinRM客户端在执行命令时自动连接，所以这里只进行简单测试

	// 执行一个简单命令测试连接
	shell, err := c.client.CreateShell()
	if err != nil {
		return fmt.Errorf("连接到目标主机失败: %w", err)
	}
	defer shell.Close()

	return nil
}

// ExecuteCommand 执行PowerShell命令
func (c *Client) ExecuteCommand(command string) (*PowerShellResult, error) {
	startTime := time.Now()
	result := &PowerShellResult{}

	// 创建Shell
	shell, err := c.client.CreateShell()
	if err != nil {
		result.Error = fmt.Sprintf("创建Shell失败: %v", err)
		return result, err
	}
	defer shell.Close()

	// 创建命令
	cmd, err := shell.Execute(command)
	if err != nil {
		result.Error = fmt.Sprintf("执行命令失败: %v", err)
		return result, err
	}
	defer cmd.Close()

	// 读取输出
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, err = stdout.ReadFrom(cmd.Stdout)
	if err != nil {
		result.Error = fmt.Sprintf("读取标准输出失败: %v", err)
		return result, err
	}

	_, err = stderr.ReadFrom(cmd.Stderr)
	if err != nil {
		result.Error = fmt.Sprintf("读取错误输出失败: %v", err)
		return result, err
	}

	// 检查是否有错误输出
	stderrStr := stderr.String()
	if stderrStr != "" {
		result.Success = false
		result.Error = stderrStr
		result.Output = stdout.String()
		result.ExecutionTime = time.Since(startTime)
		return result, fmt.Errorf("命令执行失败: %s", stderrStr)
	}

	// 成功执行
	result.Success = true
	result.Output = stdout.String()
	result.ExecutionTime = time.Since(startTime)

	return result, nil
}

// ExecuteScript 执行PowerShell脚本文件
func (c *Client) ExecuteScript(scriptContent string) (*PowerShellResult, error) {
	// 在PowerShell中执行脚本内容
	command := fmt.Sprintf("%s", scriptContent)
	return c.ExecuteCommand(command)
}

// TestWinRMConnection 测试WinRM连接
func (c *Client) TestWinRMConnection() (bool, error) {
	// 创建Shell测试连接
	shell, err := c.client.CreateShell()
	if err != nil {
		return false, err
	}
	defer shell.Close()

	return true, nil
}
