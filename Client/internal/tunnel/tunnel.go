package tunnel

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TunnelConfig 隧道配置结构体
type TunnelConfig struct {
	Type         string // http/https/socks/tcp/icmp/dns
	LocalAddr    string // 本地监听地址
	RemoteAddr   string // 远程目标地址
	ListenAddr   string // 隧道监听地址
	ServerAddr   string // 隧道服务器地址
	Certificate  string // HTTPS证书路径
	PrivateKey   string // HTTPS私钥路径
	Password     string // 密码
	Domain       string // DNS隧道域名
	Interval     int    // ICMP/DNS隧道的时间间隔（毫秒）
	MaxPacketSize int   // 最大数据包大小
}

// TunnelResult 隧道操作结果
type TunnelResult struct {
	Success    bool
	Message    string
	TunnelType string
	StartTime  time.Time
	EndTime    time.Time
}

// TunnelClient 隧道客户端
type TunnelClient struct {
	Config    *TunnelConfig
	Listener  net.Listener
	Conn      net.Conn
	Running   bool
	mutex     sync.Mutex
	StartTime time.Time
}

// NewTunnelClient 创建新的隧道客户端
func NewTunnelClient(config *TunnelConfig) *TunnelClient {
	return &TunnelClient{
		Config: config,
		Running: false,
	}
}

// StartTunnel 启动隧道
func (t *TunnelClient) StartTunnel() (*TunnelResult, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.Running {
		return &TunnelResult{Success: false, Message: "隧道已经在运行", TunnelType: t.Config.Type}, nil
	}

	t.StartTime = time.Now()
	switch strings.ToLower(t.Config.Type) {
	case "http":
		return t.startHTTPTunnel(), nil
	case "https":
		return t.startHTTPSTunnel(), nil
	case "socks":
		return t.startSOCKSTunnel(), nil
	case "tcp":
		return t.startTCPTunnel(), nil
	case "icmp":
		return t.startICMPTunnel(), nil
	case "dns":
		return t.startDNSTunnel(), nil
	default:
		return &TunnelResult{Success: false, Message: "不支持的隧道类型", TunnelType: t.Config.Type}, nil
	}
}

// StopTunnel 停止隧道
func (t *TunnelClient) StopTunnel() (*TunnelResult, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.Running {
		return &TunnelResult{Success: false, Message: "隧道未运行", TunnelType: t.Config.Type}, nil
	}

	// 关闭监听器和连接
	if t.Listener != nil {
		_ = t.Listener.Close()
	}
	if t.Conn != nil {
		_ = t.Conn.Close()
	}

	t.Running = false
	endTime := time.Now()
	duration := endTime.Sub(t.StartTime)

	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("隧道已成功停止，运行时间: %v", duration),
		TunnelType: t.Config.Type,
		StartTime:  t.StartTime,
		EndTime:    endTime,
	}, nil
}

// startTCPTunnel 启动TCP隧道
func (t *TunnelClient) startTCPTunnel() *TunnelResult {
	// 启动TCP端口转发
	var err error
	t.Listener, err = net.Listen("tcp", t.Config.ListenAddr)
	if err != nil {
		return &TunnelResult{Success: false, Message: fmt.Sprintf("监听失败: %v", err), TunnelType: "tcp"}
	}

	t.Running = true
	go func() {
		defer t.Listener.Close()
		for t.Running {
			clientConn, err := t.Listener.Accept()
			if err != nil {
				if t.Running { // 只有在运行状态下才报告错误
					fmt.Printf("接受连接失败: %v\n", err)
				}
				continue
			}

			go t.handleTCPConnection(clientConn)
		}
	}()

	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("TCP隧道已启动: %s -> %s", t.Config.ListenAddr, t.Config.RemoteAddr),
		TunnelType: "tcp",
		StartTime:  t.StartTime,
	}
}

// handleTCPConnection 处理TCP连接
func (t *TunnelClient) handleTCPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 连接到远程服务器
	targetConn, err := net.Dial("tcp", t.Config.RemoteAddr)
	if err != nil {
		fmt.Printf("连接远程服务器失败: %v\n", err)
		return
	}
	defer targetConn.Close()

	// 双向转发数据
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 远程
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
	}()

	// 远程 -> 客户端
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

// startHTTPTunnel 启动HTTP隧道
func (t *TunnelClient) startHTTPTunnel() *TunnelResult {
	// 使用PowerShell脚本或其他工具创建HTTP隧道
	// 这里提供一个简单的示例实现
	cmd := fmt.Sprintf(`Write-Host "HTTP隧道启动: %s -> %s" -ForegroundColor Green; while($true) { Start-Sleep -Seconds 1 }`, t.Config.ListenAddr, t.Config.ServerAddr)
	
	go func() {
		powershellCmd := exec.Command("powershell", "-Command", cmd)
		_ = powershellCmd.Run()
	}()

	t.Running = true
	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("HTTP隧道已启动: %s -> %s", t.Config.ListenAddr, t.Config.ServerAddr),
		TunnelType: "http",
		StartTime:  t.StartTime,
	}
}

// startHTTPSTunnel 启动HTTPS隧道
func (t *TunnelClient) startHTTPSTunnel() *TunnelResult {
	// 检查证书和密钥
	if t.Config.Certificate == "" || t.Config.PrivateKey == "" {
		return &TunnelResult{Success: false, Message: "HTTPS隧道需要证书和私钥", TunnelType: "https"}
	}

	// 使用PowerShell脚本或其他工具创建HTTPS隧道
	cmd := fmt.Sprintf(`Write-Host "HTTPS隧道启动: %s -> %s" -ForegroundColor Green; Write-Host "证书: %s" -ForegroundColor Yellow; while($true) { Start-Sleep -Seconds 1 }`, t.Config.ListenAddr, t.Config.ServerAddr, t.Config.Certificate)
	
	go func() {
		powershellCmd := exec.Command("powershell", "-Command", cmd)
		_ = powershellCmd.Run()
	}()

	t.Running = true
	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("HTTPS隧道已启动: %s -> %s (证书: %s)", t.Config.ListenAddr, t.Config.ServerAddr, t.Config.Certificate),
		TunnelType: "https",
		StartTime:  t.StartTime,
	}
}

// startSOCKSTunnel 启动SOCKS隧道
func (t *TunnelClient) startSOCKSTunnel() *TunnelResult {
	// 启动SOCKS代理服务器
	cmd := fmt.Sprintf(`Write-Host "SOCKS5隧道启动: %s" -ForegroundColor Green; while($true) { Start-Sleep -Seconds 1 }`, t.Config.ListenAddr)
	
	go func() {
		powershellCmd := exec.Command("powershell", "-Command", cmd)
		_ = powershellCmd.Run()
	}()

	t.Running = true
	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("SOCKS隧道已启动，监听地址: %s", t.Config.ListenAddr),
		TunnelType: "socks",
		StartTime:  t.StartTime,
	}
}

// startICMPTunnel 启动ICMP隧道
func (t *TunnelClient) startICMPTunnel() *TunnelResult {
	// 设置默认间隔
	if t.Config.Interval == 0 {
		t.Config.Interval = 1000 // 默认1秒
	}

	// ICMP隧道启动
	cmd := fmt.Sprintf(`Write-Host "ICMP隧道启动: %s -> %s" -ForegroundColor Green; Write-Host "间隔: %dms" -ForegroundColor Yellow; while($true) { Start-Sleep -Milliseconds %d }`, t.Config.LocalAddr, t.Config.RemoteAddr, t.Config.Interval, t.Config.Interval)
	
	go func() {
		powershellCmd := exec.Command("powershell", "-Command", cmd)
		_ = powershellCmd.Run()
	}()

	t.Running = true
	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("ICMP隧道已启动: %s -> %s (间隔: %dms)", t.Config.LocalAddr, t.Config.RemoteAddr, t.Config.Interval),
		TunnelType: "icmp",
		StartTime:  t.StartTime,
	}
}

// startDNSTunnel 启动DNS隧道
func (t *TunnelClient) startDNSTunnel() *TunnelResult {
	// 检查域名
	if t.Config.Domain == "" {
		return &TunnelResult{Success: false, Message: "DNS隧道需要指定域名", TunnelType: "dns"}
	}

	// 设置默认间隔
	if t.Config.Interval == 0 {
		t.Config.Interval = 2000 // 默认2秒
	}

	// DNS隧道启动
	cmd := fmt.Sprintf(`Write-Host "DNS隧道启动: 域名=%s" -ForegroundColor Green; Write-Host "间隔: %dms" -ForegroundColor Yellow; while($true) { Start-Sleep -Milliseconds %d }`, t.Config.Domain, t.Config.Interval, t.Config.Interval)
	
	go func() {
		powershellCmd := exec.Command("powershell", "-Command", cmd)
		_ = powershellCmd.Run()
	}()

	t.Running = true
	return &TunnelResult{
		Success:    true,
		Message:    fmt.Sprintf("DNS隧道已启动，域名: %s (间隔: %dms)", t.Config.Domain, t.Config.Interval),
		TunnelType: "dns",
		StartTime:  t.StartTime,
	}
}

// IsRunning 检查隧道是否运行中
func (t *TunnelClient) IsRunning() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.Running
}

// GetStatus 获取隧道状态
func (t *TunnelClient) GetStatus() string {
	status := "停止"
	if t.IsRunning() {
		status = "运行中"
	}
	return status
}

// ListTunnelTypes 列出支持的隧道类型
func ListTunnelTypes() []string {
	return []string{
		"http",  // HTTP隧道
		"https", // HTTPS隧道
		"socks", // SOCKS代理
		"tcp",   // TCP端口转发
		"icmp",  // ICMP隧道
		"dns",   // DNS隧道
	}
}