package ssh

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	
	"GYscan/internal/utils"
)

// SSHAuthenticator SSH认证器
type SSHAuthenticator struct {
	timeout   time.Duration
	verbose   int
	// 连接池相关字段
	maxConnections int
	connectionPool chan *ssh.Client
	poolMutex      sync.Mutex
	// 连接超时和资源管理
	connectionTimeout time.Duration
	cleanupTicker     *time.Ticker
	doneChan          chan bool
}

// NewSSHAuthenticator 创建新的SSH认证器
func NewSSHAuthenticator(config *SSHConfig) *SSHAuthenticator {
	auth := &SSHAuthenticator{
		timeout: time.Duration(config.Timeout) * time.Second,
		verbose: getVerboseLevel(config),
		// 初始化连接池
		maxConnections: 10,
		connectionPool: make(chan *ssh.Client, 10),
		// 初始化连接超时和资源管理
		connectionTimeout: 30 * time.Second,
		cleanupTicker:     time.NewTicker(1 * time.Minute),
		doneChan:          make(chan bool),
	}
	
	// 启动连接池管理协程
	go auth.manageConnectionPool()
	// 启动资源清理协程
	go auth.cleanupResources()
	
	return auth
}

// manageConnectionPool 管理连接池，定期清理空闲连接
func (a *SSHAuthenticator) manageConnectionPool() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		a.cleanupIdleConnections()
	}
}

// cleanupIdleConnections 清理空闲连接
func (a *SSHAuthenticator) cleanupIdleConnections() {
	a.poolMutex.Lock()
	defer a.poolMutex.Unlock()
	
	// 清理连接池中所有连接
	for {
		select {
		case client := <-a.connectionPool:
			if client != nil {
				client.Close()
			}
		default:
			return
		}
	}
}

// cleanupResources 定期清理资源
func (a *SSHAuthenticator) cleanupResources() {
	for {
		select {
		case <-a.cleanupTicker.C:
			// 定期清理空闲连接
			a.cleanupIdleConnections()
		case <-a.doneChan:
			// 停止清理
			a.cleanupTicker.Stop()
			return
		}
	}
}

// Close 关闭认证器，释放所有资源
func (a *SSHAuthenticator) Close() {
	// 发送停止信号
	close(a.doneChan)
	// 清理所有连接
	a.cleanupIdleConnections()
}

// TestCredentials 测试用户名密码组合
func (a *SSHAuthenticator) TestCredentials(target string, port int, username string, password string) (*SSHResult, error) {
	startTime := time.Now()
	
	result := &SSHResult{
		Target:   target,
		Port:     port,
		Username: username,
		Password: password,
		Attempts: 1,
	}

	// 创建SSH客户端配置（每次认证独立创建）
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         a.timeout,
		BannerCallback:  ssh.BannerDisplayStderr(),
		// 优化算法配置，优先使用快速安全的算法
		Config: ssh.Config{
			Ciphers: []string{
				"chacha20-poly1305@openssh.com", // 最快的现代算法
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
			},
			KeyExchanges: []string{
				"curve25519-sha256", // 最快的现代密钥交换算法
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"diffie-hellman-group14-sha256",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256",
				"hmac-sha2-512",
			},
		},
	}

	// 连接目标
	address := fmt.Sprintf("%s:%d", target, port)
	
	if a.verbose >= 2 {
		utils.Debug("[尝试] %s@%s:%d - 密码: %s", username, target, port, password)
	}

	// 优化连接策略：快速连接机制，减少不必要的重试
	var client *ssh.Client
	var err error
	
	// 第一次连接尝试
	client, err = ssh.Dial("tcp", address, config)
	
	// 只在特定情况下重试
	if err != nil {
		// 检查是否是连接被强制关闭错误，这是最常见的OpenSSH安全机制触发错误
		if strings.Contains(err.Error(), "forcibly closed") || strings.Contains(err.Error(), "EOF") {
			if a.verbose >= 2 {
				utils.Debug("[重试] 连接被强制关闭，调整策略后重试一次")
			}
			// 重试前短暂等待，给服务器足够时间处理
			time.Sleep(1500 * time.Millisecond)
			// 重试连接
			client, err = ssh.Dial("tcp", address, config)
		}
		
		// 在详细模式下显示详细的错误信息
		if a.verbose >= 1 {
			utils.Debug("[详细错误] 连接失败: %v (类型: %T)", err, err)
		}
	}
	
	if err != nil {
		result.Success = false
		result.Error = a.ParseSSHError(err)
		
		// 在详细模式下显示完整的错误信息
		if a.verbose >= 1 {
			utils.ErrorPrint("[失败] %s@%s:%d - 密码: %s - %s (原始错误: %v)", username, target, port, password, result.Error, err)
		}
		
		result.ElapsedTime = time.Since(startTime)
		return result, nil
	}
	
	// 确保连接被正确关闭
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	// 改进的验证逻辑：连接成功后尝试创建会话并执行简单命令来验证认证
	// 这是真正的认证验证，而不是仅仅检查连接是否建立
	session, err := client.NewSession()
	if err != nil {
		// 如果无法创建会话，说明认证可能失败
		result.Success = false
		result.Error = "认证失败（无法创建会话）"
		result.ElapsedTime = time.Since(startTime)
		
		if a.verbose >= 1 {
			utils.ErrorPrint("[失败] %s@%s:%d - 密码: %s - %s", username, target, port, password, result.Error)
		}
		
		return result, nil
	}
	defer session.Close()

	// 尝试执行简单的命令来验证认证状态
	err = session.Run("echo 'test'")
	if err != nil {
		// 命令执行失败，说明认证失败
		result.Success = false
		result.Error = "认证失败（命令执行失败）"
		result.ElapsedTime = time.Since(startTime)
		
		if a.verbose >= 1 {
			utils.ErrorPrint("[失败] %s@%s:%d - 密码: %s - %s", username, target, port, password, result.Error)
		}
		
		return result, nil
	}

	// 只有命令执行成功，才认为是真正的认证成功
	result.Success = true
	result.ElapsedTime = time.Since(startTime)
	
	// 在非常详细模式下显示连接信息
	if a.verbose >= 2 {
		utils.Debug("[成功] %s@%s:%d - 密码: %s", username, target, port, password)
		utils.Debug("    连接建立成功，耗时: %v", result.ElapsedTime)
	}

	return result, nil
}

// ParseSSHError 解析SSH错误信息
func (a *SSHAuthenticator) ParseSSHError(err error) string {
	errorStr := err.Error()
	
	// 基于Hydra源码分析的常见SSH错误类型
	switch {
	// 认证相关错误（优先级最高）
	case strings.Contains(errorStr, "unable to authenticate"):
		return "认证失败"
	case strings.Contains(errorStr, "password authentication failed"):
		return "认证失败"
	case strings.Contains(errorStr, "authentication failed"):
		return "认证失败"
	case strings.Contains(errorStr, "permission denied"):
		return "认证失败"
		
	// 握手相关错误
	case strings.Contains(errorStr, "handshake failed"):
		// 检查是否是认证失败导致的握手失败
		if strings.Contains(errorStr, "unable to authenticate") {
			// 检查是否是密码认证被禁用
			if strings.Contains(errorStr, "no supported methods remain") {
				return "密码认证被禁用"
			}
			return "认证失败"
		}
		// 检查是否是连接被强制关闭
		if strings.Contains(errorStr, "EOF") || strings.Contains(errorStr, "forcibly closed") {
			return "连接被强制关闭"
		}
		return "握手失败"
		
	// 连接相关错误
	case strings.Contains(errorStr, "connection refused"):
		return "连接被拒绝"
	case strings.Contains(errorStr, "i/o timeout"):
		return "连接超时"
	case strings.Contains(errorStr, "no such host"):
		return "主机不存在"
	case strings.Contains(errorStr, "network is unreachable"):
		return "网络不可达"
	case strings.Contains(errorStr, "connection reset"):
		return "连接重置"
		
	// 安全机制相关错误
	case strings.Contains(errorStr, "too many authentication failures"):
		return "认证失败次数过多"
	case strings.Contains(errorStr, "connection closed"):
		return "连接被关闭"
		
	// 协议相关错误
	case strings.Contains(errorStr, "protocol error"):
		return "协议错误"
	case strings.Contains(errorStr, "EOF"):
		return "连接中断"
		
	default:
		// 提取关键错误信息
		if strings.Contains(errorStr, ":") {
			parts := strings.Split(errorStr, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
		// 返回原始错误信息，但截断过长的错误
		if len(errorStr) > 100 {
			return errorStr[:100] + "..."
		}
		return errorStr
	}
}

// LoadDictionary 加载字典文件
func LoadDictionary(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开字典文件: %v", err)
	}
	defer file.Close()

	var items []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		items = append(items, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取字典文件失败: %v", err)
	}

	return items, nil
}

// GenerateCredentials 生成用户名密码组合
func (a *SSHAuthenticator) GenerateCredentials(config *SSHConfig) ([]Credentials, error) {
	var credentials []Credentials
	
	// 加载用户名列表
	usernames, err := a.loadUsernames(config)
	if err != nil {
		return nil, err
	}
	
	// 加载密码列表
	passwords, err := a.loadPasswords(config)
	if err != nil {
		return nil, err
	}
	
	// 生成额外的检查组合
	extraCredentials := a.generateExtraCredentials(config, usernames)
	
	// 合并所有组合
	for _, username := range usernames {
		for _, password := range passwords {
			credentials = append(credentials, Credentials{
				Username: username,
				Password: password,
			})
		}
	}
	
	// 添加额外检查的组合到开头
	credentials = append(extraCredentials, credentials...)
	
	return credentials, nil
}

// loadUsernames 加载用户名列表
func (a *SSHAuthenticator) loadUsernames(config *SSHConfig) ([]string, error) {
	var usernames []string
	
	if config.Username != "" {
		usernames = append(usernames, config.Username)
	} else if config.UsernameFile != "" {
		loaded, err := LoadDictionary(config.UsernameFile)
		if err != nil {
			return nil, err
		}
		usernames = loaded
	}
	
	return usernames, nil
}

// loadPasswords 加载密码列表
func (a *SSHAuthenticator) loadPasswords(config *SSHConfig) ([]string, error) {
	var passwords []string
	
	if config.Password != "" {
		passwords = append(passwords, config.Password)
	} else if config.PasswordFile != "" {
		loaded, err := LoadDictionary(config.PasswordFile)
		if err != nil {
			return nil, err
		}
		passwords = loaded
	}
	
	return passwords, nil
}

// generateExtraCredentials 生成额外检查的凭证组合
func (a *SSHAuthenticator) generateExtraCredentials(config *SSHConfig, usernames []string) []Credentials {
	var credentials []Credentials
	
	checks := strings.Split(config.ExtraChecks, "")
	
	for _, check := range checks {
		switch check {
		case "n": // 空密码
			for _, username := range usernames {
				credentials = append(credentials, Credentials{
					Username: username,
					Password: "",
				})
			}
		case "s": // 用户名作为密码
			for _, username := range usernames {
				credentials = append(credentials, Credentials{
					Username: username,
					Password: username,
				})
			}
		}
	}
	
	return credentials
}

// Credentials 用户名密码组合
type Credentials struct {
	Username string
	Password string
}

// TestConnection 测试SSH连接（不进行认证）
func (a *SSHAuthenticator) TestConnection(target string, port int) error {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	
	conn, err := net.DialTimeout("tcp", address, a.timeout)
	if err != nil {
		return fmt.Errorf("无法连接到 %s: %v", address, err)
	}
	defer conn.Close()
	
	// 读取SSH标识
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(a.timeout))
	
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("读取SSH标识失败: %v", err)
	}
	
	if a.verbose >= 1 {
		utils.InfoPrint("[+] SSH服务检测: %s", strings.TrimSpace(string(buffer[:n])))
	}
	
	return nil
}

// GetBanner 获取SSH服务标识
func (a *SSHAuthenticator) GetBanner(target string, port int) (string, error) {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	
	conn, err := net.DialTimeout("tcp", address, a.timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(a.timeout))
	
	// 读取SSH标识
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}
	
	return strings.TrimSpace(string(buffer[:n])), nil
}