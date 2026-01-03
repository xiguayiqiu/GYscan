package configaudit

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"GYscan/internal/utils"

	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	Client     *ssh.Client
	Session    *ssh.Session
	Config     *SSHConfig
	connected  bool
}

type SSHConfig struct {
	Host           string
	Port           int
	Username       string
	Password       string
	PrivateKey     string
	PrivateKeyPath string
	Timeout        time.Duration
	MaxRetries     int
}

type SSHConfigResult struct {
	Success    bool
	ConfigData map[string]interface{}
	Output     string
	Error      error
}

func NewSSHClient(config *SSHConfig) *SSHClient {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Port == 0 {
		config.Port = 22
	}
	return &SSHClient{
		Config: config,
	}
}

func (sc *SSHClient) Connect() error {
	var authMethods []ssh.AuthMethod

	if sc.Config.Password != "" {
		authMethods = append(authMethods, ssh.Password(sc.Config.Password))
	}

	if sc.Config.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(sc.Config.PrivateKey))
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	if sc.Config.PrivateKeyPath != "" {
		keyData, err := ioutil.ReadFile(sc.Config.PrivateKeyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyData)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("未提供任何认证方式（密码或私钥）")
	}

	sshConfig := &ssh.ClientConfig{
		User: sc.Config.Username,
		Auth: authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         sc.Config.Timeout,
	}

	var lastErr error
	for attempt := 1; attempt <= sc.Config.MaxRetries; attempt++ {
		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sc.Config.Host, sc.Config.Port), sshConfig)
		if err == nil {
			sc.Client = client
			sc.connected = true
			utils.LogInfo("SSH连接到 %s@%s:%d 成功", sc.Config.Username, sc.Config.Host, sc.Config.Port)
			return nil
		}
		lastErr = err
		utils.LogWarning("SSH连接尝试 %d/%d 失败: %v", attempt, sc.Config.MaxRetries, err)
		if attempt < sc.Config.MaxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return fmt.Errorf("SSH连接失败 (尝试 %d 次): %v", sc.Config.MaxRetries, lastErr)
}

func (sc *SSHClient) Close() {
	if sc.Client != nil {
		sc.Client.Close()
		sc.connected = false
		utils.LogInfo("SSH连接已关闭")
	}
}

func (sc *SSHClient) IsConnected() bool {
	return sc.connected
}

func (sc *SSHClient) ExecuteCommand(cmd string) (string, error) {
	if !sc.connected {
		return "", fmt.Errorf("SSH未连接")
	}

	session, err := sc.Client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(cmd)
	output := strings.TrimSpace(stdout.String())
	errOutput := strings.TrimSpace(stderr.String())

	if err != nil {
		return output, fmt.Errorf("命令执行失败: %v (stderr: %s)", err, errOutput)
	}

	return output, nil
}

func (sc *SSHClient) ReadFile(filePath string) ([]byte, error) {
	if !sc.connected {
		return nil, fmt.Errorf("SSH未连接")
	}

	cmd := fmt.Sprintf("cat '%s' 2>/dev/null || echo 'FILE_NOT_FOUND'", filePath)
	output, err := sc.ExecuteCommand(cmd)
	if err != nil {
		return nil, err
	}

	if output == "FILE_NOT_FOUND" {
		return nil, fmt.Errorf("文件不存在: %s", filePath)
	}

	return []byte(output), nil
}

func (sc *SSHClient) ReadFileContent(filePath string) string {
	data, err := sc.ReadFile(filePath)
	if err != nil {
		utils.LogWarning("读取文件 %s 失败: %v", filePath, err)
		return ""
	}
	return string(data)
}

func (sc *SSHClient) GetFilePermissions(filePath string) string {
	cmd := fmt.Sprintf("stat -c '%%a' '%s' 2>/dev/null || echo 'UNKNOWN'", filePath)
	perms, _ := sc.ExecuteCommand(cmd)
	return strings.TrimSpace(perms)
}

func (sc *SSHClient) GetFileOwner(filePath string) string {
	cmd := fmt.Sprintf("stat -c '%%U:%%G' '%s' 2>/dev/null || echo 'UNKNOWN'", filePath)
	owner, _ := sc.ExecuteCommand(cmd)
	return strings.TrimSpace(owner)
}

func (sc *SSHClient) FileExists(filePath string) bool {
	cmd := fmt.Sprintf("test -f '%s' && echo 'EXISTS' || echo 'NOT_FOUND'", filePath)
	result, _ := sc.ExecuteCommand(cmd)
	return strings.TrimSpace(result) == "EXISTS"
}

func (sc *SSHClient) DirectoryExists(dirPath string) bool {
	cmd := fmt.Sprintf("test -d '%s' && echo 'EXISTS' || echo 'NOT_FOUND'", dirPath)
	result, _ := sc.ExecuteCommand(cmd)
	return strings.TrimSpace(result) == "EXISTS"
}

func (sc *SSHClient) ListDirectory(dirPath string) []string {
	cmd := fmt.Sprintf("ls -1 '%s' 2>/dev/null || echo 'ERROR'", dirPath)
	output, _ := sc.ExecuteCommand(cmd)
	if output == "ERROR" {
		return []string{}
	}

	var files []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "ERROR" {
			files = append(files, line)
		}
	}
	return files
}

func (sc *SSHClient) GetSystemInfo() map[string]string {
	info := make(map[string]string)

	cmds := map[string]string{
		"hostname":     "hostname",
		"os_version":   "cat /etc/os-release | grep 'PRETTY_NAME' | cut -d'=' -f2 | tr -d '\"'",
		"kernel":       "uname -r",
		"architecture": "uname -m",
		"cpu_cores":    "nproc",
		"memory_total": "free -h | grep Mem | awk '{print $2}'",
		"disk_total":   "df -h / | tail -1 | awk '{print $2}'",
	}

	for key, cmd := range cmds {
		output, err := sc.ExecuteCommand(cmd)
		if err == nil {
			info[key] = strings.TrimSpace(output)
		} else {
			info[key] = "unknown"
		}
	}

	return info
}

func (sc *SSHClient) GetRunningServices() []string {
	cmd := "systemctl list-units --type=service --state=running --no-pager -q | awk '{print $1}'"
	output, _ := sc.ExecuteCommand(cmd)

	var services []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

func (sc *SSHClient) GetEnabledServices() []string {
	cmd := "systemctl list-unit-files --type=service --state=enabled --no-pager -q | awk '{print $1}'"
	output, _ := sc.ExecuteCommand(cmd)

	var services []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

func (sc *SSHClient) GetUsers() []string {
	cmd := "cat /etc/passwd | grep -v '/nologin$' | grep -v '/false$' | awk -F: '{print $1}'"
	output, _ := sc.ExecuteCommand(cmd)

	var users []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "root" {
			users = append(users, line)
		}
	}
	return users
}

func (sc *SSHClient) GetSudoersUsers() []string {
	cmd := "grep -E '^(root|%)' /etc/sudoers; grep 'ALL=' /etc/sudoers.d/ 2>/dev/null | awk '{print $1}' | sort -u"
	output, _ := sc.ExecuteCommand(cmd)

	var users []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			users = append(users, line)
		}
	}
	return users
}

func (sc *SSHClient) GetProcessList() []string {
	cmd := "ps aux --no-headers 2>/dev/null | awk '{print $11}' | sort -u"
	output, _ := sc.ExecuteCommand(cmd)

	var processes []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "[") {
			processes = append(processes, line)
		}
	}
	return processes
}

func (sc *SSHClient) GetListeningPorts() []string {
	cmd := "ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sed 's/.*://'"
	output, _ := sc.ExecuteCommand(cmd)

	var ports []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ports = append(ports, line)
		}
	}
	return ports
}

func ParseSSHKeyPath(privateKeyPath string) (string, error) {
	keyData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("读取私钥文件失败: %v", err)
	}
	return string(keyData), nil
}

func TestSSHConnection(host string, port int, username, password string, timeout time.Duration) bool {
	config := &SSHConfig{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  timeout,
		MaxRetries: 1,
	}

	client := NewSSHClient(config)
	err := client.Connect()
	if err != nil {
		log.Printf("SSH连接测试失败: %v", err)
		return false
	}
	defer client.Close()

	return client.IsConnected()
}

func GetSSHTargetFromTarget(target string) (string, int, error) {
	var host string
	var port int = 22

	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		host = parts[0]
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &port)
		}
	} else {
		host = target
	}

	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return "", 0, fmt.Errorf("无法解析主机名: %s", host)
		}
		host = ips[0].String()
	}

	return host, port, nil
}
