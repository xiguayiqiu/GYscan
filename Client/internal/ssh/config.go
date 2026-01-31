package ssh

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SSHConfig SSH爆破配置
type SSHConfig struct {
	Target       string // 目标地址
	TargetFile   string // 目标地址文件
	Port         int    // SSH端口
	Username     string // 用户名
	UsernameFile string // 用户名字典文件
	Password     string // 密码
	PasswordFile string // 密码字典文件
	Threads      int    // 并发线程数
	Timeout      int    // 连接超时时间(秒)
	AttemptDelay int    // 尝试间隔(毫秒)，避免触发服务器安全机制
	Verbose      bool   // 详细输出模式
	VeryVerbose  bool   // 更详细的输出模式
	StopOnFirst  bool   // 找到第一个匹配后停止
	ExtraChecks  string // 额外检查
}

// SSHResult SSH爆破结果
type SSHResult struct {
	Target      string        // 目标地址
	Port        int           // 端口
	Username    string        // 用户名
	Password    string        // 密码
	Success     bool          // 是否成功
	ElapsedTime time.Duration // 耗时
	Attempts    int           // 尝试次数
	Error       string        // 错误信息
}

// GetDefaultConfig 获取默认配置
func GetDefaultConfig() *SSHConfig {
	return &SSHConfig{
		Port:        22,
		Threads:     4,
		Timeout:     10,
		Verbose:     false,
		VeryVerbose: false,
		StopOnFirst: false,
	}
}

// ParseTarget 解析目标地址
func ParseTarget(target string) (string, int, error) {
	// 检查是否包含端口
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) != 2 {
			return "", 0, fmt.Errorf("无效的目标格式: %s", target)
		}

		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, fmt.Errorf("无效的端口号: %s", parts[1])
		}

		return parts[0], port, nil
	}

	// 默认使用22端口
	return target, 22, nil
}
