package ftp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// FTPConfig 配置FTP破解参数
type FTPConfig struct {
	Host     string   // FTP服务器地址
	Port     int      // FTP服务器端口，默认21
	Username []string // 用户名列表
	Password []string // 密码列表
	Timeout  int      // 连接超时时间（秒）
	Threads  int      // 并发线程数
}

// ParseTarget 解析FTP目标地址
func ParseTarget(target string) (string, int, error) {
	// 处理格式: ftp://host:port 或 host:port
	target = strings.TrimPrefix(target, "ftp://")
	
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// 如果没有端口，使用默认端口21
		if strings.Contains(err.Error(), "missing port") {
			return target, 21, nil
		}
		return "", 0, err
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("无效的端口号: %s", portStr)
	}
	
	return host, port, nil
}

// ValidateConfig 验证配置参数
func ValidateConfig(config *FTPConfig) error {
	if config.Host == "" {
		return fmt.Errorf("FTP服务器地址不能为空")
	}
	
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("无效的端口号: %d", config.Port)
	}
	
	if len(config.Username) == 0 {
		return fmt.Errorf("用户名列表不能为空")
	}
	
	if len(config.Password) == 0 {
		return fmt.Errorf("密码列表不能为空")
	}
	
	if config.Threads <= 0 {
		config.Threads = 1
	}
	
	if config.Timeout <= 0 {
		config.Timeout = 10
	}
	
	return nil
}