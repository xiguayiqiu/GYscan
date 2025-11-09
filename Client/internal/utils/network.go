package utils

import (
	"strconv"
)

// ParsePort 解析端口号，返回有效的端口号或0表示无效
func ParsePort(portStr string) int {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	
	if port < 1 || port > 65535 {
		return 0
	}
	
	return port
}

// IsValidIP 检查IP地址是否有效
func IsValidIP(ip string) bool {
	// 简单的IP验证
	if ip == "" {
		return false
	}
	
	// 检查是否为本地回环地址
	if ip == "127.0.0.1" || ip == "localhost" {
		return true
	}
	
	// 检查是否为0.0.0.0（监听所有接口）
	if ip == "0.0.0.0" {
		return true
	}
	
	// 简单的IP格式检查
	parts := splitIP(ip)
	if len(parts) != 4 {
		return false
	}
	
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	
	return true
}

// splitIP 分割IP地址为四个部分
func splitIP(ip string) []string {
	var parts []string
	var current string
	
	for _, char := range ip {
		if char == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	
	if current != "" {
		parts = append(parts, current)
	}
	
	return parts
}

// ValidateHostPort 验证主机和端口格式
func ValidateHostPort(host, port string) bool {
	if !IsValidIP(host) && host != "localhost" {
		return false
	}
	
	return ParsePort(port) != 0
}