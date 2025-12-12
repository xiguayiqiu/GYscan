package utils

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// RunCommand 执行系统命令并返回输出
func RunCommand(command string) (string, error) {
	var cmd *exec.Cmd

	// 根据操作系统选择适当的shell
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// GetCurrentTime 获取当前时间的格式化字符串
func GetCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// IsLinux 检查当前系统是否为Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsWindows 检查当前系统是否为Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsMacOS 检查当前系统是否为macOS
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// GetCurrentUser 获取当前用户名
func GetCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}
