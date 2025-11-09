//go:build !windows

package process

import "fmt"

// analyzeWindowsProcesses Windows进程分析函数（Linux空实现）
func analyzeWindowsProcesses() ([]ProcessInfo, error) {
	return nil, fmt.Errorf("Windows进程分析功能仅在Windows系统上可用")
}

// analyzeWindowsServices Windows服务分析函数（Linux空实现）
func analyzeWindowsServices() ([]ServiceInfo, error) {
	return nil, fmt.Errorf("Windows服务分析功能仅在Windows系统上可用")
}