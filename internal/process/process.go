package process

import (
	"fmt"
	"runtime"
	"strings"
)

// ProcessInfo 进程信息结构体
type ProcessInfo struct {
	PID         int     `json:"pid"`           // 进程ID
	Name        string  `json:"name"`          // 进程名称
	User        string  `json:"user"`          // 运行用户
	CPUUsage    float64 `json:"cpu_usage"`     // CPU使用率
	MemoryUsage uint64  `json:"memory_usage"` // 内存使用量(字节)
	Privilege   string  `json:"privilege"`    // 权限级别
	Path        string  `json:"path"`         // 可执行文件路径
	CommandLine string  `json:"command_line"` // 命令行参数
}

// ServiceInfo 服务信息结构体
type ServiceInfo struct {
	Name        string `json:"name"`         // 服务名称
	DisplayName string `json:"display_name"` // 显示名称
	Status      string `json:"status"`       // 服务状态
	StartType   string `json:"start_type"`   // 启动类型
	User        string `json:"user"`         // 运行用户
	Path        string `json:"path"`         // 可执行文件路径
	Privilege   string `json:"privilege"`    // 权限级别
}

// PrivilegeLevel 权限级别枚举
type PrivilegeLevel string

const (
	PrivilegeLow     PrivilegeLevel = "低权限"
	PrivilegeMedium  PrivilegeLevel = "中权限"
	PrivilegeHigh    PrivilegeLevel = "高权限"
	PrivilegeSystem  PrivilegeLevel = "系统权限"
	PrivilegeUnknown PrivilegeLevel = "未知权限"
)

// AnalyzeProcesses 分析运行中的进程
func AnalyzeProcesses() ([]ProcessInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return analyzeWindowsProcesses()
	case "linux":
		return analyzeLinuxProcesses()
	default:
		return nil, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// AnalyzeServices 分析系统服务
func AnalyzeServices() ([]ServiceInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return analyzeWindowsServices()
	case "linux":
		return analyzeLinuxServices()
	default:
		return nil, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}



// GetHighPrivilegeProcesses 获取高权限运行的进程
func GetHighPrivilegeProcesses() ([]ProcessInfo, error) {
	processes, err := AnalyzeProcesses()
	if err != nil {
		return nil, err
	}

	var highPrivilegeProcesses []ProcessInfo
	for _, process := range processes {
		if isHighPrivilege(process.Privilege) {
			highPrivilegeProcesses = append(highPrivilegeProcesses, process)
		}
	}

	return highPrivilegeProcesses, nil
}

// GetHighPrivilegeServices 获取高权限运行的服务
func GetHighPrivilegeServices() ([]ServiceInfo, error) {
	services, err := AnalyzeServices()
	if err != nil {
		return nil, err
	}

	var highPrivilegeServices []ServiceInfo
	for _, service := range services {
		if isHighPrivilege(service.Privilege) {
			highPrivilegeServices = append(highPrivilegeServices, service)
		}
	}

	return highPrivilegeServices, nil
}

// isHighPrivilege 判断是否为高权限
func isHighPrivilege(privilege string) bool {
	highPrivileges := []string{
		string(PrivilegeHigh),
		string(PrivilegeSystem),
	}

	for _, highPriv := range highPrivileges {
		if strings.Contains(privilege, highPriv) {
			return true
		}
	}

	return false
}

// FormatProcessInfo 格式化进程信息输出
func FormatProcessInfo(processes []ProcessInfo) string {
	var result strings.Builder
	
	result.WriteString("运行中的进程信息:\n")
	result.WriteString("================================================================================\n")
	result.WriteString("PID\t名称\t\t用户\t\tCPU使用率\t内存使用\t权限级别\n")
	result.WriteString("================================================================================\n")

	for _, process := range processes {
		memoryMB := float64(process.MemoryUsage) / 1024 / 1024
		result.WriteString(fmt.Sprintf("%d\t%-15s\t%-10s\t%.1f%%\t\t%.1fMB\t%s\n",
			process.PID, process.Name, process.User, process.CPUUsage, memoryMB, process.Privilege))
	}

	return result.String()
}

// FormatServiceInfo 格式化服务信息输出
func FormatServiceInfo(services []ServiceInfo) string {
	var result strings.Builder
	
	result.WriteString("系统服务信息:\n")
	result.WriteString("================================================================================\n")
	result.WriteString("名称\t\t\t状态\t\t启动类型\t\t用户\t\t权限级别\n")
	result.WriteString("================================================================================\n")

	for _, service := range services {
		result.WriteString(fmt.Sprintf("%-20s\t%-8s\t%-10s\t%-10s\t%s\n",
			service.Name, service.Status, service.StartType, service.User, service.Privilege))
	}

	return result.String()
}

// FormatHighPrivilegeInfo 格式化高权限信息输出
func FormatHighPrivilegeInfo(processes []ProcessInfo, services []ServiceInfo) string {
	var result strings.Builder
	
	result.WriteString("高权限运行的进程和服务:\n")
	result.WriteString("================================================================================\n")
	
	if len(processes) > 0 {
		result.WriteString("高权限进程:\n")
		for _, process := range processes {
			memoryMB := float64(process.MemoryUsage) / 1024 / 1024
			result.WriteString(fmt.Sprintf("  PID: %d, 名称: %s, 用户: %s, CPU: %.1f%%, 内存: %.1fMB, 权限: %s\n",
				process.PID, process.Name, process.User, process.CPUUsage, memoryMB, process.Privilege))
		}
	}

	if len(services) > 0 {
		result.WriteString("\n高权限服务:\n")
		for _, service := range services {
			result.WriteString(fmt.Sprintf("  名称: %s, 状态: %s, 用户: %s, 权限: %s\n",
				service.Name, service.Status, service.User, service.Privilege))
		}
	}

	if len(processes) == 0 && len(services) == 0 {
		result.WriteString("未发现高权限运行的进程或服务\n")
	}

	return result.String()
}