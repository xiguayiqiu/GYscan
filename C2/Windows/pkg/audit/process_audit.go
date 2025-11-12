package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

// ProcessAudit 进程审计模块
type ProcessAudit struct {
	config *Config
}

// NewProcessAudit 创建进程审计模块
func NewProcessAudit(config *Config) *ProcessAudit {
	return &ProcessAudit{
		config: config,
	}
}

// Name 返回模块名称
func (pa *ProcessAudit) Name() string {
	return "process"
}

// Description 返回模块描述
func (pa *ProcessAudit) Description() string {
	return "Windows进程安全审计，包括进程枚举、权限检查、异常进程检测"
}

// RequiredPermissions 返回所需权限
func (pa *ProcessAudit) RequiredPermissions() []string {
	return []string{"SeDebugPrivilege", "SeSecurityPrivilege"}
}

// Run 执行进程审计
func (pa *ProcessAudit) Run() ([]AuditResult, error) {
	var results []AuditResult

	// 1. 获取所有进程信息
	processes, err := pa.getAllProcesses()
	if err != nil {
		return nil, fmt.Errorf("获取进程信息失败: %v", err)
	}

	// 2. 执行各种审计检查
	results = append(results, pa.auditSuspiciousProcesses(processes)...)
	results = append(results, pa.auditHighPrivilegeProcesses(processes)...)
	results = append(results, pa.auditHiddenProcesses(processes)...)
	results = append(results, pa.auditProcessInjection(processes)...)
	results = append(results, pa.auditResourceUsage(processes)...)

	return results, nil
}

// getAllProcesses 获取所有进程信息
func (pa *ProcessAudit) getAllProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	for _, pid := range pids {
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		info, err := pa.getProcessInfo(proc)
		if err != nil {
			continue
		}

		processes = append(processes, info)
	}

	return processes, nil
}

// getProcessInfo 获取单个进程详细信息
func (pa *ProcessAudit) getProcessInfo(proc *process.Process) (ProcessInfo, error) {
	var info ProcessInfo

	info.PID = proc.Pid

	// 获取进程名
	if name, err := proc.Name(); err == nil {
		info.Name = name
	}

	// 获取进程路径
	if exe, err := proc.Exe(); err == nil {
		info.Path = exe
	}

	// 获取命令行
	if cmdline, err := proc.Cmdline(); err == nil {
		info.CommandLine = cmdline
	}

	// 获取CPU和内存使用率
	if cpuPercent, err := proc.CPUPercent(); err == nil {
		info.CPUPercent = cpuPercent
	}

	if memInfo, err := proc.MemoryInfo(); err == nil && memInfo != nil {
		info.MemoryMB = float64(memInfo.RSS) / 1024 / 1024
	}

	// 获取创建时间
	if createTime, err := proc.CreateTime(); err == nil {
		info.CreateTime = time.Unix(createTime/1000, 0)
	}

	// 获取进程所有者
	info.Owner = pa.getProcessOwner(proc.Pid)

	return info, nil
}

// getProcessOwner 获取进程所有者
func (pa *ProcessAudit) getProcessOwner(pid int32) string {
	// 使用Windows API获取进程令牌和所有者信息
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return "Unknown"
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Unknown"
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "Unknown"
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "Unknown"
	}

	if domain != "" {
		return fmt.Sprintf("%s\\%s", domain, account)
	}
	return account
}

// auditSuspiciousProcesses 审计可疑进程
func (pa *ProcessAudit) auditSuspiciousProcesses(processes []ProcessInfo) []AuditResult {
	var results []AuditResult

	// 可疑进程特征列表
	suspiciousPatterns := []struct {
		name        string
		patterns    []string
		description string
		riskScore   int
	}{
		{
			name:        "挖矿进程",
			patterns:    []string{"xmrig", "miner", "ethminer", "ccminer"},
			description: "检测到可能的加密货币挖矿进程",
			riskScore:   90,
		},
		{
			name:        "后门进程",
			patterns:    []string{"meterpreter", "beacon", "cobaltstrike", "empire"},
			description: "检测到可能的渗透测试或恶意软件进程",
			riskScore:   95,
		},
		{
			name:        "无文件进程",
			patterns:    []string{"wmic", "powershell", "cmd", "rundll32"},
			description: "检测到可能用于无文件攻击的进程",
			riskScore:   80,
		},
	}

	for _, process := range processes {
		for _, pattern := range suspiciousPatterns {
			for _, keyword := range pattern.patterns {
				if strings.Contains(strings.ToLower(process.Name), strings.ToLower(keyword)) ||
					strings.Contains(strings.ToLower(process.CommandLine), strings.ToLower(keyword)) {

					results = append(results, AuditResult{
						ModuleName:     pa.Name(),
						Level:          AuditLevelHigh,
						Status:         "fail",
						Description:    fmt.Sprintf("%s: %s (PID: %d)", pattern.name, process.Name, process.PID),
						Details:        process,
						RiskScore:      pattern.riskScore,
						Recommendation: "立即调查此进程的合法性，必要时终止进程",
						Timestamp:      time.Now(),
					})
					break
				}
			}
		}
	}

	return results
}

// auditHighPrivilegeProcesses 审计高权限进程
func (pa *ProcessAudit) auditHighPrivilegeProcesses(processes []ProcessInfo) []AuditResult {
	var results []AuditResult

	// 系统关键进程列表
	systemProcesses := []string{
		"csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",
		"smss.exe", "svchost.exe", "System", "wininit.exe",
	}

	// 检查非系统进程是否以高权限运行
	for _, process := range processes {
		isSystemProcess := false
		for _, sysProc := range systemProcesses {
			if strings.EqualFold(process.Name, sysProc) {
				isSystemProcess = true
				break
			}
		}

		if !isSystemProcess && pa.isHighPrivilegeProcess(process) {
			results = append(results, AuditResult{
				ModuleName:     pa.Name(),
				Level:          AuditLevelMedium,
				Status:         "warning",
				Description:    fmt.Sprintf("非系统进程以高权限运行: %s (PID: %d)", process.Name, process.PID),
				Details:        process,
				RiskScore:      70,
				Recommendation: "检查此进程是否需要高权限，考虑降权运行",
				Timestamp:      time.Now(),
			})
		}
	}

	return results
}

// isHighPrivilegeProcess 检查是否为高权限进程
func (pa *ProcessAudit) isHighPrivilegeProcess(process ProcessInfo) bool {
	// 检查进程所有者是否为SYSTEM或管理员组
	owners := []string{"SYSTEM", "NT AUTHORITY", "Administrators"}
	for _, owner := range owners {
		if strings.Contains(process.Owner, owner) {
			return true
		}
	}
	return false
}

// auditHiddenProcesses 审计隐藏进程
func (pa *ProcessAudit) auditHiddenProcesses(processes []ProcessInfo) []AuditResult {
	var results []AuditResult

	// 使用Windows API枚举进程，与gopsutil结果对比
	apiProcesses := pa.getProcessesByAPI()

	// 检查是否有进程在API枚举中但不在gopsutil中
	for _, apiProc := range apiProcesses {
		found := false
		for _, proc := range processes {
			if apiProc.PID == proc.PID {
				found = true
				break
			}
		}

		if !found {
			results = append(results, AuditResult{
				ModuleName:     pa.Name(),
				Level:          AuditLevelHigh,
				Status:         "fail",
				Description:    fmt.Sprintf("检测到可能的隐藏进程: PID %d", apiProc.PID),
				Details:        apiProc,
				RiskScore:      85,
				Recommendation: "立即调查此隐藏进程，可能为rootkit",
				Timestamp:      time.Now(),
			})
		}
	}

	return results
}

// getProcessesByAPI 使用Windows API枚举进程
func (pa *ProcessAudit) getProcessesByAPI() []ProcessInfo {
	var processes []ProcessInfo

	// 使用CreateToolhelp32Snapshot枚举进程
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return processes
	}
	defer windows.CloseHandle(hSnapshot)

	var processEntry windows.ProcessEntry32
	processEntry.Size = uint32(256) // 简化实现，固定大小

	err = windows.Process32First(hSnapshot, &processEntry)
	for err == nil {
		processes = append(processes, ProcessInfo{
			PID:  int32(processEntry.ProcessID),
			Name: windows.UTF16ToString(processEntry.ExeFile[:]),
		})

		err = windows.Process32Next(hSnapshot, &processEntry)
	}

	return processes
}

// auditProcessInjection 审计进程注入
func (pa *ProcessAudit) auditProcessInjection(processes []ProcessInfo) []AuditResult {
	var results []AuditResult

	// 检查可疑的进程注入模式
	for _, process := range processes {
		// 检查是否有进程被注入到系统进程中
		if pa.isSystemProcess(process.Name) && pa.hasSuspiciousModules(process.PID) {
			results = append(results, AuditResult{
				ModuleName:     pa.Name(),
				Level:          AuditLevelHigh,
				Status:         "fail",
				Description:    fmt.Sprintf("检测到系统进程可能被注入: %s (PID: %d)", process.Name, process.PID),
				Details:        process,
				RiskScore:      90,
				Recommendation: "检查此系统进程的模块加载情况",
				Timestamp:      time.Now(),
			})
		}
	}

	return results
}

// isSystemProcess 检查是否为系统进程
func (pa *ProcessAudit) isSystemProcess(processName string) bool {
	systemProcesses := []string{"lsass.exe", "services.exe", "winlogon.exe", "csrss.exe"}
	for _, sysProc := range systemProcesses {
		if strings.EqualFold(processName, sysProc) {
			return true
		}
	}
	return false
}

// hasSuspiciousModules 检查是否有可疑模块
func (pa *ProcessAudit) hasSuspiciousModules(pid int32) bool {
	// 实现模块检查逻辑
	// 这里可以检查进程加载的DLL是否可疑
	return false
}

// auditResourceUsage 审计资源使用
func (pa *ProcessAudit) auditResourceUsage(processes []ProcessInfo) []AuditResult {
	var results []AuditResult

	// 按CPU使用率排序
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].CPUPercent > processes[j].CPUPercent
	})

	// 检查高CPU使用率进程
	for i := 0; i < min(5, len(processes)); i++ {
		if processes[i].CPUPercent > 50.0 {
			results = append(results, AuditResult{
				ModuleName:     pa.Name(),
				Level:          AuditLevelMedium,
				Status:         "warning",
				Description:    fmt.Sprintf("高CPU使用率进程: %s (%.1f%%)", processes[i].Name, processes[i].CPUPercent),
				Details:        processes[i],
				RiskScore:      60,
				Recommendation: "监控此进程的资源使用情况",
				Timestamp:      time.Now(),
			})
		}
	}

	// 按内存使用率排序
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].MemoryMB > processes[j].MemoryMB
	})

	// 检查高内存使用率进程
	for i := 0; i < min(5, len(processes)); i++ {
		if processes[i].MemoryMB > 500.0 { // 500MB
			results = append(results, AuditResult{
				ModuleName:     pa.Name(),
				Level:          AuditLevelMedium,
				Status:         "warning",
				Description:    fmt.Sprintf("高内存使用率进程: %s (%.1fMB)", processes[i].Name, processes[i].MemoryMB),
				Details:        processes[i],
				RiskScore:      60,
				Recommendation: "监控此进程的内存使用情况",
				Timestamp:      time.Now(),
			})
		}
	}

	return results
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
