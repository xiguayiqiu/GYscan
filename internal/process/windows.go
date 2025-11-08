//go:build windows

package process

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API 常量
const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ          = 0x0010
	MAX_PATH                 = 260
)

// 使用golang.org/x/sys/windows包中的ProcessEntry32结构体

// analyzeWindowsProcesses 分析Windows系统进程
func analyzeWindowsProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// 方法1: 使用tasklist命令
	tasklistProcesses, err := getProcessesFromTasklist()
	if err == nil {
		processes = append(processes, tasklistProcesses...)
	}

	// 方法2: 使用Windows API获取更详细信息
	apiProcesses, err := getProcessesFromAPI()
	if err == nil {
		// 合并或替换信息
		processes = mergeProcessInfo(processes, apiProcesses)
	}

	return processes, nil
}

// getProcessesFromTasklist 使用tasklist命令获取进程信息
func getProcessesFromTasklist() ([]ProcessInfo, error) {
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行tasklist命令失败: %v", err)
	}

	var processes []ProcessInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// 解析CSV格式
		fields := parseCSVLine(line)
		if len(fields) < 5 {
			continue
		}

		// 解析进程信息
		pid, err := strconv.Atoi(strings.TrimSpace(fields[1]))
		if err != nil {
			continue
		}

		name := strings.Trim(strings.TrimSpace(fields[0]), `"`)
		sessionName := strings.Trim(strings.TrimSpace(fields[2]), `"`)
		sessionNum, _ := strconv.Atoi(strings.TrimSpace(fields[3]))
		memoryStr := strings.Trim(strings.TrimSpace(fields[4]), `"`)
		
		// 解析内存使用量
		memoryUsage := parseMemoryUsage(memoryStr)
		
		// 获取用户和权限信息
		user, privilege := getUserAndPrivilege(pid, sessionName, sessionNum)

		process := ProcessInfo{
			PID:         pid,
			Name:        name,
			User:        user,
			CPUUsage:    0.0, // tasklist不提供CPU使用率
			MemoryUsage: memoryUsage,
			Privilege:   privilege,
			Path:        "", // 需要额外获取
			CommandLine: "", // 需要额外获取
		}

		processes = append(processes, process)
	}

	return processes, nil
}

// getProcessesFromAPI 使用Windows API获取进程信息
func getProcessesFromAPI() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// 创建进程快照
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("创建进程快照失败: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, fmt.Errorf("获取第一个进程失败: %v", err)
	}

	for {
		processName := windows.UTF16ToString(entry.ExeFile[:])
		
		// 获取进程详细信息
		process, err := getProcessDetails(int(entry.ProcessID), processName)
		if err == nil {
			processes = append(processes, process)
		}

		// 获取下一个进程
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return processes, nil
}

// getProcessDetails 获取进程详细信息
func getProcessDetails(pid int, name string) (ProcessInfo, error) {
	process := ProcessInfo{
		PID:  pid,
		Name: name,
	}

	// 打开进程句柄
	processHandle, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return process, err
	}
	defer windows.CloseHandle(processHandle)

	// 获取进程路径
	if path, err := getWindowsProcessPath(processHandle); err == nil {
		process.Path = path
	}

	// 获取命令行参数
	if cmdLine, err := getCommandLine(processHandle); err == nil {
		process.CommandLine = cmdLine
	}

	// 获取用户信息
	if user, err := getProcessUser(processHandle); err == nil {
		process.User = user
	}

	// 获取内存使用量
	if memory, err := getProcessMemory(processHandle); err == nil {
		process.MemoryUsage = memory
	}

	// 判断权限级别
	process.Privilege = getPrivilegeLevel(process.User, process.Name)

	return process, nil
}

// getWindowsProcessPath 获取Windows进程可执行文件路径
func getWindowsProcessPath(processHandle windows.Handle) (string, error) {
	var path [MAX_PATH]uint16
	length := uint32(MAX_PATH)

	err := windows.GetModuleFileNameEx(processHandle, 0, &path[0], length)
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(path[:]), nil
}

// getCommandLine 获取进程命令行参数
func getCommandLine(processHandle windows.Handle) (string, error) {
	// 使用WMI获取命令行参数更可靠
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", processHandle), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) > 1 {
		return strings.TrimSpace(lines[1]), nil
	}

	return "", fmt.Errorf("无法获取命令行参数")
}

// getProcessUser 获取进程运行用户
func getProcessUser(processHandle windows.Handle) (string, error) {
	var token windows.Token
	err := windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", err
	}
	defer token.Close()

	// 获取用户SID
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}

	// 获取用户名
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "", err
	}

	if domain != "" {
		return fmt.Sprintf("%s\\%s", domain, account), nil
	}

	return account, nil
}

// getProcessMemory 获取进程内存使用量
func getProcessMemory(processHandle windows.Handle) (uint64, error) {
	// 使用tasklist命令获取内存使用量
	cmd := exec.Command("tasklist", "/fi", fmt.Sprintf("PID eq %d", processHandle), "/fo", "csv", "/nh")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("%d", processHandle)) {
			fields := parseCSVLine(line)
			if len(fields) >= 5 {
				memoryStr := strings.Trim(strings.TrimSpace(fields[4]), `"`)
				return parseMemoryUsage(memoryStr), nil
			}
		}
	}

	return 0, fmt.Errorf("无法获取进程内存使用量")
}

// getUserAndPrivilege 根据会话信息获取用户和权限
func getUserAndPrivilege(pid int, sessionName string, sessionNum int) (string, string) {
	user := "未知用户"
	privilege := string(PrivilegeUnknown)

	// 根据会话判断权限
	if sessionName == "Services" {
		user = "SYSTEM"
		privilege = string(PrivilegeSystem)
	} else if sessionNum == 0 {
		user = "SYSTEM"
		privilege = string(PrivilegeSystem)
	} else {
		// 尝试获取具体用户名
		if currentUser, err := getCurrentUser(); err == nil {
			user = currentUser
		}
		privilege = string(PrivilegeMedium)
	}

	// 特殊进程权限判断
	if isSystemProcess(pid, sessionName) {
		privilege = string(PrivilegeSystem)
	}

	return user, privilege
}

// getCurrentUser 获取当前用户名
func getCurrentUser() (string, error) {
	return os.Getenv("USERNAME"), nil
}

// isSystemProcess 判断是否为系统进程
func isSystemProcess(pid int, sessionName string) bool {
	systemProcesses := []string{
		"System", "smss.exe", "csrss.exe", "wininit.exe", 
		"services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
	}

	for _, sysProc := range systemProcesses {
		if strings.Contains(sessionName, sysProc) {
			return true
		}
	}

	return false
}

// getPrivilegeLevel 根据用户和进程名判断权限级别
func getPrivilegeLevel(user, processName string) string {
	// 系统用户
	if strings.Contains(strings.ToLower(user), "system") || 
	   strings.Contains(strings.ToLower(user), "nt authority") {
		return string(PrivilegeSystem)
	}

	// 管理员用户
	if strings.Contains(strings.ToLower(user), "administrator") {
		return string(PrivilegeHigh)
	}

	// 系统关键进程
	systemProcesses := []string{
		"csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",
		"smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe",
	}

	for _, sysProc := range systemProcesses {
		if strings.EqualFold(processName, sysProc) {
			return string(PrivilegeSystem)
		}
	}

	// 普通用户进程
	return string(PrivilegeMedium)
}

// parseCSVLine 解析CSV格式的行
func parseCSVLine(line string) []string {
	var fields []string
	var field strings.Builder
	inQuotes := false

	for _, char := range line {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				fields = append(fields, field.String())
				field.Reset()
			} else {
				field.WriteRune(char)
			}
		default:
			field.WriteRune(char)
		}
	}

	// 添加最后一个字段
	if field.Len() > 0 {
		fields = append(fields, field.String())
	}

	return fields
}

// parseMemoryUsage 解析内存使用量字符串
func parseMemoryUsage(memoryStr string) uint64 {
	// 移除逗号和单位
	memoryStr = strings.ReplaceAll(memoryStr, ",", "")
	memoryStr = strings.ReplaceAll(memoryStr, " K", "")
	
	if memory, err := strconv.ParseUint(memoryStr, 10, 64); err == nil {
		return memory * 1024 // 转换为字节
	}
	
	return 0
}

// mergeProcessInfo 合并进程信息
func mergeProcessInfo(existing, new []ProcessInfo) []ProcessInfo {
	result := make([]ProcessInfo, len(existing))
	copy(result, existing)

	// 创建现有进程的PID映射
	existingMap := make(map[int]int)
	for i, process := range existing {
		existingMap[process.PID] = i
	}

	// 合并或添加新信息
	for _, newProcess := range new {
		if idx, exists := existingMap[newProcess.PID]; exists {
			// 合并信息
			if newProcess.Path != "" {
				result[idx].Path = newProcess.Path
			}
			if newProcess.CommandLine != "" {
				result[idx].CommandLine = newProcess.CommandLine
			}
			if newProcess.User != "" {
				result[idx].User = newProcess.User
			}
			if newProcess.MemoryUsage > 0 {
				result[idx].MemoryUsage = newProcess.MemoryUsage
			}
		} else {
			// 添加新进程
			result = append(result, newProcess)
		}
	}

	return result
}