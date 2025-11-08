package process

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// analyzeLinuxProcesses 分析Linux系统进程
func analyzeLinuxProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// 方法1: 使用ps命令获取进程信息
	psProcesses, err := getProcessesFromPS()
	if err == nil {
		processes = append(processes, psProcesses...)
	}

	// 方法2: 解析/proc文件系统
	procProcesses, err := getProcessesFromProc()
	if err == nil {
		processes = mergeLinuxProcessInfo(processes, procProcesses)
	}

	// 方法3: 使用top命令获取CPU和内存使用率
	topProcesses, err := getProcessesFromTop()
	if err == nil {
		processes = mergeLinuxProcessInfo(processes, topProcesses)
	}

	return processes, nil
}

// getProcessesFromPS 使用ps命令获取进程信息
func getProcessesFromPS() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// 使用ps命令获取详细的进程信息
	cmd := exec.Command("ps", "-eo", "pid,user,pcpu,pmem,comm,args", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行ps命令失败: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 解析ps输出格式
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		user := fields[1]
		cpuUsage, _ := strconv.ParseFloat(fields[2], 64)
		memoryUsage, _ := strconv.ParseFloat(fields[3], 64)
		name := fields[4]
		commandLine := strings.Join(fields[5:], " ")

		// 获取进程路径和权限信息
		path := getProcessPath(pid)
		privilege := getLinuxProcessPrivilege(user, name)

		// 计算内存使用量（字节）
		memoryBytes := uint64(memoryUsage * 1024 * 1024) // 转换为字节

		process := ProcessInfo{
			PID:         pid,
			Name:        name,
			User:        user,
			CPUUsage:    cpuUsage,
			MemoryUsage: memoryBytes,
			Privilege:   privilege,
			Path:        path,
			CommandLine: commandLine,
		}

		processes = append(processes, process)
	}

	return processes, nil
}

// getProcessesFromProc 解析/proc文件系统获取进程信息
func getProcessesFromProc() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	procDir := "/proc"
	files, err := ioutil.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}

		// 检查是否为数字目录（进程ID）
		pidStr := file.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// 获取进程信息
		process, err := getProcessInfoFromProc(pid)
		if err == nil {
			processes = append(processes, process)
		}
	}

	return processes, nil
}

// getProcessInfoFromProc 从/proc文件系统获取单个进程信息
func getProcessInfoFromProc(pid int) (ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)
	
	// 检查进程目录是否存在
	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return ProcessInfo{}, fmt.Errorf("进程目录不存在: %s", procPath)
	}

	// 读取进程状态文件
	statusFile := filepath.Join(procPath, "status")
	statusContent, err := ioutil.ReadFile(statusFile)
	if err != nil {
		return ProcessInfo{}, err
	}

	// 读取进程命令行
	cmdlineFile := filepath.Join(procPath, "cmdline")
	cmdlineContent, err := ioutil.ReadFile(cmdlineFile)
	if err != nil {
		return ProcessInfo{}, err
	}

	// 读取进程可执行文件链接
	exeLink := filepath.Join(procPath, "exe")
	exePath, _ := os.Readlink(exeLink)

	// 解析进程状态信息
	name := ""
	user := ""
	memoryUsage := uint64(0)

	lines := strings.Split(string(statusContent), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "Uid:") {
			uidFields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(uidFields) > 0 {
				// 获取用户名
				user = getUsernameFromUID(uidFields[0])
			}
		} else if strings.HasPrefix(line, "VmRSS:") {
			// 获取内存使用量
			memoryFields := strings.Fields(strings.TrimPrefix(line, "VmRSS:"))
			if len(memoryFields) > 0 {
				memoryKB, _ := strconv.ParseUint(memoryFields[0], 10, 64)
				memoryUsage = memoryKB * 1024 // 转换为字节
			}
		}
	}

	// 解析命令行参数
	commandLine := strings.ReplaceAll(string(cmdlineContent), "\x00", " ")
	commandLine = strings.TrimSpace(commandLine)

	// 获取CPU使用率（需要计算）
	cpuUsage := getProcessCPUUsage(pid)

	// 判断权限级别
	privilege := getLinuxProcessPrivilege(user, name)

	process := ProcessInfo{
		PID:         pid,
		Name:        name,
		User:        user,
		CPUUsage:    cpuUsage,
		MemoryUsage: memoryUsage,
		Privilege:   privilege,
		Path:        exePath,
		CommandLine: commandLine,
	}

	return process, nil
}

// getProcessesFromTop 使用top命令获取进程CPU和内存使用率
func getProcessesFromTop() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// 使用top命令获取进程信息
	cmd := exec.Command("top", "-b", "-n", "1", "-o", "%CPU")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行top命令失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	inProcessSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 跳过空行和标题行
		if line == "" {
			continue
		}

		// 检查是否进入进程信息部分
		if strings.HasPrefix(line, "PID") && strings.Contains(line, "USER") {
			inProcessSection = true
			continue
		}

		if inProcessSection {
			fields := strings.Fields(line)
			if len(fields) < 12 {
				continue
			}

			pid, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}

			user := fields[1]
			cpuUsage, _ := strconv.ParseFloat(fields[8], 64)
			memoryUsage, _ := strconv.ParseFloat(fields[9], 64)
			name := fields[11]

			// 获取进程路径和权限信息
			path := getProcessPath(pid)
			privilege := getLinuxProcessPrivilege(user, name)

			// 计算内存使用量（字节）
			memoryBytes := uint64(memoryUsage * 1024 * 1024) // 转换为字节

			process := ProcessInfo{
				PID:         pid,
				Name:        name,
				User:        user,
				CPUUsage:    cpuUsage,
				MemoryUsage: memoryBytes,
				Privilege:   privilege,
				Path:        path,
				CommandLine: "", // top命令不提供完整命令行
			}

			processes = append(processes, process)
		}
	}

	return processes, nil
}

// getProcessPath 获取进程可执行文件路径
func getProcessPath(pid int) string {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(exeLink)
	if err != nil {
		return ""
	}
	return path
}

// getProcessCPUUsage 获取进程CPU使用率
func getProcessCPUUsage(pid int) float64 {
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	content, err := ioutil.ReadFile(statFile)
	if err != nil {
		return 0.0
	}

	// 解析stat文件内容
	fields := strings.Fields(string(content))
	if len(fields) < 17 {
		return 0.0
	}

	// 获取进程时间信息
	utime, _ := strconv.ParseUint(fields[13], 10, 64)
	stime, _ := strconv.ParseUint(fields[14], 10, 64)

	// 获取系统总时间
	totalTime := getSystemTotalTime()
	if totalTime == 0 {
		return 0.0
	}

	// 计算CPU使用率
	processTime := utime + stime
	cpuUsage := (float64(processTime) / float64(totalTime)) * 100.0

	return cpuUsage
}

// getSystemTotalTime 获取系统总CPU时间
func getSystemTotalTime() uint64 {
	content, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				total := uint64(0)
				for i := 1; i <= 7; i++ {
					val, _ := strconv.ParseUint(fields[i], 10, 64)
					total += val
				}
				return total
			}
		}
	}

	return 0
}

// getUsernameFromUID 根据UID获取用户名
func getUsernameFromUID(uidStr string) string {
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return ""
	}

	// 尝试从/etc/passwd获取用户名
	content, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Sprintf("uid_%d", uid)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf(":%d:", uid)) {
			fields := strings.Split(line, ":")
			if len(fields) >= 3 && fields[2] == uidStr {
				return fields[0]
			}
		}
	}

	return fmt.Sprintf("uid_%d", uid)
}

// getLinuxProcessPrivilege 判断Linux进程权限级别
func getLinuxProcessPrivilege(user, processName string) string {
	// 系统进程（以root用户运行的系统关键进程）
	if user == "root" {
		systemProcesses := []string{
			"systemd", "init", "udev", "dbus", "syslog", "rsyslog",
			"kthreadd", "ksoftirqd", "kworker", "migration", "rcu",
			"cron", "atd", "sshd", "NetworkManager",
		}

		for _, sysProc := range systemProcesses {
			if strings.Contains(strings.ToLower(processName), strings.ToLower(sysProc)) {
				return string(PrivilegeSystem)
			}
		}

		// 网络服务进程
		networkProcesses := []string{
			"apache", "nginx", "mysql", "postgres", "docker",
			"iptables", "firewalld", "ufw", "fail2ban",
		}

		for _, netProc := range networkProcesses {
			if strings.Contains(strings.ToLower(processName), strings.ToLower(netProc)) {
				return string(PrivilegeHigh)
			}
		}

		return string(PrivilegeHigh) // root用户运行的其他进程
	}

	// 普通用户进程
	if user == "nobody" || user == "www-data" || user == "mysql" || user == "postgres" {
		return string(PrivilegeMedium)
	}

	// 其他用户进程
	return string(PrivilegeLow)
}

// mergeLinuxProcessInfo 合并Linux进程信息
func mergeLinuxProcessInfo(existing, new []ProcessInfo) []ProcessInfo {
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
			if newProcess.CPUUsage > 0 {
				result[idx].CPUUsage = newProcess.CPUUsage
			}
			if newProcess.MemoryUsage > 0 {
				result[idx].MemoryUsage = newProcess.MemoryUsage
			}
			if newProcess.User != "" {
				result[idx].User = newProcess.User
			}
			if newProcess.Path != "" {
				result[idx].Path = newProcess.Path
			}
			if newProcess.Privilege != string(PrivilegeUnknown) {
				result[idx].Privilege = newProcess.Privilege
			}
			if newProcess.CommandLine != "" {
				result[idx].CommandLine = newProcess.CommandLine
			}
		} else {
			// 添加新进程
			result = append(result, newProcess)
		}
	}

	return result
}