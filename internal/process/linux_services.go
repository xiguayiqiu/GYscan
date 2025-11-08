package process

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"
)

// analyzeLinuxServices 分析Linux系统服务
func analyzeLinuxServices() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// 方法1: 使用systemctl命令（systemd系统）
	systemdServices, err := getServicesFromSystemctl()
	if err == nil {
		services = append(services, systemdServices...)
	}

	// 方法2: 使用service命令（SysV系统）
	sysvServices, err := getServicesFromService()
	if err == nil {
		services = append(services, sysvServices...)
	}

	// 方法3: 检查/etc/init.d目录
	initdServices, err := getServicesFromInitD()
	if err == nil {
		services = mergeLinuxServiceInfo(services, initdServices)
	}

	// 方法4: 检查运行中的进程，识别服务进程
	processServices, err := getServicesFromProcesses()
	if err == nil {
		services = mergeLinuxServiceInfo(services, processServices)
	}

	return services, nil
}

// getServicesFromSystemctl 使用systemctl命令获取服务信息
func getServicesFromSystemctl() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// 获取所有服务列表
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行systemctl命令失败: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 解析systemctl输出格式
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		name := fields[0]
		status := fields[3]
		description := strings.Join(fields[4:], " ")

		// 获取服务的详细信息
		service, err := getSystemctlServiceDetails(name, status, description)
		if err == nil {
			services = append(services, service)
		}
	}

	return services, nil
}

// getSystemctlServiceDetails 获取systemd服务的详细信息
func getSystemctlServiceDetails(name, status, description string) (ServiceInfo, error) {
	service := ServiceInfo{
		Name:        name,
		DisplayName: description,
		Status:      mapSystemdStatus(status),
		StartType:   getSystemdStartType(name),
		User:        getSystemdServiceUser(name),
		Path:        getSystemdServicePath(name),
		Privilege:   getLinuxServicePrivilege(name),
	}

	return service, nil
}

// getServicesFromService 使用service命令获取服务信息
func getServicesFromService() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// 检查/etc/init.d目录
	initdDir := "/etc/init.d"
	files, err := ioutil.ReadDir(initdDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		
		// 检查服务状态
		status := getServiceStatus(name)
		
		service := ServiceInfo{
			Name:        name,
			DisplayName: name,
			Status:      status,
			StartType:   getSysVStartType(name),
			User:        "root", // SysV服务通常以root运行
			Path:        filepath.Join(initdDir, name),
			Privilege:   getLinuxServicePrivilege(name),
		}

		services = append(services, service)
	}

	return services, nil
}

// getServicesFromInitD 检查/etc/init.d目录获取服务信息
func getServicesFromInitD() ([]ServiceInfo, error) {
	var services []ServiceInfo

	initdDir := "/etc/init.d"
	files, err := ioutil.ReadDir(initdDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		
		// 检查是否为可执行文件
		if file.Mode()&0111 == 0 {
			continue
		}

		service := ServiceInfo{
			Name:        name,
			DisplayName: name,
			Status:      "Unknown",
			StartType:   getSysVStartType(name),
			User:        "root",
			Path:        filepath.Join(initdDir, name),
			Privilege:   getLinuxServicePrivilege(name),
		}

		services = append(services, service)
	}

	return services, nil
}

// getServicesFromProcesses 从运行中的进程识别服务
func getServicesFromProcesses() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// 获取所有进程
	processes, err := analyzeLinuxProcesses()
	if err != nil {
		return nil, err
	}

	// 常见服务进程模式
	servicePatterns := map[string]string{
		"sshd":          "SSH服务",
		"apache2":       "Apache Web服务器",
		"nginx":         "Nginx Web服务器",
		"mysql":         "MySQL数据库",
		"postgres":      "PostgreSQL数据库",
		"docker":        "Docker容器服务",
		"cron":          "定时任务服务",
		"rsyslog":       "系统日志服务",
		"dbus":          "D-Bus消息总线",
		"NetworkManager": "网络管理服务",
	}

	for _, process := range processes {
		for pattern, description := range servicePatterns {
			if strings.Contains(strings.ToLower(process.Name), strings.ToLower(pattern)) {
				service := ServiceInfo{
					Name:        process.Name,
					DisplayName: description,
					Status:      "Running",
					StartType:   "Auto",
					User:        process.User,
					Path:        process.Path,
					Privilege:   process.Privilege,
				}
				services = append(services, service)
				break
			}
		}
	}

	return services, nil
}

// mapSystemdStatus 映射systemd服务状态
func mapSystemdStatus(status string) string {
	switch status {
	case "active":
		return "Running"
	case "inactive":
		return "Stopped"
	case "failed":
		return "Failed"
	case "activating":
		return "Starting"
	case "deactivating":
		return "Stopping"
	default:
		return "Unknown"
	}
}

// getSystemdStartType 获取systemd服务启动类型
func getSystemdStartType(serviceName string) string {
	cmd := exec.Command("systemctl", "is-enabled", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	status := strings.TrimSpace(string(output))
	switch status {
	case "enabled":
		return "Auto"
	case "disabled":
		return "Manual"
	case "static":
		return "Static"
	default:
		return "Unknown"
	}
}

// getSystemdServiceUser 获取systemd服务运行用户
func getSystemdServiceUser(serviceName string) string {
	cmd := exec.Command("systemctl", "show", serviceName, "--property=User")
	output, err := cmd.Output()
	if err != nil {
		return "root"
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "User=") {
			user := strings.TrimSpace(strings.TrimPrefix(line, "User="))
			if user != "" {
				return user
			}
		}
	}

	return "root"
}

// getSystemdServicePath 获取systemd服务可执行文件路径
func getSystemdServicePath(serviceName string) string {
	cmd := exec.Command("systemctl", "show", serviceName, "--property=ExecStart")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ExecStart=") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
			// 提取可执行文件路径
			if idx := strings.Index(path, " "); idx != -1 {
				path = path[:idx]
			}
			return path
		}
	}

	return ""
}

// getServiceStatus 获取SysV服务状态
func getServiceStatus(serviceName string) string {
	cmd := exec.Command("service", serviceName, "status")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	statusOutput := strings.ToLower(string(output))
	if strings.Contains(statusOutput, "running") || strings.Contains(statusOutput, "active") {
		return "Running"
	} else if strings.Contains(statusOutput, "stopped") || strings.Contains(statusOutput, "inactive") {
		return "Stopped"
	}

	return "Unknown"
}

// getSysVStartType 获取SysV服务启动类型
func getSysVStartType(serviceName string) string {
	// 检查运行级别目录
	runlevelDirs := []string{
		"/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d",
		"/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcS.d",
	}

	for _, dir := range runlevelDirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, file := range files {
			filename := file.Name()
			// 检查是否以S开头（启动）或K开头（停止）
			if strings.HasPrefix(filename, "S") && strings.Contains(filename, serviceName) {
				return "Auto"
			}
		}
	}

	return "Manual"
}

// getLinuxServicePrivilege 判断Linux服务权限级别
func getLinuxServicePrivilege(serviceName string) string {
	// 系统关键服务
	systemServices := []string{
		"systemd", "init", "udev", "dbus", "syslog", "rsyslog",
		"network", "networking", "NetworkManager", "systemd-logind",
		"systemd-journald", "systemd-udevd", "cron", "atd",
	}

	for _, sysService := range systemServices {
		if strings.Contains(strings.ToLower(serviceName), strings.ToLower(sysService)) {
			return string(PrivilegeSystem)
		}
	}

	// 网络服务
	networkServices := []string{
		"sshd", "apache", "nginx", "mysql", "postgres", "docker",
		"iptables", "firewalld", "ufw", "fail2ban",
	}

	for _, netService := range networkServices {
		if strings.Contains(strings.ToLower(serviceName), strings.ToLower(netService)) {
			return string(PrivilegeHigh)
		}
	}

	// 普通服务
	return string(PrivilegeMedium)
}

// mergeLinuxServiceInfo 合并Linux服务信息
func mergeLinuxServiceInfo(existing, new []ServiceInfo) []ServiceInfo {
	result := make([]ServiceInfo, len(existing))
	copy(result, existing)

	// 创建现有服务的名称映射
	existingMap := make(map[string]int)
	for i, service := range existing {
		existingMap[service.Name] = i
	}

	// 合并或添加新信息
	for _, newService := range new {
		if idx, exists := existingMap[newService.Name]; exists {
			// 合并信息
			if newService.Status != "Unknown" {
				result[idx].Status = newService.Status
			}
			if newService.StartType != "Unknown" {
				result[idx].StartType = newService.StartType
			}
			if newService.User != "" {
				result[idx].User = newService.User
			}
			if newService.Path != "" {
				result[idx].Path = newService.Path
			}
			if newService.Privilege != string(PrivilegeUnknown) {
				result[idx].Privilege = newService.Privilege
			}
			if newService.DisplayName != newService.Name {
				result[idx].DisplayName = newService.DisplayName
			}
		} else {
			// 添加新服务
			result = append(result, newService)
		}
	}

	return result
}