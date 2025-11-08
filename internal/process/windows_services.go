//go:build windows

package process

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// analyzeWindowsServices 分析Windows系统服务
func analyzeWindowsServices() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// 方法1: 使用net start命令获取运行中的服务
	runningServices, err := getServicesFromNetStart()
	if err == nil {
		services = append(services, runningServices...)
	}

	// 方法2: 使用sc query命令获取所有服务详细信息
	allServices, err := getServicesFromSC()
	if err == nil {
		services = mergeServiceInfo(services, allServices)
	}

	// 方法3: 使用wmic命令获取服务路径和用户信息
	detailedServices, err := getServicesFromWMIC()
	if err == nil {
		services = mergeServiceInfo(services, detailedServices)
	}

	return services, nil
}

// getServicesFromNetStart 使用net start命令获取运行中的服务
func getServicesFromNetStart() ([]ServiceInfo, error) {
	cmd := exec.Command("net", "start")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行net start命令失败: %v", err)
	}

	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	inServiceList := false
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" {
			continue
		}
		
		// 跳过标题行
		if strings.Contains(line, "已经启动以下 Windows 服务") || 
		   strings.Contains(line, "The following Windows services are started") {
			inServiceList = true
			continue
		}
		
		if strings.Contains(line, "命令成功完成") || 
		   strings.Contains(line, "The command completed successfully") {
			break
		}
		
		if inServiceList && !strings.Contains(line, "---") {
			service := ServiceInfo{
				Name:        extractServiceName(line),
				DisplayName: line,
				Status:      "Running",
				StartType:   "Auto", // net start只显示运行中的服务，通常是自动启动
				User:        "SYSTEM", // 默认系统用户
				Path:        "",
				Privilege:   string(PrivilegeSystem),
			}
			services = append(services, service)
		}
	}

	return services, nil
}

// getServicesFromSC 使用sc query命令获取所有服务信息
func getServicesFromSC() ([]ServiceInfo, error) {
	cmd := exec.Command("sc", "query", "type=", "service", "state=", "all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行sc query命令失败: %v", err)
	}

	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	var currentService *ServiceInfo
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" {
			continue
		}
		
		// 新服务开始
		if strings.HasPrefix(line, "SERVICE_NAME:") {
			if currentService != nil {
				services = append(services, *currentService)
			}
			
			name := strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
			currentService = &ServiceInfo{
				Name:        name,
				DisplayName: name,
				Status:      "Unknown",
				StartType:   "Unknown",
				User:        "Unknown",
				Path:        "",
				Privilege:   string(PrivilegeUnknown),
			}
			continue
		}
		
		if currentService == nil {
			continue
		}
		
		// 解析服务状态
		if strings.HasPrefix(line, "STATE:") {
			if strings.Contains(line, "RUNNING") {
				currentService.Status = "Running"
			} else if strings.Contains(line, "STOPPED") {
				currentService.Status = "Stopped"
			} else if strings.Contains(line, "PAUSED") {
				currentService.Status = "Paused"
			}
		}
		
		// 解析启动类型
		if strings.HasPrefix(line, "START_TYPE:") {
			if strings.Contains(line, "AUTO_START") {
				currentService.StartType = "Auto"
			} else if strings.Contains(line, "DEMAND_START") {
				currentService.StartType = "Manual"
			} else if strings.Contains(line, "DISABLED") {
				currentService.StartType = "Disabled"
			}
		}
		
		// 解析显示名称
		if strings.HasPrefix(line, "DISPLAY_NAME:") {
			displayName := strings.TrimSpace(strings.TrimPrefix(line, "DISPLAY_NAME:"))
			currentService.DisplayName = displayName
		}
	}
	
	// 添加最后一个服务
	if currentService != nil {
		services = append(services, *currentService)
	}

	return services, nil
}

// getServicesFromWMIC 使用wmic命令获取服务详细信息
func getServicesFromWMIC() ([]ServiceInfo, error) {
	cmd := exec.Command("wmic", "service", "get", "Name,PathName,StartName,State,StartMode", "/format:csv")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行wmic service命令失败: %v", err)
	}

	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	// 跳过标题行
	firstLine := true
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, "Node,") {
			firstLine = false
			continue
		}
		
		if firstLine {
			firstLine = false
			continue
		}
		
		fields := strings.Split(line, ",")
		if len(fields) < 6 {
			continue
		}
		
		// CSV格式: Node,Name,PathName,StartName,State,StartMode
		name := fields[1]
		pathName := fields[2]
		startName := fields[3]
		state := fields[4]
		startMode := fields[5]
		
		service := ServiceInfo{
			Name:        name,
			DisplayName: name,
			Status:      mapServiceState(state),
			StartType:   mapServiceStartMode(startMode),
			User:        startName,
			Path:        pathName,
			Privilege:   getServicePrivilege(startName, pathName),
		}
		
		services = append(services, service)
	}

	return services, nil
}

// extractServiceName 从显示名称中提取服务名称
func extractServiceName(displayName string) string {
	// 尝试从显示名称中提取简短的服务名称
	parts := strings.Fields(displayName)
	if len(parts) > 0 {
		// 取第一个单词作为服务名称
		return parts[0]
	}
	return displayName
}

// mapServiceState 映射服务状态
func mapServiceState(state string) string {
	switch strings.ToUpper(state) {
	case "RUNNING":
		return "Running"
	case "STOPPED":
		return "Stopped"
	case "PAUSED":
		return "Paused"
	case "START_PENDING":
		return "Starting"
	case "STOP_PENDING":
		return "Stopping"
	default:
		return "Unknown"
	}
}

// mapServiceStartMode 映射服务启动模式
func mapServiceStartMode(startMode string) string {
	switch strings.ToUpper(startMode) {
	case "AUTO":
		return "Auto"
	case "MANUAL":
		return "Manual"
	case "DISABLED":
		return "Disabled"
	case "BOOT":
		return "Boot"
	case "SYSTEM":
		return "System"
	default:
		return "Unknown"
	}
}

// getServicePrivilege 根据服务用户和路径判断权限级别
func getServicePrivilege(user, path string) string {
	// 系统服务
	if strings.Contains(strings.ToLower(user), "localsystem") || 
	   strings.Contains(strings.ToLower(user), "nt authority\\system") {
		return string(PrivilegeSystem)
	}
	
	// 网络服务
	if strings.Contains(strings.ToLower(user), "networkservice") || 
	   strings.Contains(strings.ToLower(user), "nt authority\\networkservice") {
		return string(PrivilegeHigh)
	}
	
	// 本地服务
	if strings.Contains(strings.ToLower(user), "localservice") || 
	   strings.Contains(strings.ToLower(user), "nt authority\\localservice") {
		return string(PrivilegeMedium)
	}
	
	// 特定用户服务
	if user != "" && !strings.Contains(strings.ToLower(user), "nt authority") {
		return string(PrivilegeMedium)
	}
	
	// 关键系统服务路径判断
	criticalPaths := []string{
		"C:\\Windows\\System32",
		"C:\\Windows\\SysWOW64",
		"%SystemRoot%",
		"system32",
	}
	
	for _, criticalPath := range criticalPaths {
		if strings.Contains(strings.ToLower(path), strings.ToLower(criticalPath)) {
			return string(PrivilegeSystem)
		}
	}
	
	return string(PrivilegeUnknown)
}

// mergeServiceInfo 合并服务信息
func mergeServiceInfo(existing, new []ServiceInfo) []ServiceInfo {
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
			if newService.User != "Unknown" && newService.User != "" {
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

// getServiceProcessInfo 获取服务对应的进程信息
func getServiceProcessInfo(serviceName string) (int, error) {
	cmd := exec.Command("wmic", "service", "where", fmt.Sprintf("Name='%s'", serviceName), "get", "ProcessId", "/value")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ProcessId=") {
			pidStr := strings.TrimSpace(strings.TrimPrefix(line, "ProcessId="))
			if pid, err := strconv.Atoi(pidStr); err == nil {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("无法获取服务进程ID")
}