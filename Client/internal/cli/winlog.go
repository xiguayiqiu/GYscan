package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"
	"GYscan/internal/wmi"

	"github.com/spf13/cobra"
)

// winlogCmd represents the winlog command
var winlogCmd = &cobra.Command{
	Use:   "winlog",
	Short: "Windows日志查看工具（支持本地和远程）",
	Long: `Windows日志查看工具（支持本地和远程）

支持功能:
- 查看系统日志 (System)
- 查看安全日志 (Security)
- 查看应用程序日志 (Application)
- 查看安装日志 (Setup)
- 查看转发事件日志 (ForwardedEvents)
- 按事件ID筛选
- 按时间范围筛选
- 按数量限制筛选
- 本地和远程查询
- 自动错误恢复和备用查询

支持日志类型:
- System: 系统事件日志
- Security: 安全审计日志
- Application: 应用程序事件日志
- Setup: 系统安装日志
- ForwardedEvents: 转发的事件日志

示例用法:
  # 查看本地系统日志
  ./GYscan winlog system
  
  # 查看远程系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password
  
  # 查看安全日志
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password
  
  # 查看应用程序日志
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password
  
  # 查看安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password
  
  # 按事件ID筛选
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --event-id 4624
  
  # 按时间范围筛选(最近24小时)
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --hours 24
  
  # 限制返回数量
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --limit 50
  
  # 使用域账号(适用于域环境)
  ./GYscan winlog system --target 192.168.1.100 --domain example.com --user admin --password password
  
  # 启用详细输出
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --verbose
  
  # 同时使用所有筛选条件
  ./GYscan winlog security --target 192.168.1.100 --domain example.com --user admin --password password --event-id 4624 --hours 48 --limit 50`,
	Run: func(cmd *cobra.Command, args []string) {
		// 直接运行winlog命令时显示帮助
		cmd.Help()
	},
}

// winlogSystemCmd 查看系统日志
var winlogSystemCmd = &cobra.Command{
	Use:   "system",
	Short: "查看系统日志",
	Long: `查看远程Windows系统的系统日志

WINDOWS 事件ID 范围:
- 系统日志: 0-1000
- 安全日志: 4600-4699
- 应用程序日志: 1000-1999

WinRM 端口: 默认 5985 (HTTP) 或 5986 (HTTPS)

WinRM 认证: 支持用户名/密码和域账号认证

WinRM 限制:
- 默认超时时间: 30秒
- 最大返回事件数: 1000

WinRM 注意事项:
- 确保目标主机已启用WinRM服务
- 检查防火墙设置, 允许WinRM流量通过
- 域账号认证时，确保账号有足够权限查询日志

Windows桌面系统默认关闭WinRM服务, 需要手动开启。
Windows服务器系统默认开启WinRM服务, 无需额外配置。

使用示例:
  # 查看系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password
  # 查看特定事件ID的系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --event-id 7036
  # 查看最近12小时的系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --hours 12
  # 限制返回的日志数量
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --limit 100`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		eventID, _ := cmd.Flags().GetInt("event-id")
		hours, _ := cmd.Flags().GetInt("hours")
		limit, _ := cmd.Flags().GetInt("limit")
		verbose, _ := cmd.Flags().GetBool("verbose")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		useColor, _ := cmd.Flags().GetBool("color")

		// 调用日志查看功能
		viewRemoteLog(target, port, username, password, domain, "System", eventID, hours, limit, verbose, pageSize, useColor)
	},
}

// winlogSecurityCmd 查看安全日志
var winlogSecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "查看安全日志",
	Long: `查看远程Windows系统的安全日志

WINDOWS 事件ID 范围:
- 系统日志: 0-1000
- 安全日志: 4600-4699
- 应用程序日志: 1000-1999

WinRM 端口: 默认 5985 (HTTP) 或 5986 (HTTPS)

WinRM 认证: 支持用户名/密码和域账号认证

WinRM 限制:
- 默认超时时间: 30秒
- 最大返回事件数: 1000

WinRM 注意事项:
- 确保目标主机已启用WinRM服务
- 检查防火墙设置, 允许WinRM流量通过
- 域账号认证时，确保账号有足够权限查询日志

Windows桌面系统默认关闭WinRM服务, 需要手动开启。
Windows服务器系统默认开启WinRM服务, 无需额外配置。

使用示例:
  # 查看安全日志
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password
  # 查看登录事件(4624成功登录)
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --event-id 4624
  # 查看失败登录尝试
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --event-id 4625
  # 查看最近7天的安全日志
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --hours 168`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		eventID, _ := cmd.Flags().GetInt("event-id")
		hours, _ := cmd.Flags().GetInt("hours")
		limit, _ := cmd.Flags().GetInt("limit")
		verbose, _ := cmd.Flags().GetBool("verbose")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		useColor, _ := cmd.Flags().GetBool("color")

		// 调用日志查看功能
		viewRemoteLog(target, port, username, password, domain, "Security", eventID, hours, limit, verbose, pageSize, useColor)
	},
}

// winlogApplicationCmd 查看应用程序日志
var winlogApplicationCmd = &cobra.Command{
	Use:   "application",
	Short: "查看应用程序日志",
	Long: `查看远程Windows系统的应用程序日志

WINDOWS 事件ID 范围:
- 系统日志: 0-1000
- 安全日志: 4600-4699
- 应用程序日志: 1000-1999

WinRM 端口: 默认 5985 (HTTP) 或 5986 (HTTPS)

WinRM 认证: 支持用户名/密码和域账号认证

WinRM 限制:
- 默认超时时间: 30秒
- 最大返回事件数: 1000

WinRM 注意事项:
- 确保目标主机已启用WinRM服务
- 检查防火墙设置, 允许WinRM流量通过
- 域账号认证时，确保账号有足够权限查询日志

Windows桌面系统默认关闭WinRM服务, 需要手动开启。
Windows服务器系统默认开启WinRM服务, 无需额外配置。

使用示例:
  # 查看应用程序日志
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password
  # 按事件ID筛选
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password --event-id 1000
  # 查看最近24小时的应用程序日志
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password --hours 24`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		eventID, _ := cmd.Flags().GetInt("event-id")
		hours, _ := cmd.Flags().GetInt("hours")
		limit, _ := cmd.Flags().GetInt("limit")
		verbose, _ := cmd.Flags().GetBool("verbose")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		useColor, _ := cmd.Flags().GetBool("color")

		// 调用日志查看功能
		viewRemoteLog(target, port, username, password, domain, "Application", eventID, hours, limit, verbose, pageSize, useColor)
	},
}

// winlogSetupCmd 查看安装日志
var winlogSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "查看安装日志",
	Long: `查看远程Windows系统的安装日志

WINDOWS 事件ID 范围:
- 系统日志: 0-1000
- 安全日志: 4600-4699
- 应用程序日志: 1000-1999
- 安装日志: 2000-2999

WinRM 端口: 默认 5985 (HTTP) 或 5986 (HTTPS)

WinRM 认证: 支持用户名/密码和域账号认证

WinRM 限制:
- 默认超时时间: 30秒
- 最大返回事件数: 1000

WinRM 注意事项:
- 确保目标主机已启用WinRM服务
- 检查防火墙设置, 允许WinRM流量通过
- 域账号认证时，确保账号有足够权限查询日志

Windows桌面系统默认关闭WinRM服务, 需要手动开启。
Windows服务器系统默认开启WinRM服务, 无需额外配置。

使用示例:
  # 查看安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password
  # 查看特定事件ID的安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password --event-id 2001
  # 查看最近24小时的安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password --hours 24`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		eventID, _ := cmd.Flags().GetInt("event-id")
		hours, _ := cmd.Flags().GetInt("hours")
		limit, _ := cmd.Flags().GetInt("limit")
		verbose, _ := cmd.Flags().GetBool("verbose")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		useColor, _ := cmd.Flags().GetBool("color")

		// 调用日志查看功能
		viewRemoteLog(target, port, username, password, domain, "Setup", eventID, hours, limit, verbose, pageSize, useColor)
	},
}

// winlogForwardedEventsCmd 查看转发事件日志
var winlogForwardedEventsCmd = &cobra.Command{
	Use:   "forwardedevents",
	Short: "查看转发事件日志",
	Long: `查看远程Windows系统的转发事件日志

WINDOWS 事件ID 范围:
- 系统日志: 0-1000
- 安全日志: 4600-4699
- 应用程序日志: 1000-1999
- 转发事件日志: 包含从其他计算机转发的事件

WinRM 端口: 默认 5985 (HTTP) 或 5986 (HTTPS)

WinRM 认证: 支持用户名/密码和域账号认证

WinRM 限制:
- 默认超时时间: 30秒
- 最大返回事件数: 1000

WinRM 注意事项:
- 确保目标主机已启用WinRM服务
- 检查防火墙设置, 允许WinRM流量通过
- 域账号认证时，确保账号有足够权限查询日志

Windows桌面系统默认关闭WinRM服务, 需要手动开启。
Windows服务器系统默认开启WinRM服务, 无需额外配置。

使用示例:
  # 查看转发事件日志
  ./GYscan winlog forwardedevents --target 192.168.1.100 --user admin --password password
  # 查看特定事件ID的转发事件日志
  ./GYscan winlog forwardedevents --target 192.168.1.100 --user admin --password password --event-id 4624
  # 查看最近7天的转发事件日志
  ./GYscan winlog forwardedevents --target 192.168.1.100 --user admin --password password --hours 168`,
	Run: func(cmd *cobra.Command, args []string) {
		// 获取参数
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		eventID, _ := cmd.Flags().GetInt("event-id")
		hours, _ := cmd.Flags().GetInt("hours")
		limit, _ := cmd.Flags().GetInt("limit")
		verbose, _ := cmd.Flags().GetBool("verbose")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		useColor, _ := cmd.Flags().GetBool("color")

		// 调用日志查看功能
		viewRemoteLog(target, port, username, password, domain, "ForwardedEvents", eventID, hours, limit, verbose, pageSize, useColor)
	},
}

// viewRemoteLog 查看Windows日志的核心函数(支持本地和远程，带缓存优化)
func viewRemoteLog(target string, port int, username, password, domain, logType string, eventID, hours, limit int, verbose bool, pageSize int, useColor bool) {
	// 验证参数
	if err := validateParameters(logType, hours, limit); err != nil {
		utils.ErrorPrint("参数验证失败: %v", err)
		return
	}

	var result string
	var err error

	if target == "" {
		utils.InfoPrint("准备本地查询 %s 日志", logType)
		// 本地查询优化
		if runtime.GOOS == "windows" {
			result, err = queryLocalLogs(logType, eventID, hours, limit, verbose)
			if err != nil {
				utils.ErrorPrint("本地日志查询失败: %v", err)
				utils.InfoPrint("回退到WMI查询...")
			} else {
				utils.SuccessPrint("本地日志查询成功")
				// 应用颜色和分页
				outputResult(result, pageSize, useColor)
				utils.SuccessPrint("日志查询完成")
				return
			}
		}
		// 如果本地查询失败或不是Windows系统，继续使用WMI查询
		result, err = queryLocalLogs(logType, eventID, hours, limit, verbose)
	} else {
		utils.InfoPrint("连接到远程主机 %s 查看 %s 日志", target, logType)
		// 远程查询
		result, err = executeRemoteQuery(target, port, username, password, domain, logType, eventID, hours, limit, verbose)
	}

	if err != nil {
		utils.ErrorPrint("日志查询失败: %v", err)
		return
	}

	// 输出查询结果
	utils.SuccessPrint("日志查询成功")
	outputResult(result, pageSize, useColor)
	utils.SuccessPrint("日志查询完成")
}

// outputResult 输出结果（支持颜色和分页）
func outputResult(result string, pageSize int, useColor bool) {
	// 应用颜色
	if useColor {
		result = addColorToLogOutput(result)
	}

	// 应用分页
	if pageSize > 0 {
		displayWithPagination(result, pageSize)
	} else {
		fmt.Println(result)
	}
}

// validateParameters 验证输入参数
func validateParameters(logType string, hours, limit int) error {
	// 验证日志类型
	validLogTypes := []string{"System", "Security", "Application", "Setup", "ForwardedEvents"}
	valid := false
	for _, t := range validLogTypes {
		if strings.EqualFold(t, logType) {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("不支持的日志类型: %s，支持的日志类型: %v", logType, validLogTypes)
	}

	// 验证时间范围
	if hours < 0 {
		return fmt.Errorf("时间范围不能为负数: %d", hours)
	}
	if hours > 8760 { // 1年
		return fmt.Errorf("时间范围过大，最大支持1年(8760小时): %d", hours)
	}

	// 验证数量限制
	if limit < 0 {
		return fmt.Errorf("数量限制不能为负数: %d", limit)
	}
	if limit > 10000 {
		return fmt.Errorf("数量限制过大，最大支持10000条记录: %d", limit)
	}

	return nil
}

// queryLocalLogs 本地日志查询优化
func queryLocalLogs(logType string, eventID, hours, limit int, verbose bool) (string, error) {
	// 使用更高效的本地API查询
	startTime := time.Now().Add(-time.Duration(hours) * time.Hour)
	startTimeStr := startTime.Format("20060102150405.000000-000")

	query := fmt.Sprintf("SELECT * FROM Win32_NTLogEvent WHERE LogFile='%s'", logType)
	if hours > 0 {
		query += fmt.Sprintf(" AND TimeGenerated >= '%s'", startTimeStr)
	}
	if eventID > 0 {
		query += fmt.Sprintf(" AND EventCode=%d", eventID)
	}

	config := &wmi.WMIConfig{
		Target:      "", // 本地查询
		Query:       query,
		Timeout:     15, // 本地查询超时时间更短
		Verbose:     verbose,
		VeryVerbose: false,
	}

	client, err := wmi.NewWMIClient(config)
	if err != nil {
		return "", err
	}

	result, err := client.ExecuteQuery()
	if err != nil {
		return "", err
	}

	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}

	return processQueryResult(result.Output, limit, verbose), nil
}

// tryAlternativeQuery 尝试备用查询方法
func tryAlternativeQuery(config *wmi.WMIConfig, logType, startTimeStr string, eventID int) *wmi.WMIResult {
	// 简化查询语句，避免复杂条件
	query := fmt.Sprintf("SELECT TimeGenerated, EventCode, SourceName, Message FROM Win32_NTLogEvent WHERE LogFile='%s'", logType)

	config.Query = query

	client, err := wmi.NewWMIClient(config)
	if err != nil {
		utils.ErrorPrint("备用查询客户端创建失败: %v", err)
		return nil
	}

	result, err := client.ExecuteQuery()
	if err != nil {
		utils.ErrorPrint("备用查询失败: %v", err)
		return nil
	}

	return result
}

// convertWMITimeFormat 将WMI时间格式转换为友好格式
func convertWMITimeFormat(wmiTime string) string {
	// WMI时间格式示例: 20251122095403.399809-000
	// 转换为: 2025-11-22 09:54:03

	if len(wmiTime) < 14 {
		return wmiTime // 如果格式不正确，返回原值
	}

	// 提取日期时间部分
	year := wmiTime[0:4]
	month := wmiTime[4:6]
	day := wmiTime[6:8]
	hour := wmiTime[8:10]
	minute := wmiTime[10:12]
	second := wmiTime[12:14]

	return fmt.Sprintf("%s-%s-%s %s:%s:%s", year, month, day, hour, minute, second)
}

// analyzeLogStatistics 分析日志统计信息
func analyzeLogStatistics(lines []string) map[string]int {
	stats := map[string]int{
		"total":    0,
		"error":    0,
		"warning":  0,
		"info":     0,
		"critical": 0,
	}

	for i, line := range lines {
		// 跳过标题行和空行
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		stats["total"]++

		// 根据事件代码和消息内容分析事件类型
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			eventCode := fields[1]
			message := strings.ToLower(strings.Join(fields[2:], " "))

			// 根据事件代码判断事件类型
			if code, err := strconv.Atoi(eventCode); err == nil {
				if code >= 1000 && code < 2000 {
					stats["info"]++
				} else if code >= 2000 && code < 3000 {
					stats["warning"]++
				} else if code >= 3000 && code < 4000 {
					stats["error"]++
				} else if code >= 4000 {
					stats["critical"]++
				}
			}

			// 根据消息内容进一步判断
			if strings.Contains(message, "error") || strings.Contains(message, "失败") ||
				strings.Contains(message, "拒绝") || strings.Contains(message, "超时") {
				stats["error"]++
			} else if strings.Contains(message, "warning") || strings.Contains(message, "警告") {
				stats["warning"]++
			} else if strings.Contains(message, "critical") || strings.Contains(message, "严重") {
				stats["critical"]++
			}
		}
	}

	return stats
}

// processQueryResult 处理查询结果（支持Format-List格式）
func processQueryResult(output string, limit int, verbose bool) string {
	lines := strings.Split(output, "\n")
	if len(lines) <= 2 { // 只有标题行或空结果
		return "查询成功，但未找到匹配的日志记录\n"
	}

	// 处理Format-List格式的输出
	resultLines := make([]string, 0, len(lines))
	currentRecord := make(map[string]string)

	// 添加表格标题行
	resultLines = append(resultLines, "TimeGenerated             EventCode EventIdentifier EventCategory SourceName                             Message")
	resultLines = append(resultLines, "-------------             --------- --------------- ------------- ----------                             -------")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析字段行（格式：字段名: 值）
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fieldName := strings.TrimSpace(parts[0])
				fieldValue := strings.TrimSpace(parts[1])

				// 存储字段值
				currentRecord[fieldName] = fieldValue

				// 如果是Message字段，表示一条记录结束
				if fieldName == "Message" {
					// 格式化记录为表格行
					formattedLine := formatRecordAsTableRow(currentRecord)
					if formattedLine != "" {
						resultLines = append(resultLines, formattedLine)
					}
					// 重置当前记录
					currentRecord = make(map[string]string)
				}
			}
		}
	}

	// 处理最后一条记录（如果没有Message字段）
	if len(currentRecord) > 0 {
		formattedLine := formatRecordAsTableRow(currentRecord)
		if formattedLine != "" {
			resultLines = append(resultLines, formattedLine)
		}
	}

	// 计算实际记录数（减去标题行）
	totalRecords := len(resultLines) - 2

	// 限制输出行数（仅在limit明确指定且大于0时）
	if limit > 0 && totalRecords > limit {
		// 保留标题行和指定数量的记录行
		resultLines = append(resultLines[:2], resultLines[2:limit+2]...)
		// 添加截断提示
		resultLines = append(resultLines, fmt.Sprintf("... (显示前 %d 条记录，共 %d 条)", limit, totalRecords))
	}

	// 添加统计信息
	if verbose {
		resultLines = append(resultLines, fmt.Sprintf("\n查询统计信息:"))
		resultLines = append(resultLines, fmt.Sprintf("   总记录数: %d", totalRecords))
		if limit > 0 && totalRecords > limit {
			resultLines = append(resultLines, fmt.Sprintf("   显示前 %d 条记录", limit))
		}
		resultLines = append(resultLines, fmt.Sprintf("   查询时间: %s", time.Now().Format("2006-01-02 15:04:05")))

		// 添加详细的事件类型统计
		logStats := analyzeLogStatistics(resultLines)
		resultLines = append(resultLines, fmt.Sprintf("\n事件类型统计:"))
		resultLines = append(resultLines, fmt.Sprintf("   信息事件: %d", logStats["info"]))
		resultLines = append(resultLines, fmt.Sprintf("   警告事件: %d", logStats["warning"]))
		resultLines = append(resultLines, fmt.Sprintf("   错误事件: %d", logStats["error"]))
		resultLines = append(resultLines, fmt.Sprintf("   严重事件: %d", logStats["critical"]))
	}

	return strings.Join(resultLines, "\n")
}

// formatRecordAsTableRow 将记录格式化为表格行
func formatRecordAsTableRow(record map[string]string) string {
	// 获取各个字段值
	timeGenerated := record["TimeGenerated"]
	eventCode := record["EventCode"]
	eventIdentifier := record["EventIdentifier"]
	eventCategory := record["EventCategory"]
	sourceName := record["SourceName"]
	message := record["Message"]

	// 转换时间格式
	if timeGenerated != "" {
		timeGenerated = convertWMITimeFormat(timeGenerated)
	}

	// 格式化各个字段的长度
	formattedTime := fmt.Sprintf("%-23s", truncateString(timeGenerated, 23))
	formattedEventCode := fmt.Sprintf("%-9s", truncateString(eventCode, 9))
	formattedEventIdentifier := fmt.Sprintf("%-15s", truncateString(eventIdentifier, 15))
	formattedEventCategory := fmt.Sprintf("%-13s", truncateString(eventCategory, 13))
	formattedSourceName := fmt.Sprintf("%-35s", truncateString(sourceName, 35))

	// 处理消息字段（可能很长）
	formattedMessage := truncateString(message, 100) // 增加消息显示长度

	// 组合成表格行
	return fmt.Sprintf("%s %s %s %s %s %s",
		formattedTime, formattedEventCode, formattedEventIdentifier,
		formattedEventCategory, formattedSourceName, formattedMessage)
}

// truncateString 截断字符串，如果超过指定长度则添加省略号
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// optimizeLogDisplay 优化日志显示格式，确保消息内容完整
func optimizeLogDisplay(line string) string {
	// 如果行长度超过一定阈值，进行格式化处理
	if len(line) > 200 {
		// 查找消息部分（通常在时间戳和事件信息之后）
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			// 提取基本信息（时间、事件代码、源名称等）
			basicInfo := strings.Join(fields[:5], " ")
			message := strings.Join(fields[5:], " ")

			// 如果消息过长，进行换行处理
			if len(message) > 100 {
				// 使用自动换行格式化消息
				formattedMessage := wordWrap(message, 120)
				// 重新组合，确保基本信息在第一行
				lines := strings.Split(formattedMessage, "\n")
				result := basicInfo + " " + lines[0]
				for i := 1; i < len(lines); i++ {
					// 后续行缩进对齐
					result += "\n" + strings.Repeat(" ", len(basicInfo)+1) + lines[i]
				}
				return result
			}
		}
	}

	return line
}

// formatLogEntry 格式化日志条目，确保完整显示
func formatLogEntry(entry string, maxWidth int) string {
	if len(entry) <= maxWidth {
		return entry
	}

	// 如果包含时间戳，先分离时间戳和内容
	timeStamp := ""
	content := entry

	// 查找时间戳（通常是前19个字符，格式：YYYY-MM-DD HH:MM:SS）
	if len(entry) >= 19 && strings.Contains(entry[:19], "-") && strings.Contains(entry[:19], ":") {
		timeStamp = entry[:19]
		content = strings.TrimSpace(entry[19:])
	}

	// 格式化内容，自动换行
	formattedContent := wordWrap(content, maxWidth-20) // 留出时间戳的空间

	// 重新组合
	if timeStamp != "" {
		lines := strings.Split(formattedContent, "\n")
		result := []string{}
		for i, line := range lines {
			if i == 0 {
				result = append(result, fmt.Sprintf("%-19s %s", timeStamp, line))
			} else {
				result = append(result, fmt.Sprintf("%-19s %s", "", line))
			}
		}
		return strings.Join(result, "\n")
	}

	return formattedContent
}

// wordWrap 文本自动换行
func wordWrap(text string, width int) string {
	if width <= 0 {
		return text
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	wrapped := ""
	line := ""

	for _, word := range words {
		if len(line)+len(word)+1 <= width {
			if line != "" {
				line += " " + word
			} else {
				line = word
			}
		} else {
			if wrapped != "" {
				wrapped += "\n"
			}
			wrapped += line
			line = word
		}
	}

	if line != "" {
		if wrapped != "" {
			wrapped += "\n"
		}
		wrapped += line
	}

	return wrapped
}

// clearScreen 跨平台清屏函数
func clearScreen() {
	// Windows系统
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		// Linux/Unix系统
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// displayWithPagination 分页显示结果（每次翻页清屏刷新）
func displayWithPagination(output string, pageSize int) {
	lines := strings.Split(output, "\n")
	if len(lines) <= pageSize {
		// 如果结果少于页面大小，直接显示
		fmt.Println(output)
		return
	}

	totalPages := (len(lines) + pageSize - 1) / pageSize
	currentPage := 1
	totalRecords := len(lines) - 2 // 减去标题行和空行

	// 获取终端宽度
	terminalWidth := getTerminalWidth()
	if terminalWidth < 80 {
		terminalWidth = 80 // 最小宽度
	}

	for {
		// 清屏并显示当前页
		clearScreen()

		start := (currentPage - 1) * pageSize
		end := start + pageSize
		if end > len(lines) {
			end = len(lines)
		}

		// 显示当前页
		for i := start; i < end; i++ {
			// 格式化日志条目，确保完整显示
			formattedLine := formatLogEntry(lines[i], terminalWidth-2) // 留出边距
			fmt.Println(formattedLine)
		}

		// 显示分页信息和统计
		fmt.Printf("\n--- 第 %d 页，共 %d 页 (记录 %d-%d，共 %d 条) ---\n",
			currentPage, totalPages, start+1, end, totalRecords)
		fmt.Printf("操作提示: 按 Enter 继续下一页，b 返回上一页，q 退出，数字 跳转到指定页\n")

		// 读取用户输入
		var input string
		fmt.Print("请输入操作: ")
		fmt.Scanln(&input)

		input = strings.ToLower(strings.TrimSpace(input))

		if input == "q" {
			break
		} else if input == "b" && currentPage > 1 {
			currentPage--
		} else if num, err := strconv.Atoi(input); err == nil {
			// 跳转到指定页
			if num >= 1 && num <= totalPages {
				currentPage = num
			} else {
				fmt.Printf("页码 %d 超出范围 (1-%d)\n", num, totalPages)
			}
		} else if input == "" {
			// 默认行为：下一页
			if currentPage < totalPages {
				currentPage++
			} else {
				break
			}
		} else {
			fmt.Println("无效输入，请重新选择")
		}
	}

	// 显示完成信息前清屏，确保显示清晰
	clearScreen()
	fmt.Printf("\n日志浏览完成，共显示 %d 条记录\n", totalRecords)
}

// getTerminalWidth 获取终端宽度
func getTerminalWidth() int {
	// Windows系统获取终端宽度
	cmd := exec.Command("cmd", "/c", "mode con")
	output, err := cmd.Output()
	if err != nil {
		return 120 // 默认宽度
	}

	// 解析输出，查找列数
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "列:") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "列:" && i+1 < len(fields) {
					if width, err := strconv.Atoi(fields[i+1]); err == nil {
						return width
					}
				}
			}
		}
	}

	return 120 // 默认宽度
}

// 缓存和批量处理相关结构定义

// QueryCache 查询缓存结构
type QueryCache struct {
	sync.RWMutex
	cache map[string]*CacheEntry
}

// CacheEntry 缓存条目
type CacheEntry struct {
	data      string
	timestamp time.Time
	ttl       time.Duration
}

// globalCache 全局查询缓存
var globalCache = &QueryCache{
	cache: make(map[string]*CacheEntry),
}

// getCacheKey 生成缓存键
func getCacheKey(target, logType string, eventID, hours, limit int) string {
	return fmt.Sprintf("%s:%s:%d:%d:%d", target, logType, eventID, hours, limit)
}

// getFromCache 从缓存获取数据
func getFromCache(key string) (string, bool) {
	globalCache.RLock()
	defer globalCache.RUnlock()

	if entry, exists := globalCache.cache[key]; exists {
		if time.Since(entry.timestamp) < entry.ttl {
			return entry.data, true
		}
		// 缓存过期，删除
		delete(globalCache.cache, key)
	}
	return "", false
}

// setToCache 设置缓存数据
func setToCache(key, data string, ttl time.Duration) {
	globalCache.Lock()
	defer globalCache.Unlock()

	globalCache.cache[key] = &CacheEntry{
		data:      data,
		timestamp: time.Now(),
		ttl:       ttl,
	}
}

// clearExpiredCache 清理过期缓存
func clearExpiredCache() {
	globalCache.Lock()
	defer globalCache.Unlock()

	now := time.Now()
	for key, entry := range globalCache.cache {
		if now.Sub(entry.timestamp) > entry.ttl {
			delete(globalCache.cache, key)
		}
	}
}

// executeRemoteQuery 执行远程查询（重构自viewRemoteLog的核心逻辑）
func executeRemoteQuery(target string, port int, username, password, domain, logType string, eventID, hours, limit int, verbose bool) (string, error) {
	// 验证参数
	if err := validateParameters(logType, hours, limit); err != nil {
		return "", err
	}

	// 计算时间范围
	startTime := time.Now().Add(-time.Duration(hours) * time.Hour)
	startTimeStr := startTime.Format("20060102150405.000000-000")

	// 构建WMI查询语句
	query := fmt.Sprintf("SELECT * FROM Win32_NTLogEvent WHERE LogFile='%s'", logType)
	if hours > 0 && hours < 8760 { // 只有当hours明确指定且不是默认值时才添加时间范围
		query += fmt.Sprintf(" AND TimeGenerated >= '%s'", startTimeStr)
	}
	if eventID > 0 {
		query += fmt.Sprintf(" AND EventCode=%d", eventID)
	}
	// 移除EventCode限制条件，因为它在WMI查询中可能导致语法错误
	// 数量限制将在结果处理阶段实现

	// 创建WMI配置
	config := &wmi.WMIConfig{
		Target:      target,
		Port:        port,
		Username:    username,
		Password:    password,
		Domain:      domain,
		Query:       query,
		Timeout:     30,
		Verbose:     verbose,
		VeryVerbose: false,
	}

	// 创建WMI客户端
	client, err := wmi.NewWMIClient(config)
	if err != nil {
		return "", fmt.Errorf("客户端创建失败: %v", err)
	}

	// 执行WMI查询（带重试机制）
	maxRetries := 2
	var result *wmi.WMIResult

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			utils.WarningPrint("第 %d 次重试查询主机 %s", attempt, target)
			time.Sleep(time.Duration(attempt) * time.Second) // 指数退避
		}

		result, err = client.ExecuteQuery()

		if err == nil && result != nil && result.Success {
			break // 查询成功，退出重试循环
		}

		// 检查是否为可重试的错误类型
		if attempt < maxRetries && isRetryableError(err, result) {
			continue
		}

		// 最后一次尝试或不可重试的错误
		if attempt == maxRetries {
			// 尝试备用查询方法
			result = tryAlternativeQuery(config, logType, startTimeStr, eventID)
			if result != nil && result.Success {
				break
			}
		}
	}

	// 处理查询结果
	if err != nil {
		// 优先使用result中的详细错误信息
		if result != nil && result.Error != "" {
			return "", classifyAndFormatError(target, fmt.Errorf(result.Error), result)
		}
		// 如果result.Error为空，但result.Output包含错误信息，使用result.Output
		if result != nil && result.Output != "" {
			return "", classifyAndFormatError(target, fmt.Errorf(result.Output), result)
		}
		// 最后使用err参数
		return "", classifyAndFormatError(target, err, result)
	}

	if result == nil {
		return "", fmt.Errorf("查询返回空结果")
	}

	if !result.Success {
		// 检查是否为"无匹配记录"的情况
		if strings.Contains(strings.ToLower(result.Error), "no instances") ||
			strings.Contains(strings.ToLower(result.Error), "没有找到") ||
			strings.Contains(strings.ToLower(result.Error), "查询成功，但未找到匹配的日志记录") {
			return "查询成功，但未找到匹配的日志记录\n", nil
		}

		// 检查是否为非致命警告（查询成功但有警告信息）
		if result.Output != "" && len(result.Output) > 10 {
			// 如果输出包含有效数据，即使有错误信息也认为是成功查询
			// 但需要过滤掉真正的错误情况
			if !strings.Contains(strings.ToLower(result.Error), "access denied") &&
				!strings.Contains(strings.ToLower(result.Error), "拒绝访问") &&
				!strings.Contains(strings.ToLower(result.Error), "rpc server") &&
				!strings.Contains(strings.ToLower(result.Error), "rpc服务器") &&
				!strings.Contains(strings.ToLower(result.Error), "connection") &&
				!strings.Contains(strings.ToLower(result.Error), "连接") &&
				!strings.Contains(strings.ToLower(result.Error), "timeout") &&
				!strings.Contains(strings.ToLower(result.Error), "超时") {
				// 非致命警告，查询成功
				utils.InfoPrint("[警告] 查询成功但包含警告信息: %s", result.Error)
				return processQueryResult(result.Output, limit, verbose), nil
			}
		}

		// 创建错误对象，优先使用result.Error中的详细信息
		var queryErr error
		if result.Error != "" {
			queryErr = fmt.Errorf(result.Error)
		} else {
			queryErr = fmt.Errorf("WMI查询失败")
		}
		return "", classifyAndFormatError(target, queryErr, result)
	}

	// 处理查询结果
	return processQueryResult(result.Output, limit, verbose), nil
}

// isRetryableError 判断是否为可重试的错误
func isRetryableError(err error, result *wmi.WMIResult) bool {
	if err != nil {
		errorStr := err.Error()
		// 网络相关错误可以重试
		if strings.Contains(errorStr, "timeout") ||
			strings.Contains(errorStr, "connection") ||
			strings.Contains(errorStr, "network") ||
			strings.Contains(errorStr, "temporarily") {
			return true
		}
	}

	if result != nil && result.Error != "" {
		errorStr := strings.ToLower(result.Error)
		// RPC服务器不可用等临时错误可以重试
		if strings.Contains(errorStr, "rpc server") ||
			strings.Contains(errorStr, "temporarily") ||
			strings.Contains(errorStr, "timeout") {
			return true
		}
	}

	return false
}

// classifyAndFormatError 分类并格式化错误信息
func classifyAndFormatError(target string, err error, result *wmi.WMIResult) error {
	var errorMsg string
	var detailedError string

	if err != nil {
		errorMsg = err.Error()
	} else if result != nil && result.Error != "" {
		errorMsg = result.Error
	} else {
		errorMsg = "未知错误"
	}

	// 获取详细的错误输出（如果有）
	if result != nil && result.Output != "" {
		detailedError = result.Output
	}

	// 合并错误信息用于分类
	combinedError := errorMsg + " " + detailedError
	combinedErrorLower := strings.ToLower(combinedError)

	// 分类错误类型
	var errorType string
	var suggestion string

	switch {
	case strings.Contains(combinedErrorLower, "access denied") ||
		strings.Contains(combinedErrorLower, "拒绝访问") ||
		strings.Contains(combinedErrorLower, "unauthorized") ||
		strings.Contains(combinedErrorLower, "unauthorizedaccessexception"):
		errorType = "权限错误"
		suggestion = "请检查用户名、密码和权限设置，确保有足够的权限访问目标主机的WMI服务"

	case strings.Contains(combinedErrorLower, "rpc server") ||
		strings.Contains(combinedErrorLower, "rpc服务器") ||
		strings.Contains(combinedErrorLower, "rpc 服务器"):
		errorType = "服务不可用"
		suggestion = "目标主机的RPC服务可能未启动或防火墙阻止了连接，请检查服务状态和防火墙设置"

	case strings.Contains(combinedErrorLower, "timeout") ||
		strings.Contains(combinedErrorLower, "超时"):
		errorType = "连接超时"
		suggestion = "网络连接较慢或目标主机响应延迟，可以尝试增加超时时间或检查网络状况"

	case strings.Contains(combinedErrorLower, "connection") ||
		strings.Contains(combinedErrorLower, "连接") ||
		strings.Contains(combinedErrorLower, "network"):
		errorType = "连接错误"
		suggestion = "无法连接到目标主机，请检查网络连通性、主机地址和端口设置"

	case strings.Contains(combinedErrorLower, "invalid") ||
		strings.Contains(combinedErrorLower, "无效") ||
		strings.Contains(combinedErrorLower, "not found"):
		errorType = "参数错误"
		suggestion = "查询参数可能无效，请检查日志类型、事件ID等参数设置"

	case strings.Contains(combinedErrorLower, "no instances") ||
		strings.Contains(combinedErrorLower, "没有找到"):
		errorType = "无匹配记录"
		suggestion = "查询成功但未找到匹配的日志记录，请检查时间范围和查询条件"

	default:
		errorType = "未知错误"
		suggestion = "请检查目标主机状态和网络连接"
	}

	// 构建详细的错误信息
	finalError := fmt.Sprintf("主机 %s 查询失败 [%s]: %s", target, errorType, errorMsg)
	if detailedError != "" {
		finalError += fmt.Sprintf("\n详细输出: %s", detailedError)
	}
	finalError += fmt.Sprintf("\n建议: %s", suggestion)

	return fmt.Errorf(finalError)
}

// addColorToLogOutput 为日志输出添加颜色
func addColorToLogOutput(output string) string {
	lines := strings.Split(output, "\n")
	coloredLines := make([]string, 0, len(lines))

	for _, line := range lines {
		if strings.Contains(line, "ERROR") || strings.Contains(line, "错误") {
			// 错误信息用红色
			coloredLines = append(coloredLines, fmt.Sprintf("\033[31m%s\033[0m", line))
		} else if strings.Contains(line, "WARNING") || strings.Contains(line, "警告") {
			// 警告信息用黄色
			coloredLines = append(coloredLines, fmt.Sprintf("\033[33m%s\033[0m", line))
		} else if strings.Contains(line, "SUCCESS") || strings.Contains(line, "成功") {
			// 成功信息用绿色
			coloredLines = append(coloredLines, fmt.Sprintf("\033[32m%s\033[0m", line))
		} else if strings.Contains(line, "INFO") || strings.Contains(line, "信息") {
			// 信息用蓝色
			coloredLines = append(coloredLines, fmt.Sprintf("\033[34m%s\033[0m", line))
		} else if strings.Contains(line, "EventCode") || strings.Contains(line, "事件ID") {
			// 事件ID用青色
			coloredLines = append(coloredLines, fmt.Sprintf("\033[36m%s\033[0m", line))
		} else if strings.Contains(line, "TimeGenerated") || strings.Contains(line, "时间") {
			// 时间信息用紫色
			coloredLines = append(coloredLines, fmt.Sprintf("\033[35m%s\033[0m", line))
		} else {
			// 其他信息保持原样
			coloredLines = append(coloredLines, line)
		}
	}

	return strings.Join(coloredLines, "\n")
}

func init() {
	// 为所有子命令添加通用参数
	commonFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringP("target", "t", "", "目标主机IP地址或主机名（不指定则查询本地系统）")
		cmd.Flags().IntP("port", "P", 135, "WMI服务端口 (默认: 135)")
		cmd.Flags().StringP("user", "u", "", "用户名（远程查询时需要）")
		cmd.Flags().StringP("password", "p", "", "密码（远程查询时需要）")
		cmd.Flags().StringP("domain", "d", "", "域名称 (可选，用于域环境认证)")
		cmd.Flags().IntP("event-id", "e", 0, "事件ID筛选 (0表示不筛选)")
		cmd.Flags().IntP("hours", "H", 24, "时间范围 (小时，默认: 24小时)")
		cmd.Flags().IntP("limit", "l", 100, "限制返回的日志数量 (默认: 100条)")
		cmd.Flags().BoolP("verbose", "v", false, "详细输出模式")
		cmd.Flags().IntP("page-size", "s", 0, "分页显示大小 (0表示不分页)")
		cmd.Flags().BoolP("color", "c", true, "启用彩色输出 (默认: 启用)")

		// 为每个参数添加详细的使用说明
		cmd.Flags().SetAnnotation("target", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("port", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("user", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("password", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("domain", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("event-id", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("hours", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("limit", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("verbose", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("page-size", cobra.BashCompOneRequiredFlag, []string{"false"})
		cmd.Flags().SetAnnotation("color", cobra.BashCompOneRequiredFlag, []string{"false"})

		// 添加参数使用示例
		cmd.SetUsageTemplate(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)

		// target不再是必填参数，允许本地查询
	}

	// 添加子命令
	winlogCmd.AddCommand(winlogSystemCmd)
	winlogCmd.AddCommand(winlogSecurityCmd)
	winlogCmd.AddCommand(winlogApplicationCmd)
	winlogCmd.AddCommand(winlogSetupCmd)
	winlogCmd.AddCommand(winlogForwardedEventsCmd)

	// 为子命令添加通用参数
	commonFlags(winlogSystemCmd)
	commonFlags(winlogSecurityCmd)
	commonFlags(winlogApplicationCmd)
	commonFlags(winlogSetupCmd)
	commonFlags(winlogForwardedEventsCmd)

	// 为每个子命令设置示例
	setCommandExamples()
}

// setCommandExamples 为每个子命令设置使用示例
func setCommandExamples() {
	// 系统日志示例
	winlogSystemCmd.Example = `  # 查看本地系统日志
  ./GYscan winlog system
  
  # 查看远程系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password
  
  # 查看特定事件ID的系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --event-id 7036
  
  # 查看最近12小时的系统日志
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --hours 12
  
  # 限制返回的日志数量
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --limit 100
  
  # 启用详细输出
  ./GYscan winlog system --target 192.168.1.100 --user admin --password password --verbose`

	// 安全日志示例
	winlogSecurityCmd.Example = `  # 查看安全日志
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password
  
  # 查看登录事件(4624成功登录)
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --event-id 4624
  
  # 查看失败登录尝试
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --event-id 4625
  
  # 查看最近7天的安全日志
  ./GYscan winlog security --target 192.168.1.100 --user admin --password password --hours 168`

	// 应用程序日志示例
	winlogApplicationCmd.Example = `  # 查看应用程序日志
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password
  
  # 按事件ID筛选
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password --event-id 1000
  
  # 查看最近24小时的应用程序日志
  ./GYscan winlog application --target 192.168.1.100 --user admin --password password --hours 24`

	// 安装日志示例
	winlogSetupCmd.Example = `  # 查看安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password
  
  # 查看特定事件ID的安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password --event-id 2001
  
  # 查看最近24小时的安装日志
  ./GYscan winlog setup --target 192.168.1.100 --user admin --password password --hours 24`

	// 转发事件日志示例
	winlogForwardedEventsCmd.Example = `  # 查看转发事件日志
  ./GYscan winlog forwardedevents --target 192.168.1.100 --user admin --password password
  
  # 查看特定事件ID的转发事件日志
  ./GYscan winlog forwardedevents --target 192.168.1.100 --user admin --password password --event-id 4624
  
  # 查看最近7天的转发事件日志
  ./GYscan winlog forwardedevents --target 192.168.1.100 --user admin --password password --hours 168`
}
