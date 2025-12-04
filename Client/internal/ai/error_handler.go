package ai

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"
)

// ErrorHandler 错误处理器
type ErrorHandler struct {
	LogFile      string
	LogLevel     string
	MaxLogSize   int64
	BackupCount  int
	Mutex        sync.RWMutex
	ErrorStats   *ErrorStatistics
	AlertManager *AlertManager
}

// ErrorStatistics 错误统计
type ErrorStatistics struct {
	TotalErrors   int64
	ErrorByType   map[string]int64
	ErrorBySource map[string]int64
	RecentErrors  []*ErrorRecord
	Mutex         sync.RWMutex
}

// AlertManager 告警管理器
type AlertManager struct {
	AlertRules    []*AlertRule
	AlertChannels []AlertChannel
	Mutex         sync.RWMutex
}

// ErrorRecord 错误记录
type ErrorRecord struct {
	ID         string
	Timestamp  time.Time
	Level      string
	Source     string
	ErrorType  string
	Message    string
	Stack      string
	Context    map[string]interface{}
	Resolved   bool
	Resolution string
}

// AlertRule 告警规则
type AlertRule struct {
	ID        string
	Name      string
	Condition string
	Threshold int
	Window    time.Duration
	Severity  string
	Enabled   bool
}

// AlertChannel 告警通道接口
type AlertChannel interface {
	SendAlert(alert *Alert) error
	Name() string
}

// Alert 告警
type Alert struct {
	ID        string
	Timestamp time.Time
	RuleID    string
	Severity  string
	Message   string
	Details   map[string]interface{}
}

// LogLevels 日志级别常量
const (
	LogLevelDebug   = "debug"
	LogLevelInfo    = "info"
	LogLevelWarning = "warning"
	LogLevelError   = "error"
	LogLevelFatal   = "fatal"
)

// NewErrorHandler 创建新的错误处理器
func NewErrorHandler(logFile string, logLevel string) *ErrorHandler {
	if logFile == "" {
		logFile = getDefaultLogPath()
	}

	handler := &ErrorHandler{
		LogFile:      logFile,
		LogLevel:     strings.ToLower(logLevel),
		MaxLogSize:   10 * 1024 * 1024, // 10MB
		BackupCount:  5,
		ErrorStats:   NewErrorStatistics(),
		AlertManager: NewAlertManager(),
	}

	// 确保日志目录存在
	dir := filepath.Dir(logFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("创建日志目录失败: %v", err)
	}

	// 初始化默认告警规则
	handler.initializeDefaultAlertRules()

	return handler
}

// NewErrorStatistics 创建错误统计
func NewErrorStatistics() *ErrorStatistics {
	return &ErrorStatistics{
		TotalErrors:   0,
		ErrorByType:   make(map[string]int64),
		ErrorBySource: make(map[string]int64),
		RecentErrors:  make([]*ErrorRecord, 0),
	}
}

// NewAlertManager 创建告警管理器
func NewAlertManager() *AlertManager {
	return &AlertManager{
		AlertRules:    make([]*AlertRule, 0),
		AlertChannels: make([]AlertChannel, 0),
	}
}

// getDefaultLogPath 获取默认日志路径
func getDefaultLogPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	logDir := filepath.Join(homeDir, "GYscan", "logs")
	logFile := filepath.Join(logDir, "ai_system.log")

	return logFile
}

// initializeDefaultAlertRules 初始化默认告警规则
func (eh *ErrorHandler) initializeDefaultAlertRules() {
	// 连接错误告警规则
	eh.AlertManager.AlertRules = append(eh.AlertManager.AlertRules, &AlertRule{
		ID:        "connection_errors",
		Name:      "连接错误告警",
		Condition: "connection_error",
		Threshold: 5,
		Window:    5 * time.Minute,
		Severity:  "high",
		Enabled:   true,
	})

	// API错误告警规则
	eh.AlertManager.AlertRules = append(eh.AlertManager.AlertRules, &AlertRule{
		ID:        "api_errors",
		Name:      "API错误告警",
		Condition: "api_error",
		Threshold: 10,
		Window:    10 * time.Minute,
		Severity:  "medium",
		Enabled:   true,
	})

	// 工具执行错误告警规则
	eh.AlertManager.AlertRules = append(eh.AlertManager.AlertRules, &AlertRule{
		ID:        "tool_execution_errors",
		Name:      "工具执行错误告警",
		Condition: "tool_execution_error",
		Threshold: 3,
		Window:    3 * time.Minute,
		Severity:  "medium",
		Enabled:   true,
	})

	// 认证错误告警规则
	eh.AlertManager.AlertRules = append(eh.AlertManager.AlertRules, &AlertRule{
		ID:        "authentication_errors",
		Name:      "认证错误告警",
		Condition: "authentication_error",
		Threshold: 2,
		Window:    2 * time.Minute,
		Severity:  "critical",
		Enabled:   true,
	})
}

// Log 记录日志
func (eh *ErrorHandler) Log(level, source, message string, context map[string]interface{}) {
	// 检查日志级别
	if !eh.shouldLog(level) {
		return
	}

	// 创建错误记录
	errorRecord := &ErrorRecord{
		ID:        generateErrorID(),
		Timestamp: time.Now(),
		Level:     level,
		Source:    source,
		ErrorType: eh.classifyError(message),
		Message:   message,
		Stack:     eh.getStackTrace(),
		Context:   context,
		Resolved:  false,
	}

	// 写入日志文件
	eh.writeToLogFile(errorRecord)

	// 更新统计信息
	eh.updateErrorStatistics(errorRecord)

	// 检查告警条件
	eh.checkAlerts(errorRecord)

	// 控制台输出
	eh.consoleOutput(errorRecord)
}

// shouldLog 检查是否应该记录日志
func (eh *ErrorHandler) shouldLog(level string) bool {
	levelPriority := map[string]int{
		LogLevelDebug:   1,
		LogLevelInfo:    2,
		LogLevelWarning: 3,
		LogLevelError:   4,
		LogLevelFatal:   5,
	}

	currentPriority, currentExists := levelPriority[eh.LogLevel]
	messagePriority, messageExists := levelPriority[level]

	if !currentExists || !messageExists {
		return true // 默认记录
	}

	return messagePriority >= currentPriority
}

// classifyError 分类错误类型
func (eh *ErrorHandler) classifyError(message string) string {
	messageLower := strings.ToLower(message)

	switch {
	case strings.Contains(messageLower, "connection") && strings.Contains(messageLower, "reset"):
		return "connection_reset"
	case strings.Contains(messageLower, "connection") && strings.Contains(messageLower, "timeout"):
		return "connection_timeout"
	case strings.Contains(messageLower, "connection") && strings.Contains(messageLower, "refused"):
		return "connection_refused"
	case strings.Contains(messageLower, "401") || strings.Contains(messageLower, "unauthorized"):
		return "authentication_error"
	case strings.Contains(messageLower, "403") || strings.Contains(messageLower, "forbidden"):
		return "authorization_error"
	case strings.Contains(messageLower, "404") || strings.Contains(messageLower, "not found"):
		return "resource_not_found"
	case strings.Contains(messageLower, "429") || strings.Contains(messageLower, "rate limit"):
		return "rate_limit_exceeded"
	case strings.Contains(messageLower, "500") || strings.Contains(messageLower, "internal server"):
		return "server_error"
	case strings.Contains(messageLower, "tool") && strings.Contains(messageLower, "execution"):
		return "tool_execution_error"
	case strings.Contains(messageLower, "ai") && strings.Contains(messageLower, "response"):
		return "ai_response_error"
	default:
		return "unknown_error"
	}
}

// getStackTrace 获取堆栈跟踪
func (eh *ErrorHandler) getStackTrace() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// writeToLogFile 写入日志文件
func (eh *ErrorHandler) writeToLogFile(record *ErrorRecord) {
	eh.Mutex.Lock()
	defer eh.Mutex.Unlock()

	// 检查日志文件大小，必要时进行轮转
	eh.rotateLogIfNeeded()

	// 打开日志文件
	file, err := os.OpenFile(eh.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("打开日志文件失败: %v", err)
		return
	}
	defer file.Close()

	// 格式化日志记录
	logEntry := eh.formatLogEntry(record)

	// 写入日志
	if _, err := file.WriteString(logEntry + "\n"); err != nil {
		log.Printf("写入日志文件失败: %v", err)
	}
}

// rotateLogIfNeeded 检查并轮转日志文件
func (eh *ErrorHandler) rotateLogIfNeeded() {
	info, err := os.Stat(eh.LogFile)
	if err != nil {
		return
	}

	if info.Size() < eh.MaxLogSize {
		return
	}

	// 执行日志轮转
	for i := eh.BackupCount - 1; i >= 0; i-- {
		oldFile := fmt.Sprintf("%s.%d", eh.LogFile, i)
		newFile := fmt.Sprintf("%s.%d", eh.LogFile, i+1)

		if i == eh.BackupCount-1 {
			// 删除最旧的备份
			os.Remove(newFile)
		} else {
			// 重命名备份文件
			os.Rename(oldFile, newFile)
		}
	}

	// 重命名当前日志文件
	backupFile := fmt.Sprintf("%s.0", eh.LogFile)
	os.Rename(eh.LogFile, backupFile)
}

// formatLogEntry 格式化日志条目
func (eh *ErrorHandler) formatLogEntry(record *ErrorRecord) string {
	logData := map[string]interface{}{
		"timestamp": record.Timestamp.Format(time.RFC3339),
		"level":     record.Level,
		"source":    record.Source,
		"type":      record.ErrorType,
		"message":   record.Message,
		"context":   record.Context,
	}

	if record.Level == LogLevelError || record.Level == LogLevelFatal {
		logData["stack"] = record.Stack
	}

	jsonData, err := json.Marshal(logData)
	if err != nil {
		return fmt.Sprintf(`{"timestamp":"%s","level":"error","message":"日志格式化失败: %v"}`,
			time.Now().Format(time.RFC3339), err)
	}

	return string(jsonData)
}

// updateErrorStatistics 更新错误统计
func (eh *ErrorHandler) updateErrorStatistics(record *ErrorRecord) {
	eh.ErrorStats.Mutex.Lock()
	defer eh.ErrorStats.Mutex.Unlock()

	// 更新总数
	eh.ErrorStats.TotalErrors++

	// 按类型统计
	eh.ErrorStats.ErrorByType[record.ErrorType]++

	// 按来源统计
	eh.ErrorStats.ErrorBySource[record.Source]++

	// 更新最近错误记录
	if len(eh.ErrorStats.RecentErrors) >= 100 {
		eh.ErrorStats.RecentErrors = eh.ErrorStats.RecentErrors[1:]
	}
	eh.ErrorStats.RecentErrors = append(eh.ErrorStats.RecentErrors, record)
}

// checkAlerts 检查告警条件
func (eh *ErrorHandler) checkAlerts(record *ErrorRecord) {
	eh.AlertManager.Mutex.RLock()
	defer eh.AlertManager.Mutex.RUnlock()

	for _, rule := range eh.AlertManager.AlertRules {
		if !rule.Enabled {
			continue
		}

		if strings.Contains(record.ErrorType, rule.Condition) ||
			strings.Contains(record.Message, rule.Condition) {

			// 检查阈值条件
			if eh.checkAlertThreshold(rule, record.ErrorType) {
				eh.triggerAlert(rule, record)
			}
		}
	}
}

// checkAlertThreshold 检查告警阈值
func (eh *ErrorHandler) checkAlertThreshold(rule *AlertRule, errorType string) bool {
	eh.ErrorStats.Mutex.RLock()
	defer eh.ErrorStats.Mutex.RUnlock()

	// 计算时间窗口内的错误数量
	windowStart := time.Now().Add(-rule.Window)
	count := int64(0)

	for _, record := range eh.ErrorStats.RecentErrors {
		if record.Timestamp.After(windowStart) &&
			(strings.Contains(record.ErrorType, rule.Condition) ||
				strings.Contains(record.Message, rule.Condition)) {
			count++
		}
	}

	return count >= int64(rule.Threshold)
}

// triggerAlert 触发告警
func (eh *ErrorHandler) triggerAlert(rule *AlertRule, record *ErrorRecord) {
	alert := &Alert{
		ID:        generateAlertID(),
		Timestamp: time.Now(),
		RuleID:    rule.ID,
		Severity:  rule.Severity,
		Message:   fmt.Sprintf("告警: %s - %s", rule.Name, record.Message),
		Details: map[string]interface{}{
			"error_type": record.ErrorType,
			"source":     record.Source,
			"context":    record.Context,
		},
	}

	// 发送告警到所有通道
	eh.AlertManager.Mutex.RLock()
	defer eh.AlertManager.Mutex.RUnlock()

	for _, channel := range eh.AlertManager.AlertChannels {
		if err := channel.SendAlert(alert); err != nil {
			log.Printf("发送告警失败 (%s): %v", channel.Name(), err)
		}
	}

	utils.WarningPrint("告警触发: %s", alert.Message)
}

// consoleOutput 控制台输出
func (eh *ErrorHandler) consoleOutput(record *ErrorRecord) {
	timestamp := record.Timestamp.Format("2006-01-02 15:04:05")
	levelColor := eh.getLevelColor(record.Level)

	message := fmt.Sprintf("[%s] %s %s: %s", timestamp, levelColor, record.Level, record.Message)

	switch record.Level {
	case LogLevelDebug:
		utils.DebugPrint(message)
	case LogLevelInfo:
		utils.InfoPrint(message)
	case LogLevelWarning:
		utils.WarningPrint(message)
	case LogLevelError:
		utils.ErrorPrint(message)
	case LogLevelFatal:
		utils.ErrorPrint(message)
	}
}

// getLevelColor 获取日志级别颜色
func (eh *ErrorHandler) getLevelColor(level string) string {
	switch level {
	case LogLevelDebug:
		return "\033[36mDEBUG\033[0m" // 青色
	case LogLevelInfo:
		return "\033[32mINFO\033[0m" // 绿色
	case LogLevelWarning:
		return "\033[33mWARNING\033[0m" // 黄色
	case LogLevelError:
		return "\033[31mERROR\033[0m" // 红色
	case LogLevelFatal:
		return "\033[35mFATAL\033[0m" // 紫色
	default:
		return "\033[37mUNKNOWN\033[0m" // 白色
	}
}

// GetErrorStats 获取错误统计信息
func (eh *ErrorHandler) GetErrorStats() map[string]interface{} {
	eh.ErrorStats.Mutex.RLock()
	defer eh.ErrorStats.Mutex.RUnlock()

	stats := map[string]interface{}{
		"total_errors":        eh.ErrorStats.TotalErrors,
		"error_by_type":       eh.ErrorStats.ErrorByType,
		"error_by_source":     eh.ErrorStats.ErrorBySource,
		"recent_errors_count": len(eh.ErrorStats.RecentErrors),
	}

	return stats
}

// AddAlertChannel 添加告警通道
func (eh *ErrorHandler) AddAlertChannel(channel AlertChannel) {
	eh.AlertManager.Mutex.Lock()
	defer eh.AlertManager.Mutex.Unlock()

	eh.AlertManager.AlertChannels = append(eh.AlertManager.AlertChannels, channel)
}

// SetLogLevel 设置日志级别
func (eh *ErrorHandler) SetLogLevel(level string) {
	eh.Mutex.Lock()
	defer eh.Mutex.Unlock()

	eh.LogLevel = strings.ToLower(level)
}

// SetMaxLogSize 设置最大日志大小
func (eh *ErrorHandler) SetMaxLogSize(size int64) {
	eh.Mutex.Lock()
	defer eh.Mutex.Unlock()

	eh.MaxLogSize = size
}

// generateErrorID 生成错误ID
func generateErrorID() string {
	return fmt.Sprintf("err_%d_%s", time.Now().Unix(), utils.GenerateRandomString(8))
}

// generateAlertID 生成告警ID
func generateAlertID() string {
	return fmt.Sprintf("alert_%d_%s", time.Now().Unix(), utils.GenerateRandomString(8))
}

// ConsoleAlertChannel 控制台告警通道
type ConsoleAlertChannel struct{}

// SendAlert 发送控制台告警
func (c *ConsoleAlertChannel) SendAlert(alert *Alert) error {
	utils.WarningPrint("🚨 告警: %s (严重性: %s)", alert.Message, alert.Severity)
	return nil
}

// Name 返回通道名称
func (c *ConsoleAlertChannel) Name() string {
	return "console"
}

// FileAlertChannel 文件告警通道
type FileAlertChannel struct {
	FilePath string
}

// SendAlert 发送文件告警
func (f *FileAlertChannel) SendAlert(alert *Alert) error {
	file, err := os.OpenFile(f.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	alertData := map[string]interface{}{
		"timestamp": alert.Timestamp.Format(time.RFC3339),
		"rule_id":   alert.RuleID,
		"severity":  alert.Severity,
		"message":   alert.Message,
		"details":   alert.Details,
	}

	jsonData, err := json.Marshal(alertData)
	if err != nil {
		return err
	}

	_, err = file.WriteString(string(jsonData) + "\n")
	return err
}

// Name 返回通道名称
func (f *FileAlertChannel) Name() string {
	return "file"
}
