package logging

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// Logger 统一的日志接口
type Logger struct {
	config      *LogConfig
	manager     *LogManager
	moduleName  string
	logLevel    LogLevel
}

// LogLevel 日志级别类型
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	FATAL
)

// String 返回日志级别的字符串表示
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ParseLogLevel 从字符串解析日志级别
func ParseLogLevel(levelStr string) LogLevel {
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARNING", "WARN":
		return WARNING
	case "ERROR":
		return ERROR
	case "FATAL":
		return FATAL
	default:
		return INFO // 默认级别
	}
}

// NewLogger 创建新的日志器
func NewLogger(moduleName string, config *LogConfig) (*Logger, error) {
	// 检查模块是否启用日志
	if !config.IsModuleEnabled(moduleName) {
		return &Logger{
			config:     config,
			moduleName: moduleName,
			logLevel:   ParseLogLevel(config.LogLevel),
		}, nil
	}
	
	var manager *LogManager
	var err error
	
	// 如果启用文件日志，创建日志管理器
	if config.LogToFile {
		manager, err = NewLogManager(config)
		if err != nil {
			return nil, fmt.Errorf("创建日志管理器失败: %v", err)
		}
	}
	
	return &Logger{
		config:     config,
		manager:    manager,
		moduleName: moduleName,
		logLevel:   ParseLogLevel(config.LogLevel),
	}, nil
}

// Debug 记录调试级别日志
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.shouldLog(DEBUG) {
		l.log(DEBUG, format, args...)
	}
}

// Info 记录信息级别日志
func (l *Logger) Info(format string, args ...interface{}) {
	if l.shouldLog(INFO) {
		l.log(INFO, format, args...)
	}
}

// Warning 记录警告级别日志
func (l *Logger) Warning(format string, args ...interface{}) {
	if l.shouldLog(WARNING) {
		l.log(WARNING, format, args...)
	}
}

// Error 记录错误级别日志
func (l *Logger) Error(format string, args ...interface{}) {
	if l.shouldLog(ERROR) {
		l.log(ERROR, format, args...)
	}
}

// Fatal 记录致命错误级别日志并退出程序
func (l *Logger) Fatal(format string, args ...interface{}) {
	if l.shouldLog(FATAL) {
		l.log(FATAL, format, args...)
		os.Exit(1)
	}
}

// shouldLog 检查是否应该记录指定级别的日志
func (l *Logger) shouldLog(level LogLevel) bool {
	// 检查模块是否启用日志
	if !l.config.IsModuleEnabled(l.moduleName) {
		return false
	}
	
	// 检查日志级别
	return level >= l.logLevel
}

// log 实际记录日志的方法
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	formattedMessage := l.formatMessage(level, message)
	
	// 输出到控制台
	if l.config.LogToConsole {
		l.logToConsole(level, formattedMessage)
	}
	
	// 输出到文件
	if l.config.LogToFile && l.manager != nil {
		if err := l.manager.WriteLog(formattedMessage); err != nil {
			// 如果文件日志失败，输出到控制台
			log.Printf("日志写入文件失败: %v", err)
		}
	}
}

// formatMessage 格式化日志消息
func (l *Logger) formatMessage(level LogLevel, message string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelStr := level.String()
	
	// 简单的格式化，可以根据配置进行更复杂的格式化
	formatted := fmt.Sprintf("%s [%s] %s: %s", 
		timestamp, 
		levelStr, 
		l.moduleName, 
		message)
	
	return formatted
}

// logToConsole 输出到控制台
func (l *Logger) logToConsole(level LogLevel, message string) {
	switch level {
	case DEBUG, INFO:
		fmt.Println(message)
	case WARNING:
		fmt.Printf("\x1b[33m%s\x1b[0m\n", message) // 黄色
	case ERROR, FATAL:
		fmt.Printf("\x1b[31m%s\x1b[0m\n", message) // 红色
	}
}

// Close 关闭日志器
func (l *Logger) Close() error {
	if l.manager != nil {
		return l.manager.Close()
	}
	return nil
}

// GetStats 获取日志统计信息
func (l *Logger) GetStats() (map[string]interface{}, error) {
	if l.manager != nil {
		return l.manager.GetLogStats()
	}
	return nil, nil
}

// SetLogLevel 设置日志级别
func (l *Logger) SetLogLevel(level LogLevel) {
	l.logLevel = level
}

// GetLogLevel 获取当前日志级别
func (l *Logger) GetLogLevel() LogLevel {
	return l.logLevel
}

// IsEnabled 检查日志器是否启用
func (l *Logger) IsEnabled() bool {
	return l.config.IsModuleEnabled(l.moduleName)
}

// GlobalLogger 全局日志器管理
type GlobalLogger struct {
	loggers map[string]*Logger
	config  *LogConfig
}

// NewGlobalLogger 创建全局日志器
func NewGlobalLogger(config *LogConfig) *GlobalLogger {
	return &GlobalLogger{
		loggers: make(map[string]*Logger),
		config:  config,
	}
}

// GetLogger 获取指定模块的日志器
func (g *GlobalLogger) GetLogger(moduleName string) *Logger {
	if logger, exists := g.loggers[moduleName]; exists {
		return logger
	}
	
	// 创建新的日志器
	logger, err := NewLogger(moduleName, g.config)
	if err != nil {
		// 如果创建失败，返回一个禁用的日志器
		return &Logger{
			config:     g.config,
			moduleName: moduleName,
			logLevel:   ParseLogLevel(g.config.LogLevel),
		}
	}
	
	g.loggers[moduleName] = logger
	return logger
}

// CloseAll 关闭所有日志器
func (g *GlobalLogger) CloseAll() {
	for _, logger := range g.loggers {
		logger.Close()
	}
	g.loggers = make(map[string]*Logger)
}