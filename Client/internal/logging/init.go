package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// GlobalLoggerInstance 全局日志器实例
var GlobalLoggerInstance *GlobalLogger

// InitLoggingSystem 初始化日志系统
func InitLoggingSystem() error {
	// 创建配置加载器
	loader := NewConfigLoader()

	// 添加项目特定的配置路径
	projectConfigPath := filepath.Join(".", "config", "logging.json")
	loader.AddConfigPath(projectConfigPath)

	// 加载配置
	config, err := loader.LoadConfig()
	if err != nil {
		return fmt.Errorf("加载日志配置失败: %v", err)
	}

	// 创建全局日志器
	GlobalLoggerInstance = NewGlobalLogger(config)

	// 记录初始化日志
	logger := GlobalLoggerInstance.GetLogger("System")
	logger.Info("日志系统初始化完成")
	logger.Info("日志级别: %s", config.LogLevel)
	logger.Info("日志目录: %s", config.LogDir)
	logger.Info("文件日志: %v", config.LogToFile)
	logger.Info("控制台日志: %v", config.LogToConsole)

	return nil
}

// GetLogger 获取指定模块的日志器
func GetLogger(moduleName string) *Logger {
	if GlobalLoggerInstance == nil {
		// 如果全局日志器未初始化，返回一个默认的日志器
		defaultConfig := DefaultConfig()
		logger, _ := NewLogger(moduleName, defaultConfig)
		return logger
	}

	return GlobalLoggerInstance.GetLogger(moduleName)
}

// CloseLoggingSystem 关闭日志系统
func CloseLoggingSystem() {
	if GlobalLoggerInstance != nil {
		logger := GlobalLoggerInstance.GetLogger("System")
		logger.Info("正在关闭日志系统...")

		GlobalLoggerInstance.CloseAll()

		// 记录关闭完成
		fmt.Println("日志系统已关闭")
	}
}

// LogSystemInfo 记录系统信息
func LogSystemInfo() {
	if GlobalLoggerInstance == nil {
		return
	}

	logger := GlobalLoggerInstance.GetLogger("System")

	// 记录操作系统信息
	logger.Info("操作系统: %s %s", runtime.GOOS, runtime.GOARCH)

	// 记录工作目录
	wd, err := os.Getwd()
	if err == nil {
		logger.Info("工作目录: %s", wd)
	}

	// 记录环境信息
	logger.Info("临时目录: %s", os.TempDir())

	// 记录内存信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logger.Info("内存使用: 分配=%vMB, 系统=%vMB",
		bToMb(m.Alloc), bToMb(m.Sys))
}

// bToMb 字节转换为MB
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// LogModuleStart 记录模块启动
func LogModuleStart(moduleName string) {
	logger := GetLogger(moduleName)
	logger.Info("模块 %s 启动", moduleName)
}

// LogModuleStop 记录模块停止
func LogModuleStop(moduleName string) {
	logger := GetLogger(moduleName)
	logger.Info("模块 %s 停止", moduleName)
}

// LogErrorWithContext 记录带上下文的错误
func LogErrorWithContext(moduleName string, err error, context string) {
	logger := GetLogger(moduleName)
	logger.Error("%s: %v", context, err)
}

// LogWarningWithContext 记录带上下文的警告
func LogWarningWithContext(moduleName string, context string) {
	logger := GetLogger(moduleName)
	logger.Warning("%s", context)
}

// LogDebugData 记录调试数据
func LogDebugData(moduleName string, dataName string, data interface{}) {
	logger := GetLogger(moduleName)
	logger.Debug("%s: %+v", dataName, data)
}

// LogPerformance 记录性能信息
func LogPerformance(moduleName string, operation string, duration time.Duration) {
	logger := GetLogger(moduleName)
	logger.Info("操作 %s 完成，耗时: %v", operation, duration)
}

// GetLogStats 获取日志统计信息
func GetLogStats() (map[string]interface{}, error) {
	if GlobalLoggerInstance == nil {
		return nil, fmt.Errorf("日志系统未初始化")
	}

	// 获取系统模块的统计信息
	systemLogger := GlobalLoggerInstance.GetLogger("System")
	return systemLogger.GetStats()
}

// SetLogLevel 设置全局日志级别
func SetLogLevel(level string) error {
	if GlobalLoggerInstance == nil {
		return fmt.Errorf("日志系统未初始化")
	}

	// 更新所有日志器的级别
	for _, logger := range GlobalLoggerInstance.loggers {
		logger.SetLogLevel(ParseLogLevel(level))
	}

	logger := GlobalLoggerInstance.GetLogger("System")
	logger.Info("全局日志级别已设置为: %s", level)

	return nil
}

// EnableModuleLogging 启用指定模块的日志
func EnableModuleLogging(moduleName string) {
	if GlobalLoggerInstance == nil {
		return
	}

	GlobalLoggerInstance.config.SetModuleEnabled(moduleName, true)

	logger := GlobalLoggerInstance.GetLogger("System")
	logger.Info("模块 %s 的日志已启用", moduleName)
}

// DisableModuleLogging 禁用指定模块的日志
func DisableModuleLogging(moduleName string) {
	if GlobalLoggerInstance == nil {
		return
	}

	GlobalLoggerInstance.config.SetModuleEnabled(moduleName, false)

	logger := GlobalLoggerInstance.GetLogger("System")
	logger.Info("模块 %s 的日志已禁用", moduleName)
}

// IsLoggingEnabled 检查日志是否启用
func IsLoggingEnabled() bool {
	return GlobalLoggerInstance != nil
}

// GetLogConfig 获取当前日志配置
func GetLogConfig() *LogConfig {
	if GlobalLoggerInstance == nil {
		return DefaultConfig()
	}

	return GlobalLoggerInstance.config
}
