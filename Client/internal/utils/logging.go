package utils

import (
	"fmt"

	"github.com/fatih/color"
)

// LogSuccess 记录成功日志
func LogSuccess(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	SuccessPrint(msg)
}

// LogError 记录错误日志
func LogError(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	ErrorPrint(msg)
}

// LogWarning 记录警告日志
func LogWarning(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	WarningPrint(msg)
}

// LogInfo 记录信息日志
func LogInfo(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	InfoPrint(msg)
}

// LogProgress 记录进度日志
func LogProgress(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	ProgressPrint(msg)
}

// LogDebug 记录调试日志
func LogDebug(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	DebugPrint(msg)
}

// DebugPrint 打印调试信息（灰色）
func DebugPrint(format string, a ...interface{}) {
	color.New(color.FgHiBlack).Printf(format+"\n", a...)
}

// LogBanner 记录横幅日志
func LogBanner(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	BannerPrint(msg)
}

// LogTitle 记录标题日志
func LogTitle(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	TitlePrint(msg)
}

// LogModuleStart 记录模块启动日志
func LogModuleStart(moduleName string) {
	InfoPrint("模块启动: %s", moduleName)
}

// LogModuleStop 记录模块停止日志
func LogModuleStop(moduleName string) {
	InfoPrint("模块停止: %s", moduleName)
}

// LogCommandExecution 记录命令执行日志
func LogCommandExecution(command string, args []string) {
	DebugPrint("执行命令: %s %v", command, args)
}

// LogNetworkOperation 记录网络操作日志
func LogNetworkOperation(operation, target string) {
	DebugPrint("网络操作: %s -> %s", operation, target)
}

// LogSecurityEvent 记录安全事件日志
func LogSecurityEvent(eventType, description string) {
	WarningPrint("安全事件: %s - %s", eventType, description)
}

// LogPerformanceInfo 记录性能信息日志
func LogPerformanceInfo(operation string, durationMs int64) {
	DebugPrint("性能信息: %s 耗时 %dms", operation, durationMs)
}
