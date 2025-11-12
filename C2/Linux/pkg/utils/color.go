package utils

import (
	"fmt"
)

// Color 颜色工具类
type Color struct{}

// NewColor 创建颜色工具实例
func NewColor() *Color {
	return &Color{}
}

// ANSI颜色代码常量
const (
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Red        = "\033[31m"
	Green      = "\033[32m"
	Yellow     = "\033[33m"
	Blue       = "\033[34m"
	Magenta    = "\033[35m"
	Cyan       = "\033[36m"
	White      = "\033[37m"
	BrightRed  = "\033[91m"
	BrightGreen = "\033[92m"
	BrightYellow = "\033[93m"
	BrightBlue = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan = "\033[96m"
	BrightWhite = "\033[97m"
)

// 颜色格式化方法

// BoldText 粗体文本
func (c *Color) BoldText(text string) string {
	return fmt.Sprintf("%s%s%s", Bold, text, Reset)
}

// Title 标题格式
func (c *Color) Title(text string) string {
	return fmt.Sprintf("%s%s%s%s", Bold, BrightCyan, text, Reset)
}

// Success 成功信息
func (c *Color) Success(text string) string {
	return fmt.Sprintf("%s%s%s", BrightGreen, text, Reset)
}

// Error 错误信息
func (c *Color) Error(text string) string {
	return fmt.Sprintf("%s%s%s", BrightRed, text, Reset)
}

// Warning 警告信息
func (c *Color) Warning(text string) string {
	return fmt.Sprintf("%s%s%s", BrightYellow, text, Reset)
}

// Info 信息文本
func (c *Color) Info(text string) string {
	return fmt.Sprintf("%s%s%s", BrightBlue, text, Reset)
}

// Highlight 高亮文本
func (c *Color) Highlight(text string) string {
	return fmt.Sprintf("%s%s%s", BrightWhite, text, Reset)
}

// 严重级别颜色

// Critical 严重级别
func (c *Color) Critical(text string) string {
	return fmt.Sprintf("%s%s%s", BrightRed, text, Reset)
}

// High 高危级别
func (c *Color) High(text string) string {
	return fmt.Sprintf("%s%s%s", BrightRed, text, Reset)
}

// Medium 中危级别
func (c *Color) Medium(text string) string {
	return fmt.Sprintf("%s%s%s", BrightYellow, text, Reset)
}

// Low 低危级别
func (c *Color) Low(text string) string {
	return fmt.Sprintf("%s%s%s", BrightGreen, text, Reset)
}

// InfoLevel 信息级别
func (c *Color) InfoLevel(text string) string {
	return fmt.Sprintf("%s%s%s", BrightBlue, text, Reset)
}

// 测试状态颜色

// Passed 通过状态
func (c *Color) Passed(text string) string {
	return fmt.Sprintf("%s%s%s", BrightGreen, text, Reset)
}

// Failed 失败状态
func (c *Color) Failed(text string) string {
	return fmt.Sprintf("%s%s%s", BrightRed, text, Reset)
}

// WarningStatus 警告状态
func (c *Color) WarningStatus(text string) string {
	return fmt.Sprintf("%s%s%s", BrightYellow, text, Reset)
}

// Skipped 跳过状态
func (c *Color) Skipped(text string) string {
	return fmt.Sprintf("%s%s%s", BrightBlue, text, Reset)
}

// 格式化输出方法

// PrintTitle 打印标题
func (c *Color) PrintTitle(title string) {
	fmt.Printf("%s\n", c.Title(title))
}

// PrintSuccess 打印成功信息
func (c *Color) PrintSuccess(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Printf("%s\n", c.Success(text))
}

// PrintError 打印错误信息
func (c *Color) PrintError(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Printf("%s\n", c.Error(text))
}

// PrintWarning 打印警告信息
func (c *Color) PrintWarning(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Printf("%s\n", c.Warning(text))
}

// PrintInfo 打印信息
func (c *Color) PrintInfo(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Printf("%s\n", c.Info(text))
}

// PrintHighlight 打印高亮文本
func (c *Color) PrintHighlight(format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Printf("%s\n", c.Highlight(text))
}

// 组合格式化方法

// FormatTestResult 格式化测试结果
func (c *Color) FormatTestResult(testID, description, status, severity string) string {
	statusColor := c.Passed(status)
	switch status {
	case "失败":
		statusColor = c.Failed(status)
	case "警告":
		statusColor = c.WarningStatus(status)
	case "跳过":
		statusColor = c.Skipped(status)
	}
	
	severityColor := c.InfoLevel(severity)
	switch severity {
	case "严重":
		severityColor = c.Critical(severity)
	case "高危":
		severityColor = c.High(severity)
	case "中危":
		severityColor = c.Medium(severity)
	case "低危":
		severityColor = c.Low(severity)
	}
	
	return fmt.Sprintf("%s - %s [%s] (严重级别: %s)", 
		c.Highlight(testID), 
		c.Highlight(description), 
		statusColor, 
		severityColor)
}

// FormatSeverityBadge 格式化严重级别徽章
func (c *Color) FormatSeverityBadge(severity string, count int) string {
	severityColor := c.InfoLevel(severity)
	switch severity {
	case "严重":
		severityColor = c.Critical(severity)
	case "高危":
		severityColor = c.High(severity)
	case "中危":
		severityColor = c.Medium(severity)
	case "低危":
		severityColor = c.Low(severity)
	}
	
	return fmt.Sprintf("%s%s%s: %s%d%s", severityColor, severity, Reset, BrightWhite, count, Reset)
}

// FormatListItem 格式化列表项
func (c *Color) FormatListItem(text string) string {
	return fmt.Sprintf("  %s•%s %s", BrightCyan, Reset, c.Highlight(text))
}

// PrintListItem 打印列表项
func (c *Color) PrintListItem(text string) {
	fmt.Printf("%s\n", c.FormatListItem(text))
}

// 静态方法（无需实例化）

// Sprintf 格式化字符串并应用颜色
func Sprintf(colorCode, format string, args ...interface{}) string {
	text := fmt.Sprintf(format, args...)
	return fmt.Sprintf("%s%s%s", colorCode, text, Reset)
}

// Printf 格式化输出并应用颜色
func Printf(colorCode, format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s%s\n", colorCode, text, Reset)
}

// Println 输出并应用颜色
func Println(colorCode, text string) {
	fmt.Printf("%s%s%s\n", colorCode, text, Reset)
}