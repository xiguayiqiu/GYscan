package utils

import (
	"fmt"
	"github.com/fatih/color"
)

// 颜色工具函数 - 使用fatih/color库实现跨平台颜色支持

// Success 成功信息（绿色）
func Success(format string, a ...interface{}) string {
	return color.GreenString(format, a...)
}

// Error 错误信息（红色）
func Error(format string, a ...interface{}) string {
	return color.RedString(format, a...)
}

// Warning 警告信息（黄色）
func Warning(format string, a ...interface{}) string {
	return color.YellowString(format, a...)
}

// Info 信息（蓝色）
func Info(format string, a ...interface{}) string {
	return color.BlueString(format, a...)
}

// Highlight 高亮信息（青色）
func Highlight(format string, a ...interface{}) string {
	return color.CyanString(format, a...)
}

// BoldSuccess 粗体成功信息（粗体绿色）
func BoldSuccess(format string, a ...interface{}) string {
	boldGreen := color.New(color.FgGreen, color.Bold)
	return boldGreen.Sprintf(format, a...)
}

// BoldError 粗体错误信息（粗体红色）
func BoldError(format string, a ...interface{}) string {
	boldRed := color.New(color.FgRed, color.Bold)
	return boldRed.Sprintf(format, a...)
}

// BoldWarning 粗体警告信息（粗体黄色）
func BoldWarning(format string, a ...interface{}) string {
	boldYellow := color.New(color.FgYellow, color.Bold)
	return boldYellow.Sprintf(format, a...)
}

// BoldInfo 粗体信息（粗体蓝色）
func BoldInfo(format string, a ...interface{}) string {
	boldBlue := color.New(color.FgBlue, color.Bold)
	return boldBlue.Sprintf(format, a...)
}

// Progress 进度信息（紫色）
func Progress(format string, a ...interface{}) string {
	return color.MagentaString(format, a...)
}

// Debug 调试信息（灰色）
func Debug(format string, a ...interface{}) string {
	return color.New(color.FgHiBlack).Sprintf(format, a...)
}

// Banner 横幅信息（粗体青色）
func Banner(format string, a ...interface{}) string {
	boldCyan := color.New(color.FgCyan, color.Bold)
	return boldCyan.Sprintf(format, a...)
}

// Title 标题信息（粗体白色）
func Title(format string, a ...interface{}) string {
	boldWhite := color.New(color.FgWhite, color.Bold)
	return boldWhite.Sprintf(format, a...)
}

// 带背景色的函数

// BgSuccess 背景成功信息（绿色背景）
func BgSuccess(format string, a ...interface{}) string {
	bgGreen := color.New(color.BgGreen, color.FgBlack)
	return bgGreen.Sprintf(format, a...)
}

// BgError 背景错误信息（红色背景）
func BgError(format string, a ...interface{}) string {
	bgRed := color.New(color.BgRed, color.FgWhite)
	return bgRed.Sprintf(format, a...)
}

// BgWarning 背景警告信息（黄色背景）
func BgWarning(format string, a ...interface{}) string {
	bgYellow := color.New(color.BgYellow, color.FgBlack)
	return bgYellow.Sprintf(format, a...)
}

// 组合颜色函数

// ColorText 自定义颜色文本
func ColorText(text string, colorCode string) string {
	// 为了向后兼容，这里保留原接口但使用fatih/color实现
	// 注意：colorCode参数在这里不再使用，因为fatih/color有自己的颜色定义
	return text
}

// ColorPrint 带颜色打印
func ColorPrint(colorCode string, format string, a ...interface{}) {
	fmt.Printf("%s\n", fmt.Sprintf(format, a...))
}

// SuccessPrint 打印成功信息
func SuccessPrint(format string, a ...interface{}) {
	color.Green(format, a...)
}

// ErrorPrint 打印错误信息
func ErrorPrint(format string, a ...interface{}) {
	color.Red(format, a...)
}

// WarningPrint 打印警告信息
func WarningPrint(format string, a ...interface{}) {
	color.Yellow(format, a...)
}

// InfoPrint 打印信息
func InfoPrint(format string, a ...interface{}) {
	color.Blue(format, a...)
}

// ProgressPrint 打印进度信息
func ProgressPrint(format string, a ...interface{}) {
	color.Magenta(format, a...)
}

// BannerPrint 打印横幅信息
func BannerPrint(format string, a ...interface{}) {
	boldCyan := color.New(color.FgCyan, color.Bold)
	boldCyan.Printf(format+"\n", a...)
}

// TitlePrint 打印标题信息
func TitlePrint(format string, a ...interface{}) {
	boldWhite := color.New(color.FgWhite, color.Bold)
	boldWhite.Printf(format+"\n", a...)
}

// 颜色常量定义（为了向后兼容）
const (
	Reset      = ""
	Red        = ""
	Green      = ""
	Yellow     = ""
	Blue       = ""
	Purple     = ""
	Cyan       = ""
	White      = ""
	Gray       = ""
	BoldRed    = ""
	BoldGreen  = ""
	BoldYellow = ""
	BoldBlue   = ""
	BoldPurple = ""
	BoldCyan   = ""
	BoldWhite  = ""
	BgRed      = ""
	BgGreen    = ""
	BgYellow   = ""
	BgBlue     = ""
	BgPurple   = ""
	BgCyan     = ""
	BgWhite    = ""
)