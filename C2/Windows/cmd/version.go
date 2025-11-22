package main

import (
	"fmt"
	"runtime"
	"time"
)

// VersionInfo 版本信息结构
type VersionInfo struct {
	Version     string    // 主版本号
	BuildDate   time.Time // 构建时间
	GoVersion   string    // Go版本
	Platform    string    // 平台信息
	Compiler    string    // 编译器信息
}

// GetVersionInfo 获取版本信息
func GetVersionInfo() VersionInfo {
	return VersionInfo{
		Version:     "2.5.2",
		BuildDate:   time.Now(),
		GoVersion:   runtime.Version(),
		Platform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Compiler:    runtime.Compiler,
	}
}

// String 版本信息字符串表示
func (v VersionInfo) String() string {
	return fmt.Sprintf(`
Windows漏洞扫描工具版本信息:
============================
版本:     %s
构建时间: %s
Go版本:   %s
平台:     %s
编译器:   %s
`,
		v.Version,
		v.BuildDate.Format("2006-01-02 15:04:05"),
		v.GoVersion,
		v.Platform,
		v.Compiler)
}

// ShortString 简短的版本信息
func (v VersionInfo) ShortString() string {
	return fmt.Sprintf("v%s (%s)", v.Version, v.BuildDate.Format("2006-01-02"))
}

// PrintVersion 打印版本信息
func PrintVersionInfo() {
	version := GetVersionInfo()
	fmt.Print(version.String())
}

// PrintShortVersion 打印简短版本信息
func PrintShortVersion() {
	version := GetVersionInfo()
	fmt.Println(version.ShortString())
}

// GetVersion 获取版本号
func GetVersion() string {
	return GetVersionInfo().Version
}

// GetBuildInfo 获取构建信息
func GetBuildInfo() string { 
	v := GetVersionInfo()
	return fmt.Sprintf("版本 %s, 构建于 %s", v.Version, v.BuildDate.Format("2006-01-02 15:04:05"))
}