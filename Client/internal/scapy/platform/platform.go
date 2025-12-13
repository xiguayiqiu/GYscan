package platform

import (
	"runtime"
	"strings"
)

// Platform 表示操作系统平台
const (
	Windows = "windows"
	Linux   = "linux"
	Darwin  = "darwin"
	FreeBSD = "freebsd"
)

// CurrentPlatform 返回当前操作系统平台
func CurrentPlatform() string {
	return runtime.GOOS
}

// IsWindows 检查当前是否为Windows系统
func IsWindows() bool {
	return runtime.GOOS == Windows
}

// IsLinux 检查当前是否为Linux系统
func IsLinux() bool {
	return runtime.GOOS == Linux
}

// IsUnix 检查当前是否为Unix系统（Linux、Darwin、FreeBSD等）
func IsUnix() bool {
	return !IsWindows()
}

// IsDarwin 检查当前是否为macOS系统
func IsDarwin() bool {
	return runtime.GOOS == Darwin
}

// IsFreeBSD 检查当前是否为FreeBSD系统
func IsFreeBSD() bool {
	return runtime.GOOS == FreeBSD
}

// GetArchitecture 返回当前系统架构
func GetArchitecture() string {
	return runtime.GOARCH
}

// Is64Bit 检查是否为64位系统
func Is64Bit() bool {
	return strings.Contains(runtime.GOARCH, "64")
}

// Is32Bit 检查是否为32位系统
func Is32Bit() bool {
	return strings.Contains(runtime.GOARCH, "386") || strings.Contains(runtime.GOARCH, "arm")
}

// PlatformInfo 包含平台相关信息
type PlatformInfo struct {
	OS           string
	Arch         string
	Is64Bit      bool
	IsUnix       bool
	IsLinux      bool
	IsWindows    bool
	IsDarwin     bool
	IsFreeBSD    bool
}

// GetPlatformInfo 返回完整的平台信息
func GetPlatformInfo() PlatformInfo {
	return PlatformInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Is64Bit:   Is64Bit(),
		IsUnix:    IsUnix(),
		IsLinux:   IsLinux(),
		IsWindows: IsWindows(),
		IsDarwin:  IsDarwin(),
		IsFreeBSD: IsFreeBSD(),
	}
}

// GetDefaultInterface 获取默认网络接口名称
func GetDefaultInterface() string {
	if IsWindows() {
		return "WLAN"
	} else if IsLinux() {
		return "eth0"
	} else if IsDarwin() {
		return "en0"
	} else {
		return "eth0"
	}
}

// GetDefaultSnapLength 获取默认快照长度
func GetDefaultSnapLength() int {
	if IsLinux() {
		// Linux系统通常支持更大的快照长度
		return 65536
	} else {
		// 其他系统使用标准长度
		return 1514
	}
}

// GetDefaultBufferSize 获取默认缓冲区大小
func GetDefaultBufferSize() int {
	if IsLinux() {
		// Linux系统支持更大的缓冲区
		return 65536
	} else {
		return 8192
	}
}

// GetRawSocketSupport 检查是否支持原始套接字
func GetRawSocketSupport() bool {
	// Linux系统通常需要root权限才能使用原始套接字
	if IsLinux() {
		// 这里可以添加更复杂的权限检查
		return true
	}
	// Windows系统支持原始套接字但可能需要管理员权限
	return true
}

// GetPCAPSupport 检查是否支持PCAP
func GetPCAPSupport() bool {
	// 所有支持libpcap的系统都支持PCAP
	return true
}