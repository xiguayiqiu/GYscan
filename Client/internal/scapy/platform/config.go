package platform

import (
	"fmt"
	"runtime"
	"strings"
)

// Config 包含跨平台配置选项
type Config struct {
	// 网络配置
	DefaultInterface string
	SnapLength       int
	BufferSize       int
	PromiscuousMode  bool
	Timeout          int

	// 性能配置
	MaxPacketRate int // 最大包速率（包/秒）
	MaxConcurrent int // 最大并发数

	// 安全配置
	RequireRoot     bool // 是否需要root权限
	AllowRawSockets bool // 是否允许原始套接字

	// 平台特定配置
	PlatformSpecific map[string]interface{}
}

// DefaultConfig 返回默认的跨平台配置
func DefaultConfig() *Config {
	config := &Config{
		DefaultInterface: GetDefaultInterface(),
		SnapLength:       GetDefaultSnapLength(),
		BufferSize:       GetDefaultBufferSize(),
		PromiscuousMode:  false,
		Timeout:          30,
		MaxPacketRate:    1000,
		MaxConcurrent:    10,
		RequireRoot:      false,
		AllowRawSockets:  true,
		PlatformSpecific: make(map[string]interface{}),
	}

	// 根据平台调整配置
	config.adjustForPlatform()

	return config
}

// adjustForPlatform 根据平台调整配置参数
func (c *Config) adjustForPlatform() {
	switch runtime.GOOS {
	case "linux":
		c.adjustForLinux()
	case "windows":
		c.adjustForWindows()
	case "darwin":
		c.adjustForDarwin()
	case "freebsd":
		c.adjustForFreeBSD()
	default:
		c.adjustForGenericUnix()
	}
}

// adjustForLinux Linux系统配置调整
func (c *Config) adjustForLinux() {
	c.RequireRoot = true   // Linux系统通常需要root权限进行原始包操作
	c.SnapLength = 65536   // Linux支持更大的快照长度
	c.BufferSize = 65536   // Linux支持更大的缓冲区
	c.MaxPacketRate = 5000 // Linux系统性能更好

	// Linux特定配置
	c.PlatformSpecific["kernel_version"] = "unknown"
	c.PlatformSpecific["libpcap_version"] = "unknown"
	c.PlatformSpecific["capabilities"] = "需要CAP_NET_RAW权限"
}

// adjustForWindows Windows系统配置调整
func (c *Config) adjustForWindows() {
	c.DefaultInterface = "WLAN" // Windows默认接口
	c.SnapLength = 1514         // Windows标准快照长度
	c.BufferSize = 8192         // Windows缓冲区大小
	c.RequireRoot = false       // Windows不需要root权限
	c.MaxPacketRate = 1000      // Windows性能限制

	// Windows特定配置
	c.PlatformSpecific["npcap_installed"] = false
	c.PlatformSpecific["winpcap_version"] = "unknown"
	c.PlatformSpecific["admin_required"] = "可能需要管理员权限"
}

// adjustForDarwin macOS系统配置调整
func (c *Config) adjustForDarwin() {
	c.DefaultInterface = "en0" // macOS默认接口
	c.SnapLength = 1514        // macOS标准快照长度
	c.BufferSize = 8192        // macOS缓冲区大小
	c.RequireRoot = false      // macOS不需要root权限
	c.MaxPacketRate = 2000     // macOS性能中等

	// macOS特定配置
	c.PlatformSpecific["xcode_installed"] = false
	c.PlatformSpecific["bpf_permissions"] = "需要BPF设备访问权限"
}

// adjustForFreeBSD FreeBSD系统配置调整
func (c *Config) adjustForFreeBSD() {
	c.DefaultInterface = "em0" // FreeBSD默认接口
	c.SnapLength = 65536       // FreeBSD支持更大的快照长度
	c.BufferSize = 65536       // FreeBSD支持更大的缓冲区
	c.RequireRoot = true       // FreeBSD需要root权限
	c.MaxPacketRate = 3000     // FreeBSD性能较好

	// FreeBSD特定配置
	c.PlatformSpecific["bpf_available"] = true
	c.PlatformSpecific["jail_restrictions"] = "jail环境中可能受限"
}

// adjustForGenericUnix 通用Unix系统配置调整
func (c *Config) adjustForGenericUnix() {
	c.DefaultInterface = "eth0" // 通用Unix默认接口
	c.SnapLength = 1514         // 标准快照长度
	c.BufferSize = 8192         // 标准缓冲区大小
	c.RequireRoot = true        // 大多数Unix系统需要root权限
	c.MaxPacketRate = 1000      // 保守的性能限制
}

// Validate 验证配置的有效性
func (c *Config) Validate() error {
	if c.SnapLength <= 0 {
		return fmt.Errorf("快照长度必须大于0")
	}

	if c.BufferSize <= 0 {
		return fmt.Errorf("缓冲区大小必须大于0")
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("超时时间必须大于0")
	}

	if c.MaxPacketRate <= 0 {
		return fmt.Errorf("最大包速率必须大于0")
	}

	if c.MaxConcurrent <= 0 {
		return fmt.Errorf("最大并发数必须大于0")
	}

	return nil
}

// GetPlatformInfoString 返回平台信息的字符串表示
func (c *Config) GetPlatformInfoString() string {
	info := GetPlatformInfo()

	return fmt.Sprintf("平台: %s/%s, 64位: %t, Unix系统: %t, 需要root: %t",
		info.OS, info.Arch, info.Is64Bit, info.IsUnix, c.RequireRoot)
}

// GetRecommendedInterface 获取推荐接口名称
func (c *Config) GetRecommendedInterface() string {
	return c.DefaultInterface
}

// IsCompatible 检查当前系统是否兼容
func (c *Config) IsCompatible() bool {
	// 检查原始套接字支持
	if !GetRawSocketSupport() && c.AllowRawSockets {
		return false
	}

	// 检查PCAP支持
	if !GetPCAPSupport() {
		return false
	}

	return true
}

// GetCompatibilityMessage 获取兼容性消息
func (c *Config) GetCompatibilityMessage() string {
	if c.IsCompatible() {
		return "系统完全兼容"
	}

	var issues []string

	if !GetRawSocketSupport() && c.AllowRawSockets {
		issues = append(issues, "原始套接字不支持")
	}

	if !GetPCAPSupport() {
		issues = append(issues, "PCAP不支持")
	}

	if len(issues) > 0 {
		return fmt.Sprintf("兼容性问题: %s", strings.Join(issues, ", "))
	}

	return "未知兼容性问题"
}
