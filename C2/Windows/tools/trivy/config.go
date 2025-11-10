package trivy

import (
	"time"
)

// Config 定义Trivy扫描的配置参数
type Config struct {
	Target    string        // 扫描目标（镜像、文件系统路径等）
	Output    string        // 输出文件路径
	Severity  string        // 漏洞严重性过滤（CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN）
	Timeout   time.Duration // 扫描超时时间
	Quiet     bool          // 静默模式
	Debug     bool          // 调试模式
	Format    string        // 输出格式（json, table, template）
}

// NewConfig 创建默认配置
func NewConfig() *Config {
	return &Config{
		Severity:  "CRITICAL,HIGH,MEDIUM",
		Timeout:   10 * time.Minute,
		Quiet:     false,
		Debug:     false,
		Format:    "json",
	}
}

// SetTarget 设置扫描目标
func (c *Config) SetTarget(target string) {
	c.Target = target
}

// SetOutput 设置输出文件路径
func (c *Config) SetOutput(output string) {
	c.Output = output
}

// SetSeverity 设置漏洞严重性过滤
func (c *Config) SetSeverity(severity string) {
	c.Severity = severity
}

// SetTimeout 设置超时时间
func (c *Config) SetTimeout(timeout time.Duration) {
	c.Timeout = timeout
}

// SetQuiet 设置静默模式
func (c *Config) SetQuiet(quiet bool) {
	c.Quiet = quiet
}

// SetDebug 设置调试模式
func (c *Config) SetDebug(debug bool) {
	c.Debug = debug
}

// SetFormat 设置输出格式
func (c *Config) SetFormat(format string) {
	c.Format = format
}