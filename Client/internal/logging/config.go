package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LogConfig 日志配置结构体
type LogConfig struct {
	// 基本配置
	LogLevel     string `json:"log_level"`      // 日志级别: DEBUG, INFO, WARNING, ERROR, FATAL
	LogToFile    bool   `json:"log_to_file"`    // 是否记录到文件
	LogToConsole bool   `json:"log_to_console"` // 是否输出到控制台
	LogFormat    string `json:"log_format"`     // 日志格式

	// 文件配置
	LogDir      string `json:"log_dir"`       // 日志目录路径
	LogFileName string `json:"log_file_name"` // 日志文件名
	MaxSizeMB   int    `json:"max_size_mb"`   // 单个日志文件最大大小(MB)
	MaxBackups  int    `json:"max_backups"`   // 最大备份文件数
	MaxAgeDays  int    `json:"max_age_days"`  // 日志文件最大保存天数
	Compress    bool   `json:"compress"`      // 是否压缩备份文件

	// 模块配置
	ModuleLogging map[string]bool `json:"module_logging"` // 模块级别的日志开关
}

// DefaultConfig 返回默认日志配置
func DefaultConfig() *LogConfig {
	return &LogConfig{
		LogLevel:     "INFO",
		LogToFile:    true,
		LogToConsole: true,
		LogFormat:    "%time% [%level%] %module%: %message%",
		LogDir:       GetDefaultLogDir(),
		LogFileName:  "gyscan.log",
		MaxSizeMB:    100,  // 100MB
		MaxBackups:   10,   // 保留10个备份文件
		MaxAgeDays:   30,   // 保留30天
		Compress:     true, // 压缩备份文件
		ModuleLogging: map[string]bool{
			"AI":       true,
			"Network":  true,
			"Security": true,
			"Database": true,
			"Web":      true,
			"System":   true,
		},
	}
}

// GetDefaultLogDir 获取默认日志目录路径
func GetDefaultLogDir() string {
	if runtime.GOOS == "windows" {
		// Windows系统默认路径: C:\Users\wwwrn\AppData\Local\Temp\GYscan\
		userProfile := os.Getenv("USERPROFILE")
		if userProfile == "" {
			userProfile = "C:\\Users\\wwwrn"
		}
		return filepath.Join(userProfile, "AppData", "Local", "Temp", "GYscan")
	} else {
		// Linux系统默认路径: /tmp/GYscan/
		return "/tmp/GYscan"
	}
}

// GetLogFilePath 获取完整的日志文件路径
func (c *LogConfig) GetLogFilePath() string {
	return filepath.Join(c.LogDir, c.LogFileName)
}

// GetBackupLogFilePath 获取备份日志文件路径
func (c *LogConfig) GetBackupLogFilePath(backupIndex int) string {
	if backupIndex <= 0 {
		return c.GetLogFilePath()
	}

	baseName := c.LogFileName
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)

	backupFileName := fmt.Sprintf("%s.%d%s", nameWithoutExt, backupIndex, ext)
	return filepath.Join(c.LogDir, backupFileName)
}

// GetCompressedBackupLogFilePath 获取压缩备份日志文件路径
func (c *LogConfig) GetCompressedBackupLogFilePath(backupIndex int) string {
	if backupIndex <= 0 {
		return c.GetLogFilePath()
	}

	baseName := c.LogFileName
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)

	backupFileName := fmt.Sprintf("%s.%d%s.gz", nameWithoutExt, backupIndex, ext)
	return filepath.Join(c.LogDir, backupFileName)
}

// Validate 验证配置的有效性
func (c *LogConfig) Validate() error {
	// 验证日志级别
	validLevels := map[string]bool{
		"DEBUG":   true,
		"INFO":    true,
		"WARNING": true,
		"ERROR":   true,
		"FATAL":   true,
	}

	if !validLevels[strings.ToUpper(c.LogLevel)] {
		return fmt.Errorf("无效的日志级别: %s", c.LogLevel)
	}

	// 验证文件大小限制
	if c.MaxSizeMB <= 0 {
		return fmt.Errorf("日志文件大小限制必须大于0")
	}

	// 验证备份文件数量
	if c.MaxBackups < 0 {
		return fmt.Errorf("备份文件数量不能为负数")
	}

	// 验证保存天数
	if c.MaxAgeDays < 0 {
		return fmt.Errorf("日志保存天数不能为负数")
	}

	return nil
}

// IsModuleEnabled 检查指定模块的日志是否启用
func (c *LogConfig) IsModuleEnabled(moduleName string) bool {
	if enabled, exists := c.ModuleLogging[moduleName]; exists {
		return enabled
	}
	// 默认启用未知模块的日志
	return true
}

// SetModuleEnabled 设置模块的日志开关
func (c *LogConfig) SetModuleEnabled(moduleName string, enabled bool) {
	if c.ModuleLogging == nil {
		c.ModuleLogging = make(map[string]bool)
	}
	c.ModuleLogging[moduleName] = enabled
}

// EnsureLogDir 确保日志目录存在
func (c *LogConfig) EnsureLogDir() error {
	return os.MkdirAll(c.LogDir, 0755)
}

// GetModuleLogFilePath 获取模块特定的日志文件路径
func (c *LogConfig) GetModuleLogFilePath(moduleName string) string {
	baseName := c.LogFileName
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)

	moduleFileName := fmt.Sprintf("%s_%s%s", nameWithoutExt, strings.ToLower(moduleName), ext)
	return filepath.Join(c.LogDir, moduleFileName)
}
