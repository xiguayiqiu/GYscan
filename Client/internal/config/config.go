package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config 应用配置
type Config struct {
	// 配置结构
}

// GetConfigPath 获取配置文件路径
func GetConfigPath() string {
	var configDir string

	switch runtime.GOOS {
	case "windows":
		// Windows: %USERPROFILE%\GYscan\config
		homeDir, err := os.UserHomeDir()
		if err != nil {
			// 如果获取失败，使用当前目录
			configDir = "./GYscan/config"
		} else {
			configDir = filepath.Join(homeDir, "GYscan", "config")
		}
	default:
		// Linux/Unix: /etc/GYscan/config
		configDir = "/etc/GYscan/config"
	}

	// 创建配置目录
	os.MkdirAll(configDir, 0755)

	// 返回配置文件路径
	return filepath.Join(configDir, "config.json")
}

// LoadConfig 加载配置
func LoadConfig() (*Config, error) {
	configPath := GetConfigPath()

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 配置文件不存在，创建默认配置
		defaultConfig := DefaultConfig()

		// 将默认配置写入文件
		if err := SaveConfig(defaultConfig); err != nil {
			return defaultConfig, fmt.Errorf("保存默认配置失败: %v", err)
		}

		return defaultConfig, nil
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析配置
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return &config, nil
}

// SaveConfig 保存配置
func SaveConfig(config *Config) error {
	configPath := GetConfigPath()

	// 转换为JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	// 写入配置文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{}
}
