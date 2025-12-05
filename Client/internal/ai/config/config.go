package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// AIConfig 定义AI功能的配置结构
type AIConfig struct {
	Provider         string          `yaml:"provider"`          // 服务提供商标识（云AI服务或本地Ollama）
	Model            string          `yaml:"model"`             // 模型名称（对于Ollama，填写本地模型名称如"llama2"）
	APIKey           string          `yaml:"api_key"`           // API密钥（云服务必填，本地Ollama服务设置为false）
	BaseURL          string          `yaml:"base_url"`          // API基础URL（用于自定义API端点，Ollama默认为http://localhost:11434）
	Timeout          int             `yaml:"timeout"`           // 请求超时时间（秒）
	MaxRetries       int             `yaml:"max_retries"`       // 最大重试次数
	Temperature      float64         `yaml:"temperature"`       // 生成文本的温度参数（控制随机性，0-2）
	TopP             float64         `yaml:"top_p"`             // 核采样参数（0-1）
	MaxTokens        int             `yaml:"max_tokens"`        // 最大生成tokens数
	EnableLogging    bool            `yaml:"enable_logging"`    // 是否启用详细日志
	EnableSandbox    bool            `yaml:"enable_sandbox"`    // 是否启用沙箱模式
	ReportFormat     string          `yaml:"report_format"`     // 报告格式（html/json）
	ToolMapping      map[string]bool `yaml:"tool_mapping"`      // 系统工具映射
	ToolTimeout      int             `yaml:"tool_timeout"`      // 工具执行超时时间（秒）
	Stream           bool            `yaml:"stream"`            // 是否使用流式响应
	RetryDelay       int             `yaml:"retry_delay"`       // 重试延迟（秒）
	AzureAPIVersion  string          `yaml:"azure_api_version"` // Azure API版本
	Organization     string          `yaml:"organization"`      // OpenAI组织ID
	ProfessionalMode bool            `yaml:"professional_mode"` // 是否启用专业渗透测试模式
}

// GetDefaultConfigPath 获取默认配置文件路径
func GetDefaultConfigPath() string {
	var configPath string

	switch runtime.GOOS {
	case "windows":
		// 优先检查用户主目录下的配置文件
		homeDir, err := os.UserHomeDir()
		if err == nil {
			userConfigPath := filepath.Join(homeDir, "GYscan", "ai_config.yml")
			if _, statErr := os.Stat(userConfigPath); statErr == nil {
				// 用户主目录下的配置文件存在，使用它
				return userConfigPath
			}
		}

		// 其次检查当前工作目录下的配置文件
		cwd, _ := os.Getwd()
		cwdConfigPath := filepath.Join(cwd, "config", "ai_config.yml")
		if _, statErr := os.Stat(cwdConfigPath); statErr == nil {
			// 当前工作目录下的配置文件存在，使用它
			return cwdConfigPath
		}

		// 最后使用可执行文件所在目录
		exePath, err := os.Executable()
		if err == nil {
			exeDir := filepath.Dir(exePath)
			configPath = filepath.Join(exeDir, "..", "config", "ai_config.yml")
		} else {
			// 回退到当前工作目录
			configPath = filepath.Join(cwd, "config", "ai_config.yml")
		}
	case "linux":
		configPath = filepath.Join("/etc/GYscan", "ai_config.yml")
	default:
		// 默认使用当前目录
		configPath = "ai_config.yml"
	}

	// 确保配置目录存在
	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err := os.MkdirAll(configDir, 0755)
		if err != nil {
			fmt.Printf("创建配置目录失败: %v\n", err)
			return "ai_config.yml" // 回退到当前目录
		}
	}

	return configPath
}

// GetDefaultConfig 获取默认配置
func GetDefaultConfig() AIConfig {
	return AIConfig{
		Provider:         "ollama",
		Model:            "llama3.1",                  // 默认使用Ollama的llama3.1模型
		APIKey:           "",                          // Ollama不需要API密钥
		BaseURL:          "http://localhost:11434/v1", // Ollama默认API地址
		Timeout:          300,                         // 增加超时时间到300秒，应对本地模型推理
		MaxRetries:       3,                           // 重试次数
		Temperature:      0.2,                         // 降低温度参数，使输出更稳定可靠
		TopP:             0.8,                         // 核采样参数
		MaxTokens:        4096,                        // 增加最大token数，支持更详细的响应
		EnableLogging:    true,
		EnableSandbox:    true,
		ReportFormat:     "html",
		ToolTimeout:      120, // 增加工具执行超时时间
		Stream:           true,
		RetryDelay:       5,
		AzureAPIVersion:  "2024-02-15-preview",
		Organization:     "",
		ProfessionalMode: false, // 默认不启用专业渗透测试模式
		ToolMapping: map[string]bool{
			"nmap":     false,
			"hydra":    false,
			"sqlmap":   false,
			"dirb":     false,
			"nikto":    false,
			"gobuster": false,
			"curl":     false,
			"whois":    false,
			"openssl":  false,
			"whatweb":  false,
		},
	}
}
