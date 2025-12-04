package config

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadConfig 从文件加载配置
func LoadConfig(configPath string) (*AIConfig, error) {
	// 如果配置文件不存在，返回默认配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML配置
	var config AIConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return &config, nil
}

// SaveConfig 保存配置到文件
func SaveConfig(config AIConfig, configPath string, force bool) error {
	// 检查文件是否存在，如果存在且不强制覆盖则返回错误
	if _, err := os.Stat(configPath); !os.IsNotExist(err) && !force {
		return fmt.Errorf("配置文件已存在: %s, 使用 -f 选项强制覆盖", configPath)
	}

	// 生成带有注释的YAML配置
	data := generateConfigWithComments(config)

	// 写入配置文件，确保使用UTF-8编码
	if err := os.WriteFile(configPath, []byte(data), 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// generateConfigWithComments 生成带有详细注释的YAML配置
func generateConfigWithComments(config AIConfig) string {
	// 构建YAML配置字符串，包含详细注释
	yamlStr := "# GYscan AI功能配置文件\n"
	yamlStr += "# 该文件包含AI功能的所有配置选项\n"
	yamlStr += "# 详细文档请参考项目说明\n\n"

	// 服务提供商配置
	yamlStr += "# 服务提供商配置\n"
	yamlStr += "# 支持的提供商: ollama, openai, azure, anthropic, deepseek\n"
	yamlStr += fmt.Sprintf("provider: %s\n", config.Provider)

	// 模型配置
	yamlStr += fmt.Sprintf("model: %s\n", config.Model)

	// API密钥配置
	yamlStr += "# API密钥（云服务必填，本地Ollama服务设置为false）\n"
	yamlStr += fmt.Sprintf("api_key: %s\n", config.APIKey)

	// API基础URL配置
	yamlStr += "# API基础URL（可选，用于自定义API端点）\n"
	yamlStr += fmt.Sprintf("base_url: %s\n", config.BaseURL)

	// 请求配置
	yamlStr += "\n# 请求配置\n"
	yamlStr += "# 请求超时时间（秒）\n"
	yamlStr += fmt.Sprintf("timeout: %d\n", config.Timeout)
	yamlStr += "# 最大重试次数\n"
	yamlStr += fmt.Sprintf("max_retries: %d\n", config.MaxRetries)

	// 模型参数配置
	yamlStr += "\n# 模型参数配置\n"
	yamlStr += "# 生成文本的温度参数（控制随机性，0-2）\n"
	yamlStr += fmt.Sprintf("temperature: %.2f\n", config.Temperature)
	yamlStr += "# 核采样参数（0-1）\n"
	yamlStr += fmt.Sprintf("top_p: %.2f\n", config.TopP)
	yamlStr += "# 最大生成tokens数\n"
	yamlStr += fmt.Sprintf("max_tokens: %d\n", config.MaxTokens)

	// 功能开关配置
	yamlStr += "\n# 功能开关配置\n"
	yamlStr += "# 是否启用详细日志\n"
	yamlStr += fmt.Sprintf("enable_logging: %v\n", config.EnableLogging)
	yamlStr += "# 是否启用沙箱模式，限制工具执行权限\n"
	yamlStr += fmt.Sprintf("enable_sandbox: %v\n", config.EnableSandbox)

	// 报告配置
	yamlStr += "\n# 报告配置\n"
	yamlStr += "# 报告格式（支持: html, json）\n"
	yamlStr += fmt.Sprintf("report_format: %s\n", config.ReportFormat)

	// 工具配置
	yamlStr += "\n# 工具配置\n"
	yamlStr += "# 工具执行超时时间（秒）\n"
	yamlStr += fmt.Sprintf("tool_timeout: %d\n", config.ToolTimeout)

	// 工具映射配置
	yamlStr += "\n# 系统工具映射\n"
	yamlStr += "# 标记系统中可用的安全工具，由系统自动检测和更新\n"
	yamlStr += "tool_mapping:\n"
	for tool, available := range config.ToolMapping {
		yamlStr += fmt.Sprintf("  %s: %v\n", tool, available)
	}

	return yamlStr
}

// TestConfig 测试配置有效性与连通性，并返回网络延迟信息
func TestConfig(config AIConfig) (time.Duration, error) {
	// 基本配置验证
	if config.Provider == "" {
		return 0, fmt.Errorf("服务提供商不能为空")
	}

	if config.Model == "" {
		return 0, fmt.Errorf("模型名称不能为空")
	}

	// 根据提供商类型进行不同的测试
	switch config.Provider {
	case "ollama":
		// Ollama本地服务测试
		if err := testOllamaConnection(config); err != nil {
			return 0, fmt.Errorf("Ollama服务测试失败: %v", err)
		}
		return 0, nil // 本地服务延迟忽略
	case "openai", "azure", "anthropic", "deepseek":
		// 云服务测试
		if config.APIKey == "" || config.APIKey == "false" {
			return 0, fmt.Errorf("云服务需要提供API密钥")
		}
		// 测试网络连通性和延迟
		return testNetworkLatency(config)
	default:
		return 0, fmt.Errorf("不支持的服务提供商: %s", config.Provider)
	}
}

// testNetworkLatency 测试网络延迟
func testNetworkLatency(config AIConfig) (time.Duration, error) {
	// 创建测试客户端
	testClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 构建测试URL
	testURL := fmt.Sprintf("%s/models", config.BaseURL)

	// 发送测试请求
	start := time.Now()
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建测试请求失败: %v", err)
	}

	// 设置认证头
	if config.Provider != "ollama" && config.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.APIKey))
	}

	resp, err := testClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("网络连通性测试失败: %v (请检查网络连接和BaseURL配置: %s)", err, config.BaseURL)
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	// 检查响应状态，提供更详细的错误信息
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case 401:
			return latency, fmt.Errorf("API认证失败 (状态码: %d) - 请检查API密钥是否正确", resp.StatusCode)
		case 404:
			return latency, fmt.Errorf("API端点不存在 (状态码: %d) - 请检查BaseURL配置是否正确: %s", resp.StatusCode, config.BaseURL)
		case 429:
			return latency, fmt.Errorf("API请求频率限制 (状态码: %d) - 请稍后重试或检查API配额", resp.StatusCode)
		case 500, 502, 503:
			return latency, fmt.Errorf("API服务暂时不可用 (状态码: %d) - 请稍后重试", resp.StatusCode)
		default:
			return latency, fmt.Errorf("API端点测试失败 (状态码: %d) - 响应: %s", resp.StatusCode, resp.Status)
		}
	}

	return latency, nil
}

// OptimizeConfig 根据网络延迟优化配置
func OptimizeConfig(config AIConfig, latency time.Duration) AIConfig {
	// 根据延迟调整超时设置
	if latency > 5*time.Second {
		// 高延迟网络，增加超时时间
		config.Timeout = 180  // 3分钟
		config.MaxRetries = 2 // 减少重试次数
	} else if latency > 2*time.Second {
		// 中等延迟网络
		config.Timeout = 120 // 2分钟
		config.MaxRetries = 3
	} else {
		// 低延迟网络
		config.Timeout = 60 // 1分钟
		config.MaxRetries = 5
	}

	// 根据网络状况调整最大token数
	if latency > 3*time.Second {
		config.MaxTokens = 1024 // 高延迟时减少token数
	} else {
		config.MaxTokens = 2048 // 正常延迟使用标准token数
	}

	return config
}

// testOllamaConnection 测试Ollama服务连接
func testOllamaConnection(config AIConfig) error {
	// 创建测试客户端
	testClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 构建测试URL - 使用Ollama的API端点
	testURL := fmt.Sprintf("%s/api/tags", config.BaseURL)

	// 发送测试请求
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("创建Ollama测试请求失败: %v", err)
	}

	resp, err := testClient.Do(req)
	if err != nil {
		return fmt.Errorf("Ollama服务连接测试失败: %v (请检查Ollama服务是否启动，BaseURL配置是否正确: %s)", err, config.BaseURL)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case 404:
			return fmt.Errorf("Ollama API端点不存在 (状态码: %d) - 请检查BaseURL配置是否正确: %s", resp.StatusCode, config.BaseURL)
		case 500, 502, 503:
			return fmt.Errorf("Ollama服务暂时不可用 (状态码: %d) - 请检查Ollama服务是否正常运行", resp.StatusCode)
		default:
			return fmt.Errorf("Ollama服务测试失败 (状态码: %d) - 响应: %s", resp.StatusCode, resp.Status)
		}
	}

	return nil
}

// MaskConfig 脱敏配置信息，用于显示
func MaskConfig(config AIConfig) AIConfig {
	maskedConfig := config

	// 脱敏API密钥
	if maskedConfig.APIKey != "" && maskedConfig.APIKey != "false" {
		// 保留前4位和后4位，中间用****替换
		if len(maskedConfig.APIKey) > 8 {
			maskedConfig.APIKey = maskedConfig.APIKey[:4] + "****" + maskedConfig.APIKey[len(maskedConfig.APIKey)-4:]
		} else {
			maskedConfig.APIKey = "****"
		}
	}

	return maskedConfig
}
