package ai

import (
	"fmt"
	"strings"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"
)

// 使用client.go中定义的接口和结构体

// ClientFactory AI客户端工厂
type ClientFactory struct{}

// NewClientFactory 创建新的客户端工厂
func NewClientFactory() *ClientFactory {
	return &ClientFactory{}
}

// CreateClient 根据配置创建AI客户端
func (f *ClientFactory) CreateClient(cfg config.AIConfig) (AIClientInterface, error) {
	utils.InfoPrint("创建AI客户端，提供商: %s", cfg.Provider)

	switch strings.ToLower(cfg.Provider) {
	case "openai", "azure", "deepseek", "ollama":
		// 使用go-openai库的客户端
		return NewOpenAIClient(cfg)
	case "custom", "http":
		// 使用现有的HTTP客户端
		client, err := NewAIClient(cfg)
		if err != nil {
			return nil, err
		}
		return client, nil
	default:
		return nil, fmt.Errorf("不支持的AI提供商: %s", cfg.Provider)
	}
}

// CreateClientWithFallback 创建客户端，支持回退机制
func (f *ClientFactory) CreateClientWithFallback(cfg config.AIConfig, fallbackProvider string) (AIClientInterface, error) {
	client, err := f.CreateClient(cfg)
	if err != nil {
		utils.WarningPrint("主客户端创建失败: %v，尝试回退到: %s", err, fallbackProvider)

		// 使用回退提供商
		fallbackCfg := cfg
		fallbackCfg.Provider = fallbackProvider
		return f.CreateClient(fallbackCfg)
	}
	return client, nil
}

// TestConnection 测试AI服务连接
func (f *ClientFactory) TestConnection(cfg config.AIConfig) (bool, error) {
	utils.InfoPrint("测试AI服务连接...")

	client, err := f.CreateClient(cfg)
	if err != nil {
		return false, fmt.Errorf("创建客户端失败: %v", err)
	}
	defer func() {
		if closer, ok := client.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	// 发送简单的测试消息
	testMessages := []Message{
		{Role: "system", Content: "你是一个测试助手，请回复'连接成功'"},
		{Role: "user", Content: "测试连接"},
	}

	_, err = client.Chat(testMessages)
	if err != nil {
		return false, fmt.Errorf("连接测试失败: %v", err)
	}

	utils.SuccessPrint("AI服务连接测试成功")
	return true, nil
}

// GetSupportedProviders 获取支持的AI提供商列表
func (f *ClientFactory) GetSupportedProviders() []string {
	return []string{
		"openai",     // OpenAI官方API
		"azure",      // Azure OpenAI服务
		"deepseek",   // DeepSeek API
		"ollama",     // 本地Ollama服务
		"llama",      // 本地Llama.cpp服务
		"go-ollama",  // go-ollama客户端
		"langchain",  // LangChain AI框架
		"custom",     // 自定义HTTP服务
		"google",     // Google Gemini API
		"cohere",     // Cohere API
		"anthropic",  // Anthropic Claude API
		"mistral",    // Mistral AI API
		"togetherai", // Together AI API
		"openrouter", // OpenRouter AI API
		"moonshot",   // 月之暗面API
		"zhipu",      // 智谱AI API
		"qwen",       // 通义千问API
		"doubao",     // 豆包API
	}
}

// GetProviderConfig 获取特定提供商的推荐配置
func (f *ClientFactory) GetProviderConfig(provider string) config.AIConfig {
	cfg := config.GetDefaultConfig()
	cfg.Provider = provider

	switch strings.ToLower(provider) {
	case "openai":
		cfg.Model = "gpt-4"
		cfg.BaseURL = "https://api.openai.com/v1"
	case "azure":
		cfg.Model = "gpt-4"
		cfg.BaseURL = "" // 需要用户配置
	case "deepseek":
		cfg.Model = "deepseek-r1"
		cfg.BaseURL = "https://api.deepseek.com/v1"
	case "ollama":
		cfg.Model = "llama2"
		cfg.BaseURL = "http://localhost:11434/v1"
		cfg.APIKey = "" // Ollama不需要API密钥
	}

	return cfg
}
