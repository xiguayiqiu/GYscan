package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"

	openai "github.com/sashabaranov/go-openai"
)

// OpenAIClient 基于go-openai库的AI客户端
type OpenAIClient struct {
	client        *openai.Client
	config        config.AIConfig
	healthChecker *HealthChecker
	errorHandler  *ErrorHandler
}

// NewOpenAIClient 创建新的OpenAI客户端
func NewOpenAIClient(cfg config.AIConfig) (*OpenAIClient, error) {
	// 根据提供商创建不同的客户端配置
	var clientConfig openai.ClientConfig

	switch strings.ToLower(cfg.Provider) {
	case "openai":
		clientConfig = openai.DefaultConfig(cfg.APIKey)
		if cfg.BaseURL != "" {
			clientConfig.BaseURL = cfg.BaseURL
		}
	case "azure":
		clientConfig = openai.DefaultAzureConfig(cfg.APIKey, cfg.BaseURL)
	case "deepseek":
		clientConfig = openai.DefaultConfig(cfg.APIKey)
		clientConfig.BaseURL = "https://api.deepseek.com/v1"
		if cfg.BaseURL != "" {
			clientConfig.BaseURL = cfg.BaseURL
		}
	case "ollama":
		clientConfig = openai.DefaultConfig("")
		clientConfig.BaseURL = "http://localhost:11434/v1"
		if cfg.BaseURL != "" {
			clientConfig.BaseURL = cfg.BaseURL
		}
	default:
		return nil, fmt.Errorf("不支持的AI提供商: %s", cfg.Provider)
	}

	// 设置超时
	clientConfig.HTTPClient.Timeout = time.Duration(cfg.Timeout) * time.Second

	// 创建客户端
	client := openai.NewClientWithConfig(clientConfig)

	// 创建健康检查器
	healthChecker := NewHealthChecker(
		cfg.BaseURL,
		cfg.APIKey,
		time.Duration(cfg.Timeout)*time.Second,
		30*time.Second,
	)

	// 创建错误处理器
	errorHandler := NewErrorHandler("", "info")

	return &OpenAIClient{
		client:        client,
		config:        cfg,
		healthChecker: healthChecker,
		errorHandler:  errorHandler,
	}, nil
}

// Chat 发送聊天请求，使用go-openai的流式响应
func (c *OpenAIClient) Chat(messages []Message) (string, error) {
	utils.InfoPrint("使用OpenAI客户端发送聊天请求...")

	// 转换消息格式
	openaiMessages := make([]openai.ChatCompletionMessage, len(messages))
	for i, msg := range messages {
		var role string
		switch msg.Role {
		case "system":
			role = openai.ChatMessageRoleSystem
		case "user":
			role = openai.ChatMessageRoleUser
		case "assistant":
			role = openai.ChatMessageRoleAssistant
		default:
			role = openai.ChatMessageRoleUser
		}
		openaiMessages[i] = openai.ChatCompletionMessage{
			Role:    role,
			Content: msg.Content,
		}
	}

	// 创建请求
	req := openai.ChatCompletionRequest{
		Model:       c.config.Model,
		Messages:    openaiMessages,
		MaxTokens:   c.config.MaxTokens,
		Temperature: float32(c.config.Temperature),
		TopP:        float32(c.config.TopP),
	}

	// 发送请求
	resp, err := c.client.CreateChatCompletion(context.Background(), req)
	if err != nil {
		c.errorHandler.Log("error", "openai_chat_error", "OpenAI聊天请求失败", map[string]interface{}{
			"model":    c.config.Model,
			"messages": len(messages),
			"error":    err.Error(),
		})
		return "", fmt.Errorf("OpenAI聊天请求失败: %v", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("OpenAI返回空响应")
	}

	utils.SuccessPrint("OpenAI请求成功，返回%d个选择", len(resp.Choices))
	return resp.Choices[0].Message.Content, nil
}

// ChatStream 流式聊天，用于实时响应
func (c *OpenAIClient) ChatStream(messages []Message, onChunk func(string)) error {
	utils.InfoPrint("开始流式聊天...")

	// 转换消息格式
	openaiMessages := make([]openai.ChatCompletionMessage, len(messages))
	for i, msg := range messages {
		var role string
		switch msg.Role {
		case "system":
			role = openai.ChatMessageRoleSystem
		case "user":
			role = openai.ChatMessageRoleUser
		case "assistant":
			role = openai.ChatMessageRoleAssistant
		default:
			role = openai.ChatMessageRoleUser
		}
		openaiMessages[i] = openai.ChatCompletionMessage{
			Role:    role,
			Content: msg.Content,
		}
	}

	req := openai.ChatCompletionRequest{
		Model:       c.config.Model,
		Messages:    openaiMessages,
		MaxTokens:   c.config.MaxTokens,
		Temperature: float32(c.config.Temperature),
		TopP:        float32(c.config.TopP),
		Stream:      true,
	}

	stream, err := c.client.CreateChatCompletionStream(context.Background(), req)
	if err != nil {
		return fmt.Errorf("创建流式聊天失败: %v", err)
	}
	defer stream.Close()

	var fullResponse strings.Builder
	for {
		response, err := stream.Recv()
		if err != nil {
			break
		}

		if len(response.Choices) > 0 && response.Choices[0].Delta.Content != "" {
			content := response.Choices[0].Delta.Content
			fullResponse.WriteString(content)
			if onChunk != nil {
				onChunk(content)
			}
		}
	}

	utils.SuccessPrint("流式聊天完成，总响应长度: %d", fullResponse.Len())
	return nil
}

// AnalyzeScanResults 分析扫描结果，使用更智能的提示
func (c *OpenAIClient) AnalyzeScanResults(target string, scanResults string, availableTools map[string]bool) (string, error) {
	// 构建可用工具列表字符串
	var availableToolsStr string
	for tool, available := range availableTools {
		if available {
			if availableToolsStr != "" {
				availableToolsStr += ", "
			}
			availableToolsStr += tool
		}
	}

	// 智能漏洞探测与利用系统提示 - 专注于漏洞探测和利用
	systemPrompt := `你是一名专业的漏洞探测与利用AI助手。请根据目标信息、扫描结果和可用工具，自主制定完整的漏洞探测与利用策略并执行具体操作。

你的任务：
1. 分析目标信息和已有扫描结果，识别潜在的漏洞点
2. 根据目标类型（IP地址、域名、URL）和服务版本选择最合适的漏洞探测和利用工具
3. 自主决策漏洞探测与利用步骤，包括漏洞识别、验证和实际利用
4. 根据前一步的结果动态调整后续策略，优先利用高风险漏洞
5. 生成具体的、可执行的命令行操作，确保命令的安全性和可执行性

决策原则：
- 优先识别已知CVE漏洞：根据服务版本匹配已知的CVE漏洞
- 分阶段探测：先进行被动探测，再进行主动探测，最后进行漏洞利用
- 工具选择：根据漏洞类型选择最合适的工具（例如：Web漏洞使用sqlmap、nikto；系统漏洞使用nmap NSE脚本）
- 安全第一：确保命令不会对目标系统造成不可逆的损害
- 利用效果评估：对每次利用尝试进行效果评估，并调整后续策略

输出格式：
请以JSON格式返回决策结果，包含以下字段：
{
  "strategy": "漏洞探测与利用策略描述",
  "steps": [
    {
      "step": "步骤描述",
      "tool": "工具名称",
      "command": "完整命令行",
      "reason": "选择此步骤的原因",
      "expected_result": "预期结果描述"
    }
  ],
  "next_action": "下一步建议"
}

可用工具：` + availableToolsStr

	// 构建用户请求 - 专注于漏洞探测与利用
	userContent := fmt.Sprintf(`目标: %s

目标类型分析: %s

已有扫描结果:
%s

可用工具: %s

请根据目标信息和扫描结果自主制定漏洞探测与利用策略，包括：
1. 分析目标服务和版本，识别潜在漏洞
2. 选择合适的工具进行漏洞验证
3. 生成具体的漏洞利用命令
4. 提供下一步行动建议

请以JSON格式返回完整的决策方案，确保命令可直接执行。`,
		target, getTargetType(target), scanResults, availableToolsStr)

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userContent},
	}

	return c.Chat(messages)
}

// Plan 生成渗透测试计划
func (c *OpenAIClient) Plan(target string, scanResults string, availableTools map[string]bool) (string, error) {
	systemPrompt := `你是一名专业的渗透测试工程师。请根据目标信息和扫描结果，制定详细的渗透测试计划。`

	userContent := fmt.Sprintf(`目标: %s

扫描结果:
%s

可用工具: %v

请制定详细的渗透测试计划，包括:
1. 信息收集阶段的具体步骤
2. 漏洞扫描和验证方法
3. 攻击向量和利用技术
4. 后渗透行动建议
5. 风险评估和规避措施`, target, scanResults, availableTools)

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userContent},
	}

	return c.Chat(messages)
}

// ParseResult 解析AI返回的结果
func (c *OpenAIClient) ParseResult(result string) (string, error) {
	// 这里可以实现更复杂的解析逻辑
	// 目前直接返回原始结果
	return result, nil
}

// GetHealthStatus 获取健康状态
func (c *OpenAIClient) GetHealthStatus() bool {
	return c.healthChecker.IsHealthy
}

// Close 关闭客户端连接
func (c *OpenAIClient) Close() error {
	// go-openai客户端不需要显式关闭
	return nil
}
