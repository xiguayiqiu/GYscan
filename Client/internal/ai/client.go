package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"
)

// 全局连接池
var connectionPool = NewConnectionPool(10) // 最多10个不同的API端点

// AIClient 定义AI服务客户端
type AIClient struct {
	Config            config.AIConfig
	Client            *http.Client
	HealthChecker     *HealthChecker
	ConnectionMonitor *ConnectionMonitor
	ErrorHandler      *ErrorHandler
}

// AIClientInterface 定义统一的AI客户端接口
type AIClientInterface interface {
	// Plan 生成渗透测试计划
	Plan(target string, scanResults string, availableTools map[string]bool) (string, error)
	// ParseResult 解析AI返回的结果
	ParseResult(result string) (string, error)
	// Chat 与AI服务进行对话
	Chat(messages []Message) (string, error)
	// AnalyzeScanResults 分析扫描结果
	AnalyzeScanResults(target string, scanResults string, availableTools map[string]bool) (string, error)
}

// Message 定义AI对话消息
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AIRequest 定义AI请求结构
type AIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
	TopP        float64   `json:"top_p"`
	MaxTokens   int       `json:"max_tokens"`
}

// AIResponse 定义AI响应结构
type AIResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

// NewAIClient 创建新的AI服务客户端，自动优化配置并使用连接池
func NewAIClient(cfg config.AIConfig) (*AIClient, error) {
	// 测试网络延迟并优化配置
	latency, err := config.TestConfig(cfg)
	if err != nil {
		// 如果测试失败，使用默认配置但记录警告
		utils.WarningPrint("警告: 网络测试失败，使用默认配置: %v", err)
	} else {
		// 根据网络延迟优化配置
		cfg = config.OptimizeConfig(cfg, latency)
		utils.InfoPrint("网络延迟: %v, 优化后超时: %d秒, 最大重试: %d次",
			latency, cfg.Timeout, cfg.MaxRetries)
	}

	// 从连接池获取HTTP客户端
	client := connectionPool.GetClient(cfg.BaseURL, cfg.Timeout)

	// 创建健康检查器
	healthChecker := NewHealthChecker(
		cfg.BaseURL,
		cfg.APIKey,
		time.Duration(cfg.Timeout)*time.Second,
		30*time.Second, // 每30秒检查一次
	)

	// 创建重试策略
	retryStrategy := NewRetryStrategy(
		cfg.MaxRetries,
		1*time.Second,  // 基础延迟1秒
		15*time.Second, // 最大延迟15秒
	)

	// 创建连接监控器
	connectionMonitor := NewConnectionMonitor(healthChecker, retryStrategy)

	// 创建错误处理器
	errorHandler := NewErrorHandler("", "info")

	return &AIClient{
		Config:            cfg,
		Client:            client,
		HealthChecker:     healthChecker,
		ConnectionMonitor: connectionMonitor,
		ErrorHandler:      errorHandler,
	}, nil
}

// GetBaseURL 获取API基础URL
func (c *AIClient) GetBaseURL() string {
	// 如果配置了自定义BaseURL，使用配置的URL
	if c.Config.BaseURL != "" {
		return c.Config.BaseURL
	}

	// 根据服务提供商返回默认BaseURL
	switch c.Config.Provider {
	case "openai":
		return "https://api.openai.com/v1"
	case "azure":
		return "https://api.openai.azure.com/v1"
	case "anthropic":
		return "https://api.anthropic.com/v1"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	case "ollama":
		return "http://localhost:11434/v1"
	// 新增云AI提供商
	case "google":
		return "https://generativelanguage.googleapis.com/v1"
	case "cohere":
		return "https://api.cohere.ai/v1"
	case "huggingface":
		return "https://api-inference.huggingface.co/v1"
	case "mistral":
		return "https://api.mistral.ai/v1"
	case "togetherai":
		return "https://api.together.xyz/v1"
	case "replicate":
		return "https://api.replicate.com/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "moonshot":
		return "https://api.moonshot.cn/v1"
	case "zhipu":
		return "https://open.bigmodel.cn/api/paas/v4"
	case "qwen":
		return "https://dashscope.aliyuncs.com/compatible-mode/v1"
	case "doubao":
		return "https://ark.cn-beijing.volces.com/api/v3"
	case "dashscope":
		return "https://dashscope.aliyuncs.com/api/v1"
	case "perplexity":
		return "https://api.perplexity.ai/v1"
	case "fireworks":
		return "https://api.fireworks.ai/inference/v1"
	case "inflection":
		return "https://api.inflection.ai/v1"
	case "anthropic-streaming":
		return "https://streaming.api.anthropic.com/v1"
	case "siliconflow":
		return "https://api.siliconflow.cn/v1"
	default:
		return "https://api.openai.com/v1"
	}
}

// GetAuthorizationHeader 获取授权头
func (c *AIClient) GetAuthorizationHeader() string {
	// 根据服务提供商返回不同的授权头格式
	switch c.Config.Provider {
	case "openai", "deepseek", "mistral", "togetherai", "openrouter", "moonshot", "perplexity", "fireworks", "inflection", "siliconflow":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "azure":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "anthropic", "anthropic-streaming":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "google":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "cohere":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "huggingface":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "replicate":
		return fmt.Sprintf("Token %s", c.Config.APIKey)
	case "zhipu":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "qwen":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "doubao":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "dashscope":
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	case "ollama":
		return ""
	default:
		return fmt.Sprintf("Bearer %s", c.Config.APIKey)
	}
}

// Chat 发送聊天请求，使用智能重试策略和连接池优化
func (c *AIClient) Chat(messages []Message) (string, error) {
	// 创建重试策略
	retryStrategy := NewRetryStrategy(
		c.Config.MaxRetries,
		1*time.Second,  // 基础延迟1秒
		15*time.Second, // 最大延迟15秒
	)

	var lastErr error
	var totalDelay time.Duration
	var attempts int

	for attempts = 0; attempts <= retryStrategy.MaxRetries; attempts++ {
		utils.InfoPrint("正在发送AI请求... (重试: %d/%d)", attempts, retryStrategy.MaxRetries)

		// 构建请求URL
		baseURL := c.GetBaseURL()
		// 根据服务提供商选择不同的API端点
		var url string

		// 检查是否使用用户配置的完整URL
		if c.Config.BaseURL != "" && c.Config.BaseURL != baseURL {
			// 用户已配置完整URL，直接使用
			url = c.Config.BaseURL
		} else {
			// 根据提供商选择API端点
			switch c.Config.Provider {
			case "ollama":
				// Ollama使用/api/chat端点
				url = fmt.Sprintf("%s/api/chat", baseURL)
			case "google":
				// Google Gemini使用/models/[model]:generateContent端点
				url = fmt.Sprintf("%s/models/%s:generateContent", baseURL, c.Config.Model)
			case "cohere":
				// Cohere使用/generate端点
				url = fmt.Sprintf("%s/generate", baseURL)
			case "anthropic", "anthropic-streaming":
				// Anthropic使用/messages端点
				url = fmt.Sprintf("%s/messages", baseURL)
			default:
				// 其他提供商使用OpenAI兼容的/chat/completions路径
				url = fmt.Sprintf("%s/chat/completions", baseURL)
			}
		}
		utils.InfoPrint("请求URL: %s", url)

		// 根据提供商构建不同的请求体
		var reqJSON []byte
		var err error

		switch c.Config.Provider {
		case "google":
			// Google Gemini请求格式
			type GoogleContent struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			}

			type GoogleRequest struct {
				Contents         []GoogleContent `json:"contents"`
				GenerationConfig struct {
					Temperature     float64 `json:"temperature"`
					TopP            float64 `json:"topP"`
					MaxOutputTokens int     `json:"maxOutputTokens"`
				} `json:"generationConfig"`
			}

			// 构建Google请求体
			googleReq := GoogleRequest{
				GenerationConfig: struct {
					Temperature     float64 `json:"temperature"`
					TopP            float64 `json:"topP"`
					MaxOutputTokens int     `json:"maxOutputTokens"`
				}{
					Temperature:     c.Config.Temperature,
					TopP:            c.Config.TopP,
					MaxOutputTokens: c.Config.MaxTokens,
				},
			}

			// 转换messages为Google格式
			for _, msg := range messages {
				googleReq.Contents = append(googleReq.Contents, GoogleContent{
					Parts: []struct {
						Text string `json:"text"`
					}{{
						Text: msg.Content,
					}},
				})
			}

			reqJSON, err = json.Marshal(googleReq)
		case "cohere":
			// Cohere请求格式
			type CohereRequest struct {
				Model       string  `json:"model"`
				Prompt      string  `json:"prompt"`
				Temperature float64 `json:"temperature"`
				TopP        float64 `json:"p"`
				MaxTokens   int     `json:"max_tokens"`
			}

			// 构建Cohere请求体
			// 将messages转换为单条prompt
			var promptBuilder strings.Builder
			for _, msg := range messages {
				promptBuilder.WriteString(fmt.Sprintf("%s: %s\n", msg.Role, msg.Content))
			}

			cohereReq := CohereRequest{
				Model:       c.Config.Model,
				Prompt:      promptBuilder.String(),
				Temperature: c.Config.Temperature,
				TopP:        c.Config.TopP,
				MaxTokens:   c.Config.MaxTokens,
			}

			reqJSON, err = json.Marshal(cohereReq)
		case "anthropic", "anthropic-streaming":
			// Anthropic请求格式
			type AnthropicRequest struct {
				Model       string    `json:"model"`
				Messages    []Message `json:"messages"`
				Temperature float64   `json:"temperature"`
				TopP        float64   `json:"top_p"`
				MaxTokens   int       `json:"max_tokens"`
			}

			anthropicReq := AnthropicRequest{
				Model:       c.Config.Model,
				Messages:    messages,
				Temperature: c.Config.Temperature,
				TopP:        c.Config.TopP,
				MaxTokens:   c.Config.MaxTokens,
			}

			reqJSON, err = json.Marshal(anthropicReq)
		default:
			// 默认使用OpenAI兼容格式
			reqBody := AIRequest{
				Model:       c.Config.Model,
				Messages:    messages,
				Temperature: c.Config.Temperature,
				TopP:        c.Config.TopP,
				MaxTokens:   c.Config.MaxTokens,
			}
			reqJSON, err = json.Marshal(reqBody)
		}

		// 检查JSON序列化错误
		if err != nil {
			return "", fmt.Errorf("序列化请求失败: %v", err)
		}
		if err != nil {
			return "", fmt.Errorf("序列化请求失败: %v", err)
		}

		// 创建HTTP请求
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqJSON))
		if err != nil {
			return "", fmt.Errorf("创建请求失败: %v", err)
		}

		// 设置请求头
		req.Header.Set("Content-Type", "application/json")
		if authHeader := c.GetAuthorizationHeader(); authHeader != "" {
			utils.InfoPrint("使用API密钥进行认证...")
			req.Header.Set("Authorization", authHeader)
		}

		// 记录请求信息
		utils.InfoPrint("发送请求，模型: %s, 消息数: %d, 超时: %d秒",
			c.Config.Model, len(messages), c.Config.Timeout)

		// 发送请求
		startTime := time.Now()
		resp, err := c.Client.Do(req)
		requestDuration := time.Since(startTime)
		utils.InfoPrint("请求耗时: %v", requestDuration)

		// 记录请求信息到错误处理器
		if c.ErrorHandler != nil {
			c.ErrorHandler.Log("info", "ai_client", fmt.Sprintf("请求发送成功，耗时: %v", requestDuration),
				map[string]interface{}{
					"model":         c.Config.Model,
					"message_count": len(messages),
					"timeout":       c.Config.Timeout,
				})
		}

		// 监控连接状态
		if !c.ConnectionMonitor.MonitorConnection(err) {
			lastErr = fmt.Errorf("AI服务连接异常，建议检查网络和API配置")
			utils.ErrorPrint("连接监控器检测到服务异常，停止重试")

			// 记录连接异常
			if c.ErrorHandler != nil {
				c.ErrorHandler.Log("error", "connection_monitor", "连接监控器检测到服务异常",
					map[string]interface{}{
						"attempt": attempts,
						"error":   lastErr.Error(),
					})
			}

			break
		}

		if err != nil {
			lastErr = fmt.Errorf("发送请求失败: %v", err)
			utils.WarningPrint("AI请求失败，将重试: %v", lastErr)

			// 记录请求失败
			if c.ErrorHandler != nil {
				c.ErrorHandler.Log("warning", "ai_client", "请求发送失败",
					map[string]interface{}{
						"attempt":        attempts,
						"error":          err.Error(),
						"retry_strategy": retryStrategy.ShouldRetry(attempts, err),
					})
			}

			// 检查是否应该重试
			if !retryStrategy.ShouldRetry(attempts, err) {
				break
			}

			// 计算重试延迟
			delay := retryStrategy.CalculateDelay(attempts)
			time.Sleep(delay)
			totalDelay += delay
			continue
		}

		// 使用带超时的读取器读取响应
		startReadTime := time.Now()

		// 设置读取响应超时为总超时时间的90%，为流式响应留出更多时间
		readTimeout := time.Duration(float64(c.Config.Timeout)*0.9) * time.Second

		// 创建带超时的读取器，优化流式响应处理
		respBody, err := func() ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
			defer cancel()

			done := make(chan []byte)
			errChan := make(chan error)

			go func() {
				// 使用缓冲区读取，避免一次性读取大响应
				var body []byte
				buffer := make([]byte, 1024)

				for {
					n, readErr := resp.Body.Read(buffer)
					if n > 0 {
						body = append(body, buffer[:n]...)
					}

					if readErr != nil {
						if readErr == io.EOF {
							done <- body
							return
						}
						errChan <- readErr
						return
					}
				}
			}()

			select {
			case body := <-done:
				return body, nil
			case <-ctx.Done():
				resp.Body.Close()
				return nil, fmt.Errorf("读取响应超时: %v", ctx.Err())
			case err = <-errChan:
				return nil, err
			}
		}()

		resp.Body.Close() // 确保关闭响应体
		readDuration := time.Since(startReadTime)
		utils.InfoPrint("读取响应耗时: %v, 响应长度: %d字节", readDuration, len(respBody))

		if err != nil {
			lastErr = fmt.Errorf("读取响应失败: %v", err)
			utils.WarningPrint("读取AI响应失败，将重试: %v", lastErr)

			// 检查是否应该重试
			if !retryStrategy.ShouldRetry(attempts, err) {
				break
			}

			// 计算重试延迟
			delay := retryStrategy.CalculateDelay(attempts)
			time.Sleep(delay)
			totalDelay += delay
			continue
		}

		// 检查响应状态码，并进行智能重试决策
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API请求失败 (状态码: %d): %s", resp.StatusCode, string(respBody))
			utils.WarningPrint("AI API返回错误，状态码: %d", resp.StatusCode)

			// 智能状态码处理策略
			shouldRetry := false
			switch {
			case resp.StatusCode >= 500 && resp.StatusCode < 600:
				// 服务器错误（5xx）进行重试
				utils.InfoPrint("服务器错误 %d，将重试", resp.StatusCode)
				shouldRetry = true
			case resp.StatusCode == 429:
				// 限流错误，进行重试但增加延迟
				utils.InfoPrint("限流错误 429，将重试并增加延迟")
				shouldRetry = true
			case resp.StatusCode == 401:
				// 认证错误，不重试，直接返回错误
				utils.ErrorPrint("认证失败 (401)，请检查API密钥配置")
				return "", fmt.Errorf("API认证失败: 请检查API密钥和配置")
			case resp.StatusCode == 404:
				// 端点不存在，不重试，直接返回错误
				utils.ErrorPrint("API端点不存在 (404)，请检查BaseURL配置")
				return "", fmt.Errorf("API端点不存在: 请检查BaseURL配置是否正确")
			case resp.StatusCode == 400:
				// 请求错误，不重试，直接返回错误
				utils.ErrorPrint("请求参数错误 (400): %s", string(respBody))
				return "", fmt.Errorf("请求参数错误: %s", string(respBody))
			case resp.StatusCode >= 400 && resp.StatusCode < 500:
				// 其他客户端错误，不重试
				utils.ErrorPrint("客户端错误 %d: %s", resp.StatusCode, string(respBody))
				return "", lastErr
			default:
				// 其他未知状态码，进行重试
				utils.WarningPrint("未知状态码 %d，将重试", resp.StatusCode)
				shouldRetry = true
			}

			if shouldRetry {
				if !retryStrategy.ShouldRetry(attempts, fmt.Errorf("status code: %d", resp.StatusCode)) {
					break
				}

				// 对于429错误，增加额外的延迟
				if resp.StatusCode == 429 {
					time.Sleep(5 * time.Second) // 额外5秒延迟
				}

				// 计算重试延迟
				delay := retryStrategy.CalculateDelay(attempts)
				time.Sleep(delay)
				totalDelay += delay
				continue
			}

			return "", lastErr
		}

		// 解析响应
		content, err := c.parseResponse(respBody, c.Config.Provider)
		if err != nil {
			lastErr = fmt.Errorf("解析响应失败: %v", err)
			utils.WarningPrint("解析AI响应失败，将重试: %v", lastErr)

			// 检查是否应该重试
			if !retryStrategy.ShouldRetry(attempts, err) {
				break
			}

			// 计算重试延迟
			delay := retryStrategy.CalculateDelay(attempts)
			time.Sleep(delay)
			totalDelay += delay
			continue
		}

		// 检查是否有响应内容
		if content == "" {
			lastErr = fmt.Errorf("AI未返回有效响应")
			utils.WarningPrint("AI未返回有效响应，将重试")

			// 检查是否应该重试
			if !retryStrategy.ShouldRetry(attempts, fmt.Errorf("empty response")) {
				break
			}

			// 计算重试延迟
			delay := retryStrategy.CalculateDelay(attempts)
			time.Sleep(delay)
			totalDelay += delay
			continue
		}

		// 记录重试统计
		stats := retryStrategy.GetRetryStats(attempts, totalDelay)
		utils.InfoPrint("重试统计: 尝试次数=%d, 总延迟=%v, 平均延迟=%v",
			stats["attempts_made"], stats["total_delay"], stats["average_delay"])

		utils.InfoPrint("AI请求成功，获得响应")
		return content, nil
	}

	utils.ErrorPrint("AI请求最终失败，尝试次数: %d", attempts)
	return "", lastErr
}

// AnalyzeScanResults 分析扫描结果并生成漏洞利用建议
func (c *AIClient) AnalyzeScanResults(target string, scanResults string, availableTools map[string]bool) (string, error) {
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

	// 构建对话消息
	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: userContent,
		},
	}

	// 记录请求大小
	utils.InfoPrint("请求消息大小: 系统提示 %d 字符, 用户请求 %d 字符",
		len(systemPrompt), len(userContent))

	// 调用AI服务
	response, err := c.Chat(messages)
	if err != nil {
		return "", fmt.Errorf("AI分析失败: %v", err)
	}

	return response, nil
}

// DecideInfoCollectionStrategy 让AI自主制定信息收集策略
func (c *AIClient) DecideInfoCollectionStrategy(target string, availableTools map[string]bool) (string, error) {
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

	// 智能信息收集策略提示 - 让AI自主决策
	systemPrompt := `你是一名专业的信息安全专家。请根据目标特点和可用工具，自主制定个性化的信息收集策略。

你的任务：
1. 分析目标类型（IP地址、域名、URL）并选择最合适的信息收集方法
2. 根据可用工具制定具体的执行步骤
3. 考虑目标特点，制定针对性的信息收集策略
4. 生成具体的、可执行的命令行操作

决策原则：
- IP地址：优先进行端口扫描、服务识别、操作系统检测
- 域名：优先进行DNS查询、子域名枚举、WHOIS查询
- URL：优先进行HTTP头信息收集、目录扫描、技术栈识别
- 根据开放端口选择进一步的信息收集方法
- 动态调整策略：根据前一步的结果决定后续操作

输出格式：
请以JSON格式返回决策结果，包含以下字段：
{
  "strategy": "信息收集策略描述",
  "steps": [
    {
      "step": "步骤描述",
      "tool": "工具名称",
      "command": "完整命令行",
      "reason": "选择此步骤的原因"
    }
  ]
}

可用工具：` + availableToolsStr

	// 构建用户请求
	targetType := getTargetType(target)
	userContent := fmt.Sprintf(`目标: %s
目标类型: %s
可用工具: %s

请根据目标特点制定个性化的信息收集策略，包括：
1. 分析目标类型并选择合适的信息收集方法
2. 制定具体的执行步骤和命令
3. 提供每个步骤的选择理由

请以JSON格式返回完整的决策方案。`,
		target, targetType, availableToolsStr)

	// 构建对话消息
	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: userContent,
		},
	}

	// 调用AI服务
	response, err := c.Chat(messages)
	if err != nil {
		return "", fmt.Errorf("AI信息收集策略制定失败: %v", err)
	}

	return response, nil
}

// getTargetType 分析目标类型
func getTargetType(target string) string {
	// 判断目标类型
	if strings.Contains(target, "://") {
		return "URL"
	} else if strings.Contains(target, ".") && !strings.Contains(target, " ") {
		// 检查是否是IP地址
		if net.ParseIP(target) != nil {
			return "IP地址"
		}
		return "域名"
	}
	return "未知类型"
}

// parseResponse 解析不同服务提供商的响应格式
func (c *AIClient) parseResponse(respBody []byte, provider string) (string, error) {
	// 根据服务提供商选择不同的解析策略
	switch provider {
	case "ollama":
		// Ollama返回的是流式响应，每行一个JSON对象
		return c.parseOllamaResponse(respBody)
	case "anthropic", "anthropic-streaming":
		// Anthropic使用不同的响应格式
		return c.parseAnthropicResponse(respBody)
	case "google":
		// Google Gemini使用不同的响应格式
		return c.parseGoogleResponse(respBody)
	case "cohere":
		// Cohere使用不同的响应格式
		return c.parseCohereResponse(respBody)
	case "deepseek", "openai", "azure", "mistral", "togetherai", "openrouter", "moonshot", "zhipu", "qwen", "doubao", "dashscope", "perplexity", "fireworks", "inflection", "siliconflow":
		// 这些提供商使用OpenAI兼容格式
		return c.parseOpenAIResponse(respBody)
	default:
		// 其他提供商使用OpenAI兼容格式
		return c.parseOpenAIResponse(respBody)
	}
}

// parseOllamaResponse 解析Ollama的流式响应格式
func (c *AIClient) parseOllamaResponse(respBody []byte) (string, error) {
	var contentBuilder strings.Builder

	// 按行分割响应体
	lines := strings.Split(string(respBody), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析每行的JSON对象
		var ollamaResp struct {
			Model     string `json:"model"`
			CreatedAt string `json:"created_at"`
			Message   struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			Done       bool   `json:"done"`
			DoneReason string `json:"done_reason"`
		}

		if err := json.Unmarshal([]byte(line), &ollamaResp); err != nil {
			utils.WarningPrint("解析Ollama响应行失败: %v, 行内容: %s", err, line)
			continue
		}

		// 只处理assistant角色的消息内容
		if ollamaResp.Message.Role == "assistant" && ollamaResp.Message.Content != "" {
			contentBuilder.WriteString(ollamaResp.Message.Content)
		}

		// 如果响应完成，则停止处理
		if ollamaResp.Done {
			break
		}
	}

	content := contentBuilder.String()
	if content == "" {
		return "", fmt.Errorf("Ollama未返回有效内容")
	}

	utils.InfoPrint("Ollama响应解析成功，内容长度: %d 字符", len(content))
	return content, nil
}

// parseOpenAIResponse 解析OpenAI兼容的响应格式
func (c *AIClient) parseOpenAIResponse(respBody []byte) (string, error) {
	// 首先尝试标准的OpenAI格式
	var aiResp AIResponse
	if err := json.Unmarshal(respBody, &aiResp); err == nil {
		if len(aiResp.Choices) > 0 && aiResp.Choices[0].Message.Content != "" {
			utils.InfoPrint("OpenAI标准格式解析成功，内容长度: %d 字符", len(aiResp.Choices[0].Message.Content))
			return aiResp.Choices[0].Message.Content, nil
		}
	}

	// 如果标准格式失败，尝试更通用的格式
	var genericResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Text string `json:"text"`
		Data struct {
			Text string `json:"text"`
		} `json:"data"`
		Result   string `json:"result"`
		Output   string `json:"output"`
		Response string `json:"response"`
		Message  string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &genericResp); err != nil {
		return "", fmt.Errorf("解析OpenAI兼容响应失败: %v", err)
	}

	// 尝试不同的字段获取内容
	if len(genericResp.Choices) > 0 && genericResp.Choices[0].Message.Content != "" {
		utils.InfoPrint("OpenAI兼容格式解析成功，内容长度: %d 字符", len(genericResp.Choices[0].Message.Content))
		return genericResp.Choices[0].Message.Content, nil
	}

	if genericResp.Text != "" {
		utils.InfoPrint("文本字段解析成功，内容长度: %d 字符", len(genericResp.Text))
		return genericResp.Text, nil
	}

	if genericResp.Data.Text != "" {
		utils.InfoPrint("数据文本字段解析成功，内容长度: %d 字符", len(genericResp.Data.Text))
		return genericResp.Data.Text, nil
	}

	if genericResp.Result != "" {
		utils.InfoPrint("结果字段解析成功，内容长度: %d 字符", len(genericResp.Result))
		return genericResp.Result, nil
	}

	if genericResp.Output != "" {
		utils.InfoPrint("输出字段解析成功，内容长度: %d 字符", len(genericResp.Output))
		return genericResp.Output, nil
	}

	if genericResp.Response != "" {
		utils.InfoPrint("响应字段解析成功，内容长度: %d 字符", len(genericResp.Response))
		return genericResp.Response, nil
	}

	if genericResp.Message != "" {
		utils.InfoPrint("消息字段解析成功，内容长度: %d 字符", len(genericResp.Message))
		return genericResp.Message, nil
	}

	return "", fmt.Errorf("OpenAI兼容响应未包含有效内容")
}

// parseAnthropicResponse 解析Anthropic的响应格式
func (c *AIClient) parseAnthropicResponse(respBody []byte) (string, error) {
	var anthropicResp struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason,omitempty"`
		StopSeq    string `json:"stop_sequence,omitempty"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return "", fmt.Errorf("解析Anthropic响应失败: %v", err)
	}

	// 检查是否有响应内容
	if len(anthropicResp.Content) == 0 || anthropicResp.Content[0].Text == "" {
		return "", fmt.Errorf("Anthropic未返回有效响应")
	}

	content := anthropicResp.Content[0].Text
	utils.InfoPrint("Anthropic响应解析成功，内容长度: %d 字符", len(content))
	return content, nil
}

// parseGoogleResponse 解析Google Gemini的响应格式
func (c *AIClient) parseGoogleResponse(respBody []byte) (string, error) {
	var googleResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason  string `json:"finishReason"`
			SafetyRatings []struct {
				Category    string `json:"category"`
				Probability string `json:"probability"`
			} `json:"safetyRatings"`
		} `json:"candidates"`
		Usage struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(respBody, &googleResp); err != nil {
		return "", fmt.Errorf("解析Google响应失败: %v", err)
	}

	// 检查是否有响应内容
	if len(googleResp.Candidates) == 0 || len(googleResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("Google未返回有效响应")
	}

	content := googleResp.Candidates[0].Content.Parts[0].Text
	utils.InfoPrint("Google响应解析成功，内容长度: %d 字符", len(content))
	return content, nil
}

// parseCohereResponse 解析Cohere的响应格式
func (c *AIClient) parseCohereResponse(respBody []byte) (string, error) {
	var cohereResp struct {
		ID           string `json:"id"`
		Text         string `json:"text"`
		FinishReason string `json:"finish_reason"`
		Usage        struct {
			PromptTokens     int `json:"prompt_tokens"`
			GenerationTokens int `json:"generation_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(respBody, &cohereResp); err != nil {
		return "", fmt.Errorf("解析Cohere响应失败: %v", err)
	}

	// 检查是否有响应内容
	if cohereResp.Text == "" {
		return "", fmt.Errorf("Cohere未返回有效响应")
	}

	utils.InfoPrint("Cohere响应解析成功，内容长度: %d 字符", len(cohereResp.Text))
	return cohereResp.Text, nil
}

// Plan 生成渗透测试计划
func (c *AIClient) Plan(target string, scanResults string, availableTools map[string]bool) (string, error) {
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

	// 构建计划请求
	systemPrompt := `你是一名专业的渗透测试工程师。请根据目标信息和可用工具，生成详细的渗透测试计划。`
	userContent := fmt.Sprintf("目标: %s\n\n扫描结果:\n%s\n\n可用工具: %s\n\n请生成一个结构化的渗透测试计划，包括：\n1. 阶段划分\n2. 每个阶段使用的工具和参数\n3. 预期目标\n4. 执行顺序",
		target, scanResults, availableToolsStr)

	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: userContent,
		},
	}

	return c.Chat(messages)
}

// ParseResult 解析AI返回的结果
func (c *AIClient) ParseResult(result string) (string, error) {
	// 这里可以实现AI结果的解析逻辑
	// 暂时直接返回结果
	return result, nil
}

// ChatStream 流式聊天（当前实现不支持流式，暂返回错误）
func (c *AIClient) ChatStream(messages []Message, onChunk func(string)) error {
	return fmt.Errorf("当前HTTP客户端不支持流式响应，请使用OpenAIClient")
}

// GetHealthStatus 获取健康状态
func (c *AIClient) GetHealthStatus() bool {
	return c.HealthChecker.IsHealthy
}

// Close 关闭客户端连接
func (c *AIClient) Close() error {
	// HTTP客户端不需要显式关闭
	return nil
}

// Analyze 分析数据并生成AI决策建议
func (c *AIClient) Analyze(analysisData interface{}) (string, error) {
	// 将分析数据转换为JSON字符串
	dataJSON, err := json.Marshal(analysisData)
	if err != nil {
		return "", fmt.Errorf("序列化分析数据失败: %v", err)
	}

	// 构建系统提示
	systemPrompt := `你是一名专业的AI决策系统。请分析提供的数据，生成智能决策建议。`

	// 构建用户请求
	userContent := fmt.Sprintf("请分析以下数据并生成决策建议:\n\n%s", string(dataJSON))

	// 构建对话消息
	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: userContent,
		},
	}

	// 调用AI服务
	response, err := c.Chat(messages)
	if err != nil {
		return "", fmt.Errorf("AI分析失败: %v", err)
	}

	return response, nil
}
