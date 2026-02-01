package ws

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"
	"github.com/gorilla/websocket"
)

type MessageType string

const (
	TextMessage   MessageType = "text"
	BinaryMessage MessageType = "binary"
)

type AssertionType string

const (
	ContainsAssertion      AssertionType = "contains"
	RegexAssertion         AssertionType = "regex"
	EqualsAssertion        AssertionType = "equals"
	JSONFieldAssertion     AssertionType = "json_field"
	LengthGreaterAssertion AssertionType = "length_greater"
)

type Assertion struct {
	Type      AssertionType
	Target    string
	Field     string
	Negated   bool
	MinLength int
}

type WsConfig struct {
	URL               string
	Message           string
	MessageType       MessageType
	Headers           map[string]string
	Reconnect         bool
	MaxRetries        int
	MaxDelay          time.Duration
	Assertions        []Assertion
	Timeout           time.Duration
	Count             int
	Interval          time.Duration
	Verbose           bool
	Heartbeat         bool
	HeartbeatMsg      string
	HeartbeatInterval time.Duration
	SkipVerify        bool
	Origin            string
	Subprotocols      []string
	SendDelay         time.Duration
	NetworkTimeout    time.Duration
}

type WsResult struct {
	Connected        bool
	ConnectionState  string
	HandshakeSuccess bool
	HTTPStatusCode   int
	Messages         []string
	BinaryMessages   [][]byte
	AssertionPassed  bool
	AssertionError   string
	AssertionDetails []AssertionResult
	RetryCount       int
	TotalDuration    time.Duration
	BytesSent        int64
	BytesReceived    int64
	Error            string
	CloseCode        int
	CloseReason      string
	Latency          []time.Duration
	SuccessCount     int
	FailureCount     int
}

type AssertionResult struct {
	Passed   bool
	Type     AssertionType
	Target   string
	Expected string
	Actual   string
}

type ReconnectPolicy struct {
	MaxRetries   int
	MaxDelay     time.Duration
	InitialDelay time.Duration
	Jitter       float64
}

type WsClient struct {
	conn             *websocket.Conn
	config           *WsConfig
	reconnectPolicy  *ReconnectPolicy
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	closed           bool
	messagesSent     int64
	messagesReceived int64
	bytesSent        int64
	bytesReceived    int64
	latency          []time.Duration
	latencyMu        sync.Mutex
	startTime        time.Time
	rnd              *rand.Rand
}

type Message struct {
	Type     int
	Data     []byte
	Received time.Time
}

func NewWsClient(config *WsConfig) *WsClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &WsClient{
		config: config,
		reconnectPolicy: &ReconnectPolicy{
			MaxRetries:   config.MaxRetries,
			MaxDelay:     config.MaxDelay,
			InitialDelay: time.Second,
			Jitter:       0.1,
		},
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		latency:   make([]time.Duration, 0),
		startTime: time.Now(),
		rnd:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (c *WsClient) Connect() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dialer := websocket.Dialer{
		HandshakeTimeout: c.config.NetworkTimeout,
		Subprotocols:     c.config.Subprotocols,
	}

	headers := make(http.Header)
	for k, v := range c.config.Headers {
		headers.Set(k, v)
	}

	if c.config.Origin != "" {
		headers.Set("Origin", c.config.Origin)
	}

	conn, resp, err := dialer.DialContext(c.ctx, c.config.URL, headers)
	if err != nil {
		if strings.Contains(err.Error(), "bad handshake") && len(c.config.Subprotocols) > 0 {
			return 0, fmt.Errorf("连接失败: %v\n提示: 连接可能被Subprotocol拒绝。可尝试不使用--subprotocols参数", err)
		}
		return 0, fmt.Errorf("连接失败: %v", err)
	}

	c.conn = conn

	if c.config.Verbose {
		utils.LogInfo("握手成功: HTTP %d", resp.StatusCode)
		if resp.Header.Get("Sec-WebSocket-Protocol") != "" {
			utils.LogInfo("WebSocket协议: %s", resp.Header.Get("Sec-WebSocket-Protocol"))
		}
	}

	return resp.StatusCode, nil
}

func (c *WsClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func (c *WsClient) SendMessage() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, fmt.Errorf("连接未建立")
	}

	var data []byte
	var msgType int
	var err error

	switch c.config.MessageType {
	case BinaryMessage:
		data, err = c.parseBinaryInput(c.config.Message)
		if err != nil {
			data = []byte(c.config.Message)
		}
		msgType = websocket.BinaryMessage
		if c.config.Verbose {
			utils.LogInfo("发送二进制消息: %d 字节", len(data))
		}
	default:
		data = []byte(c.config.Message)
		msgType = websocket.TextMessage
		if c.config.Verbose {
			utils.LogInfo("发送文本消息: %s", truncate(c.config.Message, 100))
		}
	}

	err = c.conn.WriteMessage(msgType, data)
	if err != nil {
		return 0, err
	}

	c.messagesSent++
	c.bytesSent += int64(len(data))
	return len(data), nil
}

func (c *WsClient) SendLargeMessage(size int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}

	data := make([]byte, size)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}

	if c.config.Verbose {
		utils.LogInfo("发送大消息: %d 字节", size)
	}

	err := c.conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return nil, err
	}

	c.messagesSent++
	c.bytesSent += int64(len(data))
	return data, nil
}

func (c *WsClient) SendMessages(count int, interval time.Duration) ([]int64, error) {
	sizes := make([]int64, 0, count)

	for i := 0; i < count; i++ {
		size, err := c.SendMessage()
		if err != nil {
			return sizes, err
		}
		sizes = append(sizes, int64(size))

		if i < count-1 {
			time.Sleep(interval)
		}
	}

	return sizes, nil
}

func (c *WsClient) ReceiveMessage() (*Message, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}

	conn.SetReadDeadline(time.Now().Add(c.config.Timeout))
	msgType, data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.messagesReceived++
	c.bytesReceived += int64(len(data))
	c.mu.Unlock()

	return &Message{
		Type:     msgType,
		Data:     data,
		Received: time.Now(),
	}, nil
}

func (c *WsClient) ReceiveMultiple(count int, timeout time.Duration) ([]*Message, error) {
	messages := make([]*Message, 0, count)

	for i := 0; i < count; i++ {
		msg, err := c.ReceiveWithTimeout(timeout)
		if err != nil {
			if c.config.Verbose {
				utils.LogWarning("接收消息 %d/%d 失败: %v", i+1, count, err)
			}
			break
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

func (c *WsClient) ReceiveWithTimeout(timeout time.Duration) (*Message, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("连接未建立")
	}

	type result struct {
		msg *Message
		err error
	}
	respChan := make(chan result, 1)

	go func() {
		conn.SetReadDeadline(time.Now().Add(timeout))
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			respChan <- result{nil, err}
			return
		}

		c.mu.Lock()
		c.messagesReceived++
		c.bytesReceived += int64(len(data))
		c.mu.Unlock()

		respChan <- result{
			msg: &Message{
				Type:     msgType,
				Data:     data,
				Received: time.Now(),
			},
			err: nil,
		}
	}()

	select {
	case r := <-respChan:
		return r.msg, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("接收超时")
	case <-c.ctx.Done():
		return nil, fmt.Errorf("上下文已取消")
	}
}

func (c *WsClient) SendPing() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("连接未建立")
	}

	return c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.config.Timeout))
}

func (c *WsClient) SendPong(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("连接未建立")
	}

	return c.conn.WriteControl(websocket.PongMessage, data, time.Now().Add(c.config.Timeout))
}

func (c *WsClient) CloseWithReason(code int, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	close(c.done)
	c.cancel()

	if c.conn != nil {
		if c.config.Verbose {
			utils.LogInfo("发送关闭帧: 代码=%d, 原因=%s", code, reason)
		}
		return c.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(code, reason),
			time.Now().Add(c.config.Timeout))
	}
	return nil
}

func (c *WsClient) parseBinaryInput(input string) ([]byte, error) {
	input = strings.TrimSpace(input)

	if strings.HasPrefix(input, "base64:") {
		encoded := strings.TrimPrefix(input, "base64:")
		return base64.StdEncoding.DecodeString(encoded)
	}

	if strings.HasPrefix(input, "hex:") {
		encoded := strings.TrimPrefix(input, "hex:")
		return hex.DecodeString(encoded)
	}

	if isValidHexString(input) {
		return hex.DecodeString(input)
	}

	return nil, fmt.Errorf("无法识别的二进制格式，支持: hex编码或base64:前缀")
}

func isValidHexString(s string) bool {
	s = strings.TrimSpace(s)
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func (c *WsClient) RunWithReconnect() WsResult {
	result := WsResult{
		Messages:         make([]string, 0),
		BinaryMessages:   make([][]byte, 0),
		AssertionDetails: make([]AssertionResult, 0),
		Latency:          make([]time.Duration, 0),
	}
	startTime := time.Now()

	for attempt := 0; attempt <= c.reconnectPolicy.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := c.calculateBackoff(attempt)
			utils.LogWarning("第 %d 次重连尝试，延迟 %v", attempt, delay)

			select {
			case <-time.After(delay):
			case <-c.ctx.Done():
				result.Error = "上下文已取消"
				return result
			}
		}

		statusCode, err := c.Connect()
		if err != nil {
			result.RetryCount = attempt
			result.HTTPStatusCode = statusCode
			if attempt == c.reconnectPolicy.MaxRetries {
				result.Error = fmt.Sprintf("达到最大重试次数 (%d): %v", attempt, err)
				return result
			}
			continue
		}

		result.Connected = true
		result.HandshakeSuccess = true
		result.HTTPStatusCode = statusCode
		if c.IsConnected() {
			result.ConnectionState = "open"
		}
		utils.LogSuccess("WebSocket 连接成功，状态: %s", result.ConnectionState)

		break
	}

	if !result.Connected {
		result.Error = "无法建立连接"
		result.ConnectionState = "closed"
		return result
	}

	defer c.CloseWithReason(websocket.CloseNormalClosure, "测试完成")

	msgs, err := c.sendAndReceiveWithMetrics()
	if err != nil {
		result.Error = err.Error()
	}

	for _, msg := range msgs {
		if msg.Type == websocket.TextMessage {
			result.Messages = append(result.Messages, string(msg.Data))
		} else {
			result.BinaryMessages = append(result.BinaryMessages, msg.Data)
		}
	}

	result.TotalDuration = time.Since(startTime)
	result.Latency = c.getLatency()

	if len(c.config.Assertions) > 0 {
		assertionResults, passed, errMsg := c.validateAllAssertions(result.Messages, result.BinaryMessages)
		result.AssertionDetails = assertionResults
		result.AssertionPassed = passed
		result.AssertionError = errMsg
	}

	result.BytesSent = c.bytesSent
	result.BytesReceived = c.bytesReceived
	result.SuccessCount = int(c.messagesReceived)
	result.FailureCount = len(msgs) - int(c.messagesReceived)

	return result
}

func (c *WsClient) sendAndReceiveWithMetrics() ([]*Message, error) {
	messages := make([]*Message, 0)

	var heartbeatTicker *time.Ticker
	if c.config.Heartbeat && c.config.HeartbeatInterval > 0 {
		heartbeatTicker = time.NewTicker(c.config.HeartbeatInterval)
		defer heartbeatTicker.Stop()
	}

	for i := 0; i < c.config.Count; i++ {
		if heartbeatTicker != nil {
			select {
			case <-heartbeatTicker.C:
				if c.config.Heartbeat && c.IsConnected() {
					if c.config.Verbose {
						utils.LogInfo("发送心跳: %s", c.config.HeartbeatMsg)
					}
					c.SendPing()
				}
			default:
			}
		}

		sendTime := time.Now()

		var err error
		switch c.config.MessageType {
		case BinaryMessage:
			_, err = c.SendMessage()
		default:
			_, err = c.SendMessage()
		}

		if err != nil {
			return messages, fmt.Errorf("发送消息失败: %v", err)
		}

		if c.config.Verbose {
			utils.LogInfo("消息已发送 (第 %d/%d 次)", i+1, c.config.Count)
		}

		time.Sleep(c.config.SendDelay)

		if i < c.config.Count-1 || c.config.Count == 1 {
			msg, err := c.ReceiveWithTimeout(c.config.Timeout)
			if err != nil {
				if c.config.Verbose {
					utils.LogWarning("接收消息失败: %v", err)
				}
				continue
			}

			c.latencyMu.Lock()
			c.latency = append(c.latency, time.Since(sendTime))
			c.latencyMu.Unlock()

			messages = append(messages, msg)

			if c.config.Verbose {
				if msg.Type == websocket.TextMessage {
					utils.LogInfo("收到响应: %s", truncate(string(msg.Data), 200))
				} else {
					utils.LogInfo("收到二进制响应: %d 字节", len(msg.Data))
				}
			}
		}

		if i < c.config.Count-1 {
			time.Sleep(c.config.Interval)
		}
	}

	return messages, nil
}

func (c *WsClient) calculateBackoff(attempt int) time.Duration {
	delay := float64(c.reconnectPolicy.InitialDelay) * math.Pow(2, float64(attempt))
	if delay > float64(c.reconnectPolicy.MaxDelay) {
		delay = float64(c.reconnectPolicy.MaxDelay)
	}
	jitter := delay * c.reconnectPolicy.Jitter * (c.rnd.Float64()*2 - 1)
	delay += jitter
	return time.Duration(delay)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (c *WsClient) validateAllAssertions(textMessages []string, binaryMessages [][]byte) ([]AssertionResult, bool, string) {
	results := make([]AssertionResult, 0)
	allPassed := true

	for _, assertion := range c.config.Assertions {
		result := c.validateSingleAssertion(assertion, textMessages, binaryMessages)
		results = append(results, result)
		if !result.Passed {
			allPassed = false
		}
	}

	var errorMsg string
	if !allPassed {
		errorMsg = fmt.Sprintf("%d/%d 断言失败", len(results)-countPassed(results), len(results))
	}

	return results, allPassed, errorMsg
}

func (c *WsClient) validateSingleAssertion(assertion Assertion, textMessages []string, binaryMessages [][]byte) AssertionResult {
	result := AssertionResult{
		Type:   assertion.Type,
		Target: assertion.Target,
		Passed: false,
	}

	switch assertion.Type {
	case ContainsAssertion:
		for _, msg := range textMessages {
			if strings.Contains(msg, assertion.Target) {
				result.Passed = true
				result.Actual = msg
				break
			}
		}
		if assertion.Negated {
			result.Passed = !result.Passed
		}
		result.Expected = fmt.Sprintf("包含 '%s'", assertion.Target)

	case RegexAssertion:
		pattern := regexp.MustCompile(assertion.Target)
		for _, msg := range textMessages {
			if pattern.MatchString(msg) {
				result.Passed = true
				result.Actual = msg
				break
			}
		}
		if assertion.Negated {
			result.Passed = !result.Passed
		}
		result.Expected = fmt.Sprintf("匹配正则 '%s'", assertion.Target)

	case EqualsAssertion:
		for _, msg := range textMessages {
			if msg == assertion.Target {
				result.Passed = true
				break
			}
		}
		if assertion.Negated {
			result.Passed = !result.Passed
		}
		result.Expected = fmt.Sprintf("等于 '%s'", assertion.Target)

	case JSONFieldAssertion:
		for _, msg := range textMessages {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(msg), &data); err == nil {
				if assertion.Field != "" {
					if val, ok := data[assertion.Field]; ok {
						valStr := fmt.Sprintf("%v", val)
						if strings.Contains(valStr, assertion.Target) {
							result.Passed = true
							result.Actual = valStr
							break
						}
					}
				}
			}
		}
		result.Expected = fmt.Sprintf("JSON字段%s包含 '%s'", assertion.Field, assertion.Target)

	case LengthGreaterAssertion:
		totalLen := len(strings.Join(textMessages, ""))
		for _, binMsg := range binaryMessages {
			totalLen += len(binMsg)
		}
		result.Passed = totalLen > assertion.MinLength
		result.Actual = fmt.Sprintf("%d 字节", totalLen)
		result.Expected = fmt.Sprintf("长度 > %d", assertion.MinLength)
	}

	return result
}

func countPassed(results []AssertionResult) int {
	count := 0
	for _, r := range results {
		if r.Passed {
			count++
		}
	}
	return count
}

func (c *WsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	close(c.done)
	c.cancel()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *WsClient) GetStats() (sent, received int64, bytesS, bytesR int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.messagesSent, c.messagesReceived, c.bytesSent, c.bytesReceived
}

func (c *WsClient) getLatency() []time.Duration {
	c.latencyMu.Lock()
	defer c.latencyMu.Unlock()
	return append([]time.Duration{}, c.latency...)
}

func RunWsTest(config WsConfig) WsResult {
	if config.Verbose {
		utils.LogModuleStart("WebSocket 测试")
	}

	client := NewWsClient(&config)

	if config.Reconnect {
		return client.RunWithReconnect()
	}

	result := WsResult{
		Messages:         make([]string, 0),
		BinaryMessages:   make([][]byte, 0),
		AssertionDetails: make([]AssertionResult, 0),
		Latency:          make([]time.Duration, 0),
	}
	startTime := time.Now()

	statusCode, err := client.Connect()
	if err != nil {
		result.Error = err.Error()
		result.HTTPStatusCode = statusCode
		result.ConnectionState = "failed"
		if config.Verbose {
			utils.LogError("连接失败: %v", err)
		}
		return result
	}

	result.Connected = true
	result.HandshakeSuccess = true
	result.HTTPStatusCode = statusCode
	if client.IsConnected() {
		result.ConnectionState = "open"
	}
	utils.LogSuccess("WebSocket 连接成功，状态: %s", result.ConnectionState)

	defer client.Close()

	msgs, err := client.sendAndReceiveWithMetrics()
	if err != nil {
		result.Error = err.Error()
		if config.Verbose {
			utils.LogError("测试失败: %v", err)
		}
	}

	for _, msg := range msgs {
		if msg.Type == websocket.TextMessage {
			result.Messages = append(result.Messages, string(msg.Data))
		} else {
			result.BinaryMessages = append(result.BinaryMessages, msg.Data)
		}
	}

	result.TotalDuration = time.Since(startTime)
	result.Latency = client.getLatency()

	if len(config.Assertions) > 0 {
		assertionResults, passed, errMsg := client.validateAllAssertions(result.Messages, result.BinaryMessages)
		result.AssertionDetails = assertionResults
		result.AssertionPassed = passed
		result.AssertionError = errMsg
		if config.Verbose {
			if result.AssertionPassed {
				utils.LogSuccess("断言验证通过 (%d/%d)", countPassed(assertionResults), len(assertionResults))
			} else {
				utils.LogWarning("断言验证失败: %s", errMsg)
			}
		}
	}

	result.BytesSent = client.bytesSent
	result.BytesReceived = client.bytesReceived
	result.SuccessCount = int(client.messagesReceived)

	return result
}

func RunPerformanceTest(config WsConfig, duration time.Duration) WsResult {
	if config.Verbose {
		utils.LogModuleStart("WebSocket 性能测试")
	}

	client := NewWsClient(&config)

	statusCode, err := client.Connect()
	if err != nil {
		return WsResult{Error: err.Error(), HTTPStatusCode: statusCode}
	}

	result := WsResult{
		Connected:        true,
		HandshakeSuccess: true,
		HTTPStatusCode:   statusCode,
		ConnectionState:  "open",
		TotalDuration:    duration,
		Latency:          make([]time.Duration, 0),
	}
	startTime := time.Now()

	endTime := startTime.Add(duration)
	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Now().After(endTime) {
				goto done
			}
			_, err := client.SendMessage()
			if err != nil {
				if config.Verbose {
					utils.LogWarning("发送失败: %v", err)
				}
				continue
			}

			msg, err := client.ReceiveWithTimeout(config.Timeout)
			if err != nil {
				if config.Verbose {
					utils.LogWarning("接收失败: %v", err)
				}
				continue
			}

			client.latencyMu.Lock()
			client.latency = append(client.latency, time.Since(startTime))
			client.latencyMu.Unlock()

			result.Messages = append(result.Messages, string(msg.Data))
			result.SuccessCount++

		case <-client.ctx.Done():
			goto done
		}
	}

done:
	client.Close()
	result.TotalDuration = time.Since(startTime)
	result.Latency = client.getLatency()
	result.BytesSent = client.bytesSent
	result.BytesReceived = client.bytesReceived

	return result
}

func RunStressTest(config WsConfig, connections int, duration time.Duration) []WsResult {
	results := make([]WsResult, connections)
	var wg sync.WaitGroup

	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = RunWsTest(config)
		}(i)
	}

	wg.Wait()
	return results
}
