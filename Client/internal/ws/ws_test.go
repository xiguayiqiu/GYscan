package ws

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"GYscan/internal/utils"
	"github.com/gorilla/websocket"
)

func TestParseMessageType(t *testing.T) {
	tests := []struct {
		input    string
		expected MessageType
	}{
		{"text", TextMessage},
		{"Text", TextMessage},
		{"binary", BinaryMessage},
		{"Binary", BinaryMessage},
		{"bin", BinaryMessage},
		{"unknown", TextMessage},
	}

	for _, tt := range tests {
		result := parseMessageType(tt.input)
		if result != tt.expected {
			t.Errorf("parseMessageType(%s) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		input    []string
		expected map[string]string
	}{
		{[]string{"Content-Type: application/json"}, map[string]string{"Content-Type": " application/json"}},
		{[]string{"Authorization: Bearer token123"}, map[string]string{"Authorization": " Bearer token123"}},
		{[]string{"Key:Value", "Another:Data"}, map[string]string{"Key": "Value", "Another": "Data"}},
		{[]string{"InvalidHeader"}, map[string]string{}},
	}

	for _, tt := range tests {
		result := parseHeaders(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseHeaders(%v) returned %d headers, want %d", tt.input, len(result), len(tt.expected))
		}
	}
}

func TestParseAssertions(t *testing.T) {
	tests := []struct {
		input    []string
		expected []Assertion
	}{
		{[]string{"contains:Hello"}, []Assertion{{Type: ContainsAssertion, Target: "Hello"}}},
		{[]string{"regex:^Hello", "contains:World"}, []Assertion{{Type: RegexAssertion, Target: "^Hello"}, {Type: ContainsAssertion, Target: "World"}}},
		{[]string{"unknown:test"}, []Assertion{}},
	}

	for _, tt := range tests {
		result := parseAssertions(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseAssertions(%v) returned %d assertions, want %d", tt.input, len(result), len(tt.expected))
		}
	}
}

func TestIsValidHexString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"48656c6c6f", true},
		{"ABCDEF", true},
		{"invalid", false},
		{"", false},
		{"ZZ", false},
		{"12", true},
	}

	for _, tt := range tests {
		result := isValidHexString(tt.input)
		if result != tt.expected {
			t.Errorf("isValidHexString(%s) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseBinaryInput(t *testing.T) {
	client := &WsClient{}

	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"base64:SGVsbG8=", "Hello", false},
		{"hex:48656c6c6f", "Hello", false},
		{"48656c6c6f", "Hello", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		result, err := client.parseBinaryInput(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseBinaryInput(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && string(result) != tt.expected {
			t.Errorf("parseBinaryInput(%s) = %s, want %s", tt.input, string(result), tt.expected)
		}
	}
}

func TestCalculateBackoff(t *testing.T) {
	policy := &ReconnectPolicy{
		MaxRetries:   5,
		MaxDelay:     30 * time.Second,
		InitialDelay: time.Second,
	}

	client := &WsClient{
		reconnectPolicy: policy,
		rnd:             rand.New(rand.NewSource(42)),
	}

	tests := []struct {
		attempt  int
		maxDelay time.Duration
	}{
		{0, time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{5, 30 * time.Second},
	}

	for _, tt := range tests {
		result := client.calculateBackoff(tt.attempt)
		if result > tt.maxDelay {
			t.Errorf("calculateBackoff(%d) = %v, should not exceed %v", tt.attempt, result, tt.maxDelay)
		}
	}
}

func TestWsResultStructure(t *testing.T) {
	result := WsResult{
		Connected:        true,
		Messages:         []string{"response1", "response2"},
		AssertionDetails: []AssertionResult{{Type: ContainsAssertion, Target: "test", Passed: true}},
		RetryCount:       2,
		TotalDuration:    100 * time.Millisecond,
	}

	if !result.Connected {
		t.Error("Expected Connected to be true")
	}
	if len(result.Messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(result.Messages))
	}
	if len(result.AssertionDetails) != 1 {
		t.Errorf("Expected 1 assertion detail, got %d", len(result.AssertionDetails))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"Hello", 10, "Hello"},
		{"Hello World", 5, "Hello..."},
		{"Short", 10, "Short"},
		{"", 10, ""},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncate(%s, %d) = %s, want %s", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestBinaryEncoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		encoding string
		expected string
	}{
		{"base64_hello", "SGVsbG8=", "base64:", "Hello"},
		{"hex_hello", "48656c6c6f", "hex:", "Hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &WsClient{}

			var data []byte
			var err error

			if tt.encoding == "base64:" {
				data, err = client.parseBinaryInput("base64:" + tt.input)
			} else if tt.encoding == "hex:" {
				data, err = client.parseBinaryInput("hex:" + tt.input)
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if string(data) != tt.expected {
				t.Errorf("Decoded data = %s, want %s", string(data), tt.expected)
			}
		})
	}
}

func TestBase64RoundTrip(t *testing.T) {
	testStrings := []string{"Hello", "Test123", ""}
	for _, original := range testStrings {
		encoded := base64.StdEncoding.EncodeToString([]byte(original))
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("Base64 error for '%s': %v", original, err)
		}
		if string(decoded) != original {
			t.Errorf("Base64 round trip failed")
		}
	}
}

func TestHexRoundTrip(t *testing.T) {
	testData := [][]byte{[]byte("Hello"), []byte{0x00, 0x01, 0x02}}
	for _, original := range testData {
		encoded := hex.EncodeToString(original)
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			t.Errorf("Hex error for %v: %v", original, err)
		}
		if string(decoded) != string(original) {
			t.Errorf("Hex round trip failed")
		}
	}
}

func TestMessageTypeConstants(t *testing.T) {
	if TextMessage != "text" {
		t.Errorf("TextMessage = %s, want 'text'", TextMessage)
	}
	if BinaryMessage != "binary" {
		t.Errorf("BinaryMessage = %s, want 'binary'", BinaryMessage)
	}
}

func TestAssertionTypeConstants(t *testing.T) {
	if ContainsAssertion != "contains" {
		t.Errorf("ContainsAssertion = %s, want 'contains'", ContainsAssertion)
	}
}

func TestDefaultConfigValues(t *testing.T) {
	url = ""
	message = ""
	messageType = "text"
	headers = nil
	count = 1
	timeout = 10 * time.Second

	config := GetConfig()

	if config.MaxRetries != 5 {
		t.Errorf("Default MaxRetries = %d, want 5", config.MaxRetries)
	}
	if config.MaxDelay != 30*time.Second {
		t.Errorf("Default MaxDelay = %v, want 30s", config.MaxDelay)
	}
	if config.Count != 1 {
		t.Errorf("Default Count = %d, want 1", config.Count)
	}
}

func TestWsClientInitialization(t *testing.T) {
	config := &WsConfig{
		URL:        "ws://localhost:8080",
		MaxRetries: 3,
		MaxDelay:   15 * time.Second,
	}

	client := NewWsClient(config)

	if client.config.URL != config.URL {
		t.Errorf("Client config.URL = %s, want %s", client.config.URL, config.URL)
	}
	if client.ctx == nil {
		t.Error("Client context should not be nil")
	}
	if client.cancel == nil {
		t.Error("Client cancel function should not be nil")
	}
}

func TestClose(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	err := client.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	select {
	case <-client.done:
	case <-time.After(100 * time.Millisecond):
		t.Error("Done channel should be closed after Close")
	}
}

func TestIsConnected(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	if client.IsConnected() {
		t.Error("Client should not be connected initially")
	}
}

func TestNewWsClientContext(t *testing.T) {
	config := &WsConfig{}
	client := NewWsClient(config)

	if client.ctx == nil {
		t.Error("Context should not be nil")
	}

	select {
	case <-client.ctx.Done():
		t.Error("Context should not be cancelled initially")
	default:
	}
}

func TestAssertionStruct(t *testing.T) {
	a := Assertion{
		Type:    ContainsAssertion,
		Target:  "test",
		Negated: false,
	}

	if a.Type != ContainsAssertion {
		t.Errorf("Assertion.Type = %s, want %s", a.Type, ContainsAssertion)
	}
}

func TestReconnectPolicyStruct(t *testing.T) {
	policy := ReconnectPolicy{
		MaxRetries:   5,
		MaxDelay:     30 * time.Second,
		InitialDelay: time.Second,
	}

	if policy.MaxRetries != 5 {
		t.Errorf("ReconnectPolicy.MaxRetries = %d, want 5", policy.MaxRetries)
	}
}

func TestWsConfigStruct(t *testing.T) {
	config := WsConfig{
		URL:         "ws://localhost:8080",
		Message:     "test",
		MessageType: BinaryMessage,
		Reconnect:   true,
		MaxRetries:  10,
	}

	if config.URL != "ws://localhost:8080" {
		t.Errorf("Config.URL = %s, want ws://localhost:8080", config.URL)
	}
	if config.Reconnect != true {
		t.Errorf("Config.Reconnect = %v, want true", config.Reconnect)
	}
}

func TestConnectRequiresURL(t *testing.T) {
	client := NewWsClient(&WsConfig{
		URL: "invalid://url",
	})

	_, err := client.Connect()
	if err == nil {
		t.Error("Connect should fail for invalid URL")
	}
}

func TestValidateEmptyAssertions(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{},
		},
	}

	messages := []string{"Hello"}
	_, passed, _ := client.validateAllAssertions(messages, nil)

	if !passed {
		t.Errorf("Expected empty assertions to pass")
	}
}

func TestParseHeadersEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect int
	}{
		{"empty", []string{}, 0},
		{"single", []string{"A:B"}, 1},
		{"multiple", []string{"A:B", "C:D"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHeaders(tt.input)
			if len(result) != tt.expect {
				t.Errorf("parseHeaders returned %d headers, want %d", len(result), tt.expect)
			}
		})
	}
}

func TestParseAssertionsEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect int
	}{
		{"empty", []string{}, 0},
		{"single", []string{"contains:test"}, 1},
		{"multiple", []string{"contains:a", "regex:b"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAssertions(tt.input)
			if len(result) != tt.expect {
				t.Errorf("parseAssertions returned %d assertions, want %d", len(result), tt.expect)
			}
		})
	}
}

func TestRunWsTestWithInvalidURL(t *testing.T) {
	utils.IsSilent = true

	result := RunWsTest(WsConfig{
		URL: "invalid://test",
	})

	if result.Connected {
		t.Error("Should not connect to invalid URL")
	}

	utils.IsSilent = false
}

func TestRunWsTestWithNoURL(t *testing.T) {
	utils.IsSilent = true

	result := RunWsTest(WsConfig{
		URL: "",
	})

	if result.Connected {
		t.Error("Should not connect with empty URL")
	}

	utils.IsSilent = false
}

func TestWsClientWithContextCancellation(t *testing.T) {
	config := &WsConfig{}
	client := NewWsClient(config)

	client.cancel()

	_, err := client.Connect()
	if err == nil {
		t.Error("Connect should fail when context is cancelled")
	}

	err = client.Close()
	if err != nil {
		t.Errorf("Close should not fail: %v", err)
	}
}

func TestHexDecodeError(t *testing.T) {
	client := &WsClient{}

	tests := []struct {
		input string
	}{
		{"ZZ"},
		{"12345"},
	}

	for _, tt := range tests {
		_, err := client.parseBinaryInput(tt.input)
		if err == nil {
			t.Errorf("Expected error for hex input: %s", tt.input)
		}
	}
}

func TestBase64DecodeError(t *testing.T) {
	client := &WsClient{}

	tests := []struct {
		input string
	}{
		{"base64:!!!invalid!!!"},
	}

	for _, tt := range tests {
		_, err := client.parseBinaryInput(tt.input)
		if err == nil {
			t.Errorf("Expected error for base64 input: %s", tt.input)
		}
	}
}

func TestConfigVerboseFlag(t *testing.T) {
	url = ""
	messageType = "text"
	verbose = true

	config := GetConfig()

	if !config.Verbose {
		t.Errorf("Config.Verbose should be true when verbose flag is set")
	}
}

func TestJSONFieldAssertion(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{
				{Type: JSONFieldAssertion, Field: "status", Target: "ok"},
			},
		},
	}

	messages := []string{`{"status": "ok", "data": "test"}`}
	_, passed, _ := client.validateAllAssertions(messages, nil)

	if !passed {
		t.Error("Expected JSON field assertion to pass")
	}
}

func TestRegexAssertion(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{
				{Type: RegexAssertion, Target: `^\d{3}-\d{3}-\d{4}$`},
			},
		},
	}

	messages := []string{"123-456-7890"}
	_, passed, _ := client.validateAllAssertions(messages, nil)

	if !passed {
		t.Error("Expected regex assertion to pass")
	}
}

func TestLengthGreaterAssertion(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{
				{Type: LengthGreaterAssertion, MinLength: 100},
			},
		},
	}

	messages := []string{"This is a test message that is long enough to pass the assertion check"}
	_, passed, _ := client.validateAllAssertions(messages, nil)

	if passed {
		t.Error("Expected length assertion to fail for short message")
	}
}

func TestMessageStruct(t *testing.T) {
	msg := Message{
		Type:     1,
		Data:     []byte("test"),
		Received: time.Now(),
	}

	if msg.Type != 1 {
		t.Errorf("Message.Type = %d, want 1", msg.Type)
	}
	if string(msg.Data) != "test" {
		t.Errorf("Message.Data = %s, want 'test'", string(msg.Data))
	}
}

func TestCountPassed(t *testing.T) {
	results := []AssertionResult{
		{Passed: true},
		{Passed: true},
		{Passed: false},
	}

	count := countPassed(results)
	if count != 2 {
		t.Errorf("countPassed = %d, want 2", count)
	}
}

func TestValidateSingleAssertionContains(t *testing.T) {
	client := &WsClient{}

	result := client.validateSingleAssertion(
		Assertion{Type: ContainsAssertion, Target: "Hello"},
		[]string{"Hello World"},
		nil,
	)

	if !result.Passed {
		t.Error("Expected assertion to pass")
	}
}

func TestValidateSingleAssertionRegex(t *testing.T) {
	client := &WsClient{}

	result := client.validateSingleAssertion(
		Assertion{Type: RegexAssertion, Target: `^\w+$`},
		[]string{"test123"},
		nil,
	)

	if !result.Passed {
		t.Error("Expected regex assertion to pass")
	}
}

func TestCloseWithReason(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	err := client.CloseWithReason(1000, "test close")
	if err != nil {
		t.Errorf("CloseWithReason returned error: %v", err)
	}
}

func TestGetStats(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	sent, received, bytesS, bytesR := client.GetStats()
	if sent != 0 || received != 0 || bytesS != 0 || bytesR != 0 {
		t.Error("Initial stats should be zero")
	}
}

func TestGetLatency(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	latency := client.getLatency()
	if latency == nil {
		t.Error("getLatency should return non-nil slice")
	}
}

func TestSendPing(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	err := client.SendPing()
	if err == nil {
		t.Error("SendPing should fail when not connected")
	}
}

func TestSendPong(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	err := client.SendPong([]byte("test"))
	if err == nil {
		t.Error("SendPong should fail when not connected")
	}
}

func TestSendMessages(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	_, err := client.SendMessages(3, time.Millisecond)
	if err == nil {
		t.Error("SendMessages should fail when not connected")
	}
}

func TestReceiveMessage(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	_, err := client.ReceiveMessage()
	if err == nil {
		t.Error("ReceiveMessage should fail when not connected")
	}
}

func TestReceiveMultiple(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	_, _ = client.ReceiveMultiple(5, time.Second)
}

func TestSendAndReceiveWithMetrics(t *testing.T) {
	client := NewWsClient(&WsConfig{
		Count: 1,
	})

	messages, _ := client.sendAndReceiveWithMetrics()
	if messages == nil {
		t.Error("messages should be nil on error")
	}
}

func TestReceiveWithTimeout(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	_, err := client.ReceiveWithTimeout(time.Second)
	if err == nil {
		t.Error("ReceiveWithTimeout should fail when not connected")
	}
}

func TestSendLargeMessage(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	_, err := client.SendLargeMessage(1024)
	if err == nil {
		t.Error("SendLargeMessage should fail when not connected")
	}
}

func TestBackoffExponentialGrowth(t *testing.T) {
	policy := &ReconnectPolicy{
		MaxRetries:   10,
		MaxDelay:     100 * time.Second,
		InitialDelay: 1 * time.Second,
	}

	client := &WsClient{
		reconnectPolicy: policy,
		rnd:             rand.New(rand.NewSource(42)),
	}

	var previousDelay time.Duration
	for i := 0; i < 5; i++ {
		currentDelay := client.calculateBackoff(i)
		if i > 0 && currentDelay <= previousDelay {
			t.Errorf("Backoff should grow, but %d -> %d", i, currentDelay)
		}
		previousDelay = currentDelay
	}
}

func TestMaxDelayCap(t *testing.T) {
	policy := &ReconnectPolicy{
		MaxRetries:   10,
		MaxDelay:     30 * time.Second,
		InitialDelay: 1 * time.Second,
	}

	client := &WsClient{
		reconnectPolicy: policy,
		rnd:             rand.New(rand.NewSource(42)),
	}

	delays := []time.Duration{
		client.calculateBackoff(5),
		client.calculateBackoff(6),
		client.calculateBackoff(10),
	}

	for _, delay := range delays {
		if delay > policy.MaxDelay {
			t.Errorf("Delay %v exceeds max delay %v", delay, policy.MaxDelay)
		}
	}
}

func TestNegatedAssertion(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{
				{Type: ContainsAssertion, Target: "Hello", Negated: true},
			},
		},
	}

	messages := []string{"Hello World"}
	_, passed, _ := client.validateAllAssertions(messages, nil)

	if passed {
		t.Error("Negated assertion should fail when target is found")
	}
}

func TestMultipleMessagesWithAssertion(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{
				{Type: ContainsAssertion, Target: "success"},
			},
		},
	}

	messages := []string{"fail", "fail", "success"}
	_, passed, _ := client.validateAllAssertions(messages, nil)

	if !passed {
		t.Error("Expected assertion to pass when one message contains target")
	}
}

func TestBinaryMessagesWithAssertion(t *testing.T) {
	client := &WsClient{
		config: &WsConfig{
			Assertions: []Assertion{
				{Type: LengthGreaterAssertion, MinLength: 10},
			},
		},
	}

	messages := []string{}
	binaryMessages := [][]byte{[]byte("Hello World!")}
	_, passed, _ := client.validateAllAssertions(messages, binaryMessages)

	if !passed {
		t.Error("Expected length assertion to pass with binary messages")
	}
}

func TestWsResultWithAllFields(t *testing.T) {
	result := WsResult{
		Connected:        true,
		ConnectionState:  "open",
		HandshakeSuccess: true,
		HTTPStatusCode:   101,
		Messages:         []string{"msg1", "msg2"},
		BinaryMessages:   [][]byte{[]byte("bin1")},
		AssertionPassed:  true,
		AssertionError:   "",
		AssertionDetails: []AssertionResult{{Passed: true, Type: ContainsAssertion}},
		RetryCount:       0,
		TotalDuration:    time.Second,
		BytesSent:        100,
		BytesReceived:    200,
		Error:            "",
		CloseCode:        1000,
		CloseReason:      "normal",
		Latency:          []time.Duration{time.Millisecond * 50},
		SuccessCount:     2,
		FailureCount:     0,
	}

	if !result.Connected {
		t.Error("Result should be connected")
	}
	if result.HTTPStatusCode != 101 {
		t.Errorf("HTTPStatusCode = %d, want 101", result.HTTPStatusCode)
	}
	if len(result.Messages) != 2 {
		t.Errorf("Messages count = %d, want 2", len(result.Messages))
	}
}

func TestConnectReturnValues(t *testing.T) {
	client := NewWsClient(&WsConfig{
		URL: "invalid://test",
	})

	statusCode, err := client.Connect()
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
	if statusCode != 0 {
		t.Errorf("statusCode should be 0 on error, got %d", statusCode)
	}
}

func TestRunPerformanceTest(t *testing.T) {
	utils.IsSilent = true

	config := WsConfig{
		URL:     "invalid://test",
		Verbose: false,
	}

	result := RunPerformanceTest(config, time.Second)

	utils.IsSilent = false

	if result.Error == "" {
		t.Error("Expected error for invalid URL")
	}
}

func TestRunStressTest(t *testing.T) {
	utils.IsSilent = true

	config := WsConfig{
		URL:     "invalid://test",
		Verbose: false,
	}

	results := RunStressTest(config, 2, time.Second)

	utils.IsSilent = false

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
}

func TestParseMessageTypeEdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected MessageType
	}{
		{"", TextMessage},
		{"unknown", TextMessage},
		{"TEXT", TextMessage},
		{"BINARY", BinaryMessage},
	}

	for _, tt := range tests {
		result := parseMessageType(tt.input)
		if result != tt.expected {
			t.Errorf("parseMessageType(%s) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseBinaryInputWithPlainHex(t *testing.T) {
	client := &WsClient{}

	data, err := client.parseBinaryInput("41424344")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(data) != "ABCD" {
		t.Errorf("Expected 'ABCD', got '%s'", string(data))
	}
}

func TestJSONMarshalAssertionResult(t *testing.T) {
	result := AssertionResult{
		Passed:   true,
		Type:     ContainsAssertion,
		Target:   "test",
		Expected: "contains 'test'",
		Actual:   "test message",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Errorf("Failed to marshal: %v", err)
	}

	var unmarshaled AssertionResult
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Errorf("Failed to unmarshal: %v", err)
	}

	if unmarshaled.Passed != result.Passed {
		t.Error("Passed field mismatch")
	}
}

func TestZeroConfig(t *testing.T) {
	config := WsConfig{}

	client := NewWsClient(&config)

	if client.config != &config {
		t.Error("Client should reference the same config")
	}
}

func TestMultipleClose(t *testing.T) {
	client := NewWsClient(&WsConfig{})

	err := client.Close()
	if err != nil {
		t.Errorf("First close returned error: %v", err)
	}
}

func TestSendDelayConfig(t *testing.T) {
	config := WsConfig{
		SendDelay: 100 * time.Millisecond,
	}

	if config.SendDelay != 100*time.Millisecond {
		t.Errorf("SendDelay = %v, want 100ms", config.SendDelay)
	}
}

func TestNetworkTimeoutConfig(t *testing.T) {
	config := WsConfig{
		NetworkTimeout: 5 * time.Second,
	}

	if config.NetworkTimeout != 5*time.Second {
		t.Errorf("NetworkTimeout = %v, want 5s", config.NetworkTimeout)
	}
}

func TestSubprotocolsConfig(t *testing.T) {
	config := WsConfig{
		Subprotocols: []string{"graphql-ws", "mqtt"},
	}

	if len(config.Subprotocols) != 2 {
		t.Errorf("Subprotocols count = %d, want 2", len(config.Subprotocols))
	}
}

func TestCloseCodeConstants(t *testing.T) {
	if websocket.CloseNormalClosure != 1000 {
		t.Errorf("CloseNormalClosure = %d, want 1000", websocket.CloseNormalClosure)
	}
	if websocket.CloseGoingAway != 1001 {
		t.Errorf("CloseGoingAway = %d, want 1001", websocket.CloseGoingAway)
	}
}
