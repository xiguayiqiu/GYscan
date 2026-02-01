package ws

import (
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	url               string
	message           string
	messageType       string
	headers           []string
	reconnect         bool
	maxRetries        int
	maxDelay          time.Duration
	assertions        []string
	count             int
	interval          time.Duration
	timeout           time.Duration
	verbose           bool
	heartbeat         bool
	heartbeatMsg      string
	heartbeatInterval time.Duration
	skipVerify        bool
	origin            string
	subprotocols      []string
	sendDelay         time.Duration
	networkTimeout    time.Duration
)

func InitFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&url, "url", "u", "", "WebSocket服务器地址 (ws://host:port/path)")
	cmd.Flags().StringVarP(&message, "message", "m", "Hello GYscan", "发送的消息内容")
	cmd.Flags().StringVarP(&messageType, "type", "t", "text", "消息类型: text 或 binary")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", []string{}, "自定义HTTP头 (格式: Key:Value)")
	cmd.Flags().BoolVarP(&reconnect, "reconnect", "r", false, "启用自动重连机制")
	cmd.Flags().IntVarP(&maxRetries, "retries", "k", 5, "最大重试次数")
	cmd.Flags().DurationVarP(&maxDelay, "max-delay", "d", 30*time.Second, "最大重连延迟")
	cmd.Flags().StringArrayVarP(&assertions, "assert", "a", []string{}, "响应断言 (contains:text | regex:pattern | json:field:value | length_greater:N)")
	cmd.Flags().IntVarP(&count, "count", "c", 1, "发送消息次数")
	cmd.Flags().DurationVarP(&interval, "interval", "i", 1*time.Second, "发送消息间隔")
	cmd.Flags().DurationVarP(&timeout, "timeout", "o", 10*time.Second, "超时时间")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出")
	cmd.Flags().BoolVar(&heartbeat, "heartbeat", false, "启用心跳检测")
	cmd.Flags().StringVar(&heartbeatMsg, "heartbeat-msg", "ping", "心跳消息内容")
	cmd.Flags().DurationVar(&heartbeatInterval, "heartbeat-interval", 30*time.Second, "心跳间隔")
	cmd.Flags().BoolVar(&skipVerify, "skip-verify", false, "跳过TLS证书验证")
	cmd.Flags().StringVar(&origin, "origin", "", "Origin请求头")
	cmd.Flags().StringArrayVar(&subprotocols, "subprotocols", []string{}, "WebSocket子协议列表 (逗号分隔, 可能导致连接失败)")
	cmd.Flags().DurationVar(&sendDelay, "send-delay", 0, "发送消息后延迟")
	cmd.Flags().DurationVar(&networkTimeout, "network-timeout", 10*time.Second, "网络操作超时时间")
}

func GetConfig() WsConfig {
	config := WsConfig{
		URL:               url,
		Message:           message,
		MessageType:       parseMessageType(messageType),
		Headers:           parseHeaders(headers),
		Reconnect:         reconnect,
		MaxRetries:        maxRetries,
		MaxDelay:          maxDelay,
		Count:             count,
		Interval:          interval,
		Timeout:           timeout,
		Verbose:           verbose,
		Heartbeat:         heartbeat,
		HeartbeatMsg:      heartbeatMsg,
		HeartbeatInterval: heartbeatInterval,
		SkipVerify:        skipVerify,
		Origin:            origin,
		Subprotocols:      parseSubprotocols(subprotocols),
		SendDelay:         sendDelay,
		NetworkTimeout:    networkTimeout,
	}

	config.Assertions = parseAssertions(assertions)

	return config
}

func parseSubprotocols(input []string) []string {
	result := make([]string, 0)
	for _, s := range input {
		parts := strings.Split(s, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
	}
	return result
}

func parseMessageType(s string) MessageType {
	switch strings.ToLower(s) {
	case "binary", "bin":
		return BinaryMessage
	default:
		return TextMessage
	}
}

func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := splitHeader(h)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func splitHeader(s string) []string {
	idx := -1
	for i, c := range s {
		if c == ':' {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil
	}
	return []string{s[:idx], s[idx+1:]}
}

func parseAssertions(assertions []string) []Assertion {
	result := make([]Assertion, 0)
	for _, a := range assertions {
		if strings.HasPrefix(a, "contains:") {
			target := strings.TrimPrefix(a, "contains:")
			result = append(result, Assertion{
				Type:   ContainsAssertion,
				Target: target,
			})
		} else if strings.HasPrefix(a, "regex:") {
			target := strings.TrimPrefix(a, "regex:")
			result = append(result, Assertion{
				Type:   RegexAssertion,
				Target: target,
			})
		} else if strings.HasPrefix(a, "json:") {
			parts := strings.SplitN(strings.TrimPrefix(a, "json:"), ":", 2)
			if len(parts) == 2 {
				result = append(result, Assertion{
					Type:   JSONFieldAssertion,
					Field:  parts[0],
					Target: parts[1],
				})
			}
		}
	}
	return result
}
