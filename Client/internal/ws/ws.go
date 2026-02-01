package ws

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var WsCmd = &cobra.Command{
	Use:   "ws",
	Short: "WebSocket 测试工具",
	Long: `WebSocket 测试工具，支持发送消息、自动重连和响应断言验证

支持的功能:
  - 发送文本和二进制消息
  - 二进制消息支持 Base64 和十六进制编码
  - 自动重连机制（指数退避策略，带抖动）
  - 多种响应断言验证（包含/正则/JSON/长度）
  - Ping/Pong心跳检测
  - WSS (TLS) 连接支持
  - 自定义HTTP头和Subprotocols
  - 连接状态和握手信息验证
  - 延迟统计和性能监控

断言类型:
  - contains:text    响应包含指定文本
  - regex:pattern    响应匹配正则表达式
  - json:field:value JSON字段包含指定值
  - length_greater:N 响应长度大于N字节

使用示例:
  # 基础连接测试
  ./GYscan ws -u ws://localhost:8080/echo

  # 发送自定义消息
  ./GYscan ws -u ws://localhost:8080 -m "Hello WebSocket"

  # 发送二进制消息 (Base64)
  ./GYscan ws -u ws://localhost:8080 -t binary -m "base64:SGVsbG8=" --verbose

  # 发送二进制消息 (十六进制)
  ./GYscan ws -u ws://localhost:8080 -t binary -m "hex:48656c6c6f"

  # 启用自动重连
  ./GYscan ws -u ws://localhost:8080 -r --retries 5 --max-delay 30s

  # 响应断言验证
  ./GYscan ws -u ws://localhost:8080 -a "contains:Pong"
  ./GYscan ws -u ws://localhost:8080 -a "regex:^\\d+$"
  ./GYscan ws -u ws://localhost:8080 -a "json:status:ok"
  ./GYscan ws -u ws://localhost:8080 -a "length_greater:100"

  # 多次发送测试
  ./GYscan ws -u ws://localhost:8080 -c 5 -i 2s

  # 添加自定义头
  ./GYscan ws -u ws://localhost:8080 -H "Authorization: Bearer token123"

  # 跳过TLS证书验证 (WSS)
  ./GYscan ws -u wss://localhost:8080 --skip-verify

  # 指定Origin头
  ./GYscan ws -u ws://localhost:8080 --origin "http://example.com"

  # 启用心跳检测
  ./GYscan ws -u ws://localhost:8080 --heartbeat --heartbeat-msg "ping" --heartbeat-interval 30s

  # 完整配置示例
  ./GYscan ws -u ws://localhost:8080/echo -m "test" -t text -r -k 3 -d 10s -a "contains:response" -v

注意: 
  - Subprotocol参数(--subprotocols)需要服务器支持，否则可能导致连接失败
  - 如遇到"bad handshake"错误，请尝试不指定subprotocols
  - 性能测试和压力测试需要通过API调用RunPerformanceTest和RunStressTest函数`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := GetConfig()

		if config.URL == "" {
			return fmt.Errorf("请指定 WebSocket 地址 (--url/-u)")
		}

		result := RunWsTest(config)

		if !result.Connected {
			fmt.Printf("[WS] 连接失败: %s\n", result.Error)
			return nil
		}

		fmt.Printf("[WS] 连接成功，耗时: %v\n", result.TotalDuration)
		fmt.Printf("[WS] 收到消息数: %d\n", len(result.Messages))

		if len(result.AssertionDetails) > 0 {
			if result.AssertionPassed {
				fmt.Printf("[WS] 断言验证: 通过 (%d/%d)\n", countAssertions(result.AssertionDetails), len(result.AssertionDetails))
			} else {
				fmt.Printf("[WS] 断言验证: 失败 - %s\n", result.AssertionError)
				for _, ar := range result.AssertionDetails {
					if !ar.Passed {
						fmt.Printf("[WS]   - %s: 期望 %s, 实际: %s\n", ar.Type, ar.Expected, ar.Actual)
					}
				}
			}
		}

		if result.Latency != nil && len(result.Latency) > 0 {
			avgLatency := calculateAvgLatency(result.Latency)
			fmt.Printf("[WS] 平均延迟: %v\n", avgLatency)
		}

		if result.RetryCount > 0 {
			fmt.Printf("[WS] 重试次数: %d\n", result.RetryCount)
		}

		return nil
	},
}

func init() {
	InitFlags(WsCmd)
}

func countAssertions(details []AssertionResult) int {
	count := 0
	for _, d := range details {
		if d.Passed {
			count++
		}
	}
	return count
}

func calculateAvgLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	return total / time.Duration(len(latencies))
}
