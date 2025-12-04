package ai

import (
	"math"
	"math/rand"
	"strings"
	"time"
)

// RetryStrategy 重试策略管理器
type RetryStrategy struct {
	MaxRetries    int
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	JitterFactor  float64
	BackoffFactor float64
}

// NewRetryStrategy 创建新的重试策略
func NewRetryStrategy(maxRetries int, baseDelay, maxDelay time.Duration) *RetryStrategy {
	return &RetryStrategy{
		MaxRetries:    maxRetries,
		BaseDelay:     baseDelay,
		MaxDelay:      maxDelay,
		JitterFactor:  0.2, // 20%的抖动因子
		BackoffFactor: 2.0, // 指数退避因子
	}
}

// CalculateDelay 计算下一次重试的延迟时间
func (rs *RetryStrategy) CalculateDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return rs.BaseDelay
	}

	// 指数退避计算
	delay := float64(rs.BaseDelay) * math.Pow(rs.BackoffFactor, float64(attempt-1))

	// 添加随机抖动
	jitter := delay * rs.JitterFactor * (rand.Float64()*2 - 1) // -20% 到 +20%
	delay += jitter

	// 确保延迟不超过最大值
	if delay > float64(rs.MaxDelay) {
		delay = float64(rs.MaxDelay)
	}

	// 确保延迟不小于基础延迟
	if delay < float64(rs.BaseDelay) {
		delay = float64(rs.BaseDelay)
	}

	return time.Duration(delay)
}

// ShouldRetry 判断是否应该重试
func (rs *RetryStrategy) ShouldRetry(attempt int, err error) bool {
	if attempt >= rs.MaxRetries {
		return false
	}

	// 根据错误类型决定是否重试
	return isRetryableError(err)
}

// isRetryableError 判断错误是否可重试
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// 可重试的错误类型
	retryableErrors := []string{
		"timeout",
		"deadline exceeded",
		"connection reset",
		"connection refused",
		"temporary failure",
		"network error",
		"context canceled",
		"EOF",
		"connection reset by peer",
		"no route to host",
		"network is unreachable",
		"i/o timeout",
	}

	// 特定HTTP状态码处理
	if strings.Contains(errStr, "status code") {
		// 对于服务器错误（5xx）进行重试
		if strings.Contains(errStr, "50") || strings.Contains(errStr, "502") ||
			strings.Contains(errStr, "503") || strings.Contains(errStr, "504") {
			return true
		}
		// 对于429（限流）进行重试
		if strings.Contains(errStr, "429") {
			return true
		}
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(strings.ToLower(errStr), retryableErr) {
			return true
		}
	}

	return false
}

// GetRetryStats 获取重试统计信息
func (rs *RetryStrategy) GetRetryStats(attempts int, totalDelay time.Duration) map[string]interface{} {
	stats := map[string]interface{}{
		"max_retries":    rs.MaxRetries,
		"base_delay":     rs.BaseDelay,
		"max_delay":      rs.MaxDelay,
		"backoff_factor": rs.BackoffFactor,
		"jitter_factor":  rs.JitterFactor,
		"attempts_made":  attempts,
		"total_delay":    totalDelay,
	}

	// 只有在有重试时才计算平均延迟，避免除以零错误
	if attempts > 0 {
		stats["average_delay"] = totalDelay / time.Duration(attempts)
	} else {
		stats["average_delay"] = time.Duration(0)
	}

	return stats
}

// DefaultRetryStrategy 获取默认的重试策略
func DefaultRetryStrategy() *RetryStrategy {
	return NewRetryStrategy(
		3,              // 最大重试3次
		1*time.Second,  // 基础延迟1秒
		10*time.Second, // 最大延迟10秒
	)
}
