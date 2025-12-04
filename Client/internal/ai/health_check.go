package ai

import (
	"net/http"
	"time"

	"GYscan/internal/utils"
)

// HealthChecker 连接健康检查器
type HealthChecker struct {
	BaseURL       string
	APIKey        string
	Timeout       time.Duration
	CheckInterval time.Duration
	LastCheck     time.Time
	IsHealthy     bool
	FailureCount  int
	MaxFailures   int
}

// NewHealthChecker 创建新的健康检查器
func NewHealthChecker(baseURL, apiKey string, timeout, checkInterval time.Duration) *HealthChecker {
	return &HealthChecker{
		BaseURL:       baseURL,
		APIKey:        apiKey,
		Timeout:       timeout,
		CheckInterval: checkInterval,
		LastCheck:     time.Now(),
		IsHealthy:     true,
		FailureCount:  0,
		MaxFailures:   3,
	}
}

// CheckHealth 执行健康检查
func (hc *HealthChecker) CheckHealth() bool {
	// 检查是否达到检查间隔
	if time.Since(hc.LastCheck) < hc.CheckInterval {
		return hc.IsHealthy
	}

	hc.LastCheck = time.Now()

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: hc.Timeout,
	}

	// 构建健康检查请求
	req, err := http.NewRequest("GET", hc.BaseURL+"/health", nil)
	if err != nil {
		utils.WarningPrint("创建健康检查请求失败: %v", err)
		hc.recordFailure()
		return false
	}

	// 添加认证头
	if hc.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+hc.APIKey)
	}

	// 执行健康检查
	resp, err := client.Do(req)
	if err != nil {
		utils.WarningPrint("健康检查请求失败: %v", err)
		hc.recordFailure()
		return false
	}
	defer resp.Body.Close()

	// 检查响应状态码
	if resp.StatusCode == http.StatusOK {
		hc.recordSuccess()
		utils.InfoPrint("AI服务健康检查通过")
		return true
	}

	utils.WarningPrint("健康检查失败，状态码: %d", resp.StatusCode)
	hc.recordFailure()
	return false
}

// recordSuccess 记录成功检查
func (hc *HealthChecker) recordSuccess() {
	hc.IsHealthy = true
	hc.FailureCount = 0
}

// recordFailure 记录失败检查
func (hc *HealthChecker) recordFailure() {
	hc.FailureCount++
	if hc.FailureCount >= hc.MaxFailures {
		hc.IsHealthy = false
		utils.ErrorPrint("AI服务连续失败 %d 次，标记为不健康", hc.FailureCount)
	}
}

// IsHealthyNow 检查当前健康状态
func (hc *HealthChecker) IsHealthyNow() bool {
	return hc.IsHealthy
}

// Reset 重置健康检查器
func (hc *HealthChecker) Reset() {
	hc.IsHealthy = true
	hc.FailureCount = 0
	hc.LastCheck = time.Now()
}

// GetStatus 获取健康状态信息
func (hc *HealthChecker) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"is_healthy":     hc.IsHealthy,
		"failure_count":  hc.FailureCount,
		"last_check":     hc.LastCheck.Format(time.RFC3339),
		"check_interval": hc.CheckInterval.String(),
		"max_failures":   hc.MaxFailures,
	}
}

// ConnectionMonitor 连接监控器
type ConnectionMonitor struct {
	HealthChecker *HealthChecker
	RetryStrategy *RetryStrategy
	LastErrorTime time.Time
	ErrorCount    int
}

// NewConnectionMonitor 创建新的连接监控器
func NewConnectionMonitor(healthChecker *HealthChecker, retryStrategy *RetryStrategy) *ConnectionMonitor {
	return &ConnectionMonitor{
		HealthChecker: healthChecker,
		RetryStrategy: retryStrategy,
		LastErrorTime: time.Time{},
		ErrorCount:    0,
	}
}

// MonitorConnection 监控连接状态
func (cm *ConnectionMonitor) MonitorConnection(err error) bool {
	if err == nil {
		// 连接成功，重置错误计数
		cm.ErrorCount = 0
		cm.LastErrorTime = time.Time{}
		return true
	}

	// 记录错误
	cm.ErrorCount++
	cm.LastErrorTime = time.Now()

	// 检查是否需要触发健康检查
	if cm.ErrorCount >= 2 {
		utils.WarningPrint("连接连续失败 %d 次，触发健康检查", cm.ErrorCount)
		if !cm.HealthChecker.CheckHealth() {
			utils.ErrorPrint("AI服务不健康，建议检查网络连接和API配置")
			return false
		}
	}

	return true
}

// GetConnectionStats 获取连接统计信息
func (cm *ConnectionMonitor) GetConnectionStats() map[string]interface{} {
	return map[string]interface{}{
		"error_count":     cm.ErrorCount,
		"last_error_time": cm.LastErrorTime.Format(time.RFC3339),
		"health_status":   cm.HealthChecker.GetStatus(),
	}
}
