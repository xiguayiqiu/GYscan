package ai

import (
	"net/http"
	"sync"
	"time"
)

// ConnectionPool 连接池管理器
type ConnectionPool struct {
	clients    map[string]*http.Client
	mu         sync.RWMutex
	maxClients int
}

// NewConnectionPool 创建新的连接池
func NewConnectionPool(maxClients int) *ConnectionPool {
	return &ConnectionPool{
		clients:    make(map[string]*http.Client),
		maxClients: maxClients,
	}
}

// GetClient 获取或创建HTTP客户端
func (cp *ConnectionPool) GetClient(baseURL string, timeout int) *http.Client {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	// 如果连接池已满，清理最旧的连接
	if len(cp.clients) >= cp.maxClients {
		cp.cleanup()
	}

	// 检查是否已存在该URL的客户端
	if client, exists := cp.clients[baseURL]; exists {
		return client
	}

	// 创建新的客户端
	client := cp.createOptimizedClient(timeout)
	cp.clients[baseURL] = client

	return client
}

// createOptimizedClient 创建优化的HTTP客户端
func (cp *ConnectionPool) createOptimizedClient(timeout int) *http.Client {
	// 创建高度优化的Transport
	transport := &http.Transport{
		MaxIdleConns:          200,               // 增加最大空闲连接数
		MaxIdleConnsPerHost:   50,                // 增加每个主机的最大空闲连接数
		MaxConnsPerHost:       100,               // 增加每个主机的最大连接数
		IdleConnTimeout:       120 * time.Second, // 增加空闲连接超时
		TLSHandshakeTimeout:   15 * time.Second,  // 增加TLS握手超时
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, // 增加响应头超时
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}
}

// cleanup 清理最旧的连接
func (cp *ConnectionPool) cleanup() {
	// 简单的清理策略：删除第一个连接
	for key := range cp.clients {
		delete(cp.clients, key)
		break
	}
}

// Close 关闭连接池中的所有客户端
type closeIdleTransport interface {
	CloseIdleConnections()
}

func (cp *ConnectionPool) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for _, client := range cp.clients {
		if transport, ok := client.Transport.(closeIdleTransport); ok {
			transport.CloseIdleConnections()
		}
	}
	cp.clients = make(map[string]*http.Client)
}

// GetStats 获取连接池统计信息
func (cp *ConnectionPool) GetStats() map[string]interface{} {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	return map[string]interface{}{
		"total_clients":     len(cp.clients),
		"max_clients":       cp.maxClients,
		"available_clients": len(cp.clients),
	}
}
