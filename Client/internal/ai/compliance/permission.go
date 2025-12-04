package compliance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PermissionManager 权限管理结构体
type PermissionManager struct {
	authList       *AuthorizationList
	permissionCache *sync.Map
	// 简单的内存限流实现
	rateLimitCache *sync.Map // 存储IP的请求计数和时间
}

// AuthorizationList 授权清单
type AuthorizationList struct {
	IPs       []string    `json:"ips"`       // 授权IP列表
	Domains   []string    `json:"domains"`   // 授权域名列表
	CIDRs     []string    `json:"cidrs"`     // 授权CIDR网段
	StartTime time.Time   `json:"start_time"` // 授权开始时间
	EndTime   time.Time   `json:"end_time"`   // 授权结束时间
	Services  []string    `json:"services"`   // 授权服务列表
}

// RateLimitInfo 限流信息
type RateLimitInfo struct {
	Count    int       `json:"count"`    // 请求计数
	LastTime time.Time `json:"last_time"` // 最后请求时间
}

// NewPermissionManager 创建新的权限管理器实例
func NewPermissionManager() *PermissionManager {
	pm := &PermissionManager{
		permissionCache: &sync.Map{},
		rateLimitCache:  &sync.Map{},
	}

	// 加载授权清单（简化实现）
	pm.authList = &AuthorizationList{
		// 默认允许所有本地IP
		IPs: []string{"127.0.0.1", "localhost", "::1"},
		// 默认允许所有服务
		Services: []string{"*"},
	}

	return pm
}

// ValidateTarget 验证目标是否在授权清单内
func (pm *PermissionManager) ValidateTarget(ctx context.Context, target string) (bool, error) {
	// 检查缓存
	if cachedResult, ok := pm.permissionCache.Load(target); ok {
		return cachedResult.(bool), nil
	}

	// 检查时间范围
	now := time.Now()
	if !pm.authList.StartTime.IsZero() && now.Before(pm.authList.StartTime) {
		pm.permissionCache.Store(target, false)
		return false, fmt.Errorf("授权尚未开始")
	}

	if !pm.authList.EndTime.IsZero() && now.After(pm.authList.EndTime) {
		pm.permissionCache.Store(target, false)
		return false, fmt.Errorf("授权已过期")
	}

	// 检查IP
	if pm.isIPInList(target) {
		pm.permissionCache.Store(target, true)
		return true, nil
	}

	// 检查域名
	if pm.isDomainInList(target) {
		pm.permissionCache.Store(target, true)
		return true, nil
	}

	// 检查CIDR
	if pm.isIPInCIDR(target) {
		pm.permissionCache.Store(target, true)
		return true, nil
	}

	pm.permissionCache.Store(target, false)
	return false, fmt.Errorf("目标 %s 不在授权清单内", target)
}

// isIPInList 检查IP是否在授权列表内
func (pm *PermissionManager) isIPInList(ip string) bool {
	for _, allowedIP := range pm.authList.IPs {
		if allowedIP == ip {
			return true
		}
	}
	return false
}

// isDomainInList 检查域名是否在授权列表内
func (pm *PermissionManager) isDomainInList(domain string) bool {
	for _, allowedDomain := range pm.authList.Domains {
		if allowedDomain == domain {
			return true
		}
		// 支持通配符，如 *.example.com
		if strings.HasPrefix(allowedDomain, "*") && strings.HasSuffix(domain, allowedDomain[1:]) {
			return true
		}
	}
	return false
}

// isIPInCIDR 检查IP是否在CIDR范围内
func (pm *PermissionManager) isIPInCIDR(ip string) bool {
	// 简化实现，实际应该使用maxminddb或net包进行CIDR匹配
	for _, cidr := range pm.authList.CIDRs {
		// 这里应该添加CIDR匹配逻辑
		// 简化实现：如果IP以CIDR前缀开头，则认为匹配
		if strings.HasPrefix(cidr, ip+"/") || strings.HasPrefix(ip, strings.Split(cidr, "/")[0]) {
			return true
		}
	}
	return false
}

// CheckPermission 检查当前用户是否具有执行操作的权限
func (pm *PermissionManager) CheckPermission(ctx context.Context, operation string) (bool, error) {
	// 检查系统权限
	if err := pm.checkSystemPermission(operation); err != nil {
		return false, err
	}

	// 检查限流
	if err := pm.checkRateLimit(ctx); err != nil {
		return false, err
	}

	return true, nil
}

// checkSystemPermission 检查系统权限
func (pm *PermissionManager) checkSystemPermission(operation string) error {
	switch runtime.GOOS {
	case "linux":
		// 检查Linux权限
		if operation == "privileged" {
			// 检查是否为root用户
			if os.Getuid() != 0 {
				// 尝试获取root权限
				return fmt.Errorf("需要root权限执行此操作")
			}
		}
	case "windows":
		// 检查Windows权限
		if operation == "privileged" {
			// 检查是否为管理员用户
			isAdmin, err := pm.isWindowsAdmin()
			if err != nil {
				return fmt.Errorf("检查管理员权限失败: %v", err)
			}
			if !isAdmin {
				// 尝试获取管理员权限
				return fmt.Errorf("需要管理员权限执行此操作")
			}
		}
	}

	return nil
}

// isWindowsAdmin 检查是否为Windows管理员
func (pm *PermissionManager) isWindowsAdmin() (bool, error) {
	// 简化实现，实际应该使用Windows API检查管理员权限
	cmd := exec.Command("net", "session")
	if err := cmd.Run(); err != nil {
		return false, nil
	}
	return true, nil
}

// checkRateLimit 检查操作是否超出限流
func (pm *PermissionManager) checkRateLimit(ctx context.Context) error {
	// 从上下文获取IP地址
	ip := "127.0.0.1" // 默认值，实际应该从请求中获取
	if ctxIP, ok := ctx.Value("ip").(string); ok {
		ip = ctxIP
	}

	// 简单的限流实现：每分钟最多100个请求
	now := time.Now()
	key := fmt.Sprintf("rate_limit:%s", ip)
	
	// 获取当前IP的限流信息
	info, ok := pm.rateLimitCache.Load(key)
	if !ok {
		// 首次请求，初始化限流信息
		pm.rateLimitCache.Store(key, &RateLimitInfo{
			Count:    1,
			LastTime: now,
		})
		return nil
	}

	rateInfo := info.(*RateLimitInfo)
	
	// 检查是否超过时间窗口
	if now.Sub(rateInfo.LastTime) > time.Minute {
		// 重置计数
		rateInfo.Count = 1
		rateInfo.LastTime = now
		pm.rateLimitCache.Store(key, rateInfo)
		return nil
	}

	// 检查是否超过请求限制
	if rateInfo.Count >= 100 {
		return fmt.Errorf("操作过于频繁，请稍后重试")
	}

	// 更新计数
	rateInfo.Count++
	pm.rateLimitCache.Store(key, rateInfo)

	return nil
}

// RequirePermission 要求特定权限，缺失则尝试获取
func (pm *PermissionManager) RequirePermission(ctx context.Context, operation string) error {
	// 检查当前是否有足够权限
	if hasPermission, err := pm.CheckPermission(ctx, operation); hasPermission && err == nil {
		return nil
	}

	// 尝试获取权限
	if err := pm.acquirePermission(operation); err != nil {
		return err
	}

	// 再次检查权限
	if hasPermission, err := pm.CheckPermission(ctx, operation); !hasPermission || err != nil {
		return fmt.Errorf("获取权限失败: %v", err)
	}

	return nil
}

// acquirePermission 尝试获取权限
func (pm *PermissionManager) acquirePermission(operation string) error {
	switch runtime.GOOS {
	case "linux":
		// Linux：提示用户使用sudo重新运行
		return fmt.Errorf("请使用sudo权限重新运行此命令")
	case "windows":
		// Windows：提示用户以管理员身份重新运行
		return fmt.Errorf("请以管理员身份重新运行此命令")
	default:
		return fmt.Errorf("无法获取所需权限")
	}
}

// LogOperation 记录操作日志
func (pm *PermissionManager) LogOperation(ctx context.Context, operation string, target string, success bool) {
	// 记录操作日志到文件（简化实现）
	logPath := "./compliance.log"

	logEntry := fmt.Sprintf("%s | %s | %s | %s | %t\n", 
		time.Now().Format("2006-01-02 15:04:05"),
		operation,
		target,
		pm.getClientIP(ctx),
		success)

	// 写入日志文件
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	if _, err := file.WriteString(logEntry); err != nil {
		return
	}
}

// getClientIP 获取客户端IP地址
func (pm *PermissionManager) getClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value("ip").(string); ok {
		return ip
	}
	return "127.0.0.1"
}

// ValidateService 验证服务是否在授权清单内
func (pm *PermissionManager) ValidateService(ctx context.Context, service string) (bool, error) {
	for _, allowedService := range pm.authList.Services {
		if allowedService == "*" || allowedService == service {
			return true, nil
		}
	}
	return false, fmt.Errorf("服务 %s 不在授权清单内", service)
}
