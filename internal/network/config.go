package network

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// NetworkConfig 表示网络配置
type NetworkConfig struct {
	// 基础配置
	TargetCIDR      string        `json:"target_cidr"`
	TargetPorts     []int         `json:"target_ports"`
	Threads         int           `json:"threads"`
	Timeout         time.Duration `json:"timeout"`
	
	// 代理配置
	ProxyURL        string        `json:"proxy_url"`
	ProxyType       string        `json:"proxy_type"` // http, socks5
	
	// 防火墙规避
	UseFragmentation bool         `json:"use_fragmentation"`
	MTU              int          `json:"mtu"`
	TTL              int          `json:"ttl"`
	
	// 流量伪装
	RandomDelay      bool         `json:"random_delay"`
	MinDelay         time.Duration `json:"min_delay"`
	MaxDelay         time.Duration `json:"max_delay"`
	
	// 协议伪装
	UseHTTPProxy    bool          `json:"use_http_proxy"`
	UseHTTPS        bool          `json:"use_https"`
	UserAgent       string        `json:"user_agent"`
	
	// 网络环境检测
	DetectIDS       bool          `json:"detect_ids"`
	DetectFirewall  bool          `json:"detect_firewall"`
}

// DefaultNetworkConfig 返回默认网络配置
func DefaultNetworkConfig() *NetworkConfig {
	return &NetworkConfig{
		TargetCIDR:      "192.168.1.0/24",
		TargetPorts:     []int{22, 80, 135, 139, 443, 445, 3389},
		Threads:         50,
		Timeout:         3 * time.Second,
		ProxyURL:        "",
		ProxyType:       "http",
		UseFragmentation: false,
		MTU:             1500,
		TTL:             64,
		RandomDelay:      true,
		MinDelay:         100 * time.Millisecond,
		MaxDelay:         500 * time.Millisecond,
		UseHTTPProxy:     false,
		UseHTTPS:         false,
		UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		DetectIDS:        true,
		DetectFirewall:   true,
	}
}

// ValidateConfig 验证网络配置
func (c *NetworkConfig) ValidateConfig() error {
	// 验证CIDR格式
	if _, _, err := net.ParseCIDR(c.TargetCIDR); err != nil {
		return fmt.Errorf("无效的CIDR格式: %s", c.TargetCIDR)
	}
	
	// 验证端口范围
	for _, port := range c.TargetPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("无效端口号: %d", port)
		}
	}
	
	// 验证线程数
	if c.Threads < 1 || c.Threads > 1000 {
		return fmt.Errorf("线程数必须在1-1000之间: %d", c.Threads)
	}
	
	// 验证代理配置
	if c.ProxyURL != "" {
		if c.ProxyType != "http" && c.ProxyType != "socks5" {
			return fmt.Errorf("不支持的代理类型: %s", c.ProxyType)
		}
	}
	
	return nil
}

// ParseTargets 解析目标地址
func (c *NetworkConfig) ParseTargets() ([]string, error) {
	var targets []string
	
	// 解析CIDR
	ip, ipnet, err := net.ParseCIDR(c.TargetCIDR)
	if err != nil {
		return nil, err
	}
	
	// 生成IP列表
	for ip = ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		targets = append(targets, ip.String())
	}
	
	logrus.Infof("[GYscan-Network] 解析目标范围: %s, 生成 %d 个IP地址", c.TargetCIDR, len(targets))
	return targets, nil
}

// ParsePorts 解析端口字符串
func (c *NetworkConfig) ParsePorts(portStr string) error {
	if portStr == "" {
		return nil
	}
	
	var ports []int
	portRanges := strings.Split(portStr, ",")
	
	for _, portRange := range portRanges {
		if strings.Contains(portRange, "-") {
			// 端口范围
			rangeParts := strings.Split(portRange, "-")
			if len(rangeParts) != 2 {
				return fmt.Errorf("无效的端口范围格式: %s", portRange)
			}
			
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return fmt.Errorf("无效的起始端口: %s", rangeParts[0])
			}
			
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return fmt.Errorf("无效的结束端口: %s", rangeParts[1])
			}
			
			if start > end {
				return fmt.Errorf("起始端口不能大于结束端口: %d-%d", start, end)
			}
			
			for port := start; port <= end; port++ {
				if port >= 1 && port <= 65535 {
					ports = append(ports, port)
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(strings.TrimSpace(portRange))
			if err != nil {
				return fmt.Errorf("无效的端口号: %s", portRange)
			}
			
			if port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	
	c.TargetPorts = ports
	logrus.Infof("[GYscan-Network] 解析端口范围: %s, 生成 %d 个端口", portStr, len(ports))
	return nil
}

// incIP 递增IP地址
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetDelay 获取随机延迟时间
func (c *NetworkConfig) GetDelay() time.Duration {
	if !c.RandomDelay {
		return 0
	}
	
	delay := c.MinDelay + time.Duration(rand.Int63n(int64(c.MaxDelay-c.MinDelay)))
	return delay
}