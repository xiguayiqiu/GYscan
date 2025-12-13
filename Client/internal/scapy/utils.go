package scapy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ParsePorts 解析端口字符串
func ParsePorts(portStr string) ([]int, error) {
	if portStr == "" {
		// 返回常用端口
		return []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080}, nil
	}

	if portStr == "-" || portStr == "1-65535" {
		// 全端口扫描
		var allPorts []int
		for i := 1; i <= 65535; i++ {
			allPorts = append(allPorts, i)
		}
		return allPorts, nil
	}

	var ports []int
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 端口范围
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", part)
			}

			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", rangeParts[1])
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("端口范围无效: %d-%d", start, end)
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效的端口: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号超出范围: %d", port)
			}

			ports = append(ports, port)
		}
	}

	return removeDuplicates(ports), nil
}

// ParseTarget 解析目标字符串
func ParseTarget(target string) ([]string, error) {
	if target == "" {
		return nil, fmt.Errorf("目标不能为空")
	}

	// 检查是否是CIDR表示法
	if strings.Contains(target, "/") {
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}

		var ips []string
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}

		// 移除网络地址和广播地址
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1]
		}

		return ips, nil
	}

	// 检查是否是IP范围
	if strings.Contains(target, "-") {
		return parseIPRange(target)
	}

	// 单个IP或域名
	return []string{target}, nil
}

// parseIPRange 解析IP范围
func parseIPRange(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的IP范围格式: %s", ipRange)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("无效的IP地址")
	}

	var ips []string
	for ip := startIP; compareIPs(ip, endIP) <= 0; inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// compareIPs 比较两个IP地址
func compareIPs(ip1, ip2 net.IP) int {
	ip1 = ip1.To4()
	ip2 = ip2.To4()

	for i := 0; i < 4; i++ {
		if ip1[i] < ip2[i] {
			return -1
		} else if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// inc 递增IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// removeDuplicates 移除重复的端口
func removeDuplicates(ports []int) []int {
	seen := make(map[int]bool)
	result := []int{}

	for _, port := range ports {
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}

	return result
}

// GetNetworkInterfaces 获取网络接口列表
func GetNetworkInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var validInterfaces []net.Interface
	for _, iface := range interfaces {
		// 过滤掉回环接口和未启用的接口
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			validInterfaces = append(validInterfaces, iface)
		}
	}

	return validInterfaces, nil
}

// GetInterfaceIPs 获取接口的IP地址
func GetInterfaceIPs(ifaceName string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP)
			}
		}
	}

	return ips, nil
}

// FormatDuration 格式化持续时间
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
}

// FormatBytes 格式化字节大小
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// IsPrivateIP 检查是否为私有IP地址
func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}

// ResolveHostname 解析主机名
func ResolveHostname(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipv4s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}

	return ipv4s, nil
}

// ReverseDNS 反向DNS查询
func ReverseDNS(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}

	return names, nil
}

// CalculateChecksum 计算校验和（通用实现）
func CalculateChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		} else {
			sum += uint32(data[i]) << 8
		}
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// ValidateIP 验证IP地址格式
func ValidateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

// ValidatePort 验证端口号
func ValidatePort(port int) bool {
	return port >= 1 && port <= 65535
}

// GetCommonPorts 获取常用端口列表
func GetCommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
		993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
		8443, 27017,
	}
}

// GetWebPorts 获取Web服务常用端口
func GetWebPorts() []int {
	return []int{80, 443, 8080, 8443, 8000, 3000, 5000}
}

// GetDatabasePorts 获取数据库常用端口
func GetDatabasePorts() []int {
	return []int{1433, 1521, 3306, 5432, 27017, 6379}
}

// GetRemoteAccessPorts 获取远程访问常用端口
func GetRemoteAccessPorts() []int {
	return []int{22, 23, 3389, 5900}
}
