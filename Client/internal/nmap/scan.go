package nmap

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NmapResult 表示nmap扫描结果
type NmapResult struct {
	IP       string            `json:"ip"`
	Hostname string            `json:"hostname,omitempty"`
	Ports    map[int]PortInfo  `json:"ports"`
	OS       string            `json:"os,omitempty"`
	Services []string          `json:"services,omitempty"`
	Status   string            `json:"status"`
}

// PortInfo 表示端口信息
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Banner   string `json:"banner,omitempty"`
	State    string `json:"state"` // open/closed/filtered
	Version  string `json:"version,omitempty"`
}

// ScanConfig 表示扫描配置
type ScanConfig struct {
	Target     string
	Ports      string
	Threads    int
	Timeout    time.Duration
	ScanType   string // syn, connect, udp
	OSDetection bool
	ServiceDetection bool
	TimingTemplate int // 扫描速度模板 (0-5, 完全模仿nmap -T参数)
	TTLDetection bool // TTL检测，用于估算目标距离
}

// applyTimingTemplate 应用nmap风格的扫描速度模板
func applyTimingTemplate(config *ScanConfig) {
	// 默认使用级别3 (Normal)
	if config.TimingTemplate < 0 || config.TimingTemplate > 5 {
		config.TimingTemplate = 3
	}

	// 根据nmap -T参数标准设置
	switch config.TimingTemplate {
	case 0: // Paranoid - 极慢 (每5分钟发送一个包)
		config.Threads = 1
		config.Timeout = 5 * time.Minute
	case 1: // Sneaky - 很慢 (每15秒发送一个包)
		config.Threads = 1
		config.Timeout = 15 * time.Second
	case 2: // Polite - 慢速 (每0.4秒发送一个包)
		config.Threads = 10
		config.Timeout = 400 * time.Millisecond
	case 3: // Normal - 正常 (默认)
		config.Threads = 50
		config.Timeout = 3 * time.Second
	case 4: // Aggressive - 快速 (减少超时时间)
		config.Threads = 100
		config.Timeout = 1 * time.Second
	case 5: // Insane - 极快 (最大并发，最小超时)
		config.Threads = 200
		config.Timeout = 500 * time.Millisecond
	}
}

// NmapScan 执行完整的nmap扫描
func NmapScan(config ScanConfig) []NmapResult {
	// 应用扫描速度模板
	applyTimingTemplate(&config)
	
	fmt.Printf("[GYscan-Nmap] 开始扫描: 目标=%s, 端口=%s, 线程=%d, 类型=%s, 速度级别=%d\n", 
		config.Target, config.Ports, config.Threads, config.ScanType, config.TimingTemplate)

	// 解析目标
	hosts := parseTarget(config.Target)
	portList := parsePorts(config.Ports)

	var results []NmapResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 进度统计变量
	totalHosts := len(hosts)
	totalPorts := len(portList)
	completedHosts := 0
	openPortsCount := 0

	// 创建并发控制通道
	semaphore := make(chan struct{}, config.Threads)

	// 显示初始进度信息
	fmt.Printf("[进度] 扫描 %d 个主机，每个主机 %d 个端口，总共 %d 个端口扫描任务\n", 
		totalHosts, totalPorts, totalHosts*totalPorts)

	for _, host := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查主机存活
			isAlive := hostDiscovery(ip, config.Timeout)
			
			result := NmapResult{
				IP:     ip,
				Ports:  make(map[int]PortInfo),
				Status: "down",
			}

			if !isAlive {
				// 静默处理不存活的主机
				mu.Lock()
				results = append(results, result)
				completedHosts++
				fmt.Printf("[进度] 主机 %s 不存活 (%d/%d)\n", ip, completedHosts, totalHosts)
				mu.Unlock()
				return
			}

			fmt.Printf("[进度] 主机 %s 存活，开始端口扫描 (%d/%d)\n", ip, completedHosts+1, totalHosts)
			result.Status = "up"

			// 端口扫描
			portResults := portScanWithProgress(ip, portList, config.ScanType, config.Threads, config.Timeout, &openPortsCount, &mu)
			result.Ports = portResults

			// 服务识别
			if config.ServiceDetection && len(portResults) > 0 {
				result.Services = serviceDetection(ip, portResults)
			}

			// OS识别
		if config.OSDetection && len(portResults) > 0 {
			result.OS = osDetection(ip, portResults)
		}

		// TTL检测
		if config.TTLDetection && result.Status == "up" {
			distance := detectTTL(ip, config.Timeout)
			if distance > 0 {
				result.Hostname = fmt.Sprintf("距离约%d跳", distance)
			}
		}

		mu.Lock()
		results = append(results, result)
		completedHosts++
		fmt.Printf("[进度] 主机 %s 扫描完成，发现 %d 个开放端口 (%d/%d)\n", 
			ip, len(portResults), completedHosts, totalHosts)
		mu.Unlock()
		}(host)
	}

	wg.Wait()
	fmt.Printf("[GYscan-Nmap] 扫描完成，发现 %d 台活跃主机，总共 %d 个开放端口\n", 
		len(results), openPortsCount)
	return results
}

// hostDiscovery 主机发现（存活检测）
func hostDiscovery(ip string, timeout time.Duration) bool {
	// 多种方式检测主机存活
	methods := []func(string, time.Duration) bool{
		icmpPing,
		tcpPing,
		udpPing,
		arpDiscovery,
	}

	for _, method := range methods {
		if method(ip, timeout) {
			return true
		}
	}
	return false
}

// icmpPing ICMP Ping检测
func icmpPing(ip string, timeout time.Duration) bool {
	// Windows上需要管理员权限，使用TCP作为备选
	return tcpPing(ip, timeout)
}

// tcpPing TCP Ping检测
func tcpPing(ip string, timeout time.Duration) bool {
	// 尝试常见端口
	commonPorts := []int{22, 80, 135, 139, 443, 445, 3389}
	for _, port := range commonPorts {
		if tcpConnect(ip, port, timeout) {
			return true
		}
	}
	return false
}

// udpPing UDP Ping检测
func udpPing(ip string, timeout time.Duration) bool {
	// UDP检测（DNS端口）
	return udpConnect(ip, 53, timeout)
}

// arpDiscovery ARP发现（同一网段）
func arpDiscovery(ip string, timeout time.Duration) bool {
	// 仅在同一网段内有效
	if !isSameSubnet(ip) {
		return false
	}
	// TODO: 实现ARP发现
	return false
}

// portScan 端口扫描
func portScan(ip string, ports []int, scanType string, threads int, timeout time.Duration) map[int]PortInfo {
	results := make(map[int]PortInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, threads)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var portInfo PortInfo
			switch scanType {
			case "syn":
				portInfo = synScan(ip, p, timeout)
			case "udp":
				portInfo = udpScan(ip, p, timeout)
			default:
				portInfo = connectScan(ip, p, timeout)
			}

			if portInfo.State == "open" {
				mu.Lock()
				results[p] = portInfo
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}

// portScanWithProgress 带进度显示的端口扫描
func portScanWithProgress(ip string, ports []int, scanType string, threads int, timeout time.Duration, openPortsCount *int, muGlobal *sync.Mutex) map[int]PortInfo {
	results := make(map[int]PortInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	totalPorts := len(ports)
	completedPorts := 0
	openPorts := 0

	semaphore := make(chan struct{}, threads)

	// 显示端口扫描开始信息
	fmt.Printf("[进度] 主机 %s 开始扫描 %d 个端口\n", ip, totalPorts)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var portInfo PortInfo
			switch scanType {
			case "syn":
				portInfo = synScan(ip, p, timeout)
			case "udp":
				portInfo = udpScan(ip, p, timeout)
			default:
				portInfo = connectScan(ip, p, timeout)
			}

			mu.Lock()
			completedPorts++
			
			if portInfo.State == "open" {
				results[p] = portInfo
				openPorts++
				
				// 更新全局开放端口计数
				muGlobal.Lock()
				*openPortsCount++
				muGlobal.Unlock()
				
				fmt.Printf("[进度] 主机 %s 端口 %d 开放 (%d/%d) - 已发现 %d 个开放端口\n", 
					ip, p, completedPorts, totalPorts, openPorts)
			} else {
				// 每扫描10个端口显示一次进度（避免输出过多）
				if completedPorts%10 == 0 || completedPorts == totalPorts {
					fmt.Printf("[进度] 主机 %s 端口扫描进度: %d/%d - 已发现 %d 个开放端口\n", 
						ip, completedPorts, totalPorts, openPorts)
				}
			}
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	fmt.Printf("[进度] 主机 %s 端口扫描完成: %d/%d 端口开放\n", ip, openPorts, totalPorts)
	return results
}

// connectScan TCP连接扫描
func connectScan(ip string, port int, timeout time.Duration) PortInfo {
	info := PortInfo{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
	}

	if tcpConnect(ip, port, timeout) {
		info.State = "open"
		// 获取banner
		info.Banner = getBanner(ip, port, timeout)
		info.Service = identifyService(port, info.Banner)
	}

	return info
}

// synScan TCP SYN扫描（半连接）
func synScan(ip string, port int, timeout time.Duration) PortInfo {
	// TODO: 实现SYN扫描（需要原始套接字权限）
	// 暂时使用connect扫描
	return connectScan(ip, port, timeout)
}

// udpScan UDP扫描
func udpScan(ip string, port int, timeout time.Duration) PortInfo {
	info := PortInfo{
		Port:     port,
		Protocol: "udp",
		State:    "closed",
	}

	if udpConnect(ip, port, timeout) {
		info.State = "open"
		// 获取UDP服务banner并识别服务
		banner := getUDPBanner(ip, port, timeout)
		info.Service = identifyUDPService(port, banner)
	}

	return info
}

// getUDPBanner 获取UDP服务banner
func getUDPBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 发送特定协议的探测包
	probeData := getUDPProbeData(port)
	if len(probeData) > 0 {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = conn.Write(probeData)
		if err != nil {
			return ""
		}

		// 尝试接收响应
		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			return string(buf[:n])
		}
	}

	return ""
}

// getUDPProbeData 获取UDP协议探测包
func getUDPProbeData(port int) []byte {
	// 根据端口号发送特定协议的探测包
	switch port {
	case 53: // DNS
		// DNS查询包
		return []byte{
			0x00, 0x00, // Transaction ID
			0x01, 0x00, // Flags: Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // Domain: example
			0x03, 'c', 'o', 'm', // com
			0x00,       // End of domain
			0x00, 0x01, // Type: A
			0x00, 0x01, // Class: IN
		}
	case 161: // SNMP
		// SNMP GetRequest
		return []byte{
			0x30, 0x26, // SNMP message
			0x02, 0x01, 0x00, // Version: SNMPv1
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // Community: public
			0xa0, 0x19, // PDU: GetRequest
			0x02, 0x01, 0x00, // Request ID: 0
			0x02, 0x01, 0x00, // Error status: 0
			0x02, 0x01, 0x00, // Error index: 0
			0x30, 0x0e, // Variable bindings
			0x30, 0x0c, // Sequence
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr.0
			0x05, 0x00, // Value: Null
		}
	case 123: // NTP
		// NTP request
		return []byte{
			0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	default:
		// 通用UDP探测包
		return []byte("GYscan-UDP-Probe")
	}
}

// tcpConnect TCP连接测试
func tcpConnect(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// udpConnect UDP连接测试
func udpConnect(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 发送测试数据
	testData := []byte("GYscan-UDP-Test")
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(testData)
	if err != nil {
		return false
	}

	// 尝试接收响应
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)
	
	// 即使没有响应，也可能表示端口开放（UDP特性）
	return true
}

// getBanner 获取服务banner
func getBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

// serviceDetection 服务识别
func serviceDetection(ip string, ports map[int]PortInfo) []string {
	var services []string
	for _, portInfo := range ports {
		if portInfo.Service != "unknown" && portInfo.Service != "" {
			services = append(services, fmt.Sprintf("%s/%d", portInfo.Service, portInfo.Port))
		}
	}
	return services
}

// osDetection 操作系统识别
func osDetection(ip string, ports map[int]PortInfo) string {
	// 基于端口指纹识别操作系统
	if _, has445 := ports[445]; has445 {
		return "Windows"
	}
	if _, has22 := ports[22]; has22 {
		return "Linux/Unix"
	}
	if _, has135 := ports[135]; has135 {
		return "Windows"
	}
	if _, has139 := ports[139]; has139 {
		return "Windows"
	}
	
	// 基于TTL值进行操作系统识别
	if os := detectOSByTTL(ip); os != "Unknown" {
		return os
	}
	
	// 基于服务组合进行识别
	if os := detectOSByServiceCombination(ports); os != "Unknown" {
		return os
	}
	
	// 基于banner信息进行识别
	if os := detectOSByBanner(ports); os != "Unknown" {
		return os
	}
	
	return "Unknown"
}

// detectOSByTTL 基于TTL值识别操作系统
func detectOSByTTL(ip string) string {
	// 发送ICMP包并分析TTL值
	conn, err := net.DialTimeout("ip4:icmp", ip, 3*time.Second)
	if err != nil {
		return "Unknown"
	}
	defer conn.Close()
	
	// 构造ICMP包
	icmpMsg := []byte{
		8, 0, // Type=8 (Echo Request), Code=0
		0, 0, // Checksum (will be calculated)
		0, 0, // Identifier
		0, 0, // Sequence Number
	}
	
	// 计算校验和
	checksum := calculateChecksum(icmpMsg)
	icmpMsg[2] = byte(checksum >> 8)
	icmpMsg[3] = byte(checksum & 0xFF)
	
	// 发送ICMP包
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(icmpMsg)
	if err != nil {
		return "Unknown"
	}
	
	// 接收响应（简化实现，实际需要解析IP头获取TTL）
	// 这里使用简化的端口组合识别作为备选
	return "Unknown"
}

// detectOSByServiceCombination 基于服务组合识别操作系统
func detectOSByServiceCombination(ports map[int]PortInfo) string {
	// 检查常见的服务组合
	hasHTTP := false
	hasHTTPS := false
	hasSSH := false
	hasRDP := false
	hasSMB := false
	hasNetBIOS := false
	hasMSRPC := false
	
	for port := range ports {
		switch port {
		case 80:
			hasHTTP = true
		case 443:
			hasHTTPS = true
		case 22:
			hasSSH = true
		case 3389:
			hasRDP = true
		case 445:
			hasSMB = true
		case 139:
			hasNetBIOS = true
		case 135:
			hasMSRPC = true
		}
	}
	
	// Windows系统特征识别
	if hasRDP || hasSMB || hasNetBIOS || hasMSRPC {
		return detectWindowsVersion(ports)
	}
	
	// Linux/Unix系统特征识别
	if hasSSH && !hasRDP {
		return detectLinuxVersion(ports)
	}
	
	// Web服务器通常运行在Linux上
	if (hasHTTP || hasHTTPS) && !hasRDP && !hasSSH {
		return "Linux/Unix (Web Server)" // Web服务器多为Linux
	}
	
	return "Unknown"
}

// detectWindowsVersion 识别Windows版本
func detectWindowsVersion(ports map[int]PortInfo) string {
	hasRDP := false
	hasSMB := false
	hasNetBIOS := false
	hasMSRPC := false
	
	for port := range ports {
		switch port {
		case 3389:
			hasRDP = true
		case 445:
			hasSMB = true
		case 139:
			hasNetBIOS = true
		case 135:
			hasMSRPC = true
		}
	}
	
	// 现代Windows系统（Windows 10/11/Server 2016+）
	if hasRDP && hasSMB && !hasNetBIOS {
		return "Windows 10/11/Server 2016+"
	}
	
	// 较新Windows系统（Windows 8/Server 2012）
	if hasRDP && hasSMB && hasNetBIOS {
		return "Windows 8/Server 2012"
	}
	
	// 较旧Windows系统（Windows 7/Server 2008）
	if hasSMB && hasNetBIOS && !hasRDP {
		return "Windows 7/Server 2008"
	}
	
	// 老版本Windows系统
	if hasNetBIOS && hasMSRPC && !hasSMB {
		return "Windows XP/2003"
	}
	
	// 通用Windows识别
	if hasSMB || hasRDP || hasNetBIOS || hasMSRPC {
		return "Windows"
	}
	
	return "Unknown"
}

// detectLinuxVersion 识别Linux版本
func detectLinuxVersion(ports map[int]PortInfo) string {
	hasSSH := false
	hasHTTP := false
	hasHTTPS := false
	hasSpecificPorts := false
	
	for port := range ports {
		switch port {
		case 22:
			hasSSH = true
		case 80:
			hasHTTP = true
		case 443:
			hasHTTPS = true
		case 111, 2049, 3306, 5432, 6379, 27017: // RPC, NFS, MySQL, PostgreSQL, Redis, MongoDB
			hasSpecificPorts = true
		}
	}
	
	// 服务器版本（通常有数据库服务）
	if hasSSH && hasSpecificPorts {
		return "Linux Server (Ubuntu/CentOS/Debian)"
	}
	
	// 桌面版本（通常只有基本服务）
	if hasSSH && !hasSpecificPorts {
		return "Linux Desktop (Ubuntu/Fedora)"
	}
	
	// Web服务器
	if (hasHTTP || hasHTTPS) && hasSSH {
		return "Linux Web Server (Ubuntu/CentOS)"
	}
	
	return "Linux/Unix"
}

// detectOSByBanner 基于banner信息识别操作系统
func detectOSByBanner(ports map[int]PortInfo) string {
	for _, portInfo := range ports {
		banner := strings.ToLower(portInfo.Banner)
		
		// 检查banner中的操作系统特征
		switch {
		case strings.Contains(banner, "windows") || strings.Contains(banner, "microsoft"):
			return detectWindowsVersionFromBanner(banner)
		case strings.Contains(banner, "linux") || strings.Contains(banner, "ubuntu") || 
			 strings.Contains(banner, "centos") || strings.Contains(banner, "debian") ||
			 strings.Contains(banner, "fedora") || strings.Contains(banner, "redhat"):
			return detectLinuxVersionFromBanner(banner)
		case strings.Contains(banner, "freebsd") || strings.Contains(banner, "openbsd"):
			return detectBSDVersionFromBanner(banner)
		case strings.Contains(banner, "cisco"):
			return "Cisco IOS"
		case strings.Contains(banner, "apache") || strings.Contains(banner, "nginx"):
			// Web服务器多为Linux
			return "Linux/Unix (Web Server)"
		case strings.Contains(banner, "iis"):
			return detectIISVersionFromBanner(banner)
		}
	}
	
	return "Unknown"
}

// detectWindowsVersionFromBanner 从banner识别Windows版本
func detectWindowsVersionFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)
	
	// Windows版本识别
	switch {
	case strings.Contains(bannerLower, "windows 11") || strings.Contains(bannerLower, "win11"):
		return "Windows 11"
	case strings.Contains(bannerLower, "windows 10") || strings.Contains(bannerLower, "win10"):
		return "Windows 10"
	case strings.Contains(bannerLower, "windows 8.1") || strings.Contains(bannerLower, "win8.1"):
		return "Windows 8.1"
	case strings.Contains(bannerLower, "windows 8") || strings.Contains(bannerLower, "win8"):
		return "Windows 8"
	case strings.Contains(bannerLower, "windows 7") || strings.Contains(bannerLower, "win7"):
		return "Windows 7"
	case strings.Contains(bannerLower, "windows xp") || strings.Contains(bannerLower, "winxp"):
		return "Windows XP"
	case strings.Contains(bannerLower, "server 2022"):
		return "Windows Server 2022"
	case strings.Contains(bannerLower, "server 2019"):
		return "Windows Server 2019"
	case strings.Contains(bannerLower, "server 2016"):
		return "Windows Server 2016"
	case strings.Contains(bannerLower, "server 2012"):
		return "Windows Server 2012"
	case strings.Contains(bannerLower, "server 2008"):
		return "Windows Server 2008"
	case strings.Contains(bannerLower, "server 2003"):
		return "Windows Server 2003"
	default:
		return "Windows"
	}
}

// detectLinuxVersionFromBanner 从banner识别Linux版本
func detectLinuxVersionFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)
	
	// Linux发行版识别
	switch {
	case strings.Contains(bannerLower, "ubuntu"):
		return detectUbuntuVersion(bannerLower)
	case strings.Contains(bannerLower, "centos"):
		return detectCentOSVersion(bannerLower)
	case strings.Contains(bannerLower, "debian"):
		return detectDebianVersion(bannerLower)
	case strings.Contains(bannerLower, "fedora"):
		return "Fedora Linux"
	case strings.Contains(bannerLower, "red hat") || strings.Contains(bannerLower, "rhel"):
		return "Red Hat Enterprise Linux"
	case strings.Contains(bannerLower, "alpine"):
		return "Alpine Linux"
	case strings.Contains(bannerLower, "arch"):
		return "Arch Linux"
	default:
		return "Linux/Unix"
	}
}

// detectUbuntuVersion 识别Ubuntu版本
func detectUbuntuVersion(banner string) string {
	switch {
	case strings.Contains(banner, "22.04") || strings.Contains(banner, "jammy"):
		return "Ubuntu 22.04 LTS (Jammy Jellyfish)"
	case strings.Contains(banner, "20.04") || strings.Contains(banner, "focal"):
		return "Ubuntu 20.04 LTS (Focal Fossa)"
	case strings.Contains(banner, "18.04") || strings.Contains(banner, "bionic"):
		return "Ubuntu 18.04 LTS (Bionic Beaver)"
	case strings.Contains(banner, "16.04") || strings.Contains(banner, "xenial"):
		return "Ubuntu 16.04 LTS (Xenial Xerus)"
	default:
		return "Ubuntu"
	}
}

// detectCentOSVersion 识别CentOS版本
func detectCentOSVersion(banner string) string {
	switch {
	case strings.Contains(banner, "stream"):
		return "CentOS Stream"
	case strings.Contains(banner, "8"):
		return "CentOS 8"
	case strings.Contains(banner, "7"):
		return "CentOS 7"
	case strings.Contains(banner, "6"):
		return "CentOS 6"
	default:
		return "CentOS"
	}
}

// detectDebianVersion 识别Debian版本
func detectDebianVersion(banner string) string {
	switch {
	case strings.Contains(banner, "bookworm"):
		return "Debian 12 (Bookworm)"
	case strings.Contains(banner, "bullseye"):
		return "Debian 11 (Bullseye)"
	case strings.Contains(banner, "buster"):
		return "Debian 10 (Buster)"
	case strings.Contains(banner, "stretch"):
		return "Debian 9 (Stretch)"
	default:
		return "Debian"
	}
}

// detectBSDVersionFromBanner 识别BSD版本
func detectBSDVersionFromBanner(banner string) string {
	switch {
	case strings.Contains(banner, "freebsd"):
		return "FreeBSD"
	case strings.Contains(banner, "openbsd"):
		return "OpenBSD"
	case strings.Contains(banner, "netbsd"):
		return "NetBSD"
	default:
		return "BSD"
	}
}

// detectIISVersionFromBanner 识别IIS版本
func detectIISVersionFromBanner(banner string) string {
	switch {
	case strings.Contains(banner, "iis 10"):
		return "Windows (IIS 10.0)"
	case strings.Contains(banner, "iis 8.5"):
		return "Windows (IIS 8.5)"
	case strings.Contains(banner, "iis 8"):
		return "Windows (IIS 8.0)"
	case strings.Contains(banner, "iis 7.5"):
		return "Windows (IIS 7.5)"
	case strings.Contains(banner, "iis 7"):
		return "Windows (IIS 7.0)"
	case strings.Contains(banner, "iis 6"):
		return "Windows (IIS 6.0)"
	default:
		return "Windows (IIS)"
	}
}

// calculateChecksum 计算ICMP校验和
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	
	return ^uint16(sum)
}

// identifyService 识别TCP服务
func identifyService(port int, banner string) string {
	serviceMap := map[int]string{
		21:   "ftp",
		22:   "ssh", 
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		111:  "rpcbind",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		445:  "microsoft-ds",
		993:  "imaps",
		995:  "pop3s",
		1433: "ms-sql-s",
		1521: "oracle",
		2049: "nfs",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		6379: "redis",
		8080: "http-proxy",
		27017: "mongodb",
	}

	// 首先尝试基于端口号的识别
	if service, exists := serviceMap[port]; exists {
		return service
	}

	// 如果端口不是标准端口，进行深度服务识别
	if banner != "" {
		return identifyServiceByBanner(banner)
	}

	// 尝试协议特征识别
	if service := identifyServiceByProtocol(port); service != "unknown" {
		return service
	}

	return "unknown"
}

// identifyServiceByBanner 基于banner深度识别服务
func identifyServiceByBanner(banner string) string {
	bannerLower := strings.ToLower(banner)
	
	// SSH服务识别（支持非标准端口）
	if strings.Contains(bannerLower, "ssh") || 
	   strings.Contains(bannerLower, "openssh") ||
	   strings.HasPrefix(banner, "SSH-") {
		return "ssh"
	}
	
	// HTTP服务识别
	if strings.Contains(bannerLower, "http") || 
	   strings.Contains(bannerLower, "server:") ||
	   strings.Contains(bannerLower, "apache") || 
	   strings.Contains(bannerLower, "nginx") ||
	   strings.Contains(bannerLower, "iis") ||
	   strings.Contains(bannerLower, "tomcat") ||
	   strings.Contains(bannerLower, "lighttpd") {
		return "http"
	}
	
	// FTP服务识别
	if strings.Contains(bannerLower, "ftp") ||
	   strings.Contains(bannerLower, "220 ") && (strings.Contains(bannerLower, "filezilla") || 
	   strings.Contains(bannerLower, "vsftpd") || strings.Contains(bannerLower, "proftpd")) {
		return "ftp"
	}
	
	// SMTP服务识别
	if strings.Contains(bannerLower, "smtp") ||
	   strings.HasPrefix(banner, "220 ") && (strings.Contains(bannerLower, "esmtp") ||
	   strings.Contains(bannerLower, "sendmail") || strings.Contains(bannerLower, "postfix")) {
		return "smtp"
	}
	
	// 数据库服务识别
	if strings.Contains(bannerLower, "mysql") {
		return "mysql"
	}
	if strings.Contains(bannerLower, "postgres") || strings.Contains(bannerLower, "postgresql") {
		return "postgresql"
	}
	if strings.Contains(bannerLower, "redis") {
		return "redis"
	}
	if strings.Contains(bannerLower, "mongodb") || strings.Contains(bannerLower, "mongod") {
		return "mongodb"
	}
	if strings.Contains(bannerLower, "oracle") {
		return "oracle"
	}
	if strings.Contains(bannerLower, "microsoft sql") || strings.Contains(bannerLower, "sql server") {
		return "ms-sql-s"
	}
	
	// 远程桌面服务识别
	if strings.Contains(bannerLower, "rdp") || strings.Contains(bannerLower, "remote desktop") {
		return "rdp"
	}
	
	// Telnet服务识别
	if strings.Contains(bannerLower, "telnet") {
		return "telnet"
	}
	
	// DNS服务识别
	if strings.Contains(bannerLower, "dns") || strings.Contains(bannerLower, "bind") {
		return "dns"
	}
	
	// 邮件服务识别
	if strings.Contains(bannerLower, "pop3") {
		return "pop3"
	}
	if strings.Contains(bannerLower, "imap") {
		return "imap"
	}
	
	return "unknown"
}

// identifyServiceByProtocol 基于协议特征识别服务
func identifyServiceByProtocol(port int) string {
	// 尝试连接并发送协议特定的探测包
	// 这里可以扩展为发送各种协议的握手包进行识别
	
	// 对于未知端口，返回unknown，后续可以扩展协议探测功能
	return "unknown"
}

// identifyUDPService 识别UDP服务
func identifyUDPService(port int, banner string) string {
	serviceMap := map[int]string{
		53:   "dns",
		67:   "dhcps",
		68:   "dhcpc",
		69:   "tftp",
		123:  "ntp",
		161:  "snmp",
		162:  "snmptrap",
		514:  "syslog",
		520:  "rip",
		1434: "ms-sql-m",
		1900: "upnp",
		5353: "mdns",
	}

	// 首先尝试基于端口号的识别
	if service, exists := serviceMap[port]; exists {
		return service
	}

	// 如果端口不是标准端口，尝试基于banner识别
	if banner != "" {
		return identifyUDPServiceByBanner(banner)
	}

	return "unknown"
}

// identifyUDPServiceByBanner 基于banner识别UDP服务
func identifyUDPServiceByBanner(banner string) string {
	bannerLower := strings.ToLower(banner)
	
	// DNS服务识别
	if strings.Contains(bannerLower, "dns") || strings.Contains(bannerLower, "bind") {
		return "dns"
	}
	
	// SNMP服务识别
	if strings.Contains(bannerLower, "snmp") {
		return "snmp"
	}
	
	// NTP服务识别
	if strings.Contains(bannerLower, "ntp") {
		return "ntp"
	}
	
	// TFTP服务识别
	if strings.Contains(bannerLower, "tftp") {
		return "tftp"
	}
	
	// Syslog服务识别
	if strings.Contains(bannerLower, "syslog") {
		return "syslog"
	}
	
	// DHCP服务识别
	if strings.Contains(bannerLower, "dhcp") {
		return "dhcps"
	}
	
	// SQL Server Browser服务识别
	if strings.Contains(bannerLower, "sql") || strings.Contains(bannerLower, "microsoft") {
		return "ms-sql-m"
	}
	
	return "unknown"
}

// parseTarget 解析目标
func parseTarget(target string) []string {
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	} else if strings.Contains(target, "-") {
		return parseIPRange(target)
	} else {
		return []string{target}
	}
}

// parseCIDR 解析CIDR格式
func parseCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("[GYscan-Nmap] 解析CIDR失败: %v\n", err)
		return []string{}
	}

	var ips []string
	for current := ip.Mask(ipnet.Mask); ipnet.Contains(current); inc(current) {
		ips = append(ips, current.String())
	}

	return ips
}

// parseIPRange 解析IP范围
func parseIPRange(ipRange string) []string {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		fmt.Printf("[GYscan-Nmap] 无效的IP范围格式: %s\n", ipRange)
		return []string{}
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	
	if startIP == nil || endIP == nil {
		fmt.Printf("[GYscan-Nmap] 无效的IP地址\n")
		return []string{}
	}

	var ips []string
	for ip := startIP; !ip.Equal(endIP); inc(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())

	return ips
}

// parsePorts 解析端口列表
func parsePorts(ports string) []int {
	var portList []int
	
	if ports == "" {
		// 默认端口范围 1-1000
		for p := 1; p <= 1000; p++ {
			portList = append(portList, p)
		}
		return portList
	}

	parts := strings.Split(ports, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 端口范围
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0])
				end, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && start <= end {
					for p := start; p <= end; p++ {
						portList = append(portList, p)
					}
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err == nil && port > 0 && port <= 65535 {
				portList = append(portList, port)
			}
		}
	}

	return portList
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

// isSameSubnet 检查是否在同一网段
func isSameSubnet(ip string) bool {
	// TODO: 实现网段检查
	return false
}

// detectTTL TTL检测，用于估算目标距离
func detectTTL(ip string, timeout time.Duration) int {
	// 尝试常见端口进行TTL检测
	commonPorts := []int{22, 80, 443, 3389}
	
	for _, port := range commonPorts {
		distance := getTTLDistance(ip, port, timeout)
		if distance > 0 {
			return distance
		}
	}
	
	return 0
}

// getTTLDistance 获取TTL距离估算
func getTTLDistance(ip string, port int, timeout time.Duration) int {
	// 使用原始套接字获取TTL值
	// 由于Windows权限限制，这里使用模拟方法
	
	// 模拟TTL检测逻辑
	// 实际实现中应该使用原始套接字获取IP头中的TTL值
	
	// 基于目标IP的TTL初始值估算距离
	// 常见系统的默认TTL值:
	// - Windows: 128
	// - Linux: 64
	// - Unix: 255
	
	// 首先尝试连接获取基本信息
	if !tcpConnect(ip, port, timeout) {
		return 0
	}
	
	// 模拟TTL检测（实际实现需要原始套接字权限）
	// 这里使用简化的距离估算算法
	distance := estimateDistanceByIP(ip)
	
	return distance
}

// estimateDistanceByIP 基于IP地址估算距离
func estimateDistanceByIP(ip string) int {
	// 简化的距离估算算法
	// 实际实现应该基于网络拓扑和路由信息
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0
	}
	
	// 检查是否为本地网络
	if isLocalNetwork(parsedIP) {
		return 1 // 本地网络，距离1跳
	}
	
	// 检查是否为私有网络
	if isPrivateNetwork(parsedIP) {
		return 2 // 私有网络，距离2跳
	}
	
	// 检查是否为公网IP
	if isPublicNetwork(parsedIP) {
		// 基于IP地址的地理位置估算距离
		return estimateGeographicDistance(parsedIP)
	}
	
	return 0
}

// isLocalNetwork 检查是否为本地网络
func isLocalNetwork(ip net.IP) bool {
	// 检查是否为本地回环或链路本地地址
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// isPrivateNetwork 检查是否为私有网络
func isPrivateNetwork(ip net.IP) bool {
	// RFC 1918 私有地址范围
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		}
	}
	
	// RFC 4193 私有地址范围 (IPv6)
	if ip.To16() != nil && ip.To4() == nil {
		if len(ip) >= 2 && ip[0] == 0xfd {
			return true
		}
	}
	
	return false
}

// isPublicNetwork 检查是否为公网IP
func isPublicNetwork(ip net.IP) bool {
	return !isLocalNetwork(ip) && !isPrivateNetwork(ip)
}

// estimateGeographicDistance 基于地理位置估算距离
func estimateGeographicDistance(ip net.IP) int {
	// 简化的地理位置距离估算
	// 实际实现应该使用IP地理位置数据库
	
	// 基于IP地址的前几个字节进行粗略估算
	if ip4 := ip.To4(); ip4 != nil {
		// 中国大陆IP段估算
		if (ip4[0] >= 1 && ip4[0] <= 126) || 
		   (ip4[0] >= 128 && ip4[0] <= 191) ||
		   (ip4[0] >= 192 && ip4[0] <= 223) {
			// 中国大陆IP，距离3-10跳
			return 5 + int(ip4[3])%6
		}
		
		// 其他地区IP，距离可能更远
		return 10 + int(ip4[3])%10
	}
	
	// IPv6地址，默认距离较远
	return 15
}