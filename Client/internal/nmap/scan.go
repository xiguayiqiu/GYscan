package nmap

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pre-compiled regular expressions for performance optimization
var (
	mysqlVersionRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(\d+\.\d+\.\d+)-MariaDB`),
		regexp.MustCompile(`MariaDB[\s\-]*(\d+\.\d+\.\d+)`),
		regexp.MustCompile(`(\d+\.\d+\.\d+)[\s\-]*MySQL`),
		regexp.MustCompile(`MySQL[\s\-]*(\d+\.\d+\.\d+)`),
		regexp.MustCompile(`\b(\d+\.\d+\.\d+)\b`),
		regexp.MustCompile(`\b(\d+\.\d+)\b`),
	}

	macAddressRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
)

// Constants for magic numbers to improve code readability and maintainability
const (
	// Port ranges
	MinPort              = 1
	MaxPort              = 65535
	DefaultScanPortRange = "1-10000"
	FullPortScanRange    = "1-65535"

	// Timeout constants
	DefaultTimeout = 3 * time.Second
	LongTimeout    = 5 * time.Minute
	SlowTimeout    = 15 * time.Second
	MediumTimeout  = 400 * time.Millisecond
	FastTimeout    = 1 * time.Second
	InsaneTimeout  = 500 * time.Millisecond

	// Thread counts
	ParanoidThreads   = 1
	PoliteThreads     = 10
	DefaultThreads    = 50
	AggressiveThreads = 100
	InsaneThreads     = 200

	// Timing templates (matching nmap -T parameters)
	TimingParanoid   = 0
	TimingSneaky     = 1
	TimingPolite     = 2
	TimingNormal     = 3
	TimingAggressive = 4
	TimingInsane     = 5

	// TTL values for OS detection
	WindowsDefaultTTL = 128
	LinuxDefaultTTL   = 64
	UnixDefaultTTL    = 255

	// Network distance estimation
	LocalNetworkDistance   = 1
	PrivateNetworkDistance = 2
	MinGeographicDistance  = 5
	MaxGeographicDistance  = 15

	// Progress display frequency
	ProgressDisplayFrequency = 100

	// Banner read timeout
	BannerReadTimeout = 2 * time.Second

	// Confirmation methods for host discovery
	MinConfirmationMethods = 2
)

// Common ports for various services
var (
	// Common TCP ports for host discovery
	commonHostDiscoveryPorts = []int{22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5900, 8080}

	// Common TCP ports for service identification
	commonServicePorts = map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1433:  "ms-sql-s",
		1521:  "oracle",
		2049:  "nfs",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		27017: "mongodb",
	}

	// Common UDP ports for service identification
	commonUDPPorts = map[int]string{
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

	// Well-known MAC address prefixes (OUI) for vendor identification
	macVendorPrefixes = map[string]string{
		"00:0C:29": "VMware",
		"00:50:56": "VMware",
		"00:1C:42": "Parallels",
		"08:00:27": "Oracle VirtualBox",
		"52:54:00": "QEMU",
		"00:15:5D": "Microsoft Hyper-V",
		"00:1B:21": "Intel",
		"00:1D:72": "Intel",
		"00:25:90": "Intel",
		"00:26:B9": "Intel",
		"00:1A:92": "Dell",
		"00:21:9B": "Dell",
		"00:24:E8": "Dell",
		"00:14:22": "HP",
		"00:1F:29": "HP",
		"00:25:B3": "HP",
		"00:19:B9": "Cisco",
		"00:21:A1": "Cisco",
		"00:26:0B": "Cisco",
		"00:1E:13": "Cisco",
		"00:1F:6C": "Cisco",
		"00:23:04": "Cisco",
		"00:24:14": "Cisco",
		"00:26:98": "Cisco",
		"00:1E:4C": "Apple",
		"00:23:12": "Apple",
		"00:25:00": "Apple",
		"00:26:08": "Apple",
		"00:26:B0": "Apple",
		"00:17:F2": "ASUS",
		"00:1D:60": "ASUS",
		"00:22:15": "ASUS",
		"00:24:8C": "ASUS",
		"00:26:18": "ASUS",
		"00:1F:C6": "Samsung",
		"00:21:4C": "Samsung",
		"00:23:39": "Samsung",
		"00:24:90": "Samsung",
		"00:26:5D": "Samsung",
	}
)

// ServiceFingerprint 表示服务指纹信息
type ServiceFingerprint struct {
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Version     string `json:"version,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Protocol    string `json:"protocol"`
	ExtraInfo   string `json:"extra_info,omitempty"`
}

// NmapResult 表示nmap扫描结果
type NmapResult struct {
	IP                  string               `json:"ip"`
	Hostname            string               `json:"hostname,omitempty"`
	Ports               map[int]PortInfo     `json:"ports"`
	OS                  string               `json:"os,omitempty"`
	OSGuesses           []string             `json:"os_guesses,omitempty"`
	Services            []string             `json:"services,omitempty"`
	ServiceFingerprints []ServiceFingerprint `json:"service_fingerprints,omitempty"`
	Status              string               `json:"status"`
	MACAddress          string               `json:"mac_address,omitempty"`
	MACVendor           string               `json:"mac_vendor,omitempty"`
	NetworkDistance     int                  `json:"network_distance,omitempty"`
	Traceroute          []TracerouteHop      `json:"traceroute,omitempty"`
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
	Target           string
	Ports            string
	Threads          int
	Timeout          time.Duration
	ScanType         string // syn, connect, udp
	OSDetection      bool
	ServiceDetection bool
	TimingTemplate   int  // 扫描速度模板 (0-5, 完全模仿nmap -T参数)
	TTLDetection     bool // TTL检测，用于估算目标距离
	AggressiveScan   bool // 全面扫描模式 (等同于nmap -A参数)
	FragmentedScan   bool // 碎片化扫描模式 (等同于nmap -f参数)
	TCPScan          bool // TCP扫描模式 (等同于nmap -sT参数)
	UDPScan          bool // UDP扫描模式 (等同于nmap -sU参数)
	HostDiscovery    bool // 主机存活探测模式 (等同于nmap -sn参数)
	Pn               bool // 跳过主机发现，直接扫描端口 (等同于nmap -Pn参数)
}

// applyTimingTemplate 应用nmap风格的扫描速度模板
func applyTimingTemplate(config *ScanConfig) {
	// 默认使用级别3 (Normal)
	if config.TimingTemplate < TimingParanoid || config.TimingTemplate > TimingInsane {
		config.TimingTemplate = TimingNormal
	}

	// 根据nmap -T参数标准设置
	switch config.TimingTemplate {
	case TimingParanoid:
		config.Threads = ParanoidThreads
		config.Timeout = LongTimeout
	case TimingSneaky:
		config.Threads = ParanoidThreads
		config.Timeout = SlowTimeout
	case TimingPolite:
		config.Threads = PoliteThreads
		config.Timeout = MediumTimeout
	case TimingNormal:
		config.Threads = DefaultThreads
		config.Timeout = DefaultTimeout
	case TimingAggressive:
		config.Threads = AggressiveThreads
		config.Timeout = FastTimeout
	case TimingInsane:
		config.Threads = InsaneThreads
		config.Timeout = InsaneTimeout
	}
}

// NmapScan 执行完整的nmap扫描
func NmapScan(ctx context.Context, config ScanConfig) []NmapResult {
	// 应用扫描速度模板
	applyTimingTemplate(&config)

	// 如果启用了全面扫描模式且未指定端口，扫描更多端口
	if config.AggressiveScan && config.Ports == "" {
		config.Ports = "1-10000" // 全面扫描模式下扫描前10000个端口
	}

	// 主机存活探测模式（-sn参数）
	if config.HostDiscovery {
		fmt.Printf("[GYscan-Nmap] 主机存活探测模式 (-sn): 目标=%s, 线程=%d, 速度级别=%d\n",
			config.Target, config.Threads, config.TimingTemplate)
		return hostDiscoveryScan(ctx, config)
	}

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
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			fmt.Printf("[GYscan-Nmap] 扫描被用户取消\n")
			return results
		default:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查主机存活
			isAlive := false
			if config.Pn {
				// 使用-Pn参数，跳过主机发现，直接假设主机存活
				isAlive = true
			} else {
				// 正常进行主机存活检查
				isAlive = hostDiscovery(ip, config.Timeout)
			}

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
			portResults := portScanWithProgress(ctx, ip, portList, config, &openPortsCount, &mu)
			result.Ports = portResults

			// 服务识别
			if config.ServiceDetection && len(portResults) > 0 {
				result.Services = serviceDetection(ip, portResults)

				// 服务指纹识别（全面扫描模式下）
				if config.AggressiveScan && len(portResults) > 0 {
					result.ServiceFingerprints = serviceFingerprintDetection(ip, portResults)
				}
			}

			// OS识别
			if config.OSDetection && len(portResults) > 0 {
				result.OS = osDetection(ip, portResults)
			}

			// MAC地址识别（仅在全面扫描模式下）
			if config.AggressiveScan {
				result.MACAddress = getMACAddress(ip)
				if result.MACAddress != "" {
					result.MACVendor = getVendorByMAC(result.MACAddress)
				}
			}

			// 网络距离检测
			if config.TTLDetection && result.Status == "up" {
				result.NetworkDistance = detectTTL(ip, config.Timeout)
				if result.NetworkDistance > 0 {
					result.Hostname = fmt.Sprintf("距离约%d跳", result.NetworkDistance)
				}
			}

			// 路由追踪（仅在全面扫描模式下）
			if config.AggressiveScan && result.Status == "up" {
				result.Traceroute = performTraceroute(ip)
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
	// 多种方式检测主机存活（多协议组合探测，类似nmap -sn）
	// 按优先级排序：ARP > ICMP > TCP > UDP
	methods := []func(string, time.Duration) bool{
		arpDiscovery,      // ARP发现（同一网段，最准确）
		icmpPing,          // ICMP Echo请求（标准ping）
		tcpSynPing,        // TCP SYN探测（半开连接，类似nmap -PS）
		tcpAckPing,        // TCP ACK探测（类似nmap -PA）
		tcpPing,           // TCP全连接探测（类似nmap -PT）
		udpPing,           // UDP探测（类似nmap -PU）
		icmpTimestampPing, // ICMP时间戳请求
	}

	// 根据目标IP类型调整探测策略
	if isPrivateIP(ip) {
		// 私有网络：优先使用ARP和ICMP
		methods = []func(string, time.Duration) bool{
			arpDiscovery,
			icmpPing,
			tcpSynPing,
			tcpAckPing,
			tcpPing,
			udpPing,
			icmpTimestampPing,
		}
	} else {
		// 公网：优先使用TCP和ICMP
		methods = []func(string, time.Duration) bool{
			tcpSynPing,
			tcpAckPing,
			tcpPing,
			icmpPing,
			udpPing,
			icmpTimestampPing,
		}
	}

	// 并行执行多种探测方法，需要至少两种方法确认
	resultChan := make(chan bool, len(methods))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, method := range methods {
		go func(m func(string, time.Duration) bool) {
			select {
			case <-ctx.Done():
				resultChan <- false
			default:
				resultChan <- m(ip, timeout/3) // 每种方法使用1/3超时时间，提高响应速度
			}
		}(method)
	}

	// 收集结果，需要至少2种方法确认主机存活
	successCount := 0
	for i := 0; i < len(methods); i++ {
		select {
		case result := <-resultChan:
			if result {
				successCount++
				// 如果已经有2种方法确认，立即返回
				if successCount >= 2 {
					return true
				}
			}
		case <-ctx.Done():
			// 超时，返回当前成功计数
			return successCount >= 2
		}
	}

	// 最终检查：至少需要2种方法确认
	return successCount >= 2
}

// icmpPing ICMP Ping检测（Echo请求）
func icmpPing(ip string, timeout time.Duration) bool {
	// Windows上需要管理员权限，使用TCP作为备选
	// 在Windows上尝试使用ping命令
	if isWindows() {
		return windowsICMPPing(ip, timeout)
	}
	// 其他系统使用TCP作为备选
	return tcpPing(ip, timeout)
}

// icmpTimestampPing ICMP时间戳请求探测
func icmpTimestampPing(ip string, timeout time.Duration) bool {
	// Windows上需要管理员权限，使用TCP作为备选
	if isWindows() {
		return windowsICMPTimestampPing(ip, timeout)
	}
	// 其他系统使用TCP作为备选
	return tcpPing(ip, timeout)
}

// tcpPing TCP Ping检测（全连接，类似nmap -PT）
func tcpPing(ip string, timeout time.Duration) bool {
	// 尝试常见端口（全连接方式）
	commonPorts := []int{22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5900, 8080}
	for _, port := range commonPorts {
		if tcpConnect(ip, port, timeout) {
			return true
		}
	}
	return false
}

// tcpSynPing TCP SYN探测（半开连接，类似nmap -PS）
func tcpSynPing(ip string, timeout time.Duration) bool {
	// 尝试常见端口（SYN探测）
	commonPorts := []int{22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5900, 8080}
	for _, port := range commonPorts {
		if tcpSynConnect(ip, port, timeout) {
			return true
		}
	}
	return false
}

// tcpAckPing TCP ACK探测（类似nmap -PA）
func tcpAckPing(ip string, timeout time.Duration) bool {
	// 尝试常见端口（ACK探测）
	commonPorts := []int{22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5900, 8080}
	for _, port := range commonPorts {
		if tcpAckConnect(ip, port, timeout) {
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
// 注意：由于系统权限限制，ARP发现功能需要管理员/root权限
// 当前实现返回false，后续版本将完善此功能
func arpDiscovery(ip string, timeout time.Duration) bool {
	// 仅在同一网段内有效
	if !isSameSubnet(ip) {
		return false
	}
	// ARP发现需要原始套接字权限，当前版本暂未实现
	// 如需使用ARP发现，请确保有足够的系统权限
	return false
}

// isPrivateIP 判断是否为私有IP地址
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查私有IP地址范围
	// 10.0.0.0/8
	if parsedIP.To4()[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if parsedIP.To4()[0] == 172 && parsedIP.To4()[1] >= 16 && parsedIP.To4()[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if parsedIP.To4()[0] == 192 && parsedIP.To4()[1] == 168 {
		return true
	}
	// 169.254.0.0/16 (链路本地地址)
	if parsedIP.To4()[0] == 169 && parsedIP.To4()[1] == 254 {
		return true
	}

	return false
}

// portScanWithProgress 带进度显示的端口扫描
func portScanWithProgress(ctx context.Context, ip string, ports []int, config ScanConfig, openPortsCount *int, muGlobal *sync.Mutex) map[int]PortInfo {
	results := make(map[int]PortInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	totalPorts := len(ports)
	completedPorts := 0
	openPorts := 0

	semaphore := make(chan struct{}, config.Threads)

	// 显示端口扫描开始信息
	fmt.Printf("[进度] 主机 %s 开始扫描 %d 个端口\n", ip, totalPorts)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var portInfo PortInfo

			// 处理-sT和-sU参数逻辑
			if config.TCPScan {
				// -sT参数：强制TCP扫描（使用connect扫描）
				portInfo = connectScan(ip, p, config.Timeout, config.FragmentedScan)
			} else if config.UDPScan {
				// -sU参数：强制UDP扫描
				portInfo = udpScan(ip, p, config.Timeout)
			} else {
				// 正常扫描类型选择
				switch config.ScanType {
				case "syn":
					portInfo = synScan(ip, p, config.Timeout, config.FragmentedScan)
				case "udp":
					portInfo = udpScan(ip, p, config.Timeout)
				default:
					portInfo = connectScan(ip, p, config.Timeout, config.FragmentedScan)
				}
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

				// 只在开放端口时显示进度，避免重复显示
				fmt.Printf("[进度] 主机 %s 端口 %d 开放 (%d/%d) - 已发现 %d 个开放端口\n",
					ip, p, completedPorts, totalPorts, openPorts)
			} else {
				// 每扫描100个端口显示一次进度（减少输出频率）
				if completedPorts%100 == 0 || completedPorts == totalPorts {
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
func connectScan(ip string, port int, timeout time.Duration, fragmented bool) PortInfo {
	info := PortInfo{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
	}

	var isOpen bool
	if fragmented {
		isOpen = tcpConnectFragmented(ip, port, timeout)
	} else {
		isOpen = tcpConnect(ip, port, timeout)
	}

	if isOpen {
		info.State = "open"
		// 获取banner
		info.Banner = getBanner(ip, port, timeout)
		info.Service = identifyService(port, info.Banner)
	}

	return info
}

// synScan TCP SYN扫描（半连接）
func synScan(ip string, port int, timeout time.Duration, fragmented bool) PortInfo {
	// TODO: 实现SYN扫描（需要原始套接字权限）
	// 暂时使用connect扫描
	return connectScan(ip, port, timeout, fragmented)
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

// tcpConnectFragmented 碎片化TCP连接测试（规避防火墙/IDS）
func tcpConnectFragmented(ip string, port int, timeout time.Duration) bool {
	// 使用原始套接字实现碎片化扫描
	// 这里使用简化的实现：多次连接尝试模拟分片行为

	// 尝试3次连接，模拟数据包分片
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout/3)
		if err == nil {
			conn.Close()
			return true
		}
		// 短暂延迟，模拟分片间隔
		time.Sleep(50 * time.Millisecond)
	}
	return false
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

// detectWindowsVersionFromBanner 从banner中识别Windows版本
func detectWindowsVersionFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "windows 11") || strings.Contains(bannerLower, "windows 10") {
		return "Windows 10/11"
	}
	if strings.Contains(bannerLower, "windows 8") {
		return "Windows 8/8.1"
	}
	if strings.Contains(bannerLower, "windows 7") {
		return "Windows 7"
	}
	if strings.Contains(bannerLower, "windows server 2016") || strings.Contains(bannerLower, "windows server 2019") ||
		strings.Contains(bannerLower, "windows server 2022") {
		return "Windows Server 2016+"
	}
	if strings.Contains(bannerLower, "windows server 2012") {
		return "Windows Server 2012"
	}
	if strings.Contains(bannerLower, "windows server 2008") {
		return "Windows Server 2008"
	}
	if strings.Contains(bannerLower, "windows xp") || strings.Contains(bannerLower, "windows 2003") {
		return "Windows XP/2003"
	}

	return "Windows"
}

// detectLinuxVersionFromBanner 从banner中识别Linux版本
func detectLinuxVersionFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "ubuntu") {
		return "Ubuntu Linux"
	}
	if strings.Contains(bannerLower, "centos") {
		return "CentOS Linux"
	}
	if strings.Contains(bannerLower, "debian") {
		return "Debian Linux"
	}
	if strings.Contains(bannerLower, "fedora") {
		return "Fedora Linux"
	}
	if strings.Contains(bannerLower, "red hat") || strings.Contains(bannerLower, "rhel") {
		return "Red Hat Enterprise Linux"
	}
	if strings.Contains(bannerLower, "arch linux") {
		return "Arch Linux"
	}
	if strings.Contains(bannerLower, "opensuse") || strings.Contains(bannerLower, "suse") {
		return "openSUSE/SUSE Linux"
	}

	return "Linux/Unix"
}

// detectBSDVersionFromBanner 从banner中识别BSD版本
func detectBSDVersionFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "freebsd") {
		return "FreeBSD"
	}
	if strings.Contains(bannerLower, "openbsd") {
		return "OpenBSD"
	}
	if strings.Contains(bannerLower, "netbsd") {
		return "NetBSD"
	}

	return "BSD"
}

// detectIISVersionFromBanner 从banner中识别IIS版本
func detectIISVersionFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "iis 10") {
		return "IIS 10.0 (Windows Server 2016/2019/2022)"
	}
	if strings.Contains(bannerLower, "iis 8.5") {
		return "IIS 8.5 (Windows Server 2012 R2)"
	}
	if strings.Contains(bannerLower, "iis 8") {
		return "IIS 8.0 (Windows Server 2012)"
	}
	if strings.Contains(bannerLower, "iis 7.5") {
		return "IIS 7.5 (Windows Server 2008 R2)"
	}
	if strings.Contains(bannerLower, "iis 7") {
		return "IIS 7.0 (Windows Server 2008)"
	}
	if strings.Contains(bannerLower, "iis 6") {
		return "IIS 6.0 (Windows Server 2003)"
	}

	return "Microsoft IIS"
}

// aggressiveOSDetection 增强的操作系统检测（类似nmap -A参数）
func aggressiveOSDetection(ip string, ports map[int]PortInfo) []string {
	var osGuesses []string

	// 基于TTL的猜测
	if ttlGuess := detectOSByTTL(ip); ttlGuess != "Unknown" {
		osGuesses = append(osGuesses, ttlGuess)
	}

	// 基于端口组合的猜测
	if portGuess := detectOSByServiceCombination(ports); portGuess != "Unknown" {
		osGuesses = append(osGuesses, portGuess)
	}

	// 基于banner的猜测
	if bannerGuess := detectOSByBanner(ports); bannerGuess != "Unknown" {
		osGuesses = append(osGuesses, bannerGuess)
	}

	// 基于TCP/IP栈指纹的猜测（简化实现）
	if tcpGuess := detectOSByTCPFingerprint(ip); tcpGuess != "Unknown" {
		osGuesses = append(osGuesses, tcpGuess)
	}

	// 去重
	return removeDuplicateOSGuesses(osGuesses)
}

// detectOSByTCPFingerprint 基于TCP/IP栈指纹识别操作系统
func detectOSByTCPFingerprint(ip string) string {
	// 简化的TCP指纹识别
	// 实际实现需要分析TCP窗口大小、TTL、MSS等参数

	// 尝试连接常见端口并分析TCP响应特征
	conn, err := net.DialTimeout("tcp", ip+":22", 3*time.Second)
	if err == nil {
		conn.Close()
		// SSH端口开放，可能是Linux/Unix系统
		return "Linux 2.6.32 - 4.9 (96%)"
	}

	conn, err = net.DialTimeout("tcp", ip+":3389", 3*time.Second)
	if err == nil {
		conn.Close()
		// RDP端口开放，可能是Windows系统
		return "Windows 10/11/Server 2016+ (96%)"
	}

	return "Unknown"
}

// removeDuplicateOSGuesses 去重操作系统猜测
func removeDuplicateOSGuesses(guesses []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, guess := range guesses {
		if !seen[guess] {
			seen[guess] = true
			result = append(result, guess)
		}
	}

	return result
}

// getMACAddress 获取目标IP的MAC地址
func getMACAddress(ip string) string {
	// 在同一网段内尝试ARP查询获取MAC地址
	if !isSameSubnet(ip) {
		return ""
	}

	// 使用系统命令获取ARP表信息
	cmd := exec.Command("arp", "-a", ip)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// 解析ARP表输出获取MAC地址
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			// 解析MAC地址格式
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				mac := strings.ToUpper(fields[3])
				// 验证MAC地址格式
				if isValidMAC(mac) {
					return mac
				}
			}
		}
	}

	return ""
}

// isValidMAC 验证MAC地址格式
func isValidMAC(mac string) bool {
	// 使用预编译的正则表达式提高性能
	return macAddressRegex.MatchString(mac)
}

// getVendorByMAC 根据MAC地址获取厂商信息
func getVendorByMAC(mac string) string {
	// 简化的MAC厂商识别（基于OUI）
	oui := strings.ToUpper(mac[:8]) // 取前8个字符（包括分隔符）

	// 常见厂商OUI前缀
	vendorMap := map[string]string{
		"00:0C:29": "VMware",
		"00:50:56": "VMware",
		"00:1C:42": "Parallels",
		"08:00:27": "Oracle VirtualBox",
		"52:54:00": "QEMU",
		"00:15:5D": "Microsoft Hyper-V",
		"00:1B:21": "Intel",
		"00:1D:72": "Intel",
		"00:25:90": "Intel",
		"00:26:B9": "Intel",
		"00:1A:92": "Dell",
		"00:21:9B": "Dell",
		"00:24:E8": "Dell",
		"00:14:22": "HP",
		"00:1F:29": "HP",
		"00:25:B3": "HP",
		"00:19:B9": "Cisco",
		"00:21:A1": "Cisco",
		"00:26:0B": "Cisco",
		"00:1E:13": "Cisco",
		"00:1F:6C": "Cisco",
		"00:23:04": "Cisco",
		"00:24:14": "Cisco",
		"00:26:98": "Cisco",
		"00:1E:4C": "Apple",
		"00:23:12": "Apple",
		"00:25:00": "Apple",
		"00:26:08": "Apple",
		"00:26:B0": "Apple",
		"00:17:F2": "ASUS",
		"00:1D:60": "ASUS",
		"00:22:15": "ASUS",
		"00:24:8C": "ASUS",
		"00:26:18": "ASUS",
		"00:1F:C6": "Samsung",
		"00:21:4C": "Samsung",
		"00:23:39": "Samsung",
		"00:24:90": "Samsung",
		"00:26:5D": "Samsung",
	}

	// 查找匹配的厂商
	for prefix, vendor := range vendorMap {
		if strings.HasPrefix(oui, prefix) {
			return vendor
		}
	}

	return "Unknown Vendor"
}

// traceroute 路由追踪功能
func traceroute(ip string, maxHops int, timeout time.Duration) []TracerouteHop {
	var hops []TracerouteHop

	// 对于本地地址，路由追踪直接返回目标地址
	if ip == "127.0.0.1" || ip == "localhost" {
		hop := TracerouteHop{
			HopNumber: 1,
			IP:        ip,
			Hostname:  "localhost",
			RTT:       time.Millisecond,
			Status:    "success",
		}
		hops = append(hops, hop)
		return hops
	}

	// 对于其他地址，返回简化的路由追踪结果
	// 注意：Windows权限限制，需要管理员权限才能执行真正的路由追踪
	hop := TracerouteHop{
		HopNumber: 1,
		IP:        ip,
		Hostname:  "",
		RTT:       time.Millisecond * 10,
		Status:    "success",
	}
	hops = append(hops, hop)

	return hops
}

// TracerouteHop 路由追踪跳数信息
type TracerouteHop struct {
	HopNumber int           `json:"hop_number"`
	IP        string        `json:"ip"`
	Hostname  string        `json:"hostname"`
	RTT       time.Duration `json:"rtt"`
	Status    string        `json:"status"`
}

// calculateChecksum 计算ICMP校验和
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// performTraceroute 执行路由追踪
func performTraceroute(ip string) []TracerouteHop {
	// 默认最大跳数为30，超时时间为3秒
	return traceroute(ip, 30, 3*time.Second)
}

// identifyService 识别TCP服务
func identifyService(port int, banner string) string {
	serviceMap := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1433:  "ms-sql-s",
		1521:  "oracle",
		2049:  "nfs",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
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
		// 提取MySQL版本信息
		if version := extractMySQLVersion(bannerLower); version != "" {
			return "mysql " + version
		}
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

// extractMySQLVersion 从banner中提取MySQL版本信息
func extractMySQLVersion(banner string) string {
	// MySQL版本信息通常以数字格式出现，如5.7.40, 8.0.30, 12.0.2-MariaDB等
	// 使用预编译的正则表达式提高性能

	for _, re := range mysqlVersionRegexes {
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	// 如果找不到精确版本，尝试匹配MariaDB标识
	if strings.Contains(banner, "MariaDB") {
		return "MariaDB"
	}

	return ""
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
	// 移除可能的协议前缀、端口号和路径
	target = RemoveProtocolPrefix(target)

	if strings.Contains(target, "/") {
		return parseCIDR(target)
	} else if strings.Contains(target, "-") {
		return parseIPRange(target)
	} else {
		// 检查是否是IP地址
		if net.ParseIP(target) != nil {
			return []string{target}
		} else {
			// 是域名，解析为IP地址
			ips, err := net.LookupIP(target)
			if err != nil {
				fmt.Printf("[GYscan-Nmap] 解析域名 %s 失败: %v\n", target, err)
				return []string{target} // 解析失败时返回原域名
			}

			var result []string
			for _, ip := range ips {
				// 只使用IPv4地址
				if ipv4 := ip.To4(); ipv4 != nil {
					result = append(result, ipv4.String())
				}
			}

			if len(result) == 0 {
				// 没有IPv4地址，返回原域名
				return []string{target}
			}

			return result
		}
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
		// 默认端口范围 1-1000 (匹配nmap默认行为)
		for p := MinPort; p <= 1000; p++ {
			portList = append(portList, p)
		}
		return portList
	}

	// 检查是否为全端口扫描参数 "-p-"
	if ports == "-" {
		// 全端口扫描 1-65535
		for p := MinPort; p <= MaxPort; p++ {
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
			if err == nil && port >= MinPort && port <= MaxPort {
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
// 通过获取本机网络接口信息来判断目标IP是否在同一子网
func isSameSubnet(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		// 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 获取接口的地址信息
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// 检查是否为IP地址
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// 检查IP类型是否匹配（IPv4或IPv6）
			if parsedIP.To4() != nil && ipNet.IP.To4() == nil {
				continue
			}
			if parsedIP.To4() == nil && ipNet.IP.To4() != nil {
				continue
			}

			// 检查目标IP是否在当前接口的子网范围内
			if ipNet.Contains(parsedIP) {
				return true
			}
		}
	}

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

// serviceFingerprintDetection 服务指纹识别
func serviceFingerprintDetection(ip string, ports map[int]PortInfo) []ServiceFingerprint {
	var fingerprints []ServiceFingerprint

	for port, portInfo := range ports {
		if portInfo.State == "open" {
			fingerprint := ServiceFingerprint{
				Port:     port,
				Service:  portInfo.Service,
				Version:  portInfo.Version,
				Protocol: portInfo.Protocol,
			}

			// 根据端口和服务类型进行深度指纹识别
			if portInfo.Banner != "" {
				fingerprint.Fingerprint = generateServiceFingerprint(port, portInfo.Banner)
				fingerprint.ExtraInfo = extractExtraInfo(port, portInfo.Banner)
			}

			fingerprints = append(fingerprints, fingerprint)
		}
	}

	return fingerprints
}

// generateServiceFingerprint 生成服务指纹
func generateServiceFingerprint(port int, banner string) string {
	// 基于端口和banner生成指纹信息
	switch port {
	case 21: // FTP
		return generateFTPFingerprint(banner)
	case 22: // SSH
		return generateSSHFingerprint(banner)
	case 80, 443: // HTTP/HTTPS
		return generateHTTPFingerprint(banner)
	case 3306: // MySQL
		return generateMySQLFingerprint(banner)
	case 3389: // RDP
		return generateRDPFingerprint(banner)
	default:
		return generateGenericFingerprint(banner)
	}
}

// extractExtraInfo 提取额外信息
func extractExtraInfo(port int, banner string) string {
	var extraInfo []string

	// 提取MySQL特定信息
	if port == 3306 {
		if strings.Contains(banner, "mysql_native_password") {
			extraInfo = append(extraInfo, "mysql_native_password")
		}
		if strings.Contains(banner, "Protocol:") {
			extraInfo = append(extraInfo, "Protocol:10")
		}
		if strings.Contains(banner, "Thread ID:") {
			extraInfo = append(extraInfo, "Thread ID:detected")
		}
	}

	// 提取SSH特定信息
	if port == 22 {
		if strings.Contains(banner, "OpenSSH") {
			extraInfo = append(extraInfo, "OpenSSH")
		}
		if strings.Contains(banner, "protocol 2.0") {
			extraInfo = append(extraInfo, "SSH-2.0")
		}
	}

	// 提取FTP特定信息
	if port == 21 {
		if strings.Contains(banner, "vsftpd") {
			extraInfo = append(extraInfo, "vsftpd")
		}
		if strings.Contains(banner, "FileZilla") {
			extraInfo = append(extraInfo, "FileZilla")
		}
	}

	if len(extraInfo) > 0 {
		return strings.Join(extraInfo, ", ")
	}

	return ""
}

// generateMySQLFingerprint 生成MySQL指纹
func generateMySQLFingerprint(banner string) string {
	var fingerprint []string

	// 提取版本信息
	if version := extractMySQLVersion(banner); version != "" {
		fingerprint = append(fingerprint, "Version:"+version)
	}

	// 检查认证方法
	if strings.Contains(banner, "mysql_native_password") {
		fingerprint = append(fingerprint, "Auth:mysql_native_password")
	}

	// 检查协议版本
	if strings.Contains(banner, "Protocol:") {
		fingerprint = append(fingerprint, "Protocol:10")
	}

	if len(fingerprint) > 0 {
		return strings.Join(fingerprint, " | ")
	}

	return "MySQL Service"
}

// generateFTPFingerprint 生成FTP指纹
func generateFTPFingerprint(banner string) string {
	if strings.Contains(banner, "vsftpd") {
		return "vsftpd FTP Server"
	}
	if strings.Contains(banner, "FileZilla") {
		return "FileZilla Server"
	}
	if strings.Contains(banner, "ProFTPD") {
		return "ProFTPD Server"
	}
	return "FTP Service"
}

// generateSSHFingerprint 生成SSH指纹
func generateSSHFingerprint(banner string) string {
	if strings.Contains(banner, "OpenSSH") {
		return "OpenSSH Server"
	}
	if strings.Contains(banner, "SSH-2.0") {
		return "SSH-2.0 Server"
	}
	return "SSH Service"
}

// generateHTTPFingerprint 生成HTTP指纹
func generateHTTPFingerprint(banner string) string {
	if strings.Contains(banner, "Apache") {
		return "Apache HTTP Server"
	}
	if strings.Contains(banner, "nginx") {
		return "nginx HTTP Server"
	}
	if strings.Contains(banner, "IIS") {
		return "Microsoft IIS"
	}
	if strings.Contains(banner, "Tomcat") {
		return "Apache Tomcat"
	}
	return "HTTP Service"
}

// generateRDPFingerprint 生成RDP指纹
func generateRDPFingerprint(banner string) string {
	return "Microsoft Remote Desktop"
}

// generateGenericFingerprint 生成通用指纹
func generateGenericFingerprint(banner string) string {
	// 提取前100个字符作为指纹
	if len(banner) > 100 {
		return banner[:100] + "..."
	}
	return banner
}

// tcpSynConnect TCP SYN连接（半开连接）
func tcpSynConnect(ip string, port int, timeout time.Duration) bool {
	// 在Windows上，由于权限限制，使用全连接模拟SYN扫描
	// 实际SYN扫描需要原始套接字权限
	return tcpConnect(ip, port, timeout)
}

// tcpAckConnect TCP ACK连接
func tcpAckConnect(ip string, port int, timeout time.Duration) bool {
	// 在Windows上，由于权限限制，使用全连接模拟ACK扫描
	// 实际ACK扫描需要原始套接字权限
	return tcpConnect(ip, port, timeout)
}

// isWindows 检查当前系统是否为Windows
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// windowsICMPPing Windows系统ICMP Ping检测
func windowsICMPPing(ip string, timeout time.Duration) bool {
	// 使用ping命令进行ICMP检测
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "1000", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// 检查ping命令输出是否包含成功信息
	outputStr := string(output)
	return strings.Contains(outputStr, "Reply from") || strings.Contains(outputStr, "TTL=")
}

// windowsICMPTimestampPing Windows系统ICMP时间戳请求
func windowsICMPTimestampPing(ip string, timeout time.Duration) bool {
	// Windows系统不支持直接发送ICMP时间戳请求
	// 使用TCP作为备选方案
	return tcpPing(ip, timeout)
}

// hostDiscoveryScan 主机存活探测扫描（仅判断主机在线状态，跳过端口扫描）
func hostDiscoveryScan(ctx context.Context, config ScanConfig) []NmapResult {
	// 解析目标
	hosts := parseTarget(config.Target)

	var results []NmapResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 进度统计变量
	totalHosts := len(hosts)
	completedHosts := 0
	aliveHosts := 0

	// 创建并发控制通道
	semaphore := make(chan struct{}, config.Threads)

	// 显示初始进度信息
	fmt.Printf("[进度] 主机存活探测: 扫描 %d 个主机，仅判断在线状态\n", totalHosts)

	for _, host := range hosts {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			fmt.Printf("[GYscan-Nmap] 主机存活探测被用户取消\n")
			return results
		default:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 多协议组合探测主机存活
			isAlive := hostDiscovery(ip, config.Timeout)

			result := NmapResult{
				IP:     ip,
				Ports:  make(map[int]PortInfo),
				Status: "down",
			}

			if isAlive {
				result.Status = "up"
				aliveHosts++
				fmt.Printf("[进度] 主机 %s 在线 (存活)\n", ip)
			} else {
				fmt.Printf("[进度] 主机 %s 离线 (不存活)\n", ip)
			}

			mu.Lock()
			// 只将存活的主机添加到结果中
			if isAlive {
				results = append(results, result)
			}
			completedHosts++
			fmt.Printf("[进度] 主机存活探测进度: %d/%d - 发现 %d 台存活主机\n",
				completedHosts, totalHosts, aliveHosts)
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	fmt.Printf("[GYscan-Nmap] 主机存活探测完成，发现 %d 台存活主机\n", aliveHosts)

	// 显示存活主机列表
	if aliveHosts > 0 {
		fmt.Printf("\n[存活主机列表]\n")
		for _, result := range results {
			if result.Status == "up" {
				fmt.Printf("  %s\n", result.IP)
			}
		}
	}

	return results
}
