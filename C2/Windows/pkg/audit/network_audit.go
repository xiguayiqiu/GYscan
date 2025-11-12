package audit

import (
	"fmt"
	"net"
	"strings"
	"time"

	gopsutil_net "github.com/shirou/gopsutil/net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// NetworkAudit 网络审计模块
type NetworkAudit struct {
	config *Config
}

// NewNetworkAudit 创建网络审计模块
func NewNetworkAudit(config *Config) *NetworkAudit {
	return &NetworkAudit{
		config: config,
	}
}

// Name 返回模块名称
func (na *NetworkAudit) Name() string {
	return "network"
}

// Description 返回模块描述
func (na *NetworkAudit) Description() string {
	return "Windows网络连接审计，包括网络连接监控、端口扫描检测、异常通信检测"
}

// RequiredPermissions 返回所需权限
func (na *NetworkAudit) RequiredPermissions() []string {
	return []string{"SeDebugPrivilege"}
}

// Run 执行网络审计
func (na *NetworkAudit) Run() ([]AuditResult, error) {
	var results []AuditResult

	// 1. 获取网络连接信息
	connections, err := na.getNetworkConnections()
	if err != nil {
		return nil, fmt.Errorf("获取网络连接信息失败: %v", err)
	}

	// 2. 执行各种审计检查
	results = append(results, na.auditSuspiciousConnections(connections)...)
	results = append(results, na.auditOpenPorts(connections)...)
	results = append(results, na.auditRemoteConnections(connections)...)
	results = append(results, na.auditPortScanning(connections)...)
	results = append(results, na.auditNetworkTraffic()...)

	return results, nil
}

// getNetworkConnections 获取网络连接信息
func (na *NetworkAudit) getNetworkConnections() ([]NetworkConnection, error) {
	var connections []NetworkConnection

	// 使用gopsutil获取网络连接
	netConns, err := gopsutil_net.Connections("all")
	if err != nil {
		return nil, err
	}

	for _, conn := range netConns {
		connection := NetworkConnection{
			Protocol:    fmt.Sprintf("%d", conn.Type),
			LocalAddr:   conn.Laddr.IP,
			LocalPort:   int(conn.Laddr.Port),
			RemoteAddr:  conn.Raddr.IP,
			RemotePort:  int(conn.Raddr.Port),
			State:       conn.Status,
			PID:         conn.Pid,
			ProcessName: na.getProcessName(conn.Pid),
		}
		connections = append(connections, connection)
	}

	return connections, nil
}

// getProcessName 根据PID获取进程名
func (na *NetworkAudit) getProcessName(pid int32) string {
	if pid == 0 {
		return "System"
	}

	// 简化实现：返回进程ID作为名称
	// 在实际实现中，应该使用Windows API获取进程名
	return fmt.Sprintf("PID-%d", pid)
}

// auditSuspiciousConnections 审计可疑连接
func (na *NetworkAudit) auditSuspiciousConnections(connections []NetworkConnection) []AuditResult {
	var results []AuditResult

	// 可疑端口列表
	suspiciousPorts := map[int]string{
		4444:  "Metasploit默认端口",
		1337:  "常见后门端口",
		31337: "Back Orifice后门",
		12345: "NetBus木马",
		54321: "Bo2k后门",
		9999:  "常见恶意软件端口",
		5555:  "Android调试端口",
		6666:  "IRC后门",
		7777:  "GodMode后门",
		8888:  "常见Web后门",
	}

	// 检查可疑的远程连接
	for _, conn := range connections {
		if conn.RemotePort > 0 {
			if desc, exists := suspiciousPorts[conn.RemotePort]; exists {
				results = append(results, AuditResult{
					ModuleName:    na.Name(),
					Level:         AuditLevelHigh,
					Status:        "fail",
					Description:   fmt.Sprintf("可疑端口连接: %s -> %s:%d (%s)", 
						conn.ProcessName, conn.RemoteAddr, conn.RemotePort, desc),
					Details:       conn,
					RiskScore:     85,
					Recommendation: "立即调查此连接，可能为恶意软件通信",
					Timestamp:     time.Now(),
				})
			}
		}

		// 检查到已知恶意IP的连接
		if na.isMaliciousIP(conn.RemoteAddr) {
			results = append(results, AuditResult{
				ModuleName:    na.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   fmt.Sprintf("连接到已知恶意IP: %s -> %s", 
					conn.ProcessName, conn.RemoteAddr),
				Details:       conn,
				RiskScore:     90,
				Recommendation: "立即断开连接并调查",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// isMaliciousIP 检查是否为恶意IP
func (na *NetworkAudit) isMaliciousIP(ip string) bool {
	// 这里可以集成威胁情报API或本地恶意IP数据库
	// 暂时返回false，实际使用时应实现真正的检查逻辑
	
	maliciousIPs := []string{
		"1.1.1.1", // 示例IP
		"2.2.2.2", // 示例IP
	}

	for _, maliciousIP := range maliciousIPs {
		if ip == maliciousIP {
			return true
		}
	}

	return false
}

// auditOpenPorts 审计开放端口
func (na *NetworkAudit) auditOpenPorts(connections []NetworkConnection) []AuditResult {
	var results []AuditResult

	// 统计每个端口的连接数
	portStats := make(map[int]int)
	for _, conn := range connections {
		if conn.LocalPort > 0 {
			portStats[conn.LocalPort]++
		}
	}

	// 检查不常见的开放端口
	commonPorts := map[int]bool{
		80:   true, // HTTP
		443:  true, // HTTPS
		22:   true, // SSH
		21:   true, // FTP
		25:   true, // SMTP
		53:   true, // DNS
		110:  true, // POP3
		143:  true, // IMAP
		993:  true, // IMAPS
		995:  true, // POP3S
		3389: true, // RDP
		5900: true, // VNC
	}

	for port, count := range portStats {
		if !commonPorts[port] && port > 1024 {
			results = append(results, AuditResult{
				ModuleName:    na.Name(),
				Level:         AuditLevelMedium,
				Status:        "warning",
				Description:   fmt.Sprintf("不常见开放端口: %d (连接数: %d)", port, count),
				Details:       portStats,
				RiskScore:     60,
				Recommendation: "检查此端口的用途和安全性",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// auditRemoteConnections 审计远程连接
func (na *NetworkAudit) auditRemoteConnections(connections []NetworkConnection) []AuditResult {
	var results []AuditResult

	// 检查到外网的连接
	for _, conn := range connections {
		if conn.RemoteAddr != "" && conn.RemoteAddr != "127.0.0.1" && 
			conn.RemoteAddr != "::1" && !na.isPrivateIP(conn.RemoteAddr) {
			
			// 检查是否为系统进程的异常外网连接
			if na.isSystemProcess(conn.ProcessName) && !na.isExpectedExternalConnection(conn) {
				results = append(results, AuditResult{
					ModuleName:    na.Name(),
					Level:         AuditLevelHigh,
					Status:        "fail",
					Description:   fmt.Sprintf("系统进程异常外网连接: %s -> %s:%d", 
						conn.ProcessName, conn.RemoteAddr, conn.RemotePort),
					Details:       conn,
					RiskScore:     80,
					Recommendation: "调查系统进程为何连接到外网",
					Timestamp:     time.Now(),
				})
			}
		}
	}

	return results
}

// isPrivateIP 检查是否为私有IP
func (na *NetworkAudit) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 检查私有IP范围
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12", 
		"192.168.0.0/16",
		"169.254.0.0/16", // 链路本地
		"127.0.0.0/8",    // 环回
		"::1/128",        // IPv6环回
		"fc00::/7",       // IPv6私有
		"fe80::/10",      // IPv6链路本地
	}

	for _, cidr := range privateRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

// isSystemProcess 检查是否为系统进程
func (na *NetworkAudit) isSystemProcess(processName string) bool {
	systemProcesses := []string{
		"svchost.exe", "lsass.exe", "services.exe", 
		"winlogon.exe", "csrss.exe", "System",
	}

	for _, sysProc := range systemProcesses {
		if strings.EqualFold(processName, sysProc) {
			return true
		}
	}

	return false
}

// isExpectedExternalConnection 检查是否为预期的外网连接
func (na *NetworkAudit) isExpectedExternalConnection(conn NetworkConnection) bool {
	// 预期的外网连接端口
	expectedPorts := map[int]bool{
		80:  true,  // HTTP
		443: true,  // HTTPS
		53:  true,  // DNS
		123: true,  // NTP
	}

	return expectedPorts[conn.RemotePort]
}

// auditPortScanning 审计端口扫描行为
func (na *NetworkAudit) auditPortScanning(connections []NetworkConnection) []AuditResult {
	var results []AuditResult

	// 统计每个远程IP的连接端口数
	ipPortStats := make(map[string]map[int]bool)
	for _, conn := range connections {
		if conn.RemoteAddr != "" {
			if _, exists := ipPortStats[conn.RemoteAddr]; !exists {
				ipPortStats[conn.RemoteAddr] = make(map[int]bool)
			}
			ipPortStats[conn.RemoteAddr][conn.RemotePort] = true
		}
	}

	// 检查可能的端口扫描
	for ip, ports := range ipPortStats {
		if len(ports) > 10 { // 连接到超过10个不同端口
			results = append(results, AuditResult{
				ModuleName:    na.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   fmt.Sprintf("检测到可能的端口扫描: %s (连接端口数: %d)", ip, len(ports)),
				Details:       ports,
				RiskScore:     75,
				Recommendation: "调查此IP的扫描行为",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// auditNetworkTraffic 审计网络流量
func (na *NetworkAudit) auditNetworkTraffic() []AuditResult {
	var results []AuditResult

	// 使用gopacket进行实时流量分析（需要Npcap）
	if na.config.Verbose {
		results = append(results, na.analyzeNetworkTraffic()...)
	}

	return results
}

// analyzeNetworkTraffic 分析网络流量
func (na *NetworkAudit) analyzeNetworkTraffic() []AuditResult {
	var results []AuditResult

	// 获取网络接口列表
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return results
	}

	// 选择第一个活动接口
	var activeDevice string
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			activeDevice = device.Name
			break
		}
	}

	if activeDevice == "" {
		return results
	}

	// 打开网络接口进行抓包（短暂抓包分析）
	handle, err := pcap.OpenLive(activeDevice, 65536, true, pcap.BlockForever)
	if err != nil {
		return results
	}
	defer handle.Close()

	// 设置过滤器（可选）
	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		return results
	}

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 分析前100个数据包
	packetCount := 0
	for packet := range packetSource.Packets() {
		if packetCount >= 100 {
			break
		}
		packetCount++

		// 分析数据包内容
		if na.isSuspiciousPacket(packet) {
			results = append(results, AuditResult{
				ModuleName:    na.Name(),
				Level:         AuditLevelMedium,
				Status:        "warning",
				Description:   "检测到可疑网络流量模式",
				Details:       packet.String(),
				RiskScore:     65,
				Recommendation: "进一步分析网络流量",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// isSuspiciousPacket 检查是否为可疑数据包
func (na *NetworkAudit) isSuspiciousPacket(packet gopacket.Packet) bool {
	// 实现数据包分析逻辑
	// 这里可以检查异常协议、加密流量、命令控制流量等
	
	return false
}