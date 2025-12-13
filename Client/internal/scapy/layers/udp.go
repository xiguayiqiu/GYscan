package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"GYscan/internal/scapy/core"
	"GYscan/internal/scapy/utils"
)

// UDP UDP数据包
type UDP struct {
	*core.BasePacket

	// UDP头部字段
	SourcePort      uint16 // 源端口
	DestinationPort uint16 // 目标端口
	Length          uint16 // UDP数据包长度
	Checksum        uint16 // 校验和
	Payload         []byte // 负载数据
}

// NewUDP 创建新的UDP数据包
func NewUDP() *UDP {
	udp := &UDP{
		BasePacket:      core.NewBasePacket(),
		SourcePort:      0,
		DestinationPort: 0,
		Length:          8, // 最小UDP头部长度
		Checksum:        0,
	}
	return udp
}

// Build 构建UDP数据包
func (udp *UDP) Build() ([]byte, error) {
	// 创建UDP头部缓冲区
	header := make([]byte, 8)

	// 源端口（大端序）
	binary.BigEndian.PutUint16(header[0:2], udp.SourcePort)

	// 目标端口（大端序）
	binary.BigEndian.PutUint16(header[2:4], udp.DestinationPort)

	// 长度（包括头部和负载）
	if udp.Length == 0 {
		// 自动计算长度
		udp.Length = uint16(8 + len(udp.Payload))
	}
	binary.BigEndian.PutUint16(header[4:6], udp.Length)

	// 校验和（先设为0，计算后再填充）
	header[6] = 0
	header[7] = 0

	// 组合头部和负载
	packet := header
	if udp.Payload != nil {
		packet = append(packet, udp.Payload...)
	}

	// 如果需要计算校验和，这里可以调用CalculateChecksum
	// 但实际校验和计算需要在IP层完成

	return packet, nil
}

// Dissect 解析UDP数据包
func (udp *UDP) Dissect(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("UDP packet too short: %d bytes", len(data))
	}

	// 源端口
	udp.SourcePort = binary.BigEndian.Uint16(data[0:2])

	// 目标端口
	udp.DestinationPort = binary.BigEndian.Uint16(data[2:4])

	// 长度
	udp.Length = binary.BigEndian.Uint16(data[4:6])

	// 校验和
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])

	// 负载数据
	if len(data) > 8 {
		udp.Payload = make([]byte, len(data)-8)
		copy(udp.Payload, data[8:])
	}

	return nil
}

// SetSourcePort 设置源端口
func (udp *UDP) SetSourcePort(port uint16) {
	udp.SourcePort = port
}

// SetDestinationPort 设置目标端口
func (udp *UDP) SetDestinationPort(port uint16) {
	udp.DestinationPort = port
}

// SetPayload 设置负载数据
func (udp *UDP) SetPayload(payload []byte) {
	udp.Payload = payload
	udp.Length = uint16(8 + len(payload))
}

// GetSourcePort 获取源端口
func (udp *UDP) GetSourcePort() uint16 {
	return udp.SourcePort
}

// GetDestinationPort 获取目标端口
func (udp *UDP) GetDestinationPort() uint16 {
	return udp.DestinationPort
}

// GetPayload 获取负载数据
func (udp *UDP) GetPayload() []byte {
	return udp.Payload
}

// GetLength 获取数据包长度
func (udp *UDP) GetLength() uint16 {
	return udp.Length
}

// GetChecksum 获取校验和
func (udp *UDP) GetChecksum() uint16 {
	return udp.Checksum
}

// String 返回UDP数据包的字符串表示
func (udp *UDP) String() string {
	return fmt.Sprintf("UDP %d > %d len=%d",
		udp.SourcePort, udp.DestinationPort, udp.Length)
}

// HexDump 返回UDP数据包的十六进制转储
func (udp *UDP) HexDump() string {
	data, err := udp.Build()
	if err != nil {
		return fmt.Sprintf("Error building UDP packet: %v", err)
	}
	return utils.HexDump(data, 0)
}

// NewUDPPacket 创建UDP数据包
func NewUDPPacket(srcPort, dstPort uint16) *UDP {
	udp := NewUDP()
	udp.SetSourcePort(srcPort)
	udp.SetDestinationPort(dstPort)
	return udp
}

// CreateDNSQueryPacket 创建DNS查询数据包
func CreateDNSQueryPacket(srcPort, dstPort uint16, domain string) (*UDP, error) {
	udp := NewUDPPacket(srcPort, dstPort)

	// 构建简单的DNS查询负载
	dnsQuery, err := buildDNSQuery(domain)
	if err != nil {
		return nil, err
	}

	udp.SetPayload(dnsQuery)
	return udp, nil
}

// CreateDHCPDiscoverPacket 创建DHCP发现数据包
func CreateDHCPDiscoverPacket() *UDP {
	udp := NewUDPPacket(68, 67) // DHCP客户端端口68，服务器端口67

	// 构建简单的DHCP发现负载
	dhcpDiscover := buildDHCPDiscover()
	udp.SetPayload(dhcpDiscover)

	return udp
}

// CreateCustomUDPPacket 创建自定义UDP数据包
func CreateCustomUDPPacket(srcPort, dstPort uint16, payload []byte) *UDP {
	udp := NewUDPPacket(srcPort, dstPort)
	udp.SetPayload(payload)
	return udp
}

// CalculateChecksum 计算UDP校验和（需要IP伪头部）
func (udp *UDP) CalculateChecksum(srcIP, dstIP net.IP, payload []byte) uint16 {
	// 构建伪头部
	pseudoHeader := make([]byte, 12)

	// 源IP地址
	if srcIP.To4() != nil {
		copy(pseudoHeader[0:4], srcIP.To4())
	}

	// 目标IP地址
	if dstIP.To4() != nil {
		copy(pseudoHeader[4:8], dstIP.To4())
	}

	// 协议类型（UDP=17）和UDP长度
	pseudoHeader[9] = 17 // UDP协议
	binary.BigEndian.PutUint16(pseudoHeader[10:12], udp.Length)

	// 构建UDP头部（不包括校验和）
	udpHeader, _ := udp.Build()
	udpHeader[6] = 0
	udpHeader[7] = 0

	// 计算校验和
	return udp.calculateChecksum(append(pseudoHeader, append(udpHeader, payload...)...))
}

// calculateChecksum 计算校验和的辅助函数
func (udp *UDP) calculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	// 对每16位进行求和
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// 如果有奇数个字节，处理最后一个字节
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	// 将进位加到低位
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 取反
	return ^uint16(sum)
}

// buildDNSQuery 构建DNS查询负载
func buildDNSQuery(domain string) ([]byte, error) {
	// 简单的DNS查询构建
	query := make([]byte, 0)

	// DNS头部（简化）
	header := []byte{
		0x00, 0x01, // ID
		0x01, 0x00, // 标志：标准查询
		0x00, 0x01, // 问题数：1
		0x00, 0x00, // 回答数：0
		0x00, 0x00, // 权威记录数：0
		0x00, 0x00, // 附加记录数：0
	}

	// 域名编码
	domainParts := splitDomain(domain)
	for _, part := range domainParts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}
	query = append(query, 0x00) // 域名结束

	// 查询类型和类
	query = append(query, []byte{0x00, 0x01, // 类型：A记录
		0x00, 0x01}...) // 类：IN

	return append(header, query...), nil
}

// buildDHCPDiscover 构建DHCP发现负载
func buildDHCPDiscover() []byte {
	// 简化的DHCP发现包
	dhcp := make([]byte, 240) // DHCP最小长度

	// DHCP操作码：BOOTREQUEST
	dhcp[0] = 0x01

	// 硬件类型：以太网
	dhcp[1] = 0x01

	// 硬件地址长度：6
	dhcp[2] = 0x06

	// 跳数：0
	dhcp[3] = 0x00

	// 事务ID
	dhcp[4] = 0x12
	dhcp[5] = 0x34
	dhcp[6] = 0x56
	dhcp[7] = 0x78

	// 标志：广播
	dhcp[10] = 0x80
	dhcp[11] = 0x00

	// 客户端IP地址：0.0.0.0
	// 你的IP地址：0.0.0.0
	// 服务器IP地址：0.0.0.0
	// 网关IP地址：0.0.0.0

	// 客户端硬件地址（示例）
	dhcp[28] = 0xAA
	dhcp[29] = 0xBB
	dhcp[30] = 0xCC
	dhcp[31] = 0xDD
	dhcp[32] = 0xEE
	dhcp[33] = 0xFF

	// 服务器主机名（空）
	// 启动文件名（空）

	// 魔术cookie：DHCP
	dhcp[236] = 0x63
	dhcp[237] = 0x82
	dhcp[238] = 0x53
	dhcp[239] = 0x63

	// 选项：DHCP消息类型（发现）
	dhcp = append(dhcp, 0x35, 0x01, 0x01)

	// 选项：参数请求列表
	dhcp = append(dhcp, 0x37, 0x04, 0x01, 0x03, 0x06, 0x2A)

	// 选项：结束
	dhcp = append(dhcp, 0xFF)

	return dhcp
}

// splitDomain 分割域名
func splitDomain(domain string) []string {
	var parts []string
	start := 0

	for i, char := range domain {
		if char == '.' {
			if i > start {
				parts = append(parts, domain[start:i])
			}
			start = i + 1
		}
	}

	if start < len(domain) {
		parts = append(parts, domain[start:])
	}

	return parts
}

// CommonUDPPorts 常用UDP端口常量
const (
	UDPPortDNS    = 53  // DNS
	UDPPortDHCP   = 67  // DHCP服务器
	UDPPortDHCPC  = 68  // DHCP客户端
	UDPPortTFTP   = 69  // TFTP
	UDPPortSNMP   = 161 // SNMP
	UDPPortNTP    = 123 // NTP
	UDPPortSyslog = 514 // Syslog
)
