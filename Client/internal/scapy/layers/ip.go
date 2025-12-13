package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"GYscan/internal/scapy/core"
	"GYscan/internal/scapy/utils"
)

// IPVersion IP版本类型
const (
	IPv4 core.LayerType = core.LayerIPv4
	IPv6 core.LayerType = core.LayerIPv6
)

// IP IPv4数据包
type IP struct {
	*core.BasePacket

	// IP头部字段
	Version        uint8  // 版本 (4 for IPv4)
	HeaderLength   uint8  // 头部长度 (以4字节为单位)
	TOS            uint8  // 服务类型
	TotalLength    uint16 // 总长度
	ID             uint16 // 标识符
	Flags          uint8  // 标志位
	FragmentOffset uint16 // 分片偏移
	TTL            uint8  // 生存时间
	Protocol       uint8  // 协议类型
	Checksum       uint16 // 头部校验和
	SourceIP       net.IP // 源IP地址
	DestinationIP  net.IP // 目标IP地址
	Options        []byte // 选项字段
	Payload        []byte // 负载数据
}

// NewIP 创建新的IPv4数据包
func NewIP() *IP {
	ip := &IP{
		BasePacket:     core.NewBasePacket(),
		Version:        4,
		HeaderLength:   5, // 20字节头部，无选项
		TOS:            0,
		TotalLength:    20, // 最小IP头部长度
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       0, // 默认无协议
		SourceIP:       net.IPv4(127, 0, 0, 1),
		DestinationIP:  net.IPv4(127, 0, 0, 1),
	}
	return ip
}

// Build 构建IP数据包
func (ip *IP) Build() ([]byte, error) {
	// 计算头部长度（包括选项）
	headerLength := int(ip.HeaderLength) * 4
	if headerLength < 20 {
		headerLength = 20
	}

	// 创建IP头部缓冲区
	header := make([]byte, headerLength)

	// 版本和头部长度（4位版本 + 4位头部长度）
	header[0] = (ip.Version << 4) | (ip.HeaderLength & 0x0F)

	// 服务类型
	header[1] = ip.TOS

	// 总长度（大端序）
	if ip.TotalLength == 0 {
		// 自动计算总长度
		payloadLength := len(ip.Payload)
		ip.TotalLength = uint16(headerLength + payloadLength)
	}
	binary.BigEndian.PutUint16(header[2:4], ip.TotalLength)

	// 标识符
	binary.BigEndian.PutUint16(header[4:6], ip.ID)

	// 标志位和分片偏移
	flagsAndOffset := (uint16(ip.Flags) << 13) | (ip.FragmentOffset & 0x1FFF)
	binary.BigEndian.PutUint16(header[6:8], flagsAndOffset)

	// TTL和协议
	header[8] = ip.TTL
	header[9] = ip.Protocol

	// 校验和（先设为0，计算后再填充）
	header[10] = 0
	header[11] = 0

	// 源IP地址
	if ip.SourceIP.To4() != nil {
		copy(header[12:16], ip.SourceIP.To4())
	} else {
		return nil, fmt.Errorf("source IP must be IPv4 address")
	}

	// 目标IP地址
	if ip.DestinationIP.To4() != nil {
		copy(header[16:20], ip.DestinationIP.To4())
	} else {
		return nil, fmt.Errorf("destination IP must be IPv4 address")
	}

	// 选项字段
	if len(ip.Options) > 0 {
		if headerLength > 20 {
			copy(header[20:], ip.Options)
		}
	}

	// 计算校验和
	checksum := ip.calculateChecksum(header)
	header[10] = byte(checksum >> 8)
	header[11] = byte(checksum & 0xFF)

	// 组合头部和负载
	packet := header
	if ip.Payload != nil {
		packet = append(packet, ip.Payload...)
	}

	return packet, nil
}

// Dissect 解析IP数据包
func (ip *IP) Dissect(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("IP packet too short: %d bytes", len(data))
	}

	// 解析版本和头部长度
	ip.Version = data[0] >> 4
	ip.HeaderLength = data[0] & 0x0F

	// 检查版本
	if ip.Version != 4 {
		return fmt.Errorf("unsupported IP version: %d", ip.Version)
	}

	// 服务类型
	ip.TOS = data[1]

	// 总长度
	ip.TotalLength = binary.BigEndian.Uint16(data[2:4])

	// 标识符
	ip.ID = binary.BigEndian.Uint16(data[4:6])

	// 标志位和分片偏移
	flagsAndOffset := binary.BigEndian.Uint16(data[6:8])
	ip.Flags = uint8(flagsAndOffset >> 13)
	ip.FragmentOffset = flagsAndOffset & 0x1FFF

	// TTL和协议
	ip.TTL = data[8]
	ip.Protocol = data[9]

	// 校验和
	ip.Checksum = binary.BigEndian.Uint16(data[10:12])

	// 源IP地址
	ip.SourceIP = net.IPv4(data[12], data[13], data[14], data[15])

	// 目标IP地址
	ip.DestinationIP = net.IPv4(data[16], data[17], data[18], data[19])

	// 选项字段
	headerLength := int(ip.HeaderLength) * 4
	if headerLength > 20 && headerLength <= len(data) {
		ip.Options = make([]byte, headerLength-20)
		copy(ip.Options, data[20:headerLength])
	}

	// 负载数据
	if len(data) > headerLength {
		ip.Payload = make([]byte, len(data)-headerLength)
		copy(ip.Payload, data[headerLength:])
	}

	return nil
}

// calculateChecksum 计算IP头部校验和
func (ip *IP) calculateChecksum(header []byte) uint16 {
	var sum uint32
	length := len(header)

	// 对每16位进行求和
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// 如果有奇数个字节，处理最后一个字节
	if length%2 == 1 {
		sum += uint32(header[length-1]) << 8
	}

	// 将进位加到低位
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 取反
	return ^uint16(sum)
}

// SetSourceIP 设置源IP地址
func (ip *IP) SetSourceIP(addr string) error {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", addr)
	}
	if parsedIP.To4() == nil {
		return fmt.Errorf("only IPv4 addresses are supported: %s", addr)
	}
	ip.SourceIP = parsedIP
	return nil
}

// SetDestinationIP 设置目标IP地址
func (ip *IP) SetDestinationIP(addr string) error {
	parsedIP := net.ParseIP(addr)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", addr)
	}
	if parsedIP.To4() == nil {
		return fmt.Errorf("only IPv4 addresses are supported: %s", addr)
	}
	ip.DestinationIP = parsedIP
	return nil
}

// SetProtocol 设置协议类型
func (ip *IP) SetProtocol(protocol uint8) {
	ip.Protocol = protocol
}

// SetTTL 设置TTL值
func (ip *IP) SetTTL(ttl uint8) {
	ip.TTL = ttl
}

// SetPayload 设置负载数据
func (ip *IP) SetPayload(payload []byte) {
	ip.Payload = payload
	// 更新总长度
	headerLength := int(ip.HeaderLength) * 4
	if headerLength < 20 {
		headerLength = 20
	}
	ip.TotalLength = uint16(headerLength + len(payload))
}

// GetSourceIP 获取源IP地址
func (ip *IP) GetSourceIP() net.IP {
	return ip.SourceIP
}

// GetDestinationIP 获取目标IP地址
func (ip *IP) GetDestinationIP() net.IP {
	return ip.DestinationIP
}

// GetProtocol 获取协议类型
func (ip *IP) GetProtocol() uint8 {
	return ip.Protocol
}

// GetTTL 获取TTL值
func (ip *IP) GetTTL() uint8 {
	return ip.TTL
}

// GetPayload 获取负载数据
func (ip *IP) GetPayload() []byte {
	return ip.Payload
}

// String 返回IP数据包的字符串表示
func (ip *IP) String() string {
	return fmt.Sprintf("IP %s > %s proto=%d ttl=%d len=%d",
		ip.SourceIP.String(), ip.DestinationIP.String(),
		ip.Protocol, ip.TTL, ip.TotalLength)
}

// HexDump 返回IP数据包的十六进制转储
func (ip *IP) HexDump() string {
	data, err := ip.Build()
	if err != nil {
		return fmt.Sprintf("Error building IP packet: %v", err)
	}
	return utils.HexDump(data, 0)
}

// IPProtocol 常用IP协议类型常量
const (
	IPProtocolICMP   = 1
	IPProtocolTCP    = 6
	IPProtocolUDP    = 17
	IPProtocolICMPv6 = 58
)

// NewIPPacket 创建指定协议的IP数据包
func NewIPPacket(srcIP, dstIP string, protocol uint8) (*IP, error) {
	ip := NewIP()

	if err := ip.SetSourceIP(srcIP); err != nil {
		return nil, err
	}

	if err := ip.SetDestinationIP(dstIP); err != nil {
		return nil, err
	}

	ip.SetProtocol(protocol)
	return ip, nil
}

// CreateICMPPacket 创建ICMP数据包
func CreateICMPPacket(srcIP, dstIP string) (*IP, error) {
	return NewIPPacket(srcIP, dstIP, IPProtocolICMP)
}

// CreateTCPPacket 创建TCP数据包
func CreateTCPPacket(srcIP, dstIP string) (*IP, error) {
	return NewIPPacket(srcIP, dstIP, IPProtocolTCP)
}

// CreateUDPPacket 创建UDP数据包
func CreateUDPPacket(srcIP, dstIP string) (*IP, error) {
	return NewIPPacket(srcIP, dstIP, IPProtocolUDP)
}
