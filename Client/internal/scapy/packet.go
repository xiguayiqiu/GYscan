package scapy

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// PacketBuilder 网络包构造器
type PacketBuilder struct {
	buffer []byte
}

// NewPacketBuilder 创建新的包构造器
func NewPacketBuilder() *PacketBuilder {
	return &PacketBuilder{
		buffer: make([]byte, 0),
	}
}

// IPPacket IP包结构
type IPPacket struct {
	Version        uint8
	HeaderLength   uint8
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
	Data           []byte
}

// TCPPacket TCP包结构
type TCPPacket struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
	Options    []byte
	Data       []byte
}

// UDPPacket UDP包结构
type UDPPacket struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Data     []byte
}

// ICMPPacket ICMP包结构
type ICMPPacket struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Data     []byte
}

// BuildIPPacket 构造IP包
func BuildIPPacket(srcIP, dstIP net.IP, protocol uint8, data []byte) ([]byte, error) {
	// IP头部长度20字节
	header := make([]byte, 20)

	// 版本和头部长度 (IPv4, 头部长度5*4=20字节)
	header[0] = 0x45

	// 服务类型
	header[1] = 0x00

	// 总长度
	totalLength := uint16(20 + len(data))
	binary.BigEndian.PutUint16(header[2:4], totalLength)

	// 标识符
	header[4] = 0x00
	header[5] = 0x00

	// 标志和分片偏移
	header[6] = 0x40 // Don't Fragment
	header[7] = 0x00

	// TTL
	header[8] = 64

	// 协议
	header[9] = protocol

	// 校验和 (先设为0)
	header[10] = 0x00
	header[11] = 0x00

	// 源IP地址
	copy(header[12:16], srcIP.To4())

	// 目的IP地址
	copy(header[16:20], dstIP.To4())

	// 计算校验和
	checksum := calculateChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)

	// 组合包
	packet := append(header, data...)
	return packet, nil
}

// BuildTCPPacket 构造TCP包
func BuildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags uint8, data []byte) ([]byte, error) {
	// TCP头部长度20字节
	header := make([]byte, 20)

	// 源端口
	binary.BigEndian.PutUint16(header[0:2], srcPort)

	// 目的端口
	binary.BigEndian.PutUint16(header[2:4], dstPort)

	// 序列号
	binary.BigEndian.PutUint32(header[4:8], uint32(time.Now().UnixNano()))

	// 确认号
	binary.BigEndian.PutUint32(header[8:12], 0)

	// 数据偏移和保留位
	header[12] = 0x50 // 数据偏移5*4=20字节

	// 标志位
	header[13] = flags

	// 窗口大小
	binary.BigEndian.PutUint16(header[14:16], 65535)

	// 校验和 (先设为0)
	header[16] = 0x00
	header[17] = 0x00

	// 紧急指针
	header[18] = 0x00
	header[19] = 0x00

	// 计算TCP伪头部校验和
	pseudoHeader := buildTCPPseudoHeader(srcIP, dstIP, uint16(20+len(data)), 6)
	tcpChecksum := calculateTCPChecksum(pseudoHeader, header, data)
	binary.BigEndian.PutUint16(header[16:18], tcpChecksum)

	// 组合TCP包
	tcpPacket := append(header, data...)

	// 封装到IP包中
	return BuildIPPacket(srcIP, dstIP, 6, tcpPacket)
}

// BuildSYNPacket 构造SYN包
func BuildSYNPacket(srcIP, dstIP net.IP, dstPort uint16) ([]byte, error) {
	// 随机源端口
	srcPort := uint16(time.Now().UnixNano() % 65536)

	// SYN标志: SYN=1, ACK=0
	flags := uint8(0x02)

	return BuildTCPPacket(srcIP, dstIP, srcPort, dstPort, flags, nil)
}

// BuildACKPacket 构造ACK包
func BuildACKPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum uint32) ([]byte, error) {
	// ACK标志: SYN=0, ACK=1
	flags := uint8(0x10)

	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	binary.BigEndian.PutUint32(header[4:8], seqNum)
	header[12] = 0x50
	header[13] = flags

	return BuildTCPPacket(srcIP, dstIP, srcPort, dstPort, flags, nil)
}

// BuildUDPPacket 构造UDP包
func BuildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, data []byte) ([]byte, error) {
	// UDP头部长度8字节
	header := make([]byte, 8)

	// 源端口
	binary.BigEndian.PutUint16(header[0:2], srcPort)

	// 目的端口
	binary.BigEndian.PutUint16(header[2:4], dstPort)

	// 长度
	length := uint16(8 + len(data))
	binary.BigEndian.PutUint16(header[4:6], length)

	// 校验和 (先设为0)
	header[6] = 0x00
	header[7] = 0x00

	// 计算UDP伪头部校验和
	pseudoHeader := buildUDPPseudoHeader(srcIP, dstIP, length, 17)
	udpChecksum := calculateUDPChecksum(pseudoHeader, header, data)
	binary.BigEndian.PutUint16(header[6:8], udpChecksum)

	// 组合UDP包
	udpPacket := append(header, data...)

	// 封装到IP包中
	return BuildIPPacket(srcIP, dstIP, 17, udpPacket)
}

// BuildICMPPacket 构造ICMP包
func BuildICMPPacket(srcIP, dstIP net.IP, icmpType, icmpCode uint8, data []byte) ([]byte, error) {
	// ICMP头部长度8字节
	header := make([]byte, 8)

	// 类型和代码
	header[0] = icmpType
	header[1] = icmpCode

	// 校验和 (先设为0)
	header[2] = 0x00
	header[3] = 0x00

	// 标识符和序列号 (用于Echo请求)
	header[4] = 0x00
	header[5] = 0x00
	header[6] = 0x00
	header[7] = 0x01

	// 计算校验和
	icmpData := append(header, data...)
	icmpChecksum := calculateChecksum(icmpData)
	binary.BigEndian.PutUint16(header[2:4], icmpChecksum)

	// 组合ICMP包
	icmpPacket := append(header, data...)

	// 封装到IP包中
	return BuildIPPacket(srcIP, dstIP, 1, icmpPacket)
}

// 计算校验和
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// 构建TCP伪头部
func buildTCPPseudoHeader(srcIP, dstIP net.IP, length uint16, protocol uint8) []byte {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], length)
	return pseudo
}

// 计算TCP校验和
func calculateTCPChecksum(pseudoHeader, tcpHeader, data []byte) uint16 {
	var sum uint32

	// 伪头部
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(pseudoHeader[i])<<8 | uint32(pseudoHeader[i+1])
	}

	// TCP头部
	for i := 0; i < len(tcpHeader); i += 2 {
		if i+1 < len(tcpHeader) {
			sum += uint32(tcpHeader[i])<<8 | uint32(tcpHeader[i+1])
		}
	}

	// 数据
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

// 构建UDP伪头部
func buildUDPPseudoHeader(srcIP, dstIP net.IP, length uint16, protocol uint8) []byte {
	return buildTCPPseudoHeader(srcIP, dstIP, length, protocol)
}

// 计算UDP校验和
func calculateUDPChecksum(pseudoHeader, udpHeader, data []byte) uint16 {
	return calculateTCPChecksum(pseudoHeader, udpHeader, data)
}

// ParseIPPacket 解析IP包
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("IP包长度不足")
	}

	packet := &IPPacket{
		Version:        data[0] >> 4,
		HeaderLength:   (data[0] & 0x0F) * 4,
		TOS:            data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		ID:             binary.BigEndian.Uint16(data[4:6]),
		Flags:          data[6] >> 5,
		FragmentOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:            data[8],
		Protocol:       data[9],
		Checksum:       binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IP(data[12:16]),
		DstIP:          net.IP(data[16:20]),
	}

	if len(data) > int(packet.HeaderLength) {
		packet.Data = data[packet.HeaderLength:]
	}

	return packet, nil
}
