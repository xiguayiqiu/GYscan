package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"GYscan/internal/scapy/core"
	"GYscan/internal/scapy/utils"
)

// TCP TCP数据包
type TCP struct {
	*core.BasePacket

	// TCP头部字段
	SourcePort      uint16 // 源端口
	DestinationPort uint16 // 目标端口
	SequenceNumber  uint32 // 序列号
	AckNumber       uint32 // 确认号
	DataOffset      uint8  // 数据偏移（头部长度，以4字节为单位）
	Flags           uint8  // 控制标志
	WindowSize      uint16 // 窗口大小
	Checksum        uint16 // 校验和
	UrgentPointer   uint16 // 紧急指针
	Options         []byte // 选项字段
	Payload         []byte // 负载数据
}

// TCPFlags TCP标志位常量
const (
	TCPFlagFIN = 1 << iota // 结束连接
	TCPFlagSYN             // 同步序列号
	TCPFlagRST             // 重置连接
	TCPFlagPSH             // 推送数据
	TCPFlagACK             // 确认号有效
	TCPFlagURG             // 紧急指针有效
	TCPFlagECE             // ECN-Echo
	TCPFlagCWR             // Congestion Window Reduced
)

// NewTCP 创建新的TCP数据包
func NewTCP() *TCP {
	tcp := &TCP{
		BasePacket:      core.NewBasePacket(),
		SourcePort:      0,
		DestinationPort: 0,
		SequenceNumber:  0,
		AckNumber:       0,
		DataOffset:      5, // 20字节头部，无选项
		Flags:           0,
		WindowSize:      65535,
		Checksum:        0,
		UrgentPointer:   0,
	}
	return tcp
}

// Build 构建TCP数据包
func (tcp *TCP) Build() ([]byte, error) {
	// 计算头部长度（包括选项）
	headerLength := int(tcp.DataOffset) * 4
	if headerLength < 20 {
		headerLength = 20
	}

	// 创建TCP头部缓冲区
	header := make([]byte, headerLength)

	// 源端口（大端序）
	binary.BigEndian.PutUint16(header[0:2], tcp.SourcePort)

	// 目标端口（大端序）
	binary.BigEndian.PutUint16(header[2:4], tcp.DestinationPort)

	// 序列号
	binary.BigEndian.PutUint32(header[4:8], tcp.SequenceNumber)

	// 确认号
	binary.BigEndian.PutUint32(header[8:12], tcp.AckNumber)

	// 数据偏移和保留位（4位数据偏移 + 4位保留 + 8位标志）
	header[12] = tcp.DataOffset << 4 // 保留位为0
	header[13] = tcp.Flags

	// 窗口大小
	binary.BigEndian.PutUint16(header[14:16], tcp.WindowSize)

	// 校验和（先设为0，计算后再填充）
	header[16] = 0
	header[17] = 0

	// 紧急指针
	binary.BigEndian.PutUint16(header[18:20], tcp.UrgentPointer)

	// 选项字段
	if len(tcp.Options) > 0 {
		if headerLength > 20 {
			copy(header[20:], tcp.Options)
		}
	}

	// 校验和需要伪头部信息，这里先设为0
	// 实际校验和计算需要在IP层完成
	tcp.Checksum = 0

	// 组合头部和负载
	packet := header
	if tcp.Payload != nil {
		packet = append(packet, tcp.Payload...)
	}

	return packet, nil
}

// Dissect 解析TCP数据包
func (tcp *TCP) Dissect(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("TCP packet too short: %d bytes", len(data))
	}

	// 源端口
	tcp.SourcePort = binary.BigEndian.Uint16(data[0:2])

	// 目标端口
	tcp.DestinationPort = binary.BigEndian.Uint16(data[2:4])

	// 序列号
	tcp.SequenceNumber = binary.BigEndian.Uint32(data[4:8])

	// 确认号
	tcp.AckNumber = binary.BigEndian.Uint32(data[8:12])

	// 数据偏移和标志
	tcp.DataOffset = data[12] >> 4
	tcp.Flags = data[13]

	// 窗口大小
	tcp.WindowSize = binary.BigEndian.Uint16(data[14:16])

	// 校验和
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])

	// 紧急指针
	tcp.UrgentPointer = binary.BigEndian.Uint16(data[18:20])

	// 选项字段
	headerLength := int(tcp.DataOffset) * 4
	if headerLength > 20 && headerLength <= len(data) {
		tcp.Options = make([]byte, headerLength-20)
		copy(tcp.Options, data[20:headerLength])
	}

	// 负载数据
	if len(data) > headerLength {
		tcp.Payload = make([]byte, len(data)-headerLength)
		copy(tcp.Payload, data[headerLength:])
	}

	return nil
}

// SetSourcePort 设置源端口
func (tcp *TCP) SetSourcePort(port uint16) {
	tcp.SourcePort = port
}

// SetDestinationPort 设置目标端口
func (tcp *TCP) SetDestinationPort(port uint16) {
	tcp.DestinationPort = port
}

// SetSequenceNumber 设置序列号
func (tcp *TCP) SetSequenceNumber(seq uint32) {
	tcp.SequenceNumber = seq
}

// SetAckNumber 设置确认号
func (tcp *TCP) SetAckNumber(ack uint32) {
	tcp.AckNumber = ack
}

// SetFlags 设置标志位
func (tcp *TCP) SetFlags(flags uint8) {
	tcp.Flags = flags
}

// SetWindowSize 设置窗口大小
func (tcp *TCP) SetWindowSize(window uint16) {
	tcp.WindowSize = window
}

// SetPayload 设置负载数据
func (tcp *TCP) SetPayload(payload []byte) {
	tcp.Payload = payload
}

// GetSourcePort 获取源端口
func (tcp *TCP) GetSourcePort() uint16 {
	return tcp.SourcePort
}

// GetDestinationPort 获取目标端口
func (tcp *TCP) GetDestinationPort() uint16 {
	return tcp.DestinationPort
}

// GetSequenceNumber 获取序列号
func (tcp *TCP) GetSequenceNumber() uint32 {
	return tcp.SequenceNumber
}

// GetAckNumber 获取确认号
func (tcp *TCP) GetAckNumber() uint32 {
	return tcp.AckNumber
}

// GetFlags 获取标志位
func (tcp *TCP) GetFlags() uint8 {
	return tcp.Flags
}

// GetWindowSize 获取窗口大小
func (tcp *TCP) GetWindowSize() uint16 {
	return tcp.WindowSize
}

// GetPayload 获取负载数据
func (tcp *TCP) GetPayload() []byte {
	return tcp.Payload
}

// HasFlag 检查是否设置了指定标志位
func (tcp *TCP) HasFlag(flag uint8) bool {
	return (tcp.Flags & flag) != 0
}

// SetFlag 设置指定标志位
func (tcp *TCP) SetFlag(flag uint8) {
	tcp.Flags |= flag
}

// ClearFlag 清除指定标志位
func (tcp *TCP) ClearFlag(flag uint8) {
	tcp.Flags &^= flag
}

// String 返回TCP数据包的字符串表示
func (tcp *TCP) String() string {
	flags := ""
	if tcp.HasFlag(TCPFlagFIN) {
		flags += "F"
	}
	if tcp.HasFlag(TCPFlagSYN) {
		flags += "S"
	}
	if tcp.HasFlag(TCPFlagRST) {
		flags += "R"
	}
	if tcp.HasFlag(TCPFlagPSH) {
		flags += "P"
	}
	if tcp.HasFlag(TCPFlagACK) {
		flags += "A"
	}
	if tcp.HasFlag(TCPFlagURG) {
		flags += "U"
	}

	return fmt.Sprintf("TCP %d > %d seq=%d ack=%d flags=%s win=%d len=%d",
		tcp.SourcePort, tcp.DestinationPort,
		tcp.SequenceNumber, tcp.AckNumber,
		flags, tcp.WindowSize, len(tcp.Payload))
}

// HexDump 返回TCP数据包的十六进制转储
func (tcp *TCP) HexDump() string {
	data, err := tcp.Build()
	if err != nil {
		return fmt.Sprintf("Error building TCP packet: %v", err)
	}
	return utils.HexDump(data, 0)
}

// NewTCPPacket 创建TCP数据包
func NewTCPPacket(srcPort, dstPort uint16) *TCP {
	tcp := NewTCP()
	tcp.SetSourcePort(srcPort)
	tcp.SetDestinationPort(dstPort)
	return tcp
}

// CreateSYNPacket 创建SYN数据包（用于TCP握手）
func CreateSYNPacket(srcPort, dstPort uint16, seq uint32) *TCP {
	tcp := NewTCPPacket(srcPort, dstPort)
	tcp.SetSequenceNumber(seq)
	tcp.SetFlag(TCPFlagSYN)
	tcp.SetWindowSize(8192)
	return tcp
}

// CreateACKPacket 创建ACK数据包
func CreateACKPacket(srcPort, dstPort uint16, seq, ack uint32) *TCP {
	tcp := NewTCPPacket(srcPort, dstPort)
	tcp.SetSequenceNumber(seq)
	tcp.SetAckNumber(ack)
	tcp.SetFlag(TCPFlagACK)
	tcp.SetWindowSize(8192)
	return tcp
}

// CreateFINPacket 创建FIN数据包（用于关闭连接）
func CreateFINPacket(srcPort, dstPort uint16, seq, ack uint32) *TCP {
	tcp := NewTCPPacket(srcPort, dstPort)
	tcp.SetSequenceNumber(seq)
	tcp.SetAckNumber(ack)
	tcp.SetFlag(TCPFlagFIN | TCPFlagACK)
	tcp.SetWindowSize(8192)
	return tcp
}

// CreateRSTPacket 创建RST数据包（用于重置连接）
func CreateRSTPacket(srcPort, dstPort uint16, seq, ack uint32) *TCP {
	tcp := NewTCPPacket(srcPort, dstPort)
	tcp.SetSequenceNumber(seq)
	tcp.SetAckNumber(ack)
	tcp.SetFlag(TCPFlagRST | TCPFlagACK)
	tcp.SetWindowSize(0)
	return tcp
}

// TCPOption TCP选项类型
const (
	TCPOptionEnd         = 0 // 选项结束
	TCPOptionNOP         = 1 // 无操作
	TCPOptionMSS         = 2 // 最大段大小
	TCPOptionWindowScale = 3 // 窗口缩放
	TCPOptionSACK        = 4 // 选择性确认
	TCPOptionTimestamp   = 8 // 时间戳
)

// AddMSSOption 添加MSS选项
func (tcp *TCP) AddMSSOption(mss uint16) {
	option := []byte{TCPOptionMSS, 4, byte(mss >> 8), byte(mss & 0xFF)}
	tcp.Options = append(tcp.Options, option...)
	tcp.DataOffset = uint8((20 + len(tcp.Options) + 3) / 4) // 更新数据偏移
}

// AddWindowScaleOption 添加窗口缩放选项
func (tcp *TCP) AddWindowScaleOption(scale uint8) {
	option := []byte{TCPOptionWindowScale, 3, scale}
	tcp.Options = append(tcp.Options, option...)
	tcp.DataOffset = uint8((20 + len(tcp.Options) + 3) / 4)
}

// AddTimestampOption 添加时间戳选项
func (tcp *TCP) AddTimestampOption(tsval, tsecr uint32) {
	option := make([]byte, 10)
	option[0] = TCPOptionTimestamp
	option[1] = 10
	binary.BigEndian.PutUint32(option[2:6], tsval)
	binary.BigEndian.PutUint32(option[6:10], tsecr)
	tcp.Options = append(tcp.Options, option...)
	tcp.DataOffset = uint8((20 + len(tcp.Options) + 3) / 4)
}

// CalculateChecksum 计算TCP校验和（需要IP伪头部）
func (tcp *TCP) CalculateChecksum(srcIP, dstIP net.IP, payload []byte) uint16 {
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

	// 协议类型（TCP=6）和TCP长度
	pseudoHeader[9] = 6 // TCP协议
	tcpLength := uint16(20 + len(tcp.Options) + len(payload))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLength)

	// 构建TCP头部（不包括校验和）
	tcpHeader, _ := tcp.Build()
	tcpHeader[16] = 0
	tcpHeader[17] = 0

	// 计算校验和
	return tcp.calculateChecksum(append(pseudoHeader, append(tcpHeader, payload...)...))
}

// calculateChecksum 计算校验和的辅助函数
func (tcp *TCP) calculateChecksum(data []byte) uint16 {
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
