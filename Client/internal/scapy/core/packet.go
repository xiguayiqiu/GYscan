package core

import (
	"fmt"
	"time"
)

// LayerType 协议层类型
type LayerType int

const (
	LayerEthernet LayerType = iota
	LayerIPv4
	LayerIPv6
	LayerTCP
	LayerUDP
	LayerICMP
	LayerICMPv6
	LayerARP
	LayerDNS
	LayerHTTP
	// 更多协议层类型...
)

// String 返回层类型的字符串表示
func (lt LayerType) String() string {
	switch lt {
	case LayerEthernet:
		return "Ethernet"
	case LayerIPv4:
		return "IPv4"
	case LayerIPv6:
		return "IPv6"
	case LayerTCP:
		return "TCP"
	case LayerUDP:
		return "UDP"
	case LayerICMP:
		return "ICMP"
	case LayerICMPv6:
		return "ICMPv6"
	case LayerARP:
		return "ARP"
	case LayerDNS:
		return "DNS"
	case LayerHTTP:
		return "HTTP"
	default:
		return "Unknown"
	}
}

// Packet 包接口定义
type Packet interface {
	// 构建和解析
	Build() ([]byte, error)    // 构建原始字节
	Dissect(data []byte) error // 解析原始字节

	// 层操作
	GetLayer(layerType LayerType) Packet   // 获取指定层
	AddLayer(layer Packet) error           // 添加协议层
	RemoveLayer(layerType LayerType) error // 移除指定层

	// 信息获取
	LayerType() LayerType     // 层类型标识
	NextLayerType() LayerType // 下一层类型
	String() string           // 字符串表示
	HexDump() string          // 十六进制转储

	// 时间戳
	SetTimestamp(t time.Time) // 设置时间戳
	GetTimestamp() time.Time  // 获取时间戳

	// 负载操作
	SetPayload(data []byte) // 设置负载数据
	GetPayload() []byte     // 获取负载数据
}

// BasePacket 基础包实现
type BasePacket struct {
	layers    []Packet  // 协议层栈
	payload   []byte    // 负载数据
	timestamp time.Time // 时间戳
}

// NewBasePacket 创建新的基础包
func NewBasePacket() *BasePacket {
	return &BasePacket{
		layers:    make([]Packet, 0),
		payload:   nil,
		timestamp: time.Now(),
	}
}

// Build 构建原始字节（基础实现，子类需要重写）
func (bp *BasePacket) Build() ([]byte, error) {
	if len(bp.layers) == 0 {
		return bp.payload, nil
	}

	// 从底层开始构建
	var result []byte
	for i := len(bp.layers) - 1; i >= 0; i-- {
		layerData, err := bp.layers[i].Build()
		if err != nil {
			return nil, err
		}
		result = append(layerData, result...)
	}

	// 添加负载
	if bp.payload != nil {
		result = append(result, bp.payload...)
	}

	return result, nil
}

// Dissect 解析原始字节（基础实现，子类需要重写）
func (bp *BasePacket) Dissect(data []byte) error {
	// 基础包不直接解析，由具体协议层实现
	return fmt.Errorf("BasePacket does not support direct dissection")
}

// GetLayer 获取指定层
func (bp *BasePacket) GetLayer(layerType LayerType) Packet {
	for _, layer := range bp.layers {
		if layer.LayerType() == layerType {
			return layer
		}
	}
	return nil
}

// AddLayer 添加协议层
func (bp *BasePacket) AddLayer(layer Packet) error {
	// 检查层类型是否已存在
	for _, existingLayer := range bp.layers {
		if existingLayer.LayerType() == layer.LayerType() {
			return fmt.Errorf("layer type %s already exists", layer.LayerType())
		}
	}

	bp.layers = append(bp.layers, layer)
	return nil
}

// RemoveLayer 移除指定层
func (bp *BasePacket) RemoveLayer(layerType LayerType) error {
	for i, layer := range bp.layers {
		if layer.LayerType() == layerType {
			bp.layers = append(bp.layers[:i], bp.layers[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("layer type %s not found", layerType)
}

// LayerType 基础包的层类型（被子类重写）
func (bp *BasePacket) LayerType() LayerType {
	return -1 // 无效类型，子类需要实现
}

// NextLayerType 下一层类型（被子类重写）
func (bp *BasePacket) NextLayerType() LayerType {
	return -1 // 无效类型，子类需要实现
}

// String 字符串表示
func (bp *BasePacket) String() string {
	if len(bp.layers) == 0 {
		return "BasePacket"
	}

	result := ""
	for i, layer := range bp.layers {
		if i > 0 {
			result += " -> "
		}
		result += layer.String()
	}

	if bp.payload != nil {
		result += fmt.Sprintf(" [Payload: %d bytes]", len(bp.payload))
	}

	return result
}

// HexDump 十六进制转储
func (bp *BasePacket) HexDump() string {
	data, err := bp.Build()
	if err != nil {
		return fmt.Sprintf("Error building packet: %v", err)
	}

	return hexDump(data)
}

// SetTimestamp 设置时间戳
func (bp *BasePacket) SetTimestamp(t time.Time) {
	bp.timestamp = t
}

// GetTimestamp 获取时间戳
func (bp *BasePacket) GetTimestamp() time.Time {
	return bp.timestamp
}

// SetPayload 设置负载数据
func (bp *BasePacket) SetPayload(data []byte) {
	bp.payload = data
}

// GetPayload 获取负载数据
func (bp *BasePacket) GetPayload() []byte {
	return bp.payload
}

// hexDump 十六进制转储辅助函数
func hexDump(data []byte) string {
	if len(data) == 0 {
		return "Empty packet"
	}

	result := ""
	for i := 0; i < len(data); i += 16 {
		// 偏移量
		result += fmt.Sprintf("%04x: ", i)

		// 十六进制
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result += fmt.Sprintf("%02x ", data[i+j])
			} else {
				result += "   "
			}

			if j == 7 {
				result += " "
			}
		}

		// ASCII
		result += " "
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				b := data[i+j]
				if b >= 32 && b <= 126 {
					result += string(b)
				} else {
					result += "."
				}
			} else {
				result += " "
			}
		}

		result += "\n"
	}

	return result
}

// PacketBuilder 包构建器接口
type PacketBuilder interface {
	BuildPacket() (Packet, error)
	SetField(name string, value interface{}) error
	GetField(name string) interface{}
}

// SimplePacketBuilder 简单包构建器实现
type SimplePacketBuilder struct {
	packet Packet
	fields map[string]interface{}
}

// NewSimplePacketBuilder 创建新的包构建器
func NewSimplePacketBuilder(packet Packet) *SimplePacketBuilder {
	return &SimplePacketBuilder{
		packet: packet,
		fields: make(map[string]interface{}),
	}
}

// BuildPacket 构建包
func (spb *SimplePacketBuilder) BuildPacket() (Packet, error) {
	return spb.packet, nil
}

// SetField 设置字段值
func (spb *SimplePacketBuilder) SetField(name string, value interface{}) error {
	spb.fields[name] = value
	return nil
}

// GetField 获取字段值
func (spb *SimplePacketBuilder) GetField(name string) interface{} {
	return spb.fields[name]
}

// LayerInfo 协议层信息
type LayerInfo struct {
	Type        string                 // 层类型
	Source      string                 // 源地址
	Destination string                 // 目标地址
	Info        string                 // 附加信息
	Data        interface{}            // 层数据
	Fields      map[string]interface{} // 字段信息
}

// PacketInfo 包信息
type PacketInfo struct {
	Timestamp time.Time   // 时间戳
	Length    int         // 包长度
	Layers    []LayerInfo // 协议层信息
	RawData   []byte      // 原始数据
}
