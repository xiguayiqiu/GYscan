package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"GYscan/internal/scapy/core"
)

// Ethernet 以太网帧
type Ethernet struct {
	*core.BasePacket
	
	// 以太网字段
	Destination net.HardwareAddr // 目标MAC地址
	Source      net.HardwareAddr // 源MAC地址
	EtherType   uint16           // 以太网类型
	Payload     []byte           // 负载数据
}

// NewEthernet 创建新的以太网帧
func NewEthernet() *Ethernet {
	eth := &Ethernet{
		BasePacket:  core.NewBasePacket(),
		Destination: make(net.HardwareAddr, 6),
		Source:      make(net.HardwareAddr, 6),
		EtherType:   0x0800, // 默认IPv4
		Payload:     nil,
	}
	
	return eth
}

// LayerType 返回层类型
func (eth *Ethernet) LayerType() core.LayerType {
	return core.LayerEthernet
}

// NextLayerType 返回下一层类型
func (eth *Ethernet) NextLayerType() core.LayerType {
	switch eth.EtherType {
	case 0x0800:
		return core.LayerIPv4
	case 0x0806:
		return core.LayerARP
	case 0x86DD:
		return core.LayerIPv6
	default:
		return -1 // 未知类型
	}
}

// Build 构建以太网帧
func (eth *Ethernet) Build() ([]byte, error) {
	// 以太网帧结构：目标MAC(6) + 源MAC(6) + 类型(2) + 负载
	frame := make([]byte, 14) // 6+6+2 = 14字节头部
	
	// 目标MAC地址
	if len(eth.Destination) != 6 {
		return nil, fmt.Errorf("invalid destination MAC address length: %d", len(eth.Destination))
	}
	copy(frame[0:6], eth.Destination)
	
	// 源MAC地址
	if len(eth.Source) != 6 {
		return nil, fmt.Errorf("invalid source MAC address length: %d", len(eth.Source))
	}
	copy(frame[6:12], eth.Source)
	
	// 以太网类型（大端序）
	binary.BigEndian.PutUint16(frame[12:14], eth.EtherType)
	
	// 添加负载
	if eth.Payload != nil {
		frame = append(frame, eth.Payload...)
	}
	
	return frame, nil
}

// Dissect 解析以太网帧
func (eth *Ethernet) Dissect(data []byte) error {
	if len(data) < 14 {
		return fmt.Errorf("ethernet frame too short: %d bytes", len(data))
	}
	
	// 解析目标MAC地址
	eth.Destination = make(net.HardwareAddr, 6)
	copy(eth.Destination, data[0:6])
	
	// 解析源MAC地址
	eth.Source = make(net.HardwareAddr, 6)
	copy(eth.Source, data[6:12])
	
	// 解析以太网类型
	eth.EtherType = binary.BigEndian.Uint16(data[12:14])
	
	// 解析负载
	if len(data) > 14 {
		eth.Payload = make([]byte, len(data)-14)
		copy(eth.Payload, data[14:])
	}
	
	return nil
}

// String 字符串表示
func (eth *Ethernet) String() string {
	return fmt.Sprintf("Ethernet %s > %s Type: 0x%04x", 
		eth.Source.String(), eth.Destination.String(), eth.EtherType)
}

// SetDestinationMAC 设置目标MAC地址
func (eth *Ethernet) SetDestinationMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("MAC address must be 6 bytes")
	}
	eth.Destination = mac
	return nil
}

// SetSourceMAC 设置源MAC地址
func (eth *Ethernet) SetSourceMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("MAC address must be 6 bytes")
	}
	eth.Source = mac
	return nil
}

// SetEtherType 设置以太网类型
func (eth *Ethernet) SetEtherType(etherType uint16) {
	eth.EtherType = etherType
}

// SetPayload 设置负载数据
func (eth *Ethernet) SetPayload(payload []byte) {
	eth.Payload = payload
}

// GetPayload 获取负载数据
func (eth *Ethernet) GetPayload() []byte {
	return eth.Payload
}

// CommonEtherTypes 常见以太网类型
const (
	EtherTypeIPv4  uint16 = 0x0800
	EtherTypeARP    uint16 = 0x0806
	EtherTypeIPv6   uint16 = 0x86DD
	EtherTypeVLAN   uint16 = 0x8100
	EtherTypeMPLS   uint16 = 0x8847
	EtherTypePPPoE  uint16 = 0x8864
)

// CreateIPv4Packet 创建IPv4以太网包
func CreateIPv4Packet(srcMAC, dstMAC net.HardwareAddr, ipPacket *IP) (*Ethernet, error) {
	eth := NewEthernet()
	
	if err := eth.SetSourceMAC(srcMAC); err != nil {
		return nil, err
	}
	
	if err := eth.SetDestinationMAC(dstMAC); err != nil {
		return nil, err
	}
	
	eth.SetEtherType(EtherTypeIPv4)
	
	// 构建IP包
	ipData, err := ipPacket.Build()
	if err != nil {
		return nil, err
	}
	
	eth.SetPayload(ipData)
	
	return eth, nil
}

/*
// CreateARPPacket 创建ARP以太网包
func CreateARPPacket(srcMAC, dstMAC net.HardwareAddr, arpPacket *ARP) (*Ethernet, error) {
	eth := NewEthernet()
	
	if err := eth.SetSourceMAC(srcMAC); err != nil {
		return nil, err
	}
	
	if err := eth.SetDestinationMAC(dstMAC); err != nil {
		return nil, err
	}
	
	eth.SetEtherType(EtherTypeARP)
	
	// 构建ARP包
	arpData, err := arpPacket.Build()
	if err != nil {
		return nil, err
	}
	
	eth.SetPayload(arpData)
	
	return eth, nil
}
*/

// BroadcastMAC 广播MAC地址
func BroadcastMAC() net.HardwareAddr {
	return net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
}

// IsBroadcastMAC 检查是否为广播MAC地址
func IsBroadcastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	
	for _, b := range mac {
		if b != 0xFF {
			return false
		}
	}
	
	return true
}

// IsMulticastMAC 检查是否为多播MAC地址
func IsMulticastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	
	// 多播MAC地址的第一个字节的最低位为1
	return (mac[0] & 0x01) != 0
}

// IsUnicastMAC 检查是否为单播MAC地址
func IsUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	
	// 单播MAC地址的第一个字节的最低位为0
	return (mac[0] & 0x01) == 0 && !IsBroadcastMAC(mac)
}