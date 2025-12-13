package builder

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"GYscan/internal/scapy/layers"
)

// BuildEthernetPacket 构建以太网数据包
func BuildEthernetPacket(srcMAC, dstMAC, etherType string, payload []byte) (*layers.Ethernet, error) {
	src, err := ParseMAC(srcMAC)
	if err != nil {
		return nil, err
	}

	dst, err := ParseMAC(dstMAC)
	if err != nil {
		return nil, err
	}

	// 解析以太网类型
	etherTypeInt, err := strconv.ParseUint(etherType, 0, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid ethertype: %s", etherType)
	}

	eth := layers.NewEthernet()
	eth.Source = src
	eth.Destination = dst
	eth.EtherType = uint16(etherTypeInt)
	eth.SetPayload(payload)

	return eth, nil
}

// BuildIPPacket 构建IP数据包
func BuildIPPacket(srcIP, dstIP string, protocol uint8, payload []byte) (*layers.IP, error) {
	src, err := ParseIP(srcIP)
	if err != nil {
		return nil, err
	}

	dst, err := ParseIP(dstIP)
	if err != nil {
		return nil, err
	}

	ip := layers.NewIP()
	ip.SourceIP = src
	ip.DestinationIP = dst
	ip.Protocol = protocol
	ip.SetPayload(payload)

	return ip, nil
}

// BuildTCPPacket 构建TCP数据包
func BuildTCPPacket(srcPort, dstPort uint16, flags string, payload []byte) (*layers.TCP, error) {
	tcp := layers.NewTCPPacket(srcPort, dstPort)

	// 解析标志位
	var tcpFlags uint8
	if strings.Contains(flags, "S") {
		tcpFlags |= layers.TCPFlagSYN
	}
	if strings.Contains(flags, "A") {
		tcpFlags |= layers.TCPFlagACK
	}
	if strings.Contains(flags, "F") {
		tcpFlags |= layers.TCPFlagFIN
	}
	if strings.Contains(flags, "R") {
		tcpFlags |= layers.TCPFlagRST
	}
	if strings.Contains(flags, "P") {
		tcpFlags |= layers.TCPFlagPSH
	}
	if strings.Contains(flags, "U") {
		tcpFlags |= layers.TCPFlagURG
	}

	tcp.SetFlags(tcpFlags)
	tcp.SetPayload(payload)

	return tcp, nil
}

// BuildUDPPacket 构建UDP数据包
func BuildUDPPacket(srcPort, dstPort uint16, payload []byte) *layers.UDP {
	udp := layers.NewUDPPacket(srcPort, dstPort)
	udp.SetPayload(payload)
	return udp
}

// ParseMAC 解析MAC地址
func ParseMAC(mac string) (net.HardwareAddr, error) {
	return net.ParseMAC(mac)
}

// ParseIP 解析IP地址
func ParseIP(ip string) (net.IP, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}
	return parsed, nil
}

// BuildTCPSynPacket 构建TCP SYN包
func BuildTCPSynPacket(srcPort, dstPort uint16, seqNum uint32) ([]byte, error) {
	tcp := layers.NewTCPPacket(srcPort, dstPort)
	tcp.SetFlags(layers.TCPFlagSYN)
	tcp.SetSequenceNumber(seqNum)

	// 构建TCP包
	data, err := tcp.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build TCP SYN packet: %v", err)
	}

	return data, nil
}

// BuildTCPAckPacket 构建TCP ACK包
func BuildTCPAckPacket(srcPort, dstPort uint16, seqNum, ackNum uint32) ([]byte, error) {
	tcp := layers.NewTCPPacket(srcPort, dstPort)
	tcp.SetFlags(layers.TCPFlagACK)
	tcp.SetSequenceNumber(seqNum)
	tcp.SetAckNumber(ackNum)

	// 构建TCP包
	data, err := tcp.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build TCP ACK packet: %v", err)
	}

	return data, nil
}

// BuildCustomTCPPacket 构建自定义TCP包
func BuildCustomTCPPacket(srcPort, dstPort int, flags uint8, window int, payload []byte) ([]byte, error) {
	tcp := layers.NewTCPPacket(uint16(srcPort), uint16(dstPort))
	tcp.SetFlags(flags)
	tcp.SetWindowSize(uint16(window))
	tcp.SetPayload(payload)

	// 构建TCP包
	data, err := tcp.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build custom TCP packet: %v", err)
	}

	return data, nil
}

// BuildCustomTCPPacketWithSeq 构建带序列号的自定义TCP包
func BuildCustomTCPPacketWithSeq(srcPort, dstPort int, flags uint8, seqNum, ackNum uint32, window int, payload []byte) ([]byte, error) {
	tcp := layers.NewTCPPacket(uint16(srcPort), uint16(dstPort))
	tcp.SetFlags(flags)
	tcp.SetSequenceNumber(seqNum)
	tcp.SetAckNumber(ackNum)
	tcp.SetWindowSize(uint16(window))
	tcp.SetPayload(payload)

	// 构建TCP包
	data, err := tcp.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build custom TCP packet with sequence: %v", err)
	}

	return data, nil
}

// BuildCustomIPPacket 构建自定义IP包
func BuildCustomIPPacket(srcIP, dstIP string, protocol uint8, payload []byte, ttl int) (*layers.IP, error) {
	src, err := ParseIP(srcIP)
	if err != nil {
		return nil, err
	}

	dst, err := ParseIP(dstIP)
	if err != nil {
		return nil, err
	}

	ip := layers.NewIP()
	ip.SourceIP = src
	ip.DestinationIP = dst
	ip.Protocol = protocol
	ip.TTL = uint8(ttl)
	ip.SetPayload(payload)

	return ip, nil
}
