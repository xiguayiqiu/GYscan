package parser

import (
	"fmt"
	"time"

	"GYscan/internal/scapy/core"
	"GYscan/internal/scapy/layers"
)

// ParsePacket 解析原始数据包
func ParsePacket(data []byte) ([]core.Packet, error) {
	var packets []core.Packet

	// 尝试解析为以太网包
	eth := layers.NewEthernet()
	if err := eth.Dissect(data); err == nil {
		packets = append(packets, eth)

		// 如果有负载，尝试解析为IP包
		if len(eth.Payload) > 0 {
			ip := layers.NewIP()
			if err := ip.Dissect(eth.Payload); err == nil {
				packets = append(packets, ip)

				// 根据协议类型解析传输层
				switch ip.Protocol {
				case 6: // TCP
					tcp := layers.NewTCP()
					if err := tcp.Dissect(ip.Payload); err == nil {
						packets = append(packets, tcp)
					}
				case 17: // UDP
					udp := layers.NewUDP()
					if err := udp.Dissect(ip.Payload); err == nil {
						packets = append(packets, udp)
					}
				}
			}
		}
	} else {
		// 尝试直接解析为IP包
		ip := layers.NewIP()
		if err := ip.Dissect(data); err == nil {
			packets = append(packets, ip)
		}
	}

	return packets, nil
}

// GetPacketSummary 获取数据包摘要信息
func GetPacketSummary(packet core.Packet) *PacketSummary {
	summary := &PacketSummary{
		Timestamp: packet.GetTimestamp(),
	}

	switch p := packet.(type) {
	case *layers.Ethernet:
		summary.Source = p.Source.String()
		summary.Destination = p.Destination.String()
		summary.Protocol = "Ethernet"
		summary.Info = fmt.Sprintf("Type: 0x%04x", p.EtherType)

	case *layers.IP:
		summary.Source = p.SourceIP.String()
		summary.Destination = p.DestinationIP.String()
		summary.Protocol = "IP"
		summary.Info = fmt.Sprintf("Protocol: %d, TTL: %d", p.Protocol, p.TTL)

	case *layers.TCP:
		summary.Source = fmt.Sprintf("%d", p.SourcePort)
		summary.Destination = fmt.Sprintf("%d", p.DestinationPort)
		summary.Protocol = "TCP"

		// 解析标志位
		var flags string
		if p.HasFlag(layers.TCPFlagSYN) {
			flags += "S"
		}
		if p.HasFlag(layers.TCPFlagACK) {
			flags += "A"
		}
		if p.HasFlag(layers.TCPFlagFIN) {
			flags += "F"
		}
		if p.HasFlag(layers.TCPFlagRST) {
			flags += "R"
		}

		summary.Info = fmt.Sprintf("Flags: %s, Seq: %d, Ack: %d", flags, p.SequenceNumber, p.AckNumber)

	case *layers.UDP:
		summary.Source = fmt.Sprintf("%d", p.SourcePort)
		summary.Destination = fmt.Sprintf("%d", p.DestinationPort)
		summary.Protocol = "UDP"
		summary.Info = fmt.Sprintf("Length: %d", p.Length)
	}

	return summary
}

// PacketSummary 数据包摘要信息
type PacketSummary struct {
	Timestamp   time.Time
	Source      string
	Destination string
	Protocol    string
	Info        string
}

// FormatPacket 格式化数据包显示
func FormatPacket(packet core.Packet, format string) string {
	switch format {
	case "hex":
		return packet.HexDump()
	case "summary":
		summary := GetPacketSummary(packet)
		return fmt.Sprintf("%s %s > %s %s %s",
			summary.Timestamp.Format("15:04:05.000"),
			summary.Source, summary.Destination,
			summary.Protocol, summary.Info)
	case "verbose":
		return packet.String()
	default:
		return packet.String()
	}
}
