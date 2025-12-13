package utils

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// HexDump 生成十六进制转储
func HexDump(data []byte, offset int) string {
	var result strings.Builder

	for i := 0; i < len(data); i += 16 {
		// 偏移量
		result.WriteString(fmt.Sprintf("%08x  ", offset+i))

		// 十六进制部分
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				result.WriteString("   ")
			}

			if j == 7 {
				result.WriteString(" ")
			}
		}

		result.WriteString(" ")

		// ASCII部分
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				b := data[i+j]
				if b >= 32 && b <= 126 {
					result.WriteByte(b)
				} else {
					result.WriteByte('.')
				}
			} else {
				result.WriteByte(' ')
			}
		}

		result.WriteString("\n")
	}

	return result.String()
}

// ParseMAC 解析MAC地址
func ParseMAC(macStr string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address: %s", macStr)
	}
	return mac, nil
}

// ParseIP 解析IP地址
func ParseIP(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return ip, nil
}

// ParsePort 解析端口号
func ParsePort(portStr string) (uint16, error) {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return uint16(port), nil
}

// IPToInt IP地址转整数
func IPToInt(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}

	ip = ip.To4()
	if ip == nil {
		return 0
	}

	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// IntToIP 整数转IP地址
func IntToIP(ipInt uint32) net.IP {
	return net.IPv4(
		byte(ipInt>>24),
		byte(ipInt>>16),
		byte(ipInt>>8),
		byte(ipInt),
	)
}

// CalculateChecksum 计算校验和
func CalculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	// 对每16位进行求和
	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
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

// RandomMAC 生成随机MAC地址
func RandomMAC() net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	for i := 0; i < 6; i++ {
		mac[i] = byte(time.Now().UnixNano() % 256)
	}
	// 设置本地管理位
	mac[0] &^= 0x01 // 清除全局/本地位
	mac[0] |= 0x02  // 设置本地管理位
	return mac
}

// RandomIP 生成随机IP地址
func RandomIP() net.IP {
	return net.IPv4(
		byte(time.Now().UnixNano()%256),
		byte(time.Now().UnixNano()%256),
		byte(time.Now().UnixNano()%256),
		byte(time.Now().UnixNano()%256),
	)
}

// RandomPort 生成随机端口号
func RandomPort() uint16 {
	return uint16(1024 + time.Now().UnixNano()%64511) // 1024-65535
}

// CommonProtocols 常用协议常量
const (
	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMPv6 = 58
)

// CommonEtherTypes 常用以太网类型
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD
)

// PortName 获取端口服务名称
func PortName(port uint16, protocol string) string {
	portNames := map[uint16]string{
		20:   "FTP Data",
		21:   "FTP Control",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		993:  "IMAPS",
		995:  "POP3S",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
	}

	if name, exists := portNames[port]; exists {
		return name
	}

	return ""
}

// HexStringToBytes 十六进制字符串转字节数组
func HexStringToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, ":", "")

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %s", hexStr)
	}

	return data, nil
}

// BytesToHexString 字节数组转十六进制字符串
func BytesToHexString(data []byte, separator string) string {
	hexStr := hex.EncodeToString(data)

	if separator != "" {
		var result strings.Builder
		for i := 0; i < len(hexStr); i += 2 {
			if i > 0 {
				result.WriteString(separator)
			}
			result.WriteString(hexStr[i : i+2])

			// 每16字节换行
			if (i/2+1)%16 == 0 && i+2 < len(hexStr) {
				result.WriteString("\n")
			}
		}
		return result.String()
	}

	return hexStr
}

// CalculateIPChecksum 计算IP校验和
func CalculateIPChecksum(header []byte) uint16 {
	return CalculateChecksum(header)
}

// ValidateIPChecksum 验证IP校验和
func ValidateIPChecksum(header []byte) bool {
	// 保存原始校验和
	originalChecksum := (uint16(header[10]) << 8) | uint16(header[11])

	// 将校验和字段设为0
	header[10] = 0
	header[11] = 0

	// 计算新校验和
	newChecksum := CalculateIPChecksum(header)

	// 恢复原始校验和
	header[10] = byte(originalChecksum >> 8)
	header[11] = byte(originalChecksum & 0xFF)

	return newChecksum == originalChecksum
}
