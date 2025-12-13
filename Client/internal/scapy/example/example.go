package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"GYscan/internal/scapy/layers"
	"GYscan/internal/scapy/parser"
	"GYscan/internal/scapy/utils"
)

func main() {
	fmt.Println("=== Go Scapy 移植示例程序 ===")
	fmt.Println()

	// 示例1: 构建以太网数据包
	exampleEthernet()
	fmt.Println()

	// 示例2: 构建IP数据包
	exampleIP()
	fmt.Println()

	// 示例3: 构建TCP数据包
	exampleTCP()
	fmt.Println()

	// 示例4: 构建UDP数据包
	exampleUDP()
	fmt.Println()

	// 示例5: 数据包解析
	examplePacketParsing()
	fmt.Println()

	// 示例6: 实用工具函数
	exampleUtils()
	fmt.Println()

	fmt.Println("=== 示例程序完成 ===")
}

func exampleEthernet() {
	fmt.Println("示例1: 以太网数据包构建")
	fmt.Println("-" + strings.Repeat("-", 40))

	// 创建以太网数据包
	eth := layers.NewEthernet()

	// 设置MAC地址
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("66:77:88:99:AA:BB")
	eth.Source = srcMAC
	eth.Destination = dstMAC
	eth.EtherType = 0x0800 // IPv4

	// 构建数据包
	data, err := eth.Build()
	if err != nil {
		log.Printf("构建以太网包失败: %v", err)
		return
	}

	fmt.Printf("以太网包长度: %d 字节\n", len(data))
	fmt.Printf("源MAC: %s\n", eth.Source.String())
	fmt.Printf("目标MAC: %s\n", eth.Destination.String())
	fmt.Printf("以太网类型: 0x%04x\n", eth.EtherType)

	// 十六进制转储
	fmt.Println("\n十六进制转储:")
	fmt.Println(utils.HexDump(data, 0))
}

func exampleIP() {
	fmt.Println("示例2: IP数据包构建")
	fmt.Println("-" + strings.Repeat("-", 40))

	// 创建IP数据包
	ip := layers.NewIP()

	// 设置IP地址
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")
	ip.SourceIP = srcIP
	ip.DestinationIP = dstIP
	ip.Protocol = 6 // TCP
	ip.TTL = 64

	// 构建数据包
	data, err := ip.Build()
	if err != nil {
		log.Printf("构建IP包失败: %v", err)
		return
	}

	fmt.Printf("IP包长度: %d 字节\n", len(data))
	fmt.Printf("源IP: %s\n", ip.SourceIP.String())
	fmt.Printf("目标IP: %s\n", ip.DestinationIP.String())
	fmt.Printf("协议: %d (TCP)\n", ip.Protocol)
	fmt.Printf("TTL: %d\n", ip.TTL)

	// 字符串表示
	fmt.Printf("\n数据包信息: %s\n", ip.String())
}

func exampleTCP() {
	fmt.Println("示例3: TCP数据包构建")
	fmt.Println("-" + strings.Repeat("-", 40))

	// 创建TCP数据包
	tcp := layers.NewTCP()
	tcp.SourcePort = 54321
	tcp.DestinationPort = 80
	tcp.SequenceNumber = 1000
	tcp.AckNumber = 0
	tcp.SetFlag(layers.TCPFlagSYN)
	tcp.WindowSize = 8192

	// 构建数据包
	data, err := tcp.Build()
	if err != nil {
		log.Printf("构建TCP包失败: %v", err)
		return
	}

	fmt.Printf("TCP包长度: %d 字节\n", len(data))
	fmt.Printf("源端口: %d\n", tcp.SourcePort)
	fmt.Printf("目标端口: %d\n", tcp.DestinationPort)
	fmt.Printf("序列号: %d\n", tcp.SequenceNumber)
	fmt.Printf("确认号: %d\n", tcp.AckNumber)
	fmt.Printf("窗口大小: %d\n", tcp.WindowSize)

	// 检查标志位
	flags := ""
	if tcp.HasFlag(layers.TCPFlagSYN) {
		flags += "SYN "
	}
	if tcp.HasFlag(layers.TCPFlagACK) {
		flags += "ACK "
	}
	if tcp.HasFlag(layers.TCPFlagFIN) {
		flags += "FIN "
	}
	if tcp.HasFlag(layers.TCPFlagRST) {
		flags += "RST "
	}

	fmt.Printf("标志位: %s\n", flags)
	fmt.Printf("\n数据包信息: %s\n", tcp.String())
}

func exampleUDP() {
	fmt.Println("示例4: UDP数据包构建")
	fmt.Println("-" + strings.Repeat("-", 40))

	// 创建UDP数据包
	udp := layers.NewUDP()
	udp.SourcePort = 12345
	udp.DestinationPort = 53 // DNS

	// 设置负载数据（简单的DNS查询）
	payload := []byte{
		0x00, 0x01, // ID
		0x01, 0x00, // 标志
		0x00, 0x01, // 问题数
		0x00, 0x00, // 回答数
		0x00, 0x00, // 权威记录数
		0x00, 0x00, // 附加记录数
		// 查询部分
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // 结束
		0x00, 0x01, // 类型: A记录
		0x00, 0x01, // 类: IN
	}

	udp.SetPayload(payload)

	// 构建数据包
	data, err := udp.Build()
	if err != nil {
		log.Printf("构建UDP包失败: %v", err)
		return
	}

	fmt.Printf("UDP包长度: %d 字节\n", len(data))
	fmt.Printf("源端口: %d\n", udp.SourcePort)
	fmt.Printf("目标端口: %d (DNS)\n", udp.DestinationPort)
	fmt.Printf("负载长度: %d 字节\n", len(udp.Payload))

	fmt.Printf("\n数据包信息: %s\n", udp.String())
}

func examplePacketParsing() {
	fmt.Println("示例5: 数据包解析")
	fmt.Println("-" + strings.Repeat("-", 40))

	// 创建一个完整的TCP/IP数据包
	// 先构建TCP包
	tcp := layers.NewTCP()
	tcp.SourcePort = 12345
	tcp.DestinationPort = 80
	tcp.SetFlag(layers.TCPFlagSYN)
	tcpData, _ := tcp.Build()

	// 构建IP包包装TCP包
	ip := layers.NewIP()
	ip.SourceIP = net.ParseIP("192.168.1.100")
	ip.DestinationIP = net.ParseIP("192.168.1.1")
	ip.Protocol = 6 // TCP
	ip.SetPayload(tcpData)
	ipData, _ := ip.Build()

	// 构建以太网包包装IP包
	eth := layers.NewEthernet()
	eth.Source, _ = net.ParseMAC("00:11:22:33:44:55")
	eth.Destination, _ = net.ParseMAC("66:77:88:99:AA:BB")
	eth.EtherType = 0x0800 // IPv4
	eth.SetPayload(ipData)
	fullPacket, _ := eth.Build()

	fmt.Printf("完整数据包长度: %d 字节\n", len(fullPacket))

	// 解析数据包
	packets, err := parser.ParsePacket(fullPacket)
	if err != nil {
		log.Printf("解析数据包失败: %v", err)
		return
	}

	fmt.Printf("解析出 %d 个协议层:\n", len(packets))
	for i, packet := range packets {
		summary := parser.GetPacketSummary(packet)
		fmt.Printf("  %d. %s: %s -> %s\n",
			i+1, summary.Protocol, summary.Source, summary.Destination)
	}
}

func exampleUtils() {
	fmt.Println("示例6: 实用工具函数")
	fmt.Println("-" + strings.Repeat("-", 40))

	// MAC地址解析
	mac, err := utils.ParseMAC("00:11:22:33:44:55")
	if err != nil {
		log.Printf("MAC地址解析失败: %v", err)
	} else {
		fmt.Printf("MAC地址解析: %s\n", mac.String())
	}

	// IP地址解析
	ip, err := utils.ParseIP("192.168.1.1")
	if err != nil {
		log.Printf("IP地址解析失败: %v", err)
	} else {
		fmt.Printf("IP地址解析: %s\n", ip.String())
	}

	// 端口解析
	port, err := utils.ParsePort("80")
	if err != nil {
		log.Printf("端口解析失败: %v", err)
	} else {
		fmt.Printf("端口解析: %d (%s)\n", port, utils.PortName(port, "tcp"))
	}

	// 十六进制转换
	hexData := "48656c6c6f20576f726c64" // "Hello World"
	bytes, err := utils.HexStringToBytes(hexData)
	if err != nil {
		log.Printf("十六进制转换失败: %v", err)
	} else {
		fmt.Printf("十六进制转换: %s -> %s\n", hexData, string(bytes))
	}

	// IP地址转整数
	ipInt := utils.IPToInt(net.ParseIP("192.168.1.1"))
	fmt.Printf("IP转整数: 192.168.1.1 -> %d\n", ipInt)

	// 整数转IP地址
	newIP := utils.IntToIP(ipInt)
	fmt.Printf("整数转IP: %d -> %s\n", ipInt, newIP.String())

	// 随机生成
	randomMAC := utils.RandomMAC()
	randomIP := utils.RandomIP()
	randomPort := utils.RandomPort()

	fmt.Printf("随机MAC: %s\n", randomMAC.String())
	fmt.Printf("随机IP: %s\n", randomIP.String())
	fmt.Printf("随机端口: %d\n", randomPort)
}
