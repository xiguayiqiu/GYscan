package scapy

import (
	"fmt"
	"net"

	"GYscan/internal/utils"
)

// ExampleUsage 演示Scapy功能的使用
func ExampleUsage() {
	utils.BoldInfo("=== GYscan Scapy功能演示 ===")

	// 1. 详细参数说明
	demoParameterExplanation()

	// 2. 网络包构造演示
	demoPacketConstruction()

	// 3. 工具函数演示
	demoUtilityFunctions()

	// 6. 实际使用示例
	demoPracticalExamples()
}

// demoParameterExplanation 详细参数说明
func demoParameterExplanation() {
	utils.BoldInfo("\n1. Scapy功能参数详细说明")
	fmt.Println("========================================")

	// 主命令参数说明
	utils.InfoPrint("主命令: GYscan scapy [子命令] [参数]")
	fmt.Println()

	// 子命令说明
	utils.SuccessPrint("可用子命令:")
	utils.InfoPrint("  packet      - 网络包构造和发送")
	utils.InfoPrint("  interface   - 网络接口检测")
	utils.InfoPrint("  example     - 功能演示")
	fmt.Println()

	// 包操作命令参数说明
	utils.SuccessPrint("包操作命令参数 (packet):")
	utils.InfoPrint("  -t, --target    目标IP地址")
	utils.InfoPrint("  -w, --timeout   超时时间(秒)")
	utils.InfoPrint("  -i, --interface 网络接口名称")
	utils.InfoPrint("  --syn           发送TCP SYN包")
	utils.InfoPrint("  --ack           发送TCP ACK包")
	utils.InfoPrint("  --udp           发送UDP包")
	utils.InfoPrint("  --sport         源端口 (0表示随机)")
	utils.InfoPrint("  --dport         目标端口")
	utils.InfoPrint("  --flags         TCP标志位 (SYN/ACK/FIN/PSH/RST/URG)")
	utils.InfoPrint("  --payload       载荷数据")
	utils.InfoPrint("  --ttl           TTL值")
	utils.InfoPrint("  --window        TCP窗口大小")
	fmt.Println()

	// 接口检测命令参数说明
	utils.SuccessPrint("接口检测命令参数 (interface):")
	utils.InfoPrint("  -v, --verbose   详细输出模式")
	fmt.Println()
}

// demoPacketConstruction 演示网络包构造
func demoPacketConstruction() {
	fmt.Println("\n1. 网络包构造演示:")

	srcIP := net.IPv4(192, 168, 1, 100)
	dstIP := net.IPv4(192, 168, 1, 1)

	// 构造TCP SYN包
	synPacket, err := BuildSYNPacket(srcIP, dstIP, 80)
	if err != nil {
		fmt.Printf("构造SYN包失败: %v\n", err)
	} else {
		fmt.Printf("构造TCP SYN包成功，长度: %d字节\n", len(synPacket))
	}

	// 构造UDP包
	udpData := []byte("GYscan UDP探测")
	udpPacket, err := BuildUDPPacket(srcIP, dstIP, 12345, 53, udpData)
	if err != nil {
		fmt.Printf("构造UDP包失败: %v\n", err)
	} else {
		fmt.Printf("构造UDP包成功，长度: %d字节\n", len(udpPacket))
	}

	// 构造ICMP包
	icmpPacket, err := BuildICMPPacket(srcIP, dstIP, 8, 0, []byte("GYscan ICMP探测"))
	if err != nil {
		fmt.Printf("构造ICMP包失败: %v\n", err)
	} else {
		fmt.Printf("构造ICMP包成功，长度: %d字节\n", len(icmpPacket))
	}
}

// demoUtilityFunctions 演示工具函数
func demoUtilityFunctions() {
	fmt.Println("\n4. 工具函数演示:")

	// 端口解析
	portStr := "22,80,443,8000-8010"
	ports, err := ParsePorts(portStr)
	if err != nil {
		fmt.Printf("端口解析失败: %v\n", err)
	} else {
		fmt.Printf("解析端口 '%s' 得到 %d 个端口\n", portStr, len(ports))
	}

	// 目标解析
	targets, err := ParseTarget("192.168.1.0/24")
	if err != nil {
		fmt.Printf("目标解析失败: %v\n", err)
	} else {
		fmt.Printf("解析CIDR得到 %d 个IP地址 (显示前5个)\n", len(targets))
		for i := 0; i < 5 && i < len(targets); i++ {
			fmt.Printf("  %s\n", targets[i])
		}
	}

	// IP验证
	testIPs := []string{"192.168.1.1", "256.256.256.256", "google.com"}
	for _, ip := range testIPs {
		if ValidateIP(ip) {
			if IsPrivateIP(net.ParseIP(ip)) {
				fmt.Printf("IP %s 是有效的私有IP\n", ip)
			} else {
				fmt.Printf("IP %s 是有效的公网IP\n", ip)
			}
		} else {
			fmt.Printf("IP %s 无效\n", ip)
		}
	}
}

// demoPracticalExamples 实际使用示例
func demoPracticalExamples() {
	utils.BoldInfo("\n6. 实际使用示例")
	fmt.Println("========================================")

	// 示例1: 快速网络扫描
	utils.SuccessPrint("示例1: 快速网络扫描")
	utils.InfoPrint("命令: GYscan scapy scan -t 192.168.1.1 -p 22,80,443,3389 -T syn")
	utils.InfoPrint("功能: 对目标进行SYN扫描，检查常用服务端口")
	utils.InfoPrint("参数说明:")
	utils.InfoPrint("  -t 192.168.1.1    指定目标IP")
	utils.InfoPrint("  -p 22,80,443,3389 扫描SSH,HTTP,HTTPS,RDP端口")
	utils.InfoPrint("  -T syn            使用SYN扫描技术")
	fmt.Println()

	// 示例2: 子网扫描
	utils.SuccessPrint("示例2: 子网扫描")
	utils.InfoPrint("命令: GYscan scapy scan -t 192.168.1.0/24 -p 1-100 -n 100 -T all")
	utils.InfoPrint("功能: 扫描整个子网，使用100个线程进行组合扫描")
	utils.InfoPrint("参数说明:")
	utils.InfoPrint("  -t 192.168.1.0/24 扫描整个C类子网")
	utils.InfoPrint("  -p 1-100          扫描前100个端口")
	utils.InfoPrint("  -n 100            使用100个并发线程")
	utils.InfoPrint("  -T all            使用所有扫描技术")
	fmt.Println()

	// 示例3: 网络包捕获
	utils.SuccessPrint("示例3: 网络包捕获")
	utils.InfoPrint("命令: GYscan scapy capture -i WLAN -t 30 -f \"tcp port 80\" -v")
	utils.InfoPrint("功能: 捕获WLAN接口的HTTP流量，持续30秒")
	utils.InfoPrint("参数说明:")
	utils.InfoPrint("  -i WLAN           指定无线网络接口")
	utils.InfoPrint("  -t 30             捕获30秒")
	utils.InfoPrint("  -f \"tcp port 80\" 过滤HTTP流量")
	utils.InfoPrint("  -v                详细输出模式")
	fmt.Println()

	// 示例4: 自定义包发送
	utils.SuccessPrint("示例4: 自定义包发送")
	utils.InfoPrint("命令: GYscan scapy packet --syn -t 8.8.8.8 -p 53 --ttl 128 --window 65535")
	utils.InfoPrint("功能: 发送自定义TCP SYN包到DNS服务器")
	utils.InfoPrint("参数说明:")
	utils.InfoPrint("  --syn             发送SYN包")
	utils.InfoPrint("  -t 8.8.8.8        目标为Google DNS")
	utils.InfoPrint("  -p 53             目标端口53(DNS)")
	utils.InfoPrint("  --ttl 128         设置TTL为128")
	utils.InfoPrint("  --window 65535    设置窗口大小为65535")
	fmt.Println()

	// 示例5: 网络接口检测
	utils.SuccessPrint("示例5: 网络接口检测")
	utils.InfoPrint("命令: GYscan scapy interface -v")
	utils.InfoPrint("功能: 检测系统所有网络接口的详细信息")
	utils.InfoPrint("参数说明:")
	utils.InfoPrint("  -v                详细输出模式")
	fmt.Println()

	// 使用建议
	utils.SuccessPrint("使用建议:")
	utils.InfoPrint("1. 先使用interface命令检测可用网络接口")
	utils.InfoPrint("2. 使用packet命令构造和发送自定义网络包")
	utils.InfoPrint("3. 合理设置超时时间(-w)参数")
	utils.InfoPrint("4. 使用-v参数获取详细输出信息")
	fmt.Println()
}
