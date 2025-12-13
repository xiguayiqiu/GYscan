package scapy

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"GYscan/internal/scapy/builder"
	"GYscan/internal/scapy/sendrecv"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// ScapyCmd 表示Scapy网络包操作命令
var ScapyCmd = &cobra.Command{
	Use:   "scapy",
	Short: "高级网络包操作工具（类似Python Scapy）",
	Long: `Scapy - 高级网络包操作工具
基于纯Go实现，提供类似Python Scapy的底层网络包操作能力
支持原始包构造、捕获、分析和高级扫描技术

功能特性:
• 原始网络包构造和发送
• 实时网络包捕获和分析
• 多种高级扫描技术（SYN/ACK/FIN/XMAS/UDP）
• 防火墙规避和检测
• 协议级精确控制

警告：仅用于授权测试，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果没有参数，显示帮助信息
		if len(args) == 0 {
			cmd.Help()
			return
		}
	},
}

// 命令参数变量
var (
	target          string
	timeout         int
	packetIfaceName string
	verbose         bool
)

// init 初始化Scapy命令
func init() {
	// 注册子命令
	ScapyCmd.AddCommand(packetCmd)
	ScapyCmd.AddCommand(exampleCmd)
	ScapyCmd.AddCommand(interfaceCmd)

	// 设置主命令的帮助模板
	ScapyCmd.SetHelpTemplate(`{{.UsageString}}

子命令:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

使用 "{{.CommandPath}} [command] --help" 获取子命令帮助信息
`)

}

// packetCmd 包操作子命令
var packetCmd = &cobra.Command{
	Use:   "packet",
	Short: "网络包构造和发送",
	Long: `网络包构造和发送工具

支持构造和发送各种类型的网络包

示例:
  GYscan scapy packet --syn -t 192.168.1.1 -p 80
  GYscan scapy packet --udp -t 8.8.8.8 -p 53 -d "test"`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.BoldInfo("网络包构造和发送...")

		// 检查参数
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址 (-t/--target)")
			return
		}

		// 获取命令行参数
		synFlag, _ := cmd.Flags().GetBool("syn")
		ackFlag, _ := cmd.Flags().GetBool("ack")
		udpFlag, _ := cmd.Flags().GetBool("udp")
		sport, _ := cmd.Flags().GetInt("sport")
		dport, _ := cmd.Flags().GetInt("dport")
		flags, _ := cmd.Flags().GetString("flags")
		payload, _ := cmd.Flags().GetString("payload")
		ttl, _ := cmd.Flags().GetInt("ttl")
		window, _ := cmd.Flags().GetInt("window")

		// 确定发送的包类型
		var packetType string
		switch {
		case synFlag:
			packetType = "TCP SYN"
		case ackFlag:
			packetType = "TCP ACK"
		case udpFlag:
			packetType = "UDP"
		default:
			utils.ErrorPrint("必须指定包类型 (--syn/--ack/--udp)")
			return
		}

		// 显式获取所有参数
		ifaceName, _ := cmd.Flags().GetString("interface")
		target, _ := cmd.Flags().GetString("target")
		timeout, _ := cmd.Flags().GetInt("timeout")

		// 如果接口名称为空，使用默认值
		if ifaceName == "" {
			ifaceName = "WLAN"
			utils.InfoPrint("使用默认接口: %s", ifaceName)
		}

		// 显示包构造参数
		utils.InfoPrint("目标: %s", target)
		utils.InfoPrint("包类型: %s", packetType)
		utils.InfoPrint("目标端口: %d", dport)
		if sport > 0 {
			utils.InfoPrint("源端口: %d", sport)
		} else {
			utils.InfoPrint("源端口: 随机")
		}
		if flags != "" {
			utils.InfoPrint("TCP标志: %s", flags)
		}
		if payload != "" {
			utils.InfoPrint("载荷: %s", payload)
		}
		utils.InfoPrint("TTL: %d", ttl)
		utils.InfoPrint("窗口大小: %d", window)
		utils.InfoPrint("超时: %d秒", timeout)
		utils.InfoPrint("接口: %s", ifaceName)

		// 执行包发送操作
		err := sendCustomPacket(packetType, target, sport, dport, flags, payload, ttl, window, timeout, ifaceName)
		if err != nil {
			utils.ErrorPrint("包发送失败: %v", err)
			return
		}

		utils.SuccessPrint("包发送成功!")
	},
}

// exampleCmd 示例子命令
var exampleCmd = &cobra.Command{
	Use:   "example",
	Short: "功能演示",
	Long: `Scapy功能演示

展示Scapy模块的各种功能和使用方法`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.BoldInfo("Scapy功能演示...")
		ExampleUsage()
	},
}

// interfaceCmd 网络接口检测子命令
var interfaceCmd = &cobra.Command{
	Use:   "interface",
	Short: "网络接口检测",
	Long: `网络接口检测工具

检测和显示系统可用的网络接口信息，包括接口名称、IP地址、MAC地址等

示例:
  GYscan scapy interface
  GYscan scapy interface --verbose`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.BoldInfo("网络接口检测...")

		// 创建接口检测器
		detector := &InterfaceDetector{}

		// 检测网络接口
		_, err := detector.DetectInterfaces()
		if err != nil {
			utils.ErrorPrint("接口检测失败: %v", err)
			return
		}

		// 显示接口信息
		detector.PrintInterfaceList()
	},
}

// initFlags 初始化命令参数
func initFlags() {
	// 包操作命令参数
	packetCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址")
	packetCmd.Flags().IntVarP(&timeout, "timeout", "w", 3, "超时时间(秒)")
	packetCmd.Flags().StringVarP(&packetIfaceName, "interface", "i", "WLAN", "网络接口名称")
	packetCmd.Flags().Bool("syn", false, "发送TCP SYN包")
	packetCmd.Flags().Bool("ack", false, "发送TCP ACK包")
	packetCmd.Flags().Bool("udp", false, "发送UDP包")
	packetCmd.Flags().Int("sport", 0, "源端口 (0表示随机)")
	packetCmd.Flags().Int("dport", 80, "目标端口")
	packetCmd.Flags().String("flags", "", "TCP标志位 (SYN/ACK/FIN/PSH/RST/URG)")
	packetCmd.Flags().String("payload", "", "载荷数据")
	packetCmd.Flags().Int("ttl", 64, "TTL值")
	packetCmd.Flags().Int("window", 8192, "TCP窗口大小")

	// 接口检测命令参数
	interfaceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出模式")
}

// sendPacket 发送指定类型的网络包
func sendPacket(packetType, target string, timeout int) error {
	return sendPacketWithInterface(packetType, target, timeout, packetIfaceName)
}

// sendPacketWithInterface 发送指定类型的网络包（带接口参数）
func sendPacketWithInterface(packetType, target string, timeout int, ifaceName string) error {
	utils.InfoPrint("构造 %s 包到 %s...", packetType, target)

	// 根据包类型构造不同的包
	switch packetType {
	case "TCP SYN":
		return sendTCPSynPacket(target, ifaceName)
	case "TCP ACK":
		return sendTCPAckPacket(target, ifaceName)
	case "UDP":
		return sendUDPPacket(target, ifaceName)
	default:
		return fmt.Errorf("不支持的包类型: %s", packetType)
	}
}

// sendTCPSynPacket 发送TCP SYN包
func sendTCPSynPacket(target, iface string) error {
	utils.InfoPrint("构造TCP SYN包...")
	utils.InfoPrint("使用的接口: %s", iface)

	// 使用builder包构造TCP SYN包
	tcpLayer, err := builder.BuildTCPSynPacket(12345, 80, 1000)
	if err != nil {
		return fmt.Errorf("构造TCP层失败: %v", err)
	}

	// 获取本机IP地址
	localIP, err := getLocalIPString()
	if err != nil {
		return fmt.Errorf("获取本地IP失败: %v", err)
	}

	// 构造IP包，包含TCP负载
	ipLayer, err := builder.BuildIPPacket(localIP, target, 6, tcpLayer)
	if err != nil {
		return fmt.Errorf("构造IP层失败: %v", err)
	}

	utils.InfoPrint("TCP SYN包构造完成，目标端口: 80, 源端口: 12345")
	utils.InfoPrint("源IP: %s, 目标IP: %s", localIP, target)

	// 创建发送器并发送包
	utils.InfoPrint("正在创建发送器，接口: %s", iface)
	sender, err := sendrecv.NewSender(iface)
	if err != nil {
		return fmt.Errorf("创建发送器失败: %v", err)
	}
	defer sender.Close()

	// 发送TCP SYN包
	err = sender.SendPacket(ipLayer)
	if err != nil {
		return fmt.Errorf("发送TCP SYN包失败: %v", err)
	}

	utils.SuccessPrint("TCP SYN包发送成功!")
	return nil
}

// sendTCPAckPacket 发送TCP ACK包
func sendTCPAckPacket(target, iface string) error {
	utils.InfoPrint("构造TCP ACK包...")

	// 使用builder包构造TCP ACK包
	tcpLayer, err := builder.BuildTCPAckPacket(12345, 80, 1000, 2000)
	if err != nil {
		return fmt.Errorf("构造TCP层失败: %v", err)
	}

	// 获取本机IP地址
	localIP, err := getLocalIPString()
	if err != nil {
		return fmt.Errorf("获取本地IP失败: %v", err)
	}

	// 构造IP包，包含TCP负载
	ipLayer, err := builder.BuildIPPacket(localIP, target, 6, tcpLayer)
	if err != nil {
		return fmt.Errorf("构造IP层失败: %v", err)
	}

	utils.InfoPrint("TCP ACK包构造完成，目标端口: 80, 源端口: 12345")
	utils.InfoPrint("源IP: %s, 目标IP: %s", localIP, target)

	// 创建发送器并发送包
	sender, err := sendrecv.NewSender(iface)
	if err != nil {
		return fmt.Errorf("创建发送器失败: %v", err)
	}
	defer sender.Close()

	// 发送TCP ACK包
	err = sender.SendPacket(ipLayer)
	if err != nil {
		return fmt.Errorf("发送TCP ACK包失败: %v", err)
	}

	utils.SuccessPrint("TCP ACK包发送成功!")
	return nil
}

// sendUDPPacket 发送UDP包
func sendUDPPacket(target, iface string) error {
	utils.InfoPrint("构造UDP包...")

	// 构造UDP数据
	data := []byte("GYscan UDP Test Packet")

	// 使用builder包构造UDP包
	udpLayer := builder.BuildUDPPacket(12345, 53, data)

	// 构建UDP包
	udpData, err := udpLayer.Build()
	if err != nil {
		return fmt.Errorf("构建UDP层失败: %v", err)
	}

	// 获取本机IP地址
	localIP, err := getLocalIPString()
	if err != nil {
		return fmt.Errorf("获取本地IP失败: %v", err)
	}

	// 构造IP包，包含UDP负载
	ipLayer, err := builder.BuildIPPacket(localIP, target, 17, udpData)
	if err != nil {
		return fmt.Errorf("构造IP层失败: %v", err)
	}

	utils.InfoPrint("UDP包构造完成，目标端口: 53 (DNS), 数据: %s", string(data))
	utils.InfoPrint("源IP: %s, 目标IP: %s", localIP, target)

	// 创建发送器并发送包
	sender, err := sendrecv.NewSender(iface)
	if err != nil {
		return fmt.Errorf("创建发送器失败: %v", err)
	}
	defer sender.Close()

	// 发送IP包（包含UDP负载）
	err = sender.SendPacket(ipLayer)
	if err != nil {
		return fmt.Errorf("发送UDP包失败: %v", err)
	}

	utils.SuccessPrint("UDP包发送成功!")
	return nil
}

// getLocalIPString 获取本机IP地址字符串
func getLocalIPString() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("无法获取本机IP地址")
}

// sendCustomPacket 发送自定义网络包
func sendCustomPacket(packetType, target string, sport, dport int, flags, payload string, ttl, window, timeout int, ifaceName string) error {
	utils.InfoPrint("构造自定义 %s 包到 %s...", packetType, target)

	// 如果源端口为0，生成随机端口
	if sport == 0 {
		sport = 1024 + rand.Intn(64511) // 1024-65535
	}

	// 根据包类型构造不同的包
	switch packetType {
	case "TCP SYN":
		return sendCustomTCPSynPacket(target, sport, dport, flags, payload, ttl, window, ifaceName)
	case "TCP ACK":
		return sendCustomTCPAckPacket(target, sport, dport, flags, payload, ttl, window, ifaceName)
	case "UDP":
		return sendCustomUDPPacket(target, sport, dport, payload, ttl, ifaceName)
	default:
		return fmt.Errorf("不支持的包类型: %s", packetType)
	}
}

// sendCustomTCPSynPacket 发送自定义TCP SYN包
func sendCustomTCPSynPacket(target string, sport, dport int, flags, payload string, ttl, window int, iface string) error {
	utils.InfoPrint("构造自定义TCP SYN包...")

	// 解析TCP标志位
	tcpFlags := parseTCPFlags(flags)
	if tcpFlags == 0 {
		tcpFlags = 0x02 // SYN标志
	}

	// 使用builder包构造自定义TCP SYN包
	tcpLayer, err := builder.BuildCustomTCPPacket(sport, dport, tcpFlags, window, []byte(payload))
	if err != nil {
		return fmt.Errorf("构造TCP层失败: %v", err)
	}

	// 获取本机IP地址
	localIP, err := getLocalIPString()
	if err != nil {
		return fmt.Errorf("获取本地IP失败: %v", err)
	}

	// 构造自定义IP包
	ipLayer, err := builder.BuildCustomIPPacket(localIP, target, 6, tcpLayer, ttl)
	if err != nil {
		return fmt.Errorf("构造IP层失败: %v", err)
	}

	utils.InfoPrint("自定义TCP SYN包构造完成")
	utils.InfoPrint("源端口: %d, 目标端口: %d", sport, dport)
	utils.InfoPrint("TCP标志: 0x%02x, 窗口大小: %d", tcpFlags, window)
	utils.InfoPrint("TTL: %d, 载荷长度: %d", ttl, len(payload))
	utils.InfoPrint("源IP: %s, 目标IP: %s", localIP, target)

	// 创建发送器并发送包
	sender, err := sendrecv.NewSender(iface)
	if err != nil {
		return fmt.Errorf("创建发送器失败: %v", err)
	}
	defer sender.Close()

	// 发送TCP SYN包
	err = sender.SendPacket(ipLayer)
	if err != nil {
		return fmt.Errorf("发送TCP SYN包失败: %v", err)
	}

	utils.SuccessPrint("自定义TCP SYN包发送成功!")
	return nil
}

// sendCustomTCPAckPacket 发送自定义TCP ACK包
func sendCustomTCPAckPacket(target string, sport, dport int, flags, payload string, ttl, window int, iface string) error {
	utils.InfoPrint("构造自定义TCP ACK包...")

	// 解析TCP标志位
	tcpFlags := parseTCPFlags(flags)
	if tcpFlags == 0 {
		tcpFlags = 0x10 // ACK标志
	}

	// 使用builder包构造自定义TCP ACK包
	seqNum := uint32(rand.Intn(1000000))
	ackNum := uint32(rand.Intn(1000000))
	tcpLayer, err := builder.BuildCustomTCPPacketWithSeq(sport, dport, tcpFlags, seqNum, ackNum, window, []byte(payload))
	if err != nil {
		return fmt.Errorf("构造TCP层失败: %v", err)
	}

	// 获取本机IP地址
	localIP, err := getLocalIPString()
	if err != nil {
		return fmt.Errorf("获取本地IP失败: %v", err)
	}

	// 构造自定义IP包
	ipLayer, err := builder.BuildCustomIPPacket(localIP, target, 6, tcpLayer, ttl)
	if err != nil {
		return fmt.Errorf("构造IP层失败: %v", err)
	}

	utils.InfoPrint("自定义TCP ACK包构造完成")
	utils.InfoPrint("源端口: %d, 目标端口: %d", sport, dport)
	utils.InfoPrint("TCP标志: 0x%02x, 窗口大小: %d", tcpFlags, window)
	utils.InfoPrint("序列号: %d, 确认号: %d", seqNum, ackNum)
	utils.InfoPrint("TTL: %d, 载荷长度: %d", ttl, len(payload))
	utils.InfoPrint("源IP: %s, 目标IP: %s", localIP, target)

	// 创建发送器并发送包
	sender, err := sendrecv.NewSender(iface)
	if err != nil {
		return fmt.Errorf("创建发送器失败: %v", err)
	}
	defer sender.Close()

	// 发送TCP ACK包
	err = sender.SendPacket(ipLayer)
	if err != nil {
		return fmt.Errorf("发送TCP ACK包失败: %v", err)
	}

	utils.SuccessPrint("自定义TCP ACK包发送成功!")
	return nil
}

// sendCustomUDPPacket 发送自定义UDP包
func sendCustomUDPPacket(target string, sport, dport int, payload string, ttl int, iface string) error {
	utils.InfoPrint("构造自定义UDP包...")

	// 构造UDP数据
	data := []byte(payload)
	if len(data) == 0 {
		data = []byte("GYscan Custom UDP Packet")
	}

	// 使用builder包构造UDP包
	udpLayer := builder.BuildUDPPacket(uint16(sport), uint16(dport), data)

	// 构建UDP包
	udpData, err := udpLayer.Build()
	if err != nil {
		return fmt.Errorf("构建UDP层失败: %v", err)
	}

	// 获取本机IP地址
	localIP, err := getLocalIPString()
	if err != nil {
		return fmt.Errorf("获取本地IP失败: %v", err)
	}

	// 构造自定义IP包
	ipLayer, err := builder.BuildCustomIPPacket(localIP, target, 17, udpData, ttl)
	if err != nil {
		return fmt.Errorf("构造IP层失败: %v", err)
	}

	utils.InfoPrint("自定义UDP包构造完成")
	utils.InfoPrint("源端口: %d, 目标端口: %d", sport, dport)
	utils.InfoPrint("TTL: %d, 载荷长度: %d", ttl, len(data))
	utils.InfoPrint("源IP: %s, 目标IP: %s", localIP, target)

	// 创建发送器并发送包
	sender, err := sendrecv.NewSender(iface)
	if err != nil {
		return fmt.Errorf("创建发送器失败: %v", err)
	}
	defer sender.Close()

	// 发送IP包（包含UDP负载）
	err = sender.SendPacket(ipLayer)
	if err != nil {
		return fmt.Errorf("发送UDP包失败: %v", err)
	}

	utils.SuccessPrint("自定义UDP包发送成功!")
	return nil
}

// parseTCPFlags 解析TCP标志位字符串
func parseTCPFlags(flags string) uint8 {
	var result uint8
	flagMap := map[string]uint8{
		"FIN": 0x01,
		"SYN": 0x02,
		"RST": 0x04,
		"PSH": 0x08,
		"ACK": 0x10,
		"URG": 0x20,
	}

	flagParts := strings.Split(strings.ToUpper(flags), "/")
	for _, part := range flagParts {
		if value, exists := flagMap[strings.TrimSpace(part)]; exists {
			result |= value
		}
	}

	return result
}

// init 初始化命令参数
func init() {
	initFlags()
}
