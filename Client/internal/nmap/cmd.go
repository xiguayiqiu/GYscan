package nmap

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// ScanCmd 表示nmap扫描命令
var ScanCmd = &cobra.Command{
	Use:   "scan [目标] [help]",
	Short: "网络扫描工具，支持主机发现、端口扫描、服务识别等功能",
	Args:  cobra.MaximumNArgs(1),
	Long: `GYscan Nmap模块 - 网络扫描工具

支持功能:
- 存活主机发现 (ICMP Ping + TCP探测)
- 端口扫描 (TCP SYN/Connect/UDP)
- 服务识别 (协议握手包匹配)
- 系统识别 (OS指纹识别)
- 网段扫描 (CIDR/IP范围)

简化命令 (nmap风格):
  -O: 启用系统识别 (等同于 --os-detection)
  -s: 启用服务识别 (等同于 --service-detection)

默认行为:
  默认仅显示端口状态信息 (nmap的六种状态)
  使用-s参数显示服务信息
  使用-O参数探测系统信息

用法:
  1. 直接传递目标: GYscan scan 目标 [选项]
  2. 使用--target标志: GYscan scan --target 目标 [选项]
  3. 获取帮助: GYscan scan help

示例用法:
  ./GYscan scan 192.168.1.1/24
  ./GYscan scan 192.168.1.1-192.168.1.100 -p 22,80,443
  ./GYscan scan example.com -p 1-1000 -n 100
  ./GYscan scan 10.0.0.0/8 -O -V
  ./GYscan scan 192.168.1.1 -O -V -p 1-1000
  ./GYscan scan --target 192.168.1.1/24
  ./GYscan scan --target example.com --ports 1-1000 --threads 100`,
}

// init 初始化nmap命令
func init() {
	var (
		target           string
		ports            string
		threads          int
		timeout          int
		timingTemplate   int
		synScan          bool
		osDetection      bool
		serviceDetection bool
		ttlDetection     bool
		aggressiveScan   bool
		fragmentedScan   bool
		tcpScan          bool
		udpScan          bool
		hostDiscovery    bool
		pn               bool
		ipv6             bool
		output           string
	)
	// 配置命令运行函数
	ScanCmd.Run = func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 优先使用命令行参数中的目标，如果没有则使用--target标志
		if len(args) > 0 {
			target = args[0]
		}

		if target == "" {
			fmt.Println("请指定扫描目标 (直接传递目标参数或使用 --target 标志)")
			fmt.Println("用法: GYscan scan 目标 [选项] 或 GYscan scan --target 目标 [选项]")
			return
		}

		// 验证目标格式
		if !ValidateTarget(target) {
			fmt.Printf("目标格式无效: %s\n", target)
			fmt.Println("支持格式: IP地址(192.168.1.1), CIDR(192.168.1.0/24), IP范围(192.168.1.1-100), 域名(example.com)")
			return
		}

		// 根据nmap参数设置扫描类型
		actualScanType := "connect" // 默认扫描类型
		if tcpScan {
			actualScanType = "connect"
		} else if udpScan {
			actualScanType = "udp"
		} else if synScan {
			actualScanType = "syn"
		}

		// 创建扫描配置
		config := ScanConfig{
			Target:           target,
			Ports:            ports,
			Threads:          threads,
			Timeout:          time.Duration(timeout) * time.Second,
			ScanType:         actualScanType,
			OSDetection:      osDetection,
			ServiceDetection: serviceDetection,
			TimingTemplate:   timingTemplate,
			TTLDetection:     ttlDetection,
			AggressiveScan:   aggressiveScan,
			FragmentedScan:   fragmentedScan,
			TCPScan:          tcpScan,
			UDPScan:          udpScan,
			HostDiscovery:    hostDiscovery,
			Pn:               pn,
			IPv6:             ipv6,
		}

		// 如果启用了全面扫描模式 (-A)，自动启用相关功能
		if aggressiveScan {
			config.OSDetection = true
			config.ServiceDetection = true
			config.TTLDetection = true
			// 设置更快的扫描速度以匹配nmap -A的行为
			if config.TimingTemplate < 4 {
				config.TimingTemplate = 4 // Aggressive模式
			}
			fmt.Printf("[GYscan-Nmap] 全面扫描模式已启用 (-A参数)\n")
		}

		// 执行扫描
		fmt.Printf("[GYscan-Nmap] 开始扫描目标: %s\n", target)
		startTime := time.Now()

		results := NmapScan(cmd.Context(), config)

		duration := time.Since(startTime)
		fmt.Printf("[GYscan-Nmap] 扫描完成，耗时: %v\n", duration)

		// 打印结果
		PrintNmapResult(results, config)

		// 保存结果
		if output != "" {
			if err := SaveNmapResult(results, output); err != nil {
				fmt.Printf("保存结果失败: %v\n", err)
			}
		}
	}

	// 定义命令行标志（完全照搬nmap参数命名）
	ScanCmd.Flags().StringVarP(&target, "target", "t", "", "扫描目标 (IP/CIDR/IP范围/域名)")
	ScanCmd.Flags().StringVarP(&ports, "ports", "p", "", "扫描端口 (默认: 1-1000, 支持: 80,443, 1-1000, 22,80,443, -p- 表示全端口扫描)")
	ScanCmd.Flags().IntVarP(&threads, "threads", "n", 50, "并发线程数")
	ScanCmd.Flags().IntVarP(&timeout, "timeout", "w", 3, "超时时间(秒)")
	ScanCmd.Flags().IntVarP(&timingTemplate, "timing", "T", 3, "扫描速度级别 (0-5, 完全模仿nmap -T参数)")

	// 扫描类型参数（nmap标准参数）
	ScanCmd.Flags().BoolVarP(&tcpScan, "sT", "", false, "TCP连接扫描")
	ScanCmd.Flags().BoolVarP(&udpScan, "sU", "", false, "UDP扫描")
	ScanCmd.Flags().BoolVarP(&synScan, "sS", "", false, "SYN扫描")

	// 服务识别和系统识别标志（nmap标准参数）
	ScanCmd.Flags().BoolVarP(&osDetection, "O", "O", false, "启用系统识别")
	ScanCmd.Flags().BoolVarP(&serviceDetection, "sV", "", false, "启用服务识别")

	// 全面扫描模式 (nmap -A参数)
	ScanCmd.Flags().BoolVarP(&aggressiveScan, "A", "A", false, "全面扫描模式")

	// 碎片化扫描模式 (nmap -f参数)
	ScanCmd.Flags().BoolVarP(&fragmentedScan, "f", "f", false, "碎片化扫描模式")

	// 主机存活探测模式 (nmap -sn参数)
	ScanCmd.Flags().BoolVarP(&hostDiscovery, "sn", "", false, "主机存活探测模式")

	// 其他功能参数
	ScanCmd.Flags().BoolVarP(&ttlDetection, "ttl", "", false, "启用TTL检测，估算目标距离")

	// 跳过主机发现，直接扫描端口 (nmap -Pn参数)
	ScanCmd.Flags().BoolVarP(&pn, "Pn", "", false, "跳过主机发现，直接扫描端口 (等同于nmap -Pn参数)")

	// IPv6扫描模式 (nmap -6参数)
	ScanCmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "启用IPv6扫描模式 (等同于nmap -6参数)")

	ScanCmd.Flags().StringVarP(&output, "output", "o", "", "结果输出文件")

	// 启用短参数支持（nmap风格）
	ScanCmd.Flags().SetInterspersed(true)

	// 添加-T参数的详细说明到帮助文档
	ScanCmd.SetHelpTemplate(`{{.UsageString}}

-T参数说明:
  0: 偏执 (Paranoid) - 非常慢的扫描，用于IDS规避
  1: 鬼祟 (Sneaky) - 慢速扫描，IDS规避
  2: 礼貌 (Polite) - 降低速度以减少对目标系统的影响
  3: 普通 (Normal) - 默认速度，平衡速度和隐蔽性
  4: 激进 (Aggressive) - 快速扫描，可能被检测到
  5: 疯狂 (Insane) - 极速扫描，容易被检测

扫描类型参数说明:
  --sT: TCP连接扫描 (nmap -sT)
  --sU: UDP扫描
  --sS: SYN扫描

服务识别和系统识别:
  --O: 启用系统识别
  --sV: 启用服务识别

全面扫描模式 (--A):
  启用全面扫描模式，等同于同时使用以下功能:
  - 启用系统识别 (--O)
  - 启用服务识别 (--sV)
  - 设置扫描速度为激进模式 (-T4)
  这是nmap -A参数的完全实现

碎片化扫描模式 (--f):
  碎片化扫描模式 (等同于nmap -f参数，数据包分片发送以规避检测)

主机存活探测模式 (--sn):
  仅进行主机存活探测，跳过端口扫描
  采用多协议组合探测（ICMP Ping + TCP SYN/ACK + UDP），提高准确性
  适用于快速发现网络中的在线主机，效率远高于全端口扫描
`)

	// 添加help子命令
	ScanCmd.AddCommand(&cobra.Command{
		Use:   "help",
		Short: "显示nmap模块详细帮助信息",
		Run: func(cmd *cobra.Command, args []string) {
			NmapHelp()
		},
	})
}

// NmapHelp 显示nmap帮助信息
func NmapHelp() {
	helpText := `
GYscan Nmap模块使用说明

基本用法:
  1. 直接传递目标: GYscan scan 目标 [选项]
  2. 使用--target标志: GYscan scan --target 目标 [选项]

目标格式:
  - IP地址: 192.168.1.1
  - CIDR网段: 192.168.1.0/24
  - IP范围: 192.168.1.1-100
  - 域名: example.com

扫描类型:
  - connect: TCP连接扫描 (默认)
  - syn: TCP SYN半连接扫描
  - udp: UDP端口扫描

常用选项:
  -t, --target: 扫描目标 (IP/CIDR/IP范围/域名)
  -p, --ports: 指定扫描端口 (默认: 1-1000, 支持: 80,443, 1-1000, 22,80,443, -p- 表示全端口扫描)
  -n, --threads: 并发线程数
  -T, --timing: 扫描速度级别 (0-5, 完全模仿nmap -T参数)
  -o, --output: 结果输出文件

扫描类型参数:
  --sT: TCP连接扫描 (等同于nmap -sT参数)
  --sU: UDP扫描 (等同于nmap -sU参数)
  --sS: SYN扫描 (等同于nmap -sS参数)

功能参数:
  --O: 启用系统识别 (等同于nmap -O参数)
  --sV: 启用服务识别 (等同于nmap -sV参数)
  --A: 全面扫描模式 (等同于nmap -A参数)
  --f: 碎片化扫描模式 (等同于nmap -f参数，数据包分片发送以规避检测)
  --ttl: 启用TTL检测，估算目标距离
  --sn: 主机存活探测模式 (等同于nmap -sn参数，仅判断主机在线状态，跳过端口扫描)

-T参数详细说明 (扫描速度级别):
  0: 偏执 (Paranoid) - 非常慢的扫描，每5分钟发送一个包，用于IDS规避
  1: 鬼祟 (Sneaky) - 慢速扫描，每15秒发送一个包，IDS规避
  2: 礼貌 (Polite) - 降低速度，每0.4秒发送一个包，减少对目标系统的影响
  3: 普通 (Normal) - 默认速度，平衡速度和隐蔽性
  4: 激进 (Aggressive) - 快速扫描，减少超时时间，可能被检测到
  5: 疯狂 (Insane) - 极速扫描，最大并发，最小超时，容易被检测

TTL检测说明:
  启用TTL检测可以估算目标距离（网络跳数），帮助判断目标位置
  本地网络: 1跳，私有网络: 2跳，公网: 3-15跳

示例:
  ./GYscan scan 192.168.1.1/24
  ./GYscan scan 192.168.1.1-192.168.1.100 -p 22,80,443
  ./GYscan scan example.com -p 1-1000 -t 100
  ./GYscan scan 10.0.0.0/8 -O -V
  ./GYscan scan 192.168.1.1 -O -V -p 1-1000
  ./GYscan scan 192.168.1.1 -D
  ./GYscan scan 192.168.1.1 -D -O -V
`
	fmt.Println(helpText)
}
