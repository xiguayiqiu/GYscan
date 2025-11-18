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
  -V: 启用服务识别 (等同于 --service-detection)

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
		target      string
		ports       string
		threads     int
		timeout     int
		timingTemplate int
		scanType    string
		osDetection bool
		serviceDetection bool
		ttlDetection bool
		output      string
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

		// 创建扫描配置
		config := ScanConfig{
			Target:          target,
			Ports:           ports,
			Threads:         threads,
			Timeout:         time.Duration(timeout) * time.Second,
			ScanType:        scanType,
			OSDetection:     osDetection,
			ServiceDetection: serviceDetection,
			TimingTemplate:  timingTemplate,
			TTLDetection:    ttlDetection,
		}

		// 执行扫描
		fmt.Printf("[GYscan-Nmap] 开始扫描目标: %s\n", target)
		startTime := time.Now()
		
		results := NmapScan(cmd.Context(), config)
		
		duration := time.Since(startTime)
		fmt.Printf("[GYscan-Nmap] 扫描完成，耗时: %v\n", duration)

		// 打印结果
		PrintNmapResult(results)

		// 保存结果
		if output != "" {
			if err := SaveNmapResult(results, output); err != nil {
				fmt.Printf("保存结果失败: %v\n", err)
			}
		}
	}

	// 定义命令行标志
	ScanCmd.Flags().StringVarP(&target, "target", "t", "", "扫描目标 (IP/CIDR/IP范围/域名)")
	ScanCmd.Flags().StringVarP(&ports, "ports", "p", "", "扫描端口 (默认: 常用端口, 支持: 80,443, 1-1000, 22,80,443)")
	ScanCmd.Flags().IntVarP(&threads, "threads", "n", 50, "并发线程数")
	ScanCmd.Flags().IntVarP(&timeout, "timeout", "", 3, "超时时间(秒)")
	ScanCmd.Flags().IntVarP(&timingTemplate, "timing", "T", 3, "扫描速度级别 (0-5, 完全模仿nmap -T参数)")
	ScanCmd.Flags().StringVarP(&scanType, "scan-type", "S", "connect", "扫描类型 (connect/syn/udp)")
	
	// 服务识别和系统识别标志（标准nmap风格简化命令）
	ScanCmd.Flags().BoolVarP(&osDetection, "os-detection", "O", false, "启用系统识别 (等同于 -O)")
	ScanCmd.Flags().BoolVarP(&serviceDetection, "service-detection", "V", true, "启用服务识别 (等同于 -sV)")
	ScanCmd.Flags().BoolVarP(&ttlDetection, "ttl-detection", "D", false, "启用TTL检测，估算目标距离")
	
	ScanCmd.Flags().StringVarP(&output, "output", "o", "", "结果输出文件")
	
	// 添加-T参数的详细说明到帮助文档
	ScanCmd.SetHelpTemplate(`{{.UsageString}}

-T参数说明:
  0: 偏执 (Paranoid) - 非常慢的扫描，用于IDS规避
  1: 鬼祟 (Sneaky) - 慢速扫描，IDS规避
  2: 礼貌 (Polite) - 降低速度以减少对目标系统的影响
  3: 普通 (Normal) - 默认速度，平衡速度和隐蔽性
  4: 激进 (Aggressive) - 快速扫描，可能被检测到
  5: 疯狂 (Insane) - 极速扫描，容易被检测

TTL检测说明 (-D):
  启用TTL检测可以估算目标距离（网络跳数），帮助判断目标位置
  本地网络: 1跳，私有网络: 2跳，公网: 3-15跳
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
  -p, --ports: 指定扫描端口
  -n, --threads: 并发线程数
  -T, --timing: 扫描速度级别 (0-5, 完全模仿nmap -T参数)
  -S, --scan-type: 扫描类型 (connect/syn/udp)
  -O, --os-detection: 启用系统识别 (nmap风格简化命令)
  -V, --service-detection: 启用服务识别 (nmap风格简化命令)
  -D, --ttl-detection: 启用TTL检测，估算目标距离
  -o, --output: 结果输出文件

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