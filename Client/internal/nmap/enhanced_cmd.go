package nmap

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// EnhancedScanCmd 增强版扫描命令
var EnhancedScanCmd = &cobra.Command{
	Use:   "escan [目标] [help]",
	Short: "增强版网络扫描（参考 Nmap 源码优化）",
	Long: `GYscan 增强扫描模块 - 基于 Nmap 源码的深度优化

支持功能:
- 拥塞控制算法（参考 nmap timing.cc）
- 自适应超时机制
- 增强的服务识别（参考 nmap service_scan.cc）
- 优化的操作系统检测（参考 nmap FPEngine.cc）
- 批量扫描优化

扫描类型:
  - TCP SYN 扫描
  - TCP Connect 扫描
  - UDP 扫描
  - 隐蔽扫描（FIN/XMAS/NULL）

性能优化:
  - Nmap 风格时序模板（T0-T5）
  - 智能并发控制
  - 结果缓存机制
  - 自适应超时调整

用法:
  ./GYscan escan 192.168.1.1
  ./GYscan escan 192.168.1.0/24 -p 1-1000
  ./GYscan escan --target 10.0.0.0/8 --timing 4`,
}

// QuickScanCmd 快速扫描命令
var QuickScanCmd = &cobra.Command{
	Use:   "qscan [目标] [help]",
	Short: "快速扫描（优化版）",
	Long: `GYscan 快速扫描模块

特点:
- 高并发扫描（100 线程）
- 自适应超时
- 实时进度显示

用法:
  ./GYscan qscan 192.168.1.1
  ./GYscan qscan 192.168.1.0/24`,
}

// ComprehensiveScanCmd 综合扫描命令
var ComprehensiveScanCmd = &cobra.Command{
	Use:   "cscan [目标] [help]",
	Short: "综合扫描（完整功能）",
	Long: `GYscan 综合扫描模块

包含:
- 服务版本检测
- 操作系统识别
- 路由追踪
- MAC 地址获取

用法:
  ./GYscan cscan 192.168.1.1
  ./GYscan cscan 192.168.1.0/24`,
}

func init() {
	// 初始化增强扫描命令
	var (
		target           string
		ports            string
		threads          int
		timeout          int
		timingTemplate   int
		osDetection      bool
		serviceDetection bool
		aggressiveScan   bool
		pn               bool
		output           string
	)

	EnhancedScanCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		if len(args) > 0 {
			target = args[0]
		}

		if target == "" {
			fmt.Println("请指定扫描目标")
			return
		}

		if !ValidateTarget(target) {
			fmt.Printf("目标格式无效: %s\n", target)
			return
		}

		config := ScanConfig{
			Target:           target,
			Ports:            ports,
			Threads:          threads,
			Timeout:          time.Duration(timeout) * time.Second,
			ScanType:         "connect",
			OSDetection:      osDetection,
			ServiceDetection: serviceDetection,
			TimingTemplate:   timingTemplate,
			AggressiveScan:   aggressiveScan,
			Pn:               pn,
		}

		if pn {
			fmt.Printf("[GYscan-Enhanced] Pn模式: 跳过主机发现\n")
		}

		fmt.Printf("[GYscan-Enhanced] 开始扫描: %s\n", target)
		startTime := time.Now()

		results := EnhancedNmapScan(cmd.Context(), config)

		duration := time.Since(startTime)
		fmt.Printf("[GYscan-Enhanced] 扫描完成，耗时: %v\n", duration)

		PrintOptimizedResult(results)

		if output != "" {
			if err := ExportOptimizedResults(results, output); err != nil {
				fmt.Printf("保存结果失败: %v\n", err)
			}
		}
	}

	EnhancedScanCmd.Flags().StringVarP(&target, "target", "t", "", "扫描目标")
	EnhancedScanCmd.Flags().StringVarP(&ports, "ports", "p", "", "扫描端口")
	EnhancedScanCmd.Flags().IntVarP(&threads, "threads", "n", 100, "并发线程数")
	EnhancedScanCmd.Flags().IntVarP(&timeout, "timeout", "w", 3, "超时时间(秒)")
	EnhancedScanCmd.Flags().IntVarP(&timingTemplate, "timing", "T", 4, "扫描速度级别 (0-5)")
	EnhancedScanCmd.Flags().BoolVarP(&osDetection, "O", "O", false, "启用系统识别")
	EnhancedScanCmd.Flags().BoolVarP(&serviceDetection, "sV", "", false, "启用服务识别")
	EnhancedScanCmd.Flags().BoolVarP(&aggressiveScan, "A", "A", false, "全面扫描模式")
	EnhancedScanCmd.Flags().BoolVarP(&pn, "Pn", "", false, "跳过主机发现，直接扫描端口 (等同于nmap -Pn参数)")
	EnhancedScanCmd.Flags().StringVarP(&output, "output", "o", "", "输出文件")

	// 初始化快速扫描命令
	QuickScanCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		target := args[0]
		if target == "" {
			fmt.Println("请指定扫描目标")
			return
		}

		fmt.Printf("[GYscan-Quick] 开始快速扫描: %s\n", target)
		startTime := time.Now()

		results := QuickOptimizedScan(cmd.Context(), target, "1-1000")

		duration := time.Since(startTime)
		fmt.Printf("[GYscan-Quick] 扫描完成，耗时: %v\n", duration)

		PrintOptimizedResult(results)
	}

	// 初始化综合扫描命令
	ComprehensiveScanCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		target := args[0]
		if target == "" {
			fmt.Println("请指定扫描目标")
			return
		}

		fmt.Printf("[GYscan-Comprehensive] 开始综合扫描: %s\n", target)
		startTime := time.Now()

		results := ComprehensiveScan(cmd.Context(), target)

		duration := time.Since(startTime)
		fmt.Printf("[GYscan-Comprehensive] 扫描完成，耗时: %v\n", duration)

		PrintOptimizedResult(results)
	}
}

// ExportOptimizedResults 导出优化后的扫描结果
func ExportOptimizedResults(results []OptimizedScanResult, filePath string) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化结果失败: %v", err)
	}

	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	fmt.Printf("[GYscan] 结果已保存到: %s\n", filePath)
	return nil
}
