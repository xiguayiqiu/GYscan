package nmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/fatih/color"
)

// SaveNmapResult 保存nmap扫描结果
func SaveNmapResult(results []NmapResult, filePath string) error {
	if filePath == "" {
		filePath = fmt.Sprintf("GYscan_scan_%s.json", time.Now().Format("20060102_150405"))
	}

	// 创建JSON格式的结果
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化结果失败: %v", err)
	}

	// 写入文件
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	fmt.Printf("[GYscan-Nmap] 扫描结果已保存到: %s\n", filePath)
	return nil
}

// PrintNmapResult 打印nmap扫描结果
func PrintNmapResult(results []NmapResult, config ScanConfig) {
	utils.TitlePrint("\n=== 扫描结果 ===")

	activeHosts := 0
	for _, result := range results {
		if result.Status == "up" {
			activeHosts++
		}
	}

	utils.InfoPrint("扫描统计: 总计 %d 台主机，活跃 %d 台\n", len(results), activeHosts)

	for _, result := range results {
		if result.Status == "up" {
			// 使用不同颜色标记主机信息
			utils.SuccessPrint("主机: %s", result.IP)
			if result.Hostname != "" {
				utils.ProgressPrint("(%s)", result.Hostname)
			}

			// 显示网络距离信息
			if result.NetworkDistance > 0 {
				utils.InfoPrint("(距离约%d跳)", result.NetworkDistance)
			}

			// 显示MAC地址和厂商信息
			if result.MACAddress != "" {
				utils.WarningPrint("[MAC: %s", result.MACAddress)
				if result.MACVendor != "" {
					fmt.Printf(" - %s]", result.MACVendor)
				} else {
					fmt.Printf("]")
				}
			}

			// 显示操作系统信息
			if result.OS != "" {
				utils.WarningPrint("[%s]", result.OS)
			}

			// 显示操作系统猜测信息
			if len(result.OSGuesses) > 0 {
				utils.ProgressPrint("操作系统猜测: %s", strings.Join(result.OSGuesses, ", "))
			}

			fmt.Println()

			// 显示路由追踪信息
			if len(result.Traceroute) > 0 {
				utils.InfoPrint("路由追踪:")
				for i, hop := range result.Traceroute {
					fmt.Printf("  %d. ", i+1)
					color.New(color.FgBlue).Printf("%s", hop.IP)
					if hop.Hostname != "" {
						fmt.Printf(" (%s)", hop.Hostname)
					}
					fmt.Printf(" %dms", hop.RTT.Milliseconds())
					fmt.Println()
				}
				fmt.Println()
			}

			if len(result.Ports) > 0 {
				utils.InfoPrint("开放端口:")
				for _, portInfo := range result.Ports {
					// 使用不同颜色标记端口信息
					fmt.Printf("  ")

					// 端口号 - 蓝色
					color.New(color.FgBlue).Printf("%d", portInfo.Port)
					fmt.Printf("/")

					// 协议 - 青色
					color.New(color.FgCyan).Printf("%s", portInfo.Protocol)
					fmt.Printf(" ")

					// 状态 - 绿色（开放）或黄色（其他状态）
					if portInfo.State == "open" {
						color.New(color.FgGreen).Printf("%-8s", portInfo.State)
					} else {
						color.New(color.FgYellow).Printf("%-8s", portInfo.State)
					}

					// 如果启用了服务识别，显示服务信息
					if config.ServiceDetection {
						if portInfo.Service != "" {
							fmt.Printf(" ")
							// 服务名称 - 紫色
							color.New(color.FgMagenta).Printf("%s", portInfo.Service)
						}
						if portInfo.Version != "" {
							fmt.Printf(" ")
							// 版本信息 - 白色
							color.New(color.FgWhite).Printf("%s", portInfo.Version)
						}
						if portInfo.Banner != "" {
							fmt.Printf(" ")
							// Banner信息 - 灰色，限制显示长度避免换行
							banner := portInfo.Banner
							// 过滤掉非ASCII字符，避免乱码
							banner = strings.Map(func(r rune) rune {
								if r >= 32 && r <= 126 {
									return r
								}
								return -1
							}, banner)
							// 限制banner显示长度
							if len(banner) > 80 {
								banner = banner[:80] + "..."
							}
							color.New(color.FgHiBlack).Printf("(%s)", banner)
						}
					}
					fmt.Println()
				}
			}
			
			// 显示HTTP/HTTPS访问链接
			var httpPorts []int
			var httpsPorts []int
			for port, portInfo := range result.Ports {
				if portInfo.State == "open" {
					switch port {
					case 80:
						httpPorts = append(httpPorts, port)
					case 443:
						httpsPorts = append(httpsPorts, port)
					default:
						// 检查是否是HTTP服务
						if strings.Contains(strings.ToLower(portInfo.Service), "http") {
							httpPorts = append(httpPorts, port)
						}
						// 检查是否是HTTPS服务
						if strings.Contains(strings.ToLower(portInfo.Service), "https") {
							httpsPorts = append(httpsPorts, port)
						}
					}
				}
			}
			
			if len(httpPorts) > 0 || len(httpsPorts) > 0 {
				utils.InfoPrint("HTTP/HTTPS访问链接:")
				// 显示HTTPS链接
				for _, port := range httpsPorts {
					fmt.Printf("  ")
					color.New(color.FgGreen).Printf("https://%s:%d\n", result.IP, port)
				}
				// 显示HTTP链接
				for _, port := range httpPorts {
					fmt.Printf("  ")
					color.New(color.FgBlue).Printf("http://%s:%d\n", result.IP, port)
				}
			}

			fmt.Println()
		} else {
			// 离线主机使用红色标记
			utils.ErrorPrint("主机: %s [down]", result.IP)
		}
	}
}

// GetHostname 获取主机名
func GetHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// ValidateTarget 验证目标格式
func ValidateTarget(target string) bool {
	// 检查是否为IP地址
	if ip := net.ParseIP(target); ip != nil {
		return true
	}

	// 检查是否为CIDR格式
	if _, _, err := net.ParseCIDR(target); err == nil {
		return true
	}

	// 检查是否为IP范围格式
	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) == 2 && net.ParseIP(strings.TrimSpace(parts[0])) != nil &&
			net.ParseIP(strings.TrimSpace(parts[1])) != nil {
			return true
		}
	}

	// 检查是否为域名
	if _, err := net.LookupHost(target); err == nil {
		return true
	}

	return false
}

// ParseScanType 解析扫描类型
func ParseScanType(scanType string) string {
	switch scanType {
	case "syn", "SYN":
		return "syn"
	case "udp", "UDP":
		return "udp"
	case "connect", "tcp":
		return "connect"
	default:
		return "connect"
	}
}

// DefaultScanConfig 获取默认扫描配置
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Target:           "",
		Ports:            "",
		Threads:          50,
		Timeout:          3 * time.Second,
		ScanType:         "connect",
		OSDetection:      false,
		ServiceDetection: false,
	}
}

// QuickScan 快速扫描（常用端口）
func QuickScan(ctx context.Context, target string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = target
	config.Ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,6379,27017"
	config.Threads = 100
	config.Timeout = 2 * time.Second

	return NmapScan(ctx, config)
}

// FullScan 全端口扫描
func FullScan(ctx context.Context, target string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = target
	config.Ports = "1-65535"
	config.Threads = 200
	config.Timeout = 1 * time.Second

	return NmapScan(ctx, config)
}

// ServiceScan 服务扫描（带版本检测）
func ServiceScan(ctx context.Context, target string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = target
	config.Ports = "" // 使用默认端口
	config.ServiceDetection = true
	config.OSDetection = true

	return NmapScan(ctx, config)
}

// NetworkDiscovery 网络发现扫描
func NetworkDiscovery(ctx context.Context, cidr string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = cidr
	config.Ports = "" // 仅主机发现
	config.Threads = 200
	config.Timeout = 1 * time.Second

	return NmapScan(ctx, config)
}
