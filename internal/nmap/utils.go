package nmap

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"GYscan/internal/utils"
)

// SaveNmapResult 保存nmap扫描结果
func SaveNmapResult(results []NmapResult, filePath string) error {
	if filePath == "" {
		filePath = fmt.Sprintf("nmap_scan_result_%s.json", time.Now().Format("20060102_150405"))
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
func PrintNmapResult(results []NmapResult) {
	utils.InfoPrint("\n=== NMAP 扫描结果 ===")
	
	activeHosts := 0
	for _, result := range results {
		if result.Status == "up" {
			activeHosts++
		}
	}
	
	utils.InfoPrint("扫描统计: 总计 %d 台主机，活跃 %d 台\n", len(results), activeHosts)

	for _, result := range results {
		if result.Status == "up" {
			utils.SuccessPrint("主机: %s", result.IP)
			if result.Hostname != "" {
				fmt.Printf(" (%s)", result.Hostname)
			}
			if result.OS != "" {
				fmt.Printf(" [%s]", result.OS)
			}
			fmt.Println()

			if len(result.Ports) > 0 {
				utils.InfoPrint("开放端口:")
				for _, portInfo := range result.Ports {
					fmt.Printf("  %d/%s %-8s %s", 
						portInfo.Port, portInfo.Protocol, portInfo.State, portInfo.Service)
					if portInfo.Version != "" {
						fmt.Printf(" %s", portInfo.Version)
					}
					if portInfo.Banner != "" {
						fmt.Printf(" (%s)", portInfo.Banner)
					}
					fmt.Println()
				}
			}
			fmt.Println()
		} else {
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
		Target:          "",
		Ports:           "",
		Threads:         50,
		Timeout:         3 * time.Second,
		ScanType:        "connect",
		OSDetection:     false,
		ServiceDetection: true,
	}
}

// QuickScan 快速扫描（常用端口）
func QuickScan(target string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = target
	config.Ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,6379,27017"
	config.Threads = 100
	config.Timeout = 2 * time.Second

	return NmapScan(config)
}

// FullScan 全端口扫描
func FullScan(target string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = target
	config.Ports = "1-65535"
	config.Threads = 200
	config.Timeout = 1 * time.Second

	return NmapScan(config)
}

// ServiceScan 服务扫描（带版本检测）
func ServiceScan(target string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = target
	config.Ports = "" // 使用默认端口
	config.ServiceDetection = true
	config.OSDetection = true

	return NmapScan(config)
}

// NetworkDiscovery 网络发现扫描
func NetworkDiscovery(cidr string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = cidr
	config.Ports = "" // 仅主机发现
	config.Threads = 200
	config.Timeout = 1 * time.Second

	return NmapScan(config)
}