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

// deduplicateResults 移除IPv4/IPv6重复结果
func deduplicateResults(results []NmapResult) []NmapResult {
	if len(results) == 0 {
		return results
	}

	seen := make(map[string]bool)
	var unique []NmapResult

	for _, result := range results {
		key := result.IP

		if result.Hostname != "" {
			key = result.Hostname
		}

		if !seen[key] {
			seen[key] = true
			unique = append(unique, result)
		}
	}

	return unique
}

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

	results = deduplicateResults(results)

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
				utils.InfoPrint("扫描端口:")
				for _, portInfo := range result.Ports {
					fmt.Printf("  ")

					color.New(color.FgBlue).Printf("%d", portInfo.Port)
					fmt.Printf("/")

					color.New(color.FgCyan).Printf("%s", portInfo.Protocol)
					fmt.Printf(" ")

					switch portInfo.State {
					case PortStateOpen:
						color.New(color.FgGreen).Printf("%-10s", portInfo.State)
					case PortStateFiltered, PortStateOpenFiltered, PortStateClosedFiltered:
						color.New(color.FgYellow).Printf("%-10s", portInfo.State)
					case PortStateUnfiltered:
						color.New(color.FgHiYellow).Printf("%-10s", portInfo.State)
					default:
						color.New(color.FgRed).Printf("%-10s", portInfo.State)
					}

					if config.ServiceDetection {
						if portInfo.Service != "" {
							fmt.Printf(" ")
							color.New(color.FgMagenta).Printf("%s", portInfo.Service)
						}
						if portInfo.Version != "" {
							fmt.Printf(" ")
							color.New(color.FgWhite).Printf("%s", portInfo.Version)
						}
						if portInfo.Banner != "" {
							fmt.Printf(" ")
							banner := portInfo.Banner
							banner = strings.Map(func(r rune) rune {
								if r >= 32 && r <= 126 {
									return r
								}
								return -1
							}, banner)
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

			// 如果没有任何输出（没有端口、没有追踪、没有链接），只打印一个换行
			if len(result.Ports) == 0 && len(result.Traceroute) == 0 && len(httpPorts) == 0 && len(httpsPorts) == 0 {
				fmt.Println()
			} else if len(result.Ports) > 0 || len(httpPorts) > 0 || len(httpsPorts) > 0 {
				fmt.Println()
			}
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
	// 移除可能的协议前缀和端口号
	target = RemoveProtocolPrefix(target)

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

// RemoveProtocolPrefix 移除URL中的协议前缀、端口号和路径
func RemoveProtocolPrefix(url string) string {
	// 移除http://或https://前缀
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}

	// 尝试直接解析为IP地址（支持IPv4和IPv6）
	if ip := net.ParseIP(url); ip != nil {
		// 是IP地址，可能包含端口号
		// IPv6地址用方括号包裹
		if strings.HasPrefix(url, "[") {
			// [IPv6]:port 格式
			if idx := strings.LastIndex(url, "]"); idx != -1 {
				url = url[1:idx] // 移除[和]
			}
		} else if strings.Count(url, ":") == 1 {
			// IPv4:port 格式
			if idx := strings.LastIndex(url, ":"); idx != -1 {
				url = url[:idx]
			}
		}
		// 如果是纯IPv6地址（无端口），保持原样
		return url
	}

	// 不是IP地址，作为域名处理
	// 移除端口号
	if strings.Contains(url, ":") {
		parts := strings.Split(url, ":")
		url = parts[0]
	}

	// 移除路径部分
	if strings.Contains(url, "/") {
		parts := strings.Split(url, "/")
		url = parts[0]
	}

	return url
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

// ExportResults 导出扫描结果到多种格式
func ExportResults(results []NmapResult, format string, filePath string) error {
	switch format {
	case "json":
		return exportToJSON(results, filePath)
	case "xml":
		return exportToXML(results, filePath)
	case "csv":
		return exportToCSV(results, filePath)
	case "txt":
		return exportToTXT(results, filePath)
	default:
		return exportToJSON(results, filePath)
	}
}

// exportToJSON 导出到JSON格式
func exportToJSON(results []NmapResult, filePath string) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化JSON失败: %v", err)
	}
	return os.WriteFile(filePath, jsonData, 0644)
}

// exportToXML 导出到XML格式
func exportToXML(results []NmapResult, filePath string) error {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<nmap_results>
`
	for _, result := range results {
		xmlData += fmt.Sprintf(`  <host ip="%s" status="%s">
`, result.IP, result.Status)
		if result.Hostname != "" {
			xmlData += fmt.Sprintf(`    <hostname>%s</hostname>
`, escapeXML(result.Hostname))
		}
		if result.OS != "" {
			xmlData += fmt.Sprintf(`    <os>%s</os>
`, escapeXML(result.OS))
		}
		for port, portInfo := range result.Ports {
			xmlData += fmt.Sprintf(`    <port number="%d" protocol="%s" state="%s">
      <service>%s</service>
    </port>
`, port, portInfo.Protocol, portInfo.State, escapeXML(portInfo.Service))
		}
		xmlData += `  </host>
`
	}
	xmlData += `</nmap_results>`
	return os.WriteFile(filePath, []byte(xmlData), 0644)
}

// exportToCSV 导出到CSV格式
func exportToCSV(results []NmapResult, filePath string) error {
	csvData := "IP,Hostname,Status,Port,Protocol,State,Service,Version\n"
	for _, result := range results {
		for port, portInfo := range result.Ports {
			csvData += fmt.Sprintf("%s,%s,%s,%d,%s,%s,%s,%s\n",
				result.IP,
				escapeCSV(result.Hostname),
				result.Status,
				port,
				portInfo.Protocol,
				portInfo.State,
				escapeCSV(portInfo.Service),
				escapeCSV(portInfo.Version))
		}
	}
	return os.WriteFile(filePath, []byte(csvData), 0644)
}

// exportToTXT 导出到TXT格式
func exportToTXT(results []NmapResult, filePath string) error {
	var sb strings.Builder
	sb.WriteString("GYscan Nmap扫描报告\n")
	sb.WriteString("==================\n\n")

	for _, result := range results {
		sb.WriteString(fmt.Sprintf("主机: %s (%s)\n", result.IP, result.Status))
		if result.Hostname != "" {
			sb.WriteString(fmt.Sprintf("主机名: %s\n", result.Hostname))
		}
		if result.OS != "" {
			sb.WriteString(fmt.Sprintf("操作系统: %s\n", result.OS))
		}

		if len(result.Ports) > 0 {
			sb.WriteString("开放端口:\n")
			for port, portInfo := range result.Ports {
				sb.WriteString(fmt.Sprintf("  %d/%s %s %s\n",
					port, portInfo.Protocol, portInfo.State, portInfo.Service))
			}
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(filePath, []byte(sb.String()), 0644)
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func escapeCSV(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	if strings.Contains(s, ",") || strings.Contains(s, "\"") {
		s = "\"" + s + "\""
	}
	return s
}

// AnalyzeResults 分析扫描结果
func AnalyzeResults(results []NmapResult) ScanAnalysis {
	analysis := ScanAnalysis{
		TotalHosts: len(results),
		OpenPorts:  make(map[int]int),
		Services:   make(map[string]int),
		OS:         make(map[string]int),
		Vulnerable: make([]string, 0),
	}

	for _, result := range results {
		if result.Status == "up" {
			analysis.ActiveHosts++
		}

		for port, portInfo := range result.Ports {
			if portInfo.State == "open" {
				analysis.OpenPorts[port]++
				analysis.TotalOpenPorts++
				analysis.Services[portInfo.Service]++
				if portInfo.Service == "unknown" || portInfo.Service == "" {
					analysis.UnknownServices++
				}
			}
		}

		if result.OS != "" {
			analysis.OS[result.OS]++
		}

		for _, port := range result.Ports {
			if isVulnerablePort(port.Port) {
				analysis.Vulnerable = append(analysis.Vulnerable,
					fmt.Sprintf("%s:%d (%s)", result.IP, port.Port, port.Service))
			}
		}
	}

	return analysis
}

// ScanAnalysis 扫描结果分析
type ScanAnalysis struct {
	TotalHosts      int
	ActiveHosts     int
	TotalOpenPorts  int
	OpenPorts       map[int]int
	Services        map[string]int
	OS              map[string]int
	UnknownServices int
	Vulnerable      []string
}

func isVulnerablePort(port int) bool {
	vulnerablePorts := []int{21, 23, 445, 3389, 5900, 6379}
	for _, p := range vulnerablePorts {
		if p == port {
			return true
		}
	}
	return false
}
func NetworkDiscovery(ctx context.Context, cidr string) []NmapResult {
	config := DefaultScanConfig()
	config.Target = cidr
	config.Ports = "" // 仅主机发现
	config.Threads = 200
	config.Timeout = 1 * time.Second

	return NmapScan(ctx, config)
}
