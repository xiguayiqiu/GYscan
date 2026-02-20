package living

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	livingTarget    string
	livingPorts     string
	livingThreads   int
	livingTimeout   int
	livingEnableWAF bool
	livingEnableSim bool
	livingSimThresh int
	livingWAFThresh float64
	livingOutput    string
	livingJSON      bool
)

var LivingCmd = &cobra.Command{
	Use:   "living [目标] [flags]",
	Short: "智能存活探测 - 识别WAF拦截和假死页面",
	Long: `GYscan 智能存活探测模块

功能特点:
- 三层存活探测: 端口检测 -> HTTP请求 -> WAF/假死识别
- WAF指纹识别: 支持阿里云、腾讯云、华为云、Cloudflare等常见WAF
- SimHash页面相似度: 自动识别相同拦截页面,过滤无效资产

用法示例:
  ./GYscan living 192.168.1.1
  ./GYscan living 192.168.1.1/24 -p 80,443,8080
  ./GYscan living example.com --waf --simhash
  ./GYscan living 10.0.0.0/8 -o results.json --json`,
	Run: runLivingCommand,
}

func init() {
	LivingCmd.Flags().StringVarP(&livingTarget, "target", "t", "", "扫描目标 (IP/CIDR/域名)")
	LivingCmd.Flags().StringVarP(&livingPorts, "ports", "p", "80,443,8080,8443", "扫描端口 (逗号分隔)")
	LivingCmd.Flags().IntVarP(&livingThreads, "threads", "n", 20, "并发线程数")
	LivingCmd.Flags().IntVarP(&livingTimeout, "timeout", "w", 3, "超时时间(秒)")
	LivingCmd.Flags().BoolVarP(&livingEnableWAF, "waf", "", true, "启用WAF检测")
	LivingCmd.Flags().BoolVarP(&livingEnableSim, "simhash", "", true, "启用SimHash页面相似度检测")
	LivingCmd.Flags().IntVarP(&livingSimThresh, "sim-threshold", "", 10, "SimHash相似度阈值 (Hamming距离)")
	LivingCmd.Flags().Float64VarP(&livingWAFThresh, "waf-threshold", "", 0.4, "WAF检测置信度阈值")
	LivingCmd.Flags().StringVarP(&livingOutput, "output", "o", "", "结果输出文件")
	LivingCmd.Flags().BoolVarP(&livingJSON, "json", "", false, "JSON格式输出")
}

func runLivingCommand(cmd *cobra.Command, args []string) {
	if len(args) > 0 && livingTarget == "" {
		livingTarget = args[0]
	}

	if livingTarget == "" {
		fmt.Println("请指定扫描目标 (使用 -t 参数或直接传递目标)")
		cmd.Help()
		return
	}

	utils.BoldInfo("GYscan 智能存活探测")
	utils.InfoPrint("目标: %s", livingTarget)
	utils.InfoPrint("端口: %s", livingPorts)

	startTime := time.Now()

	targets := parseLivingTargets(livingTarget, livingPorts)
	utils.InfoPrint("共 %d 个目标", len(targets))

	config := &LivingConfig{
		Timeout:          time.Duration(livingTimeout) * time.Second,
		Threads:          livingThreads,
		EnableWAFDetect:  livingEnableWAF,
		EnableSimHash:    livingEnableSim,
		SimHashThreshold: livingSimThresh,
		WAFThreshold:     livingWAFThresh,
	}

	detector := NewLivingDetector(config)

	results := detector.BatchDetect(targets)

	duration := time.Since(startTime)

	stats := &LivingStats{
		ScanDuration: duration,
	}
	for _, r := range results {
		stats.AddResult(r)
	}

	printResults(results, stats, livingJSON)

	if livingOutput != "" {
		saveResults(results, stats, livingOutput, livingJSON)
	}

	utils.BoldInfo("扫描完成: 存活=%d, 过滤=%d, 耗时=%v",
		stats.TotalAlive, stats.TotalFiltered, duration)
}

func parseLivingTargets(target string, ports string) []Target {
	var targets []Target

	ipList := parseIPRange(target)

	portList := parsePortList(ports)

	for _, ip := range ipList {
		for _, port := range portList {
			targets = append(targets, Target{
				IP:    ip,
				Port:  port,
				Proto: "tcp",
				URL:   fmt.Sprintf("http://%s:%d/", ip, port),
			})
		}
	}

	return targets
}

func parseIPRange(target string) []string {
	var ips []string

	if strings.Contains(target, "/") {
		cidr := strings.Split(target, "/")[0]
		mask, _ := strconv.Atoi(strings.Split(target, "/")[1])

		ip := netParseIPv4(cidr)
		if ip == nil {
			return []string{target}
		}

		hostBits := 32 - mask
		numHosts := 1 << uint(hostBits)

		for i := 0; i < numHosts && i < 256; i++ {
			ipCopy := make([]byte, 4)
			copy(ipCopy, ip)
			ipCopy[3] = byte(i)
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", ipCopy[0], ipCopy[1], ipCopy[2], ipCopy[3]))
		}
	} else if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		startIP := parts[0]
		endSuffix := parts[1]

		start := netParseIPv4(startIP)
		if start != nil && endSuffix != "" {
			lastOctet, _ := strconv.Atoi(endSuffix)
			for i := int(start[3]); i <= lastOctet && i < 256; i++ {
				ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", start[0], start[1], start[2], i))
			}
		}
	} else {
		ips = append(ips, target)
	}

	return ips
}

func netParseIPv4(s string) []byte {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	ip := make([]byte, 4)
	for i, part := range parts {
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 255 {
			return nil
		}
		ip[i] = byte(v)
	}
	return ip
}

func parsePortList(ports string) []int {
	var portList []int

	portStrs := strings.Split(ports, ",")
	for _, p := range portStrs {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			parts := strings.Split(p, "-")
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end && i <= 65535; i++ {
				portList = append(portList, i)
			}
		} else {
			port, _ := strconv.Atoi(p)
			if port > 0 && port <= 65535 {
				portList = append(portList, port)
			}
		}
	}

	if len(portList) == 0 {
		portList = []int{80, 443, 8080, 8443}
	}

	return portList
}

func printResults(results []*LivingResult, stats *LivingStats, jsonOutput bool) {
	if jsonOutput {
		type output struct {
			Results []ResultJson `json:"results"`
			Stats   *LivingStats `json:"stats"`
		}

		var resultJsons []ResultJson
		for _, r := range results {
			resultJsons = append(resultJsons, ResultJson{
				IP:       r.Target.IP,
				Port:     r.Target.Port,
				Status:   string(StatusAlive),
				Code:     r.StatusCode,
				WAF:      string(r.WAFType),
				Filtered: r.IsFakeAlive,
			})
		}

		out := output{
			Results: resultJsons,
			Stats:   stats,
		}

		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println()
	utils.BoldInfo("=== 存活目标 ===")
	for _, r := range results {
		if r.IsAlive && !r.IsFakeAlive {
			wafInfo := ""
			if r.WAFType != WAFNone {
				wafInfo = fmt.Sprintf(" [WAF: %s, %.0f%%]", GetWAFTypeName(r.WAFType), r.WAFConfidence*100)
			}
			fmt.Printf("  [%s:%d] 状态码: %d, 响应: %d bytes, 耗时: %v%s\n",
				r.Target.IP, r.Target.Port, r.StatusCode, r.ContentLength, r.ResponseTime, wafInfo)
		}
	}

	if stats.TotalFiltered > 0 {
		fmt.Println()
		utils.LogInfo("=== 过滤目标 (WAF/假死) ===")
		for _, r := range results {
			if r.IsFakeAlive {
				fmt.Printf("  [%s:%d] %s\n", r.Target.IP, r.Target.Port, r.Reason)
			}
		}
	}

	fmt.Println()
	fmt.Println(stats.String())
}

type ResultJson struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
	Code     int    `json:"status_code"`
	WAF      string `json:"waf_type"`
	Filtered bool   `json:"filtered"`
}

func saveResults(results []*LivingResult, stats *LivingStats, filename string, jsonFormat bool) {
	var data []byte
	var err error

	if jsonFormat {
		type output struct {
			Results []ResultJson `json:"results"`
			Stats   *LivingStats `json:"stats"`
		}

		var resultJsons []ResultJson
		for _, r := range results {
			status := StatusAlive
			if r.IsFakeAlive {
				status = StatusFiltered
			} else if !r.IsAlive {
				status = StatusDead
			}

			resultJsons = append(resultJsons, ResultJson{
				IP:       r.Target.IP,
				Port:     r.Target.Port,
				Status:   string(status),
				Code:     r.StatusCode,
				WAF:      string(r.WAFType),
				Filtered: r.IsFakeAlive,
			})
		}

		out := output{
			Results: resultJsons,
			Stats:   stats,
		}

		data, err = json.MarshalIndent(out, "", "  ")
	} else {
		var lines []string
		lines = append(lines, "IP,Port,Status,StatusCode,WAFType,Filtered")
		for _, r := range results {
			status := "alive"
			if r.IsFakeAlive {
				status = "filtered"
			} else if !r.IsAlive {
				status = "dead"
			}
			lines = append(lines, fmt.Sprintf("%s,%d,%s,%d,%s,%t",
				r.Target.IP, r.Target.Port, status, r.StatusCode, r.WAFType, r.IsFakeAlive))
		}
		data = []byte(strings.Join(lines, "\n"))
	}

	if err != nil {
		utils.LogError("序列化结果失败: %v", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		utils.LogError("保存结果失败: %v", err)
		return
	}

	utils.Success("结果已保存到: %s", filename)
}

var (
	_ = context.Background()
	_ = json.Marshal
	_ = os.WriteFile
)
