package nmap

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// NmapTimingTemplate Nmap 风格的扫描速度模板
type NmapTimingTemplate int

const (
	ParanoidTiming   NmapTimingTemplate = 0
	SneakyTiming     NmapTimingTemplate = 1
	PoliteTiming     NmapTimingTemplate = 2
	NormalTiming     NmapTimingTemplate = 3
	AggressiveTiming NmapTimingTemplate = 4
	InsaneTiming     NmapTimingTemplate = 5
)

// TimingConfig 扫描时序配置
type TimingConfig struct {
	Template       NmapTimingTemplate
	MinParallelism int
	MaxParallelism int
	MinRTTTimeout  time.Duration
	MaxRTTTimeout  time.Duration
	InitialTimeout time.Duration
	Retries        int
	KeepAlive      bool
	PacketRate     float64
}

func NewTimingConfig(template NmapTimingTemplate) *TimingConfig {
	config := &TimingConfig{
		Template: template,
	}

	switch template {
	case ParanoidTiming:
		config.MinParallelism = 1
		config.MaxParallelism = 1
		config.MinRTTTimeout = 5 * time.Minute
		config.MaxRTTTimeout = 15 * time.Minute
		config.InitialTimeout = 5 * time.Minute
		config.Retries = 10
		config.KeepAlive = false
		config.PacketRate = 0.1
	case SneakyTiming:
		config.MinParallelism = 1
		config.MaxParallelism = 1
		config.MinRTTTimeout = 15 * time.Second
		config.MaxRTTTimeout = 45 * time.Second
		config.InitialTimeout = 15 * time.Second
		config.Retries = 5
		config.KeepAlive = false
		config.PacketRate = 0.5
	case PoliteTiming:
		config.MinParallelism = 1
		config.MaxParallelism = 10
		config.MinRTTTimeout = 500 * time.Millisecond
		config.MaxRTTTimeout = 2 * time.Second
		config.InitialTimeout = 500 * time.Millisecond
		config.Retries = 3
		config.KeepAlive = true
		config.PacketRate = 5
	case NormalTiming:
		config.MinParallelism = 10
		config.MaxParallelism = 100
		config.MinRTTTimeout = 100 * time.Millisecond
		config.MaxRTTTimeout = 3 * time.Second
		config.InitialTimeout = 100 * time.Millisecond
		config.Retries = 2
		config.KeepAlive = true
		config.PacketRate = 50
	case AggressiveTiming:
		config.MinParallelism = 50
		config.MaxParallelism = 200
		config.MinRTTTimeout = 50 * time.Millisecond
		config.MaxRTTTimeout = 1 * time.Second
		config.InitialTimeout = 50 * time.Millisecond
		config.Retries = 1
		config.KeepAlive = true
		config.PacketRate = 100
	case InsaneTiming:
		config.MinParallelism = 100
		config.MaxParallelism = 500
		config.MinRTTTimeout = 25 * time.Millisecond
		config.MaxRTTTimeout = 500 * time.Millisecond
		config.InitialTimeout = 25 * time.Millisecond
		config.Retries = 1
		config.KeepAlive = true
		config.PacketRate = 500
	default:
		return NewTimingConfig(NormalTiming)
	}

	return config
}

// OptimizedScanResult 优化后的扫描结果
type OptimizedScanResult struct {
	IP              string
	Hostname        string
	Ports           map[int]PortInfo
	Services        []ServiceInfo
	OS              OSInfo
	Traceroute      []TracerouteHop
	Status          string
	MACAddress      string
	MACVendor       string
	NetworkDistance int
	Timing          TimingStats
}

type ServiceInfo struct {
	Name       string
	Product    string
	Version    string
	ExtraInfo  string
	Confidence float64
}

type OSInfo struct {
	Name       string
	Family     string
	Generation string
	Vendor     string
	Type       string
	Accuracy   float64
	CPE        []string
}

type TimingStats struct {
	StartTime       time.Time
	EndTime         time.Time
	TotalDuration   time.Duration
	ScanDuration    time.Duration
	PacketsSent     int
	PacketsReceived int
	PacketLoss      float64
}

// EnhancedNmapScan 增强版扫描（整合 nmap 源码优化）
func EnhancedNmapScan(ctx context.Context, config ScanConfig) []OptimizedScanResult {
	engine := NewScanEngine()

	var results []OptimizedScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	hosts := parseTarget(config.Target)
	portList := parsePorts(config.Ports)
	sort.Ints(portList)

	semaphore := make(chan struct{}, config.Threads)
	stats := &ScanStats{}

	completedHosts := 0

	fmt.Printf("[GYscan-Enhanced] 开始扫描: 目标=%s, 端口=%d, 线程=%d, 速度级别=%d\n",
		config.Target, len(portList), config.Threads, config.TimingTemplate)

	if config.Pn {
		fmt.Printf("[GYscan-Enhanced] Pn模式: 跳过主机发现，所有主机直接标记为存活\n")
	}

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			fmt.Printf("[GYscan-Enhanced] 扫描被用户取消\n")
			return results
		default:
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			startTime := time.Now()
			result := OptimizedScanResult{
				IP:         ip,
				Ports:      make(map[int]PortInfo),
				Services:   make([]ServiceInfo, 0),
				Traceroute: make([]TracerouteHop, 0),
				Timing:     TimingStats{StartTime: startTime},
			}

			isAlive := true
			if !config.Pn {
				isAlive = hostDiscovery(ip, config.Timeout)
			}

			if !isAlive {
				result.Status = "down"
				mu.Lock()
				results = append(results, result)
				completedHosts++
				mu.Unlock()
				return
			}

			result.Status = "up"

			var openPorts []int
			mu.Lock()
			completedHosts++
			mu.Unlock()

			if len(portList) > 0 {
				portResults := optimizedPortScan(ctx, ip, portList, config, engine, stats)
				for port, info := range portResults {
					result.Ports[port] = info
					if info.State == PortStateOpen {
						openPorts = append(openPorts, port)
					}
				}

				if config.ServiceDetection && len(openPorts) > 0 {
					for _, port := range openPorts {
						if info, ok := result.Ports[port]; ok {
							fingerprint := EnhancedServiceDetection(ip, port, info.Banner)
							result.Services = append(result.Services, ServiceInfo{
								Name:       fingerprint.Service,
								Version:    fingerprint.Version,
								ExtraInfo:  fingerprint.ExtraInfo,
								Confidence: calculateConfidence(fingerprint.Service, info.Banner),
							})
						}
					}
				}

				if config.OSDetection && len(openPorts) > 0 {
					osInfo := EnhancedOSDetection(ip, result.Ports)
					if len(osInfo) > 0 {
						result.OS = OSInfo{
							Name:     osInfo[0],
							Accuracy: calculateOSAccuracy(osInfo[0], result.Ports),
						}
					}
				}

				if config.AggressiveScan {
					result.MACAddress = getMACAddress(ip)
					if result.MACAddress != "" {
						result.MACVendor = getVendorByMAC(result.MACAddress)
					}
					result.Traceroute = performTraceroute(ip)
				}

				if config.TTLDetection {
					result.NetworkDistance = detectTTL(ip, config.Timeout)
				}
			}

			result.Timing.EndTime = time.Now()
			result.Timing.TotalDuration = result.Timing.EndTime.Sub(result.Timing.StartTime)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(host)
	}

	wg.Wait()

	fmt.Printf("[GYscan-Enhanced] 扫描完成，发现 %d 台活跃主机\n", len(results))
	return results
}

func optimizedPortScan(ctx context.Context, ip string, ports []int, config ScanConfig, engine *ScanEngine, stats *ScanStats) map[int]PortInfo {
	results := make(map[int]PortInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	totalPorts := len(ports)
	semaphore := make(chan struct{}, config.Threads)

	progressTicker := time.NewTicker(1 * time.Second)
	var lastProgress int

	go func() {
		for range progressTicker.C {
			select {
			case <-ctx.Done():
				return
			default:
				current := len(results)
				if current-lastProgress >= 10 || current == totalPorts {
					progress := float64(current) / float64(totalPorts) * 100
					fmt.Printf("[进度] 主机 %s 扫描进度: %.1f%% (%d/%d)\n",
						ip, progress, current, totalPorts)
					lastProgress = current
				}
			}
		}
	}()

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var portInfo PortInfo

			switch config.ScanType {
			case "syn":
				portInfo = synScan(ip, p, config.Timeout, config.FragmentedScan)
			case "udp":
				portInfo = udpScan(ip, p, config.Timeout)
			case "fin":
				state := finScan(ip, p, config.Timeout)
				portInfo = PortInfo{Port: p, Protocol: "tcp", State: state}
			case "xmas":
				state := xmasScan(ip, p, config.Timeout)
				portInfo = PortInfo{Port: p, Protocol: "tcp", State: state}
			case "null":
				state := nullScan(ip, p, config.Timeout)
				portInfo = PortInfo{Port: p, Protocol: "tcp", State: state}
			case "ack":
				state := ackScan(ip, p, config.Timeout)
				portInfo = PortInfo{Port: p, Protocol: "tcp", State: state}
			case "window":
				state := windowScan(ip, p, config.Timeout)
				portInfo = PortInfo{Port: p, Protocol: "tcp", State: state}
			case "maimon":
				state := maimonScan(ip, p, config.Timeout)
				portInfo = PortInfo{Port: p, Protocol: "tcp", State: state}
			default:
				portInfo = connectScan(ip, p, config.Timeout, config.FragmentedScan)
			}

			if portInfo.State == PortStateOpen {
				engine.Acknowledge()
				stats.Update(1)
			}

			mu.Lock()
			results[p] = portInfo
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	progressTicker.Stop()

	return results
}

func calculateConfidence(service string, banner string) float64 {
	if banner == "" {
		return 0.5
	}

	bannerLower := strings.ToLower(banner)
	serviceLower := strings.ToLower(service)

	if strings.Contains(bannerLower, serviceLower) {
		return 0.9
	}

	return 0.7
}

func calculateOSAccuracy(osName string, ports map[int]PortInfo) float64 {
	if osName == "Unknown" {
		return 0.0
	}

	openPortCount := 0
	for _, info := range ports {
		if info.State == PortStateOpen {
			openPortCount++
		}
	}

	baseAccuracy := 0.7
	if openPortCount >= 3 {
		baseAccuracy += 0.1
	}
	if openPortCount >= 5 {
		baseAccuracy += 0.1
	}

	return math.Min(baseAccuracy, 0.95)
}

// QuickOptimizedScan 快速优化扫描
func QuickOptimizedScan(ctx context.Context, target string, ports string) []OptimizedScanResult {
	config := ScanConfig{
		Target:           target,
		Ports:            ports,
		Threads:          100,
		Timeout:          2 * time.Second,
		ScanType:         "connect",
		ServiceDetection: true,
		TimingTemplate:   int(AggressiveTiming),
	}

	return EnhancedNmapScan(ctx, config)
}

// ComprehensiveScan 综合扫描
func ComprehensiveScan(ctx context.Context, target string) []OptimizedScanResult {
	config := ScanConfig{
		Target:           target,
		Ports:            "1-10000",
		Threads:          50,
		Timeout:          3 * time.Second,
		ScanType:         "connect",
		ServiceDetection: true,
		OSDetection:      true,
		AggressiveScan:   true,
		TTLDetection:     true,
		TimingTemplate:   int(AggressiveTiming),
	}

	return EnhancedNmapScan(ctx, config)
}

// ServiceVersionDetection 服务版本检测（优化）
func ServiceVersionDetection(ip string, ports map[int]PortInfo) map[int]ServiceInfo {
	services := make(map[int]ServiceInfo)

	for port, info := range ports {
		if info.State == PortStateOpen {
			fingerprint := EnhancedServiceDetection(ip, port, info.Banner)
			services[port] = ServiceInfo{
				Name:       fingerprint.Service,
				Version:    fingerprint.Version,
				ExtraInfo:  fingerprint.ExtraInfo,
				Confidence: calculateConfidence(fingerprint.Service, info.Banner),
			}
		}
	}

	return services
}

// BatchOptimizedScan 批量优化扫描
func BatchOptimizedScan(ctx context.Context, targets []string, config ScanConfig) []OptimizedScanResult {
	config.Target = strings.Join(targets, ",")
	return EnhancedNmapScan(ctx, config)
}

// PrintOptimizedResult 打印优化后的扫描结果
func PrintOptimizedResult(results []OptimizedScanResult) {
	for _, result := range results {
		fmt.Printf("\n主机: %s", result.IP)
		if result.Hostname != "" {
			fmt.Printf(" (%s)", result.Hostname)
		}
		if result.MACVendor != "" {
			fmt.Printf(" [%s]", result.MACVendor)
		}
		fmt.Printf(" 状态: %s\n", result.Status)

		if len(result.Ports) > 0 {
			fmt.Println("端口状态:")
			fmt.Println("  端口     状态      服务        版本")
			fmt.Println("  ----     -----     ----        -----")

			portKeys := make([]int, 0, len(result.Ports))
			for port := range result.Ports {
				portKeys = append(portKeys, port)
			}
			sort.Ints(portKeys)

			for _, port := range portKeys {
				info := result.Ports[port]
				version := ""
				for _, service := range result.Services {
					if port == 0 || service.Name == "" {
						continue
					}
				}
				stateColor := ""
				switch info.State {
				case "open":
					stateColor = "OPEN"
				case "filtered":
					stateColor = "FILTERED"
				case "closed":
					stateColor = "CLOSED"
				default:
					stateColor = info.State
				}
				fmt.Printf("  %-5d    %-10s %-12s %s\n", port, stateColor, info.Service, version)
			}
		}

		if result.OS.Name != "" {
			fmt.Printf("\n操作系统: %s (置信度: %.0f%%)\n", result.OS.Name, result.OS.Accuracy*100)
		}

		if result.Timing.TotalDuration > 0 {
			fmt.Printf("\n扫描时间: %v\n", result.Timing.TotalDuration)
		}
	}
}
