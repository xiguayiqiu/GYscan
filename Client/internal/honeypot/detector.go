package honeypot

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"GYscan/internal/honeypot/signatures"
	"GYscan/internal/utils"
)

type Detector struct {
	Config     *Config
	Scanner    *ServiceScanner
	Matcher    *Matcher
	SigManager *signatures.SignatureManager
	mu         sync.Mutex
}

func NewDetector(config *Config) *Detector {
	timeout := time.Duration(config.Timeout) * time.Second
	return &Detector{
		Config:  config,
		Scanner: NewServiceScanner(timeout, config.Verbose),
		Matcher: NewMatcher(),
		SigManager: signatures.NewSignatureManager(),
	}
}

func (d *Detector) LoadCustomSignatures() error {
	if d.Config.ConfigPath != "" {
		return d.SigManager.LoadCustomSignatures(d.Config.ConfigPath)
	}
	return nil
}

func (d *Detector) Detect(target string) []*DetectionResult {
	var results []*DetectionResult

	ports := d.parsePorts(d.Config.Ports)
	if len(ports) == 0 {
		ports = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 4433, 4434, 4435, 9000, 9001, 9002}
	}

	if d.Config.Verbose {
		utils.InfoPrint("[+] 开始检测目标: %s", target)
		utils.InfoPrint("[+] 检测模式: %s", d.Config.Mode)
		utils.InfoPrint("[+] 扫描端口数: %d", len(ports))
	}

	startTime := time.Now()

	if d.Config.Mode == DeepScan {
		results = d.deepScan(target, ports)
	} else {
		results = d.quickScan(target, ports)
	}

	for _, result := range results {
		result.ScanMode = d.Config.Mode
		result.ScanDuration = time.Since(startTime)
	}

	return results
}

func (d *Detector) quickScan(target string, ports []int) []*DetectionResult {
	var results []*DetectionResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	semaphore := make(chan struct{}, d.Config.Threads)

	for _, port := range ports {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := d.detectPort(target, p)
			if result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	return results
}

func (d *Detector) deepScan(target string, ports []int) []*DetectionResult {
	results := d.quickScan(target, ports)

	if len(results) == 0 {
		return results
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	semaphore := make(chan struct{}, d.Config.Threads/2)

	for _, result := range results {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(r *DetectionResult) {
			defer wg.Done()
			defer func() { <-semaphore }()

			behavior, _ := d.Scanner.CheckProtocolConsistency(r.Target, r.Port, "tcp")
			if behavior != nil {
				mu.Lock()
				r.BehaviorAnalysis = behavior
				if behavior.ResponseTimeFixed || behavior.ProtocolInconsistent {
					r.MatchedFeatures = append(r.MatchedFeatures, MatchedFeature{
						Name:        "行为分析异常",
						Weight:      25,
						Description: behavior.Details,
						Category:    "behavior",
					})
					r.Confidence = d.Matcher.CalculateConfidence(r.MatchedFeatures)
					r.RiskLevel = CalculateRiskLevel(r.Confidence)
				}
				mu.Unlock()
			}
		}(result)
	}

	wg.Wait()

	return results
}

func (d *Detector) detectPort(target string, port int) *DetectionResult {
	result := NewDetectionResult(target, port)

	serviceInfo, err := d.Scanner.DetectService(target, port)
	if err != nil {
		if d.Config.Verbose {
			utils.DebugPrint("[*] Port %d: %v", port, err)
		}
		return nil
	}

	result.ServiceInfo = serviceInfo
	result.Service = IdentifyService(serviceInfo.Banner)

	sigServiceInfo := &signatures.ServiceInfo{
		Port:     serviceInfo.Port,
		Protocol: serviceInfo.Protocol,
		Banner:   serviceInfo.Banner,
		Version:  serviceInfo.Version,
	}

	matchedSigFeatures := d.SigManager.Match(sigServiceInfo)

	features := make([]MatchedFeature, len(matchedSigFeatures))
	for i, f := range matchedSigFeatures {
		features[i] = MatchedFeature{
			Name:        f.Name,
			Weight:      f.Weight,
			Description: f.Description,
			Category:    f.Category,
		}
	}

	result.MatchedFeatures = features

	result.Confidence = d.Matcher.CalculateConfidence(features)
	result.RiskLevel = CalculateRiskLevel(result.Confidence)

	result.HoneypotType = d.Matcher.GetHoneypotType(features)
	result.Suggestion = d.Matcher.GetSuggestions(features, result.Confidence)

	if result.Confidence >= 40 {
		result.IsHoneypot = true
	}

	return result
}

func (d *Detector) DetectBatch(targets []string) []*DetectionResult {
	var allResults []*DetectionResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	semaphore := make(chan struct{}, d.Config.Threads)

	for _, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(t string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			results := d.Detect(t)
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	return allResults
}

func (d *Detector) parsePorts(portsStr string) []int {
	if portsStr == "" {
		return nil
	}

	var ports []int

	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, end := parsePortNumber(rangeParts[0]), parsePortNumber(rangeParts[1])
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
		} else {
			if p := parsePortNumber(part); p > 0 {
				ports = append(ports, p)
			}
		}
	}

	return ports
}

func parsePortNumber(s string) int {
	result := 0
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil || result < 1 || result > 65535 {
		return 0
	}
	return result
}

func (d *Detector) ValidateTarget(target string) error {
	target = strings.TrimSpace(target)

	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http:/")
	target = strings.TrimPrefix(target, "https:/")

	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	parts := strings.Split(target, ":")
	host := parts[0]
	if len(parts) > 1 {
		portPart := parts[1]
		if idx := strings.Index(portPart, "/"); idx != -1 {
			portPart = portPart[:idx]
		}
		if d.Config.Ports == "" {
			d.Config.Ports = portPart
		}
	}

	if host == "" {
		return fmt.Errorf("无效的目标地址: %s", target)
	}

	if net.ParseIP(host) == nil && !isValidHostname(host) {
		return fmt.Errorf("无效的目标地址: %s", target)
	}
	return nil
}

func isValidHostname(hostname string) bool {
	if len(hostname) < 1 || len(hostname) > 253 {
		return false
	}

	pattern := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	return pattern.MatchString(hostname)
}

func (d *Detector) GetProgress() ScanState {
	return ScanState{}
}

func (d *Detector) Cancel() {
}

func (d *Detector) GetStatistics(results []*DetectionResult) map[string]int {
	stats := map[string]int{
		"total":      len(results),
		"honeypot":   0,
		"high":       0,
		"medium":     0,
		"low":        0,
		"confidence": 0,
	}

	for _, r := range results {
		if r.IsHoneypot {
			stats["honeypot"]++
		}
		switch r.RiskLevel {
		case RiskHigh, RiskCritical:
			stats["high"]++
		case RiskMedium:
			stats["medium"]++
		case RiskLow:
			stats["low"]++
		}
		stats["confidence"] += r.Confidence
	}

	if len(results) > 0 {
		stats["confidence"] /= len(results)
	}

	return stats
}
