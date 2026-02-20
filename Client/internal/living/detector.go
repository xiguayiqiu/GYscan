package living

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Target struct {
	IP    string
	Port  int
	Proto string
	URL   string
}

type LivingConfig struct {
	Timeout          time.Duration
	Threads          int
	EnableWAFDetect  bool
	EnableSimHash    bool
	SimHashThreshold int
	WAFThreshold     float64
	SampleSize       int
	Ports            []int
}

type LivingResult struct {
	Target        Target
	IsAlive       bool
	StatusCode    int
	ContentLength int
	ContentHash   string
	SimHash       uint64
	WAFType       WAFType
	WAFConfidence float64
	IsFakeAlive   bool
	Reason        string
	ResponseTime  time.Duration
}

type LivingDetector struct {
	config     *LivingConfig
	httpClient *http.Client
	pageHashes map[string]uint64
	hashMutex  sync.RWMutex
	wafStats   map[WAFType]int
	wafMutex   sync.RWMutex
}

func NewLivingDetector(config *LivingConfig) *LivingDetector {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: config.Timeout,
		}).DialContext,
		TLSHandshakeTimeout:   config.Timeout,
		ResponseHeaderTimeout: config.Timeout,
		IdleConnTimeout:       config.Timeout,
	}

	if config.Threads <= 0 {
		config.Threads = 10
	}
	if config.SimHashThreshold <= 0 {
		config.SimHashThreshold = 10
	}
	if config.WAFThreshold <= 0 {
		config.WAFThreshold = 0.4
	}
	if config.SampleSize <= 0 {
		config.SampleSize = 5
	}

	return &LivingDetector{
		config:     config,
		httpClient: &http.Client{Transport: tr, Timeout: config.Timeout},
		pageHashes: make(map[string]uint64),
		wafStats:   make(map[WAFType]int),
	}
}

func (d *LivingDetector) Detect(target Target) *LivingResult {
	result := &LivingResult{
		Target: target,
	}

	if !d.checkPort(target.IP, target.Port, target.Proto) {
		result.IsAlive = false
		result.Reason = "Port closed or filtered"
		return result
	}

	startTime := time.Now()
	resp, err := d.fetchURL(target.URL)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		result.IsAlive = false
		result.Reason = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentLength = int(resp.ContentLength)

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	body, err := readBody(resp.Body)
	if err != nil {
		result.IsAlive = true
		result.Reason = "Connection established but failed to read body"
		return result
	}

	result.ContentHash = ComputeBodyHash(body)

	if d.config.EnableSimHash {
		result.SimHash = ComputeSimHash(body)
	}

	if d.config.EnableWAFDetect {
		wafResult := AnalyzeResponse(resp.StatusCode, headers, body)
		result.WAFType = wafResult.WAFType
		result.WAFConfidence = wafResult.Confidence
	}

	if d.shouldFilter(result) {
		result.IsAlive = false
		result.IsFakeAlive = true
		result.Reason = fmt.Sprintf("Filtered by WAF (%s)", GetWAFTypeName(result.WAFType))
		return result
	}

	if d.config.EnableSimHash {
		d.recordHash(target.IP, result.SimHash)
	}

	result.IsAlive = true
	result.Reason = "Alive"

	return result
}

func (d *LivingDetector) BatchDetect(targets []Target) []*LivingResult {
	results := make([]*LivingResult, 0, len(targets))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.config.Threads)
	var mu sync.Mutex

	for _, target := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := d.Detect(t)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	return results
}

func (d *LivingDetector) checkPort(ip string, port int, proto string) bool {
	address := fmt.Sprintf("%s:%d", ip, port)

	var conn net.Conn
	var err error

	switch proto {
	case "udp":
		conn, err = net.DialTimeout("udp", address, d.config.Timeout)
	default:
		conn, err = net.DialTimeout("tcp", address, d.config.Timeout)
	}

	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (d *LivingDetector) fetchURL(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	return d.httpClient.Do(req)
}

func readBody(reader io.Reader) (string, error) {
	buf := make([]byte, 64*1024)
	n, err := reader.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}
	return string(buf[:n]), nil
}

func (d *LivingDetector) shouldFilter(result *LivingResult) bool {
	if !d.config.EnableWAFDetect {
		return false
	}

	if result.WAFType == WAFNone {
		return false
	}

	if result.WAFConfidence < d.config.WAFThreshold {
		return false
	}

	blockTypes := []WAFType{WAFAliyun, WAF腾讯云, WAF华为云, WAFAWS, WAFAzure,
		WAFCloudflare, WAFAkamai, WAFImperva, WAFFortinet, WAFPaloAlto, WAFSucuri, WAF403, WAF429}

	for _, bt := range blockTypes {
		if result.WAFType == bt {
			return true
		}
	}

	return false
}

func (d *LivingDetector) recordHash(ip string, hash uint64) {
	d.hashMutex.Lock()
	defer d.hashMutex.Unlock()

	existingHash, exists := d.pageHashes[ip]
	if exists {
		distance := HammingDistance(existingHash, hash)
		if distance <= d.config.SimHashThreshold {
			d.pageHashes[ip] = hash
		}
	} else {
		d.pageHashes[ip] = hash
	}
}

func (d *LivingDetector) AnalyzeSimilarPages(targets []Target) map[string][]string {
	d.config.EnableSimHash = true
	d.config.EnableWAFDetect = true

	results := d.BatchDetect(targets)

	hashGroups := make(map[uint64][]string)
	ipGroups := make(map[string][]string)

	for _, result := range results {
		if !result.IsAlive || result.SimHash == 0 {
			continue
		}

		found := false
		for hash, _ := range hashGroups {
			if IsSimilar(hash, result.SimHash, d.config.SimHashThreshold) {
				hashGroups[hash] = append(hashGroups[hash], result.Target.IP)
				ipGroups[result.Target.IP] = append(ipGroups[result.Target.IP], fmt.Sprintf("%s:%d", result.Target.IP, result.Target.Port))
				found = true
				break
			}
		}

		if !found {
			hashGroups[result.SimHash] = []string{result.Target.IP}
			ipGroups[result.Target.IP] = []string{fmt.Sprintf("%s:%d", result.Target.IP, result.Target.Port)}
		}
	}

	similarGroups := make(map[string][]string)
	for _, ips := range hashGroups {
		if len(ips) >= 2 {
			key := fmt.Sprintf("similar_group_%d", len(ips))
			similarGroups[key] = ips
		}
	}

	return similarGroups
}

func (d *LivingDetector) GetWAFStats() map[WAFType]int {
	d.wafMutex.Lock()
	defer d.wafMutex.Unlock()

	stats := make(map[WAFType]int)
	for k, v := range d.wafStats {
		stats[k] = v
	}
	return stats
}

func SmartDetect(ctx context.Context, ip string, ports []int, config *LivingConfig) []*LivingResult {
	if config == nil {
		config = &LivingConfig{
			Timeout:          3 * time.Second,
			Threads:          10,
			EnableWAFDetect:  true,
			EnableSimHash:    true,
			SimHashThreshold: 10,
			WAFThreshold:     0.4,
		}
	}

	detector := NewLivingDetector(config)

	var targets []Target
	for _, port := range ports {
		targets = append(targets, Target{
			IP:    ip,
			Port:  port,
			Proto: "tcp",
			URL:   fmt.Sprintf("http://%s:%d/", ip, port),
		})
	}

	results := detector.BatchDetect(targets)

	aliveResults := make([]*LivingResult, 0)
	for _, result := range results {
		if result.IsAlive && !result.IsFakeAlive {
			aliveResults = append(aliveResults, result)
		}
	}

	return aliveResults
}

func DetectWithFingerprint(ctx context.Context, target Target, config *LivingConfig) *LivingResult {
	if config == nil {
		config = &LivingConfig{
			Timeout:         3 * time.Second,
			EnableWAFDetect: true,
			EnableSimHash:   true,
		}
	}

	detector := NewLivingDetector(config)
	return detector.Detect(target)
}

func FilterSimilarPages(results []*LivingResult, threshold int) []*LivingResult {
	if threshold <= 0 {
		threshold = 10
	}

	hashCounts := make(map[uint64]int)
	for _, result := range results {
		if result.SimHash != 0 {
			hashCounts[result.SimHash]++
		}
	}

	filtered := make([]*LivingResult, 0)
	for _, result := range results {
		if result.SimHash == 0 {
			filtered = append(filtered, result)
			continue
		}

		count := hashCounts[result.SimHash]
		if count < 2 {
			filtered = append(filtered, result)
			continue
		}

		distance := HammingDistance(result.SimHash, 0)
		if distance > threshold {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

type ScanSummary struct {
	TotalTargets    int
	AliveTargets    int
	FilteredTargets int
	WAFStats        map[WAFType]int
	SimilarGroups   int
}

func (d *LivingDetector) GetSummary(results []*LivingResult) ScanSummary {
	summary := ScanSummary{
		TotalTargets:    len(results),
		AliveTargets:    0,
		FilteredTargets: 0,
		WAFStats:        make(map[WAFType]int),
	}

	simHashCounts := make(map[uint64]int)

	for _, result := range results {
		if result.IsAlive && !result.IsFakeAlive {
			summary.AliveTargets++
		}

		if result.IsFakeAlive {
			summary.FilteredTargets++
		}

		if result.WAFType != WAFNone {
			summary.WAFStats[result.WAFType]++
		}

		if result.SimHash != 0 {
			simHashCounts[result.SimHash]++
		}
	}

	summary.SimilarGroups = 0
	for _, count := range simHashCounts {
		if count >= 2 {
			summary.SimilarGroups += count - 1
		}
	}

	return summary
}

func DefaultConfig() *LivingConfig {
	return &LivingConfig{
		Timeout:          3 * time.Second,
		Threads:          10,
		EnableWAFDetect:  true,
		EnableSimHash:    true,
		SimHashThreshold: 10,
		WAFThreshold:     0.4,
		SampleSize:       5,
		Ports:            []int{80, 443, 8080, 8443},
	}
}

var _ = context.Background
var _ = sync.Mutex{}
