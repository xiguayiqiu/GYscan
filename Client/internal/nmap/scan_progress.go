package nmap

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type ScanProgress struct {
	mu           sync.RWMutex
	Target       string                   `json:"target"`
	StartTime    time.Time                `json:"start_time"`
	LastUpdate   time.Time                `json:"last_update"`
	EndTime      time.Time                `json:"end_time,omitempty"`
	TotalHosts   int                      `json:"total_hosts"`
	ScannedHosts int                      `json:"scanned_hosts"`
	TotalPorts   int                      `json:"total_ports"`
	ScannedPorts int                      `json:"scanned_ports"`
	Results      map[string]*HostProgress `json:"results"`
	Status       string                   `json:"status"`
	Error        string                   `json:"error,omitempty"`
}

type HostProgress struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname,omitempty"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time,omitempty"`
	TotalPorts   int       `json:"total_ports"`
	ScannedPorts int       `json:"scanned_ports"`
	OpenPorts    []int     `json:"open_ports"`
	Status       string    `json:"status"`
	Services     []string  `json:"services,omitempty"`
	OS           string    `json:"os,omitempty"`
	Progress     float64   `json:"progress"`
}

func NewScanProgress(target string, totalHosts, totalPorts int) *ScanProgress {
	return &ScanProgress{
		Target:       target,
		StartTime:    time.Now(),
		LastUpdate:   time.Now(),
		TotalHosts:   totalHosts,
		ScannedHosts: 0,
		TotalPorts:   totalPorts,
		ScannedPorts: 0,
		Results:      make(map[string]*HostProgress),
		Status:       "running",
	}
}

func (p *ScanProgress) UpdateHost(ip string, progress *HostProgress) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.Results[ip]; !exists {
		p.ScannedHosts++
	}
	p.Results[ip] = progress
	p.ScannedPorts += progress.ScannedPorts
	p.LastUpdate = time.Now()
}

func (p *ScanProgress) GetProgress() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.TotalHosts == 0 {
		return 0
	}

	hostProgress := float64(p.ScannedHosts) / float64(p.TotalHosts)
	if p.TotalPorts > 0 {
		portProgress := float64(p.ScannedPorts) / float64(p.TotalPorts)
		return (hostProgress + portProgress) / 2 * 100
	}
	return hostProgress * 100
}

func (p *ScanProgress) GetETA() time.Duration {
	elapsed := time.Since(p.StartTime)
	progress := p.GetProgress()

	if progress == 0 {
		return 0
	}

	totalEstimated := elapsed.Seconds() / (progress / 100)
	remaining := totalEstimated - elapsed.Seconds()

	if remaining < 0 {
		return 0
	}

	return time.Duration(remaining) * time.Second
}

func (p *ScanProgress) Complete() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Status = "completed"
	p.EndTime = time.Now()
}

func (p *ScanProgress) Fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Status = "failed"
	p.Error = err.Error()
	p.EndTime = time.Now()
}

func (p *ScanProgress) Save(filename string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("保存进度失败: %v", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func (p *ScanProgress) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取进度文件失败: %v", err)
	}

	return json.Unmarshal(data, p)
}

func (p *ScanProgress) CanResume() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.Status != "running" && p.Status != "failed" {
		return false
	}

	if p.Error != "" && p.ScannedHosts >= p.TotalHosts {
		return false
	}

	return p.ScannedHosts < p.TotalHosts
}

func (p *HostProgress) CalculateProgress() float64 {
	if p.TotalPorts == 0 {
		return 100
	}
	return float64(p.ScannedPorts) / float64(p.TotalPorts) * 100
}

type ScanSession struct {
	ID        string        `json:"id"`
	Target    string        `json:"target"`
	Config    ScanConfig    `json:"config"`
	Progress  *ScanProgress `json:"progress"`
	Results   []NmapResult  `json:"results"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time,omitempty"`
	Status    string        `json:"status"`
}

func NewScanSession(target string, config ScanConfig) *ScanSession {
	return &ScanSession{
		ID:        fmt.Sprintf("session_%d", time.Now().UnixNano()),
		Target:    target,
		Config:    config,
		Progress:  nil,
		Results:   make([]NmapResult, 0),
		StartTime: time.Now(),
		Status:    "initialized",
	}
}

func (s *ScanSession) Start() {
	s.Status = "running"
}

func (s *ScanSession) Complete() {
	s.Status = "completed"
	s.EndTime = time.Now()
}

func (s *ScanSession) Save(filename string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("保存会话失败: %v", err)
	}
	return os.WriteFile(filename, data, 0644)
}

func (s *ScanSession) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取会话文件失败: %v", err)
	}
	return json.Unmarshal(data, s)
}

type ScanState struct {
	Version     string         `json:"version"`
	LastUpdated time.Time      `json:"last_updated"`
	Scans       []*ScanSession `json:"scans"`
}

func NewScanState() *ScanState {
	return &ScanState{
		Version:     "1.0",
		LastUpdated: time.Now(),
		Scans:       make([]*ScanSession, 0),
	}
}

func (s *ScanState) AddScan(session *ScanSession) {
	s.Scans = append(s.Scans, session)
	s.LastUpdated = time.Now()
}

func (s *ScanState) RemoveScan(sessionID string) {
	for i, session := range s.Scans {
		if session.ID == sessionID {
			s.Scans = append(s.Scans[:i], s.Scans[i+1:]...)
			s.LastUpdated = time.Now()
			return
		}
	}
}

func (s *ScanState) GetScan(sessionID string) *ScanSession {
	for _, session := range s.Scans {
		if session.ID == sessionID {
			return session
		}
	}
	return nil
}

func (s *ScanState) Save(filename string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("保存状态失败: %v", err)
	}
	return os.WriteFile(filename, data, 0644)
}

func (s *ScanState) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("读取状态文件失败: %v", err)
	}
	return json.Unmarshal(data, s)
}

func SaveScanProgress(results []NmapResult, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("保存扫描结果失败: %v", err)
	}
	return os.WriteFile(filename, data, 0644)
}

func LoadScanProgress(filename string) ([]NmapResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取扫描结果失败: %v", err)
	}

	var results []NmapResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("解析扫描结果失败: %v", err)
	}

	return results, nil
}
