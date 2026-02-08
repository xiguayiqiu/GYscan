package nmap

import (
	"context"
	"math"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanEngine 扫描引擎（参考 nmap timing.h 中的 ultra_timing_vals）
type ScanEngine struct {
	cwnd                 float64
	ssthresh             int
	numRepliesExpected   int
	numRepliesReceived   int
	numUpdates           int
	lastDrop             time.Time
	lowCwnd              int
	maxCwnd              int
	slowIncr             int
	caIncr               int
	groupDropCwndDivisor float64
	rttEstimate          time.Duration
	rttVariance          time.Duration
	timeout              time.Duration
}

func NewScanEngine() *ScanEngine {
	return &ScanEngine{
		cwnd:                 1,
		ssthresh:             100,
		numRepliesExpected:   0,
		numRepliesReceived:   0,
		numUpdates:           0,
		lastDrop:             time.Now(),
		lowCwnd:              1,
		maxCwnd:              100,
		slowIncr:             1,
		caIncr:               1,
		groupDropCwndDivisor: 2.0,
		rttEstimate:          100 * time.Millisecond,
		rttVariance:          50 * time.Millisecond,
		timeout:              3 * time.Second,
	}
}

func (e *ScanEngine) Acknowledge() {
	e.numRepliesReceived++
	e.numRepliesExpected++
	e.numUpdates++

	if e.cwnd < float64(e.ssthresh) {
		e.cwnd += float64(e.slowIncr)
	} else {
		e.cwnd += float64(e.caIncr) / e.cwnd
	}
	if e.cwnd > float64(e.maxCwnd) {
		e.cwnd = float64(e.maxCwnd)
	}
}

func (e *ScanEngine) Drop() {
	e.ssthresh = int(float64(e.cwnd) / e.groupDropCwndDivisor)
	if e.ssthresh < e.lowCwnd {
		e.ssthresh = e.lowCwnd
	}
	e.cwnd = float64(e.lowCwnd)
	e.lastDrop = time.Now()
}

func (e *ScanEngine) AdjustTimeout(rtt time.Duration) {
	alpha := 0.8
	beta := 1.2

	ewma := time.Duration(float64(e.rttEstimate)*alpha + float64(rtt)*(1-alpha))
	variance := time.Duration(math.Abs(float64(e.rttVariance)*beta - float64(e.rttVariance)*(1-beta)))

	e.rttEstimate = ewma
	e.rttVariance = variance
	e.timeout = e.rttEstimate + 4*e.rttVariance
}

func (e *ScanEngine) GetTimeout() time.Duration {
	return e.timeout
}

func (e *ScanEngine) GetCongestionWindow() int {
	return int(e.cwnd)
}

// PortList 端口列表管理（参考 nmap scan_lists.h）
type PortList struct {
	TCPPorts  []int
	UDPPorts  []int
	SCTPPorts []int
	Protocols []int
}

func NewPortList() *PortList {
	return &PortList{
		TCPPorts:  make([]int, 0),
		UDPPorts:  make([]int, 0),
		SCTPPorts: make([]int, 0),
		Protocols: make([]int, 0),
	}
}

func (p *PortList) AddPort(port int, protocol string) {
	switch protocol {
	case "tcp":
		p.TCPPorts = append(p.TCPPorts, port)
	case "udp":
		p.UDPPorts = append(p.UDPPorts, port)
	case "sctp":
		p.SCTPPorts = append(p.SCTPPorts, port)
	}
}

func (p *PortList) AddPortRange(start int, end int, protocol string) {
	for port := start; port <= end; port++ {
		p.AddPort(port, protocol)
	}
}

func (p *PortList) AddCommonPorts(protocol string) {
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
		443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432,
		5900, 6379, 8080, 8443, 27017}
	for _, port := range commonPorts {
		p.AddPort(port, protocol)
	}
}

func (p *PortList) GetPortCount(protocol string) int {
	switch protocol {
	case "tcp":
		return len(p.TCPPorts)
	case "udp":
		return len(p.UDPPorts)
	case "sctp":
		return len(p.SCTPPorts)
	default:
		return 0
	}
}

func (p *PortList) Sort(protocol string) {
	switch protocol {
	case "tcp":
		sort.Ints(p.TCPPorts)
	case "udp":
		sort.Ints(p.UDPPorts)
	case "sctp":
		sort.Ints(p.SCTPPorts)
	}
}

// ScanStats 扫描统计（参考 nmap timing.h 中的 RateMeter）
type ScanStats struct {
	totalPackets    int64
	receivedPackets int64
	startTime       time.Time
	currentRate     float64
	overallRate     float64
	mu              sync.Mutex
}

func NewScanStats() *ScanStats {
	return &ScanStats{
		totalPackets:    0,
		receivedPackets: 0,
		startTime:       time.Now(),
		currentRate:     0,
		overallRate:     0,
	}
}

func (s *ScanStats) Update(packets int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receivedPackets += packets
	elapsed := time.Since(s.startTime).Seconds()
	if elapsed > 0 {
		s.overallRate = float64(s.receivedPackets) / elapsed
	}
}

func (s *ScanStats) GetOverallRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overallRate
}

func (s *ScanStats) GetProgress() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.totalPackets == 0 {
		return 0
	}
	return float64(s.receivedPackets) / float64(s.totalPackets) * 100
}

// FingerprintMatcher OS指纹匹配（参考 nmap FPEngine.cc）
type FingerprintMatcher struct {
	osPatterns []*OSPattern
}

type OSPattern struct {
	Name         string
	Sequence     string
	TTL          int
	WindowSize   int
	ResponseType string
}

func NewFingerprintMatcher() *FingerprintMatcher {
	return &FingerprintMatcher{
		osPatterns: []*OSPattern{
			{Name: "Windows 10/11", TTL: 128, WindowSize: 64240, Sequence: "ECN"},
			{Name: "Windows Server 2016+", TTL: 128, WindowSize: 8192, Sequence: "ECN"},
			{Name: "Windows 7/8", TTL: 128, WindowSize: 65535, Sequence: "SEQ"},
			{Name: "Linux 2.6.x", TTL: 64, WindowSize: 5840, Sequence: "SEQ"},
			{Name: "Linux 3.x/4.x", TTL: 64, WindowSize: 14600, Sequence: "SEQ"},
			{Name: "Linux 5.x", TTL: 64, WindowSize: 29200, Sequence: "SEQ"},
			{Name: "FreeBSD", TTL: 64, WindowSize: 65535, Sequence: "SEQ"},
			{Name: "OpenBSD", TTL: 64, WindowSize: 16384, Sequence: "SEQ"},
			{Name: "macOS", TTL: 64, WindowSize: 65535, Sequence: "SEQ"},
			{Name: "Cisco IOS", TTL: 255, WindowSize: 4128, Sequence: "SEQ"},
			{Name: "Juniper JunOS", TTL: 64, WindowSize: 16384, Sequence: "SEQ"},
			{Name: "Android", TTL: 64, WindowSize: 5840, Sequence: "SEQ"},
		},
	}
}

func (m *FingerprintMatcher) Match(ttl int, windowSize int, responseType string) string {
	bestMatch := ""
	bestScore := 0

	for _, pattern := range m.osPatterns {
		score := 0
		if pattern.TTL == ttl {
			score += 30
		}
		if pattern.WindowSize == windowSize {
			score += 30
		}
		if strings.Contains(pattern.Sequence, responseType) {
			score += 40
		}
		if score > bestScore {
			bestScore = score
			bestMatch = pattern.Name
		}
	}

	if bestScore >= 50 {
		return bestMatch
	}
	return "Unknown"
}

// ServiceProbe 服务探测（参考 nmap service_scan.cc）
type ServiceProbe struct {
	Port       int
	Protocol   string
	Probes     []*Probe
	MatchOrder int
}

type Probe struct {
	Name     string
	Data     string
	Regexes  []*regexp.Regexp
	SSL      bool
	Priority int
}

func NewServiceProbe(port int, protocol string) *ServiceProbe {
	return &ServiceProbe{
		Port:       port,
		Protocol:   protocol,
		Probes:     make([]*Probe, 0),
		MatchOrder: 0,
	}
}

func (p *ServiceProbe) AddProbe(probe *Probe) {
	p.Probes = append(p.Probes, probe)
}

func (p *ServiceProbe) MatchBanner(banner string) (string, string) {
	for _, probe := range p.Probes {
		for _, re := range probe.Regexes {
			if match := re.FindStringSubmatch(banner); len(match) >= 2 {
				return probe.Name, match[1]
			}
		}
	}
	return "", ""
}

// DefaultServiceProbes 默认服务探测列表（参考 nmap service-probes）
var DefaultServiceProbes = []*ServiceProbe{
	{
		Port:     21,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "FTP",
				Data:     "FEAT\r\n",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)220[- ]`),
					regexp.MustCompile(`(?i)ftp.*(\d+\.\d+)`)},
			},
		},
	},
	{
		Port:     22,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "SSH",
				Data:     "SSH-2.0-\r\n",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)ssh-(\d+\.\d+)`),
					regexp.MustCompile(`(?i)openssh[_-](\d+\.\d+)`)},
			},
		},
	},
	{
		Port:     25,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "SMTP",
				Data:     "EHLO test\r\n",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)220[- ]`),
					regexp.MustCompile(`(?i)(postfix|exim|sendmail|qmail)`)},
			},
		},
	},
	{
		Port:     53,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "DNS",
				Data:     "",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)version.bind`),
					regexp.MustCompile(`(?i)(bind|named|powerdns)`)},
			},
		},
	},
	{
		Port:     80,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "HTTP",
				Data:     "GET / HTTP/1.0\r\n\r\n",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)server:`),
					regexp.MustCompile(`(?i)(apache|nginx|iis|lighttpd|caddy|tomcat)`)},
			},
		},
	},
	{
		Port:     443,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "HTTPS",
				Data:     "GET / HTTP/1.0\r\n\r\n",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)server:`),
					regexp.MustCompile(`(?i)(apache|nginx|iis|lighttpd)`)},
				SSL: true,
			},
		},
	},
	{
		Port:     3306,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "MySQL",
				Data:     "",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)mysql`),
					regexp.MustCompile(`(\d+\.\d+\.\d+)`)},
			},
		},
	},
	{
		Port:     3389,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "RDP",
				Data:     "",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)rdp`),
					regexp.MustCompile(`(?i)nla`)},
			},
		},
	},
	{
		Port:     5432,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "PostgreSQL",
				Data:     "",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)postgresql`),
					regexp.MustCompile(`(\d+\.\d+)`)},
			},
		},
	},
	{
		Port:     6379,
		Protocol: "tcp",
		Probes: []*Probe{
			{
				Name:     "Redis",
				Data:     "PING\r\n",
				Priority: 1,
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)redis`),
					regexp.MustCompile(`(\d+\.\d+)`)},
			},
		},
	},
}

// DetectService 检测服务（参考 nmap service_scan.cc）
func DetectService(port int, protocol string, banner string) (string, string, string) {
	for _, probe := range DefaultServiceProbes {
		if probe.Port == port && probe.Protocol == protocol {
			service, version := probe.MatchBanner(banner)
			if service != "" {
				return service, version, service
			}
		}
	}
	return "", "", ""
}

// HostGroup 主机组管理（参考 nmap TargetGroup.cc）
type HostGroup struct {
	Hosts    []string
	Current  int
	MaxSize  int
	Parallel bool
	mu       sync.Mutex
}

func NewHostGroup(maxSize int) *HostGroup {
	return &HostGroup{
		Hosts:   make([]string, 0),
		Current: 0,
		MaxSize: maxSize,
	}
}

func (g *HostGroup) AddHost(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Hosts = append(g.Hosts, host)
}

func (g *HostGroup) GetNextHost() (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.Current < len(g.Hosts) {
		host := g.Hosts[g.Current]
		g.Current++
		return host, true
	}
	return "", false
}

func (g *HostGroup) GetRemainingCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.Hosts) - g.Current
}

// TargetGroup 目标组管理
type TargetGroup struct {
	Groups [][]string
	Index  int
}

func NewTargetGroup() *TargetGroup {
	return &TargetGroup{
		Groups: make([][]string, 0),
		Index:  0,
	}
}

func (t *TargetGroup) AddTargets(targets []string) {
	t.Groups = append(t.Groups, targets)
}

func (t *TargetGroup) GetNextGroup() ([]string, bool) {
	if t.Index < len(t.Groups) {
		group := t.Groups[t.Index]
		t.Index++
		return group, true
	}
	return nil, false
}

// AdaptiveTimeout 自适应超时（参考 nmap timing.cc）
type AdaptiveTimeout struct {
	baseTimeout    time.Duration
	minTimeout     time.Duration
	maxTimeout     time.Duration
	currentTimeout time.Duration
	stats          *ScanStats
}

func NewAdaptiveTimeout(baseTimeout, minTimeout, maxTimeout time.Duration) *AdaptiveTimeout {
	return &AdaptiveTimeout{
		baseTimeout:    baseTimeout,
		minTimeout:     minTimeout,
		maxTimeout:     maxTimeout,
		currentTimeout: baseTimeout,
		stats:          NewScanStats(),
	}
}

func (a *AdaptiveTimeout) Adjust(successRate float64) {
	if successRate > 0.9 {
		a.currentTimeout = time.Duration(float64(a.currentTimeout) * 0.9)
	} else if successRate < 0.5 {
		a.currentTimeout = time.Duration(float64(a.currentTimeout) * 1.2)
	}

	if a.currentTimeout < a.minTimeout {
		a.currentTimeout = a.minTimeout
	}
	if a.currentTimeout > a.maxTimeout {
		a.currentTimeout = a.maxTimeout
	}
}

func (a *AdaptiveTimeout) GetTimeout() time.Duration {
	return a.currentTimeout
}

// NmapCompatScan 与Nmap兼容的扫描
type NmapCompatScan struct {
	Engine    *ScanEngine
	PortList  *PortList
	Stats     *ScanStats
	Timeout   *AdaptiveTimeout
	HostGroup *HostGroup
	FPMatcher *FingerprintMatcher
}

func NewNmapCompatScan() *NmapCompatScan {
	return &NmapCompatScan{
		Engine:    NewScanEngine(),
		PortList:  NewPortList(),
		Stats:     NewScanStats(),
		Timeout:   NewAdaptiveTimeout(3*time.Second, 100*time.Millisecond, 10*time.Second),
		HostGroup: NewHostGroup(50),
		FPMatcher: NewFingerprintMatcher(),
	}
}

func (s *NmapCompatScan) AddTargets(targets []string) {
	for _, target := range targets {
		s.HostGroup.AddHost(target)
	}
}

func (s *NmapCompatScan) AddPorts(start int, end int, protocol string) {
	s.PortList.AddPortRange(start, end, protocol)
}

func (s *NmapCompatScan) SetTimingTemplate(level int) {
	switch level {
	case 0:
		s.Engine.maxCwnd = 5
		s.Engine.slowIncr = 1
		s.Engine.groupDropCwndDivisor = 2.0
		s.Timeout.baseTimeout = 5 * time.Minute
	case 1:
		s.Engine.maxCwnd = 10
		s.Engine.slowIncr = 1
		s.Engine.groupDropCwndDivisor = 2.0
		s.Timeout.baseTimeout = 15 * time.Second
	case 2:
		s.Engine.maxCwnd = 20
		s.Engine.slowIncr = 1
		s.Engine.groupDropCwndDivisor = 2.0
		s.Timeout.baseTimeout = 400 * time.Millisecond
	case 3:
		s.Engine.maxCwnd = 50
		s.Engine.slowIncr = 1
		s.Engine.groupDropCwndDivisor = 2.0
		s.Timeout.baseTimeout = 3 * time.Second
	case 4:
		s.Engine.maxCwnd = 100
		s.Engine.slowIncr = 1
		s.Engine.groupDropCwndDivisor = 2.0
		s.Timeout.baseTimeout = 1 * time.Second
	case 5:
		s.Engine.maxCwnd = 200
		s.Engine.slowIncr = 1
		s.Engine.groupDropCwndDivisor = 2.0
		s.Timeout.baseTimeout = 500 * time.Millisecond
	}
}

// ReconScan 探测扫描（参考 nmap nmap.cc）
func (s *NmapCompatScan) ReconScan(ctx context.Context, target string, port int, protocol string) (*NmapResult, error) {
	result := &NmapResult{
		IP:     target,
		Ports:  make(map[int]PortInfo),
		Status: "down",
	}

	if !hostDiscovery(target, s.Timeout.GetTimeout()) {
		return result, nil
	}
	result.Status = "up"

	portInfo := PortInfo{
		Port:     port,
		Protocol: protocol,
		State:    PortStateFiltered,
	}

	switch protocol {
	case "tcp":
		if tcpConnect(target, port, s.Timeout.GetTimeout()) {
			portInfo.State = PortStateOpen
			portInfo.Banner = getBanner(target, port, s.Timeout.GetTimeout())
			portInfo.Service, portInfo.Version, _ = DetectService(port, protocol, portInfo.Banner)
		}
	case "udp":
		state := detectUDPPortState(target, port, s.Timeout.GetTimeout())
		portInfo.State = state
		if state == PortStateOpen {
			portInfo.Banner = getUDPBanner(target, port, s.Timeout.GetTimeout())
			portInfo.Service, portInfo.Version, _ = DetectService(port, protocol, portInfo.Banner)
		}
	}

	result.Ports[port] = portInfo
	return result, nil
}

// IdleScan 空闲扫描（参考 nmap idle_scan.cc）
type IdleScan struct {
	ZombieIP   string
	ZombiePort int
	ProbeIP    string
	ProbePort  int
	IDSequence []int
	CurrentID  int
	InitialID  int
}

func NewIdleScan(zombieIP string, zombiePort int) *IdleScan {
	return &IdleScan{
		ZombieIP:   zombieIP,
		ZombiePort: zombiePort,
		ProbeIP:    "",
		ProbePort:  0,
		IDSequence: make([]int, 0),
		CurrentID:  0,
		InitialID:  0,
	}
}

func (s *IdleScan) GetIPIDSequence() ([]int, error) {
	s.IDSequence = make([]int, 0)
	for i := 0; i < 5; i++ {
		id, err := s.getRemoteIPID(s.ZombieIP)
		if err != nil {
			return nil, err
		}
		s.IDSequence = append(s.IDSequence, id)
		time.Sleep(100 * time.Millisecond)
	}
	return s.IDSequence, nil
}

func (s *IdleScan) getRemoteIPID(ip string) (int, error) {
	cmd := exec.Command("nmap", "-O", "--osscan-limit", "-oX", "-", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	re := regexp.MustCompile(`ipidseq.*?(\d+)`)
	if match := re.FindStringSubmatch(string(output)); len(match) > 1 {
		id, _ := strconv.Atoi(match[1])
		return id, nil
	}
	return 0, nil
}

// NmapVersion 获取Nmap版本信息
func NmapVersion() string {
	cmd := exec.Command("nmap", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Nmap not found"
	}
	return strings.TrimSpace(string(output))
}
