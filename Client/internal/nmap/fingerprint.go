package nmap

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type OSScanConfig struct {
	GuessMode         bool
	MaxAttempts       int
	Timeout           time.Duration
	MinParallelism    int
	MaxParallelism    int
	OSClass           []*OSClass
	ReferenceVersions []*ReferenceVersion
}

type OSClass struct {
	Type     string
	Vendor   string
	OSFamily string
	OSGen    string
	CPE      []string
}

type ReferenceVersion struct {
	Product string
	Version string
	CPE     string
	OSType  string
}

type OSScanResult struct {
	OSMatches []*OSMatch
	UsedPorts []int
	Finished  bool
	StartTime time.Time
	EndTime   time.Time
}

type OSMatch struct {
	Name     string
	Line     string
	Accuracy float64
	Class    []*OSClass
}

type TCPISeq struct {
	Index          int
	Values         []int
	ResponseErrors []string
}

type TCPMISC struct {
	WindowSize     int
	Options        string
	ResponseErrors []string
}

type IPIDSeq struct {
	SequenceClass  string
	Values         []int
	ResponseErrors []string
}

type Fingerprint struct {
	Port         int
	Protocol     string
	TCPSequence  *TCPISeq
	TCPResponse  string
	TCPMISC      *TCPMISC
	IPIDSequence *IPIDSeq
	ICMPSequence string
	Service      string
	Difficult    bool
}

type FPEngine struct {
	Config       *OSScanConfig
	Fingerprints []*Fingerprint
	mu           sync.Mutex
	Stats        *OSScanStats
}

type OSScanStats struct {
	ProbesSent     int
	ProbesReceived int
	TCPOk          int
	TCPFailed      int
	IPIDOk         int
	IPIDFailed     int
}

func NewFPEngine() *FPEngine {
	engine := &FPEngine{
		Config: &OSScanConfig{
			GuessMode:      true,
			MaxAttempts:    2,
			Timeout:        5 * time.Second,
			MinParallelism: 1,
			MaxParallelism: 10,
		},
		Fingerprints: make([]*Fingerprint, 0),
		Stats:        &OSScanStats{},
	}

	engine.loadOSFingerprints()

	return engine
}

func (e *FPEngine) loadOSFingerprints() {
	osFingerprints := []*Fingerprint{
		{
			Port:     80,
			Protocol: "tcp",
			TCPSequence: &TCPISeq{
				Index:          100,
				Values:         []int{1000, 2000, 3000, 4000},
				ResponseErrors: []string{},
			},
			IPIDSequence: &IPIDSeq{
				SequenceClass: "Increasing",
				Values:        []int{1, 2, 3, 4},
			},
		},
		{
			Port:     22,
			Protocol: "tcp",
			TCPSequence: &TCPISeq{
				Index:          100,
				Values:         []int{5000, 10000, 15000, 20000},
				ResponseErrors: []string{},
			},
			IPIDSequence: &IPIDSeq{
				SequenceClass: "Random positive increments",
				Values:        []int{12345, 56789, 98765, 54321},
			},
		},
		{
			Port:     443,
			Protocol: "tcp",
			TCPSequence: &TCPISeq{
				Index:          100,
				Values:         []int{100, 200, 300, 400},
				ResponseErrors: []string{},
			},
			IPIDSequence: &IPIDSeq{
				SequenceClass: "Slowly increasing",
				Values:        []int{5000, 5100, 5200, 5300},
			},
		},
	}

	e.Fingerprints = osFingerprints
}

func (e *FPEngine) Scan(ctx context.Context, target string, ports []int) *OSScanResult {
	result := &OSScanResult{
		OSMatches: make([]*OSMatch, 0),
		UsedPorts: ports,
		Finished:  false,
		StartTime: time.Now(),
	}

	e.mu.Lock()
	e.Stats.ProbesSent = 0
	e.Stats.ProbesReceived = 0
	e.mu.Unlock()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, e.Config.MaxParallelism)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			result.EndTime = time.Now()
			return result
		default:
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fp := e.probePort(target, p)
			if fp != nil {
				e.mu.Lock()
				e.Fingerprints = append(e.Fingerprints, fp)
				e.Stats.ProbesReceived++
				e.mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	e.analyzeFingerprints(result)

	result.EndTime = time.Now()
	result.Finished = true

	return result
}

func (e *FPEngine) probePort(target string, port int) *Fingerprint {
	fp := &Fingerprint{
		Port:     port,
		Protocol: "tcp",
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), e.Config.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	fp.TCPMISC = &TCPMISC{
		WindowSize: 65535,
		Options:    "MSS",
	}

	fp.IPIDSequence = e.getIPIDSequence(target)

	return fp
}

func (e *FPEngine) getIPIDSequence(target string) *IPIDSeq {
	ipid := &IPIDSeq{
		SequenceClass: "Unknown",
		Values:        make([]int, 0),
	}

	for i := 0; i < 4; i++ {
		conn, err := net.DialTimeout("ip4:icmp", target, 100*time.Millisecond)
		if err != nil {
			continue
		}
		defer conn.Close()

		icmpMsg := []byte{8, 0, 0, 0, 0, 0, 0, 0}
		conn.Write(icmpMsg)

		buf := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _ := conn.Read(buf)

		if n > 8 {
			ipid.Values = append(ipid.Values, int(buf[8]))
		}
	}

	if len(ipid.Values) >= 2 {
		if ipid.Values[1] > ipid.Values[0] && ipid.Values[2] > ipid.Values[1] {
			ipid.SequenceClass = "Increasing"
		} else if ipid.Values[0] == 0 {
			ipid.SequenceClass = "All zeros"
		} else if ipid.Values[0] == ipid.Values[1] && ipid.Values[1] == ipid.Values[2] {
			ipid.SequenceClass = "Constant"
		} else {
			ipid.SequenceClass = "Random"
		}
	}

	return ipid
}

func (e *FPEngine) analyzeFingerprints(result *OSScanResult) {
	osDatabase := e.getOSDatabase()

	for _, fp := range e.Fingerprints {
		for _, os := range osDatabase {
			accuracy := e.calculateMatchAccuracy(fp, os)
			if accuracy > 0.7 {
				match := &OSMatch{
					Name:     os.Name,
					Line:     os.Description,
					Accuracy: accuracy * 100,
					Class:    os.Classes,
				}
				result.OSMatches = append(result.OSMatches, match)
			}
		}
	}

	sort.Slice(result.OSMatches, func(i, j int) bool {
		return result.OSMatches[i].Accuracy > result.OSMatches[j].Accuracy
	})
}

type OSDatabaseEntry struct {
	Name        string
	Description string
	Classes     []*OSClass
	TCPSeq      []int
	IPIDClass   string
	WindowSize  int
}

func (e *FPEngine) getOSDatabase() []*OSDatabaseEntry {
	return []*OSDatabaseEntry{
		{
			Name:        "Microsoft Windows 10",
			Description: "Microsoft Windows 10",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Microsoft", OSFamily: "Windows", OSGen: "10"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 64240,
		},
		{
			Name:        "Microsoft Windows Server 2016",
			Description: "Microsoft Windows Server 2016",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Microsoft", OSFamily: "Windows", OSGen: "Server 2016"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 8192,
		},
		{
			Name:        "Linux 3.10",
			Description: "Linux 3.10.x",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "The Linux Project", OSFamily: "Linux", OSGen: "3.10"},
			},
			TCPSeq:     []int{5000, 10000, 15000, 20000},
			IPIDClass:  "Random positive increments",
			WindowSize: 14600,
		},
		{
			Name:        "Linux 4.15",
			Description: "Linux 4.15.x",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "The Linux Project", OSFamily: "Linux", OSGen: "4.15"},
			},
			TCPSeq:     []int{5000, 10000, 15000, 20000},
			IPIDClass:  "Random positive increments",
			WindowSize: 29200,
		},
		{
			Name:        "Linux 5.4",
			Description: "Linux 5.4.x",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "The Linux Project", OSFamily: "Linux", OSGen: "5.4"},
			},
			TCPSeq:     []int{5000, 10000, 15000, 20000},
			IPIDClass:  "Random positive increments",
			WindowSize: 29200,
		},
		{
			Name:        "FreeBSD 12.1",
			Description: "FreeBSD 12.1-RELEASE",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "The FreeBSD Project", OSFamily: "FreeBSD", OSGen: "12.1"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 65535,
		},
		{
			Name:        "OpenBSD 7.0",
			Description: "OpenBSD 7.0",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "The OpenBSD Project", OSFamily: "OpenBSD", OSGen: "7.0"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 16384,
		},
		{
			Name:        "Apple macOS 11.0",
			Description: "Apple macOS 11.0 Big Sur",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Apple", OSFamily: "Mac OS X", OSGen: "11.0"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Random positive increments",
			WindowSize: 65535,
		},
		{
			Name:        "Cisco IOS 15.2",
			Description: "Cisco IOS 15.2",
			Classes: []*OSClass{
				{Type: "router", Vendor: "Cisco", OSFamily: "Cisco IOS", OSGen: "15.2"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 4128,
		},
		{
			Name:        "Juniper JunOS 20.3",
			Description: "Juniper JunOS 20.3",
			Classes: []*OSClass{
				{Type: "router", Vendor: "Juniper", OSFamily: "JunOS", OSGen: "20.3"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 16384,
		},
		{
			Name:        "Android 11",
			Description: "Android 11",
			Classes: []*OSClass{
				{Type: "phone", Vendor: "Google", OSFamily: "Android", OSGen: "11"},
			},
			TCPSeq:     []int{5000, 10000, 15000, 20000},
			IPIDClass:  "Random positive increments",
			WindowSize: 5840,
		},
		{
			Name:        "Microsoft Windows 7",
			Description: "Microsoft Windows 7 SP1",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Microsoft", OSFamily: "Windows", OSGen: "7"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 65535,
		},
		{
			Name:        "Microsoft Windows 8.1",
			Description: "Microsoft Windows 8.1",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Microsoft", OSFamily: "Windows", OSGen: "8.1"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 65535,
		},
		{
			Name:        "Microsoft Windows Server 2012 R2",
			Description: "Microsoft Windows Server 2012 R2",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Microsoft", OSFamily: "Windows", OSGen: "Server 2012"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 65535,
		},
		{
			Name:        "Microsoft Windows Server 2019",
			Description: "Microsoft Windows Server 2019",
			Classes: []*OSClass{
				{Type: "general purpose", Vendor: "Microsoft", OSFamily: "Windows", OSGen: "Server 2019"},
			},
			TCPSeq:     []int{1000, 2000, 3000, 4000},
			IPIDClass:  "Increasing",
			WindowSize: 8192,
		},
	}
}

func (e *FPEngine) calculateMatchAccuracy(fp *Fingerprint, os *OSDatabaseEntry) float64 {
	accuracy := 0.0

	if fp.IPIDSequence != nil {
		if fp.IPIDSequence.SequenceClass == os.IPIDClass {
			accuracy += 0.3
		}
	}

	if fp.TCPMISC != nil {
		if fp.TCPMISC.WindowSize == os.WindowSize {
			accuracy += 0.3
		}
	}

	if fp.TCPSequence != nil && len(os.TCPSeq) >= 2 {
		if len(fp.TCPSequence.Values) >= 2 {
			accuracy += 0.2
		}
	}

	if accuracy > 1.0 {
		accuracy = 1.0
	}

	return accuracy
}

func (e *FPEngine) GetBestMatch(result *OSScanResult) string {
	if len(result.OSMatches) == 0 {
		return "Unknown"
	}
	return result.OSMatches[0].Name
}
