package living

import (
	"fmt"
	"time"
)

type DetectType string

const (
	DetectTypePort  DetectType = "port"
	DetectTypeHTTP  DetectType = "http"
	DetectTypeICMP  DetectType = "icmp"
	DetectTypeSmart DetectType = "smart"
)

type FilterType string

const (
	FilterTypeNone    FilterType = "none"
	FilterTypeWAF     FilterType = "waf"
	FilterTypeSimHash FilterType = "simhash"
	FilterTypeCommon  FilterType = "common"
)

type ResultStatus string

const (
	StatusAlive    ResultStatus = "alive"
	StatusDead     ResultStatus = "dead"
	StatusFiltered ResultStatus = "filtered"
	StatusUnknown  ResultStatus = "unknown"
)

type LivingStats struct {
	TotalScanned  int            `json:"total_scanned"`
	TotalAlive    int            `json:"total_alive"`
	TotalFiltered int            `json:"total_filtered"`
	TotalWAF      int            `json:"total_waf"`
	SimilarGroups int            `json:"similar_groups"`
	ScannedIPs    []string       `json:"scanned_ips"`
	AliveIPs      []string       `json:"alive_ips"`
	FilteredIPs   []string       `json:"filtered_ips"`
	WAFBreakdown  map[string]int `json:"waf_breakdown"`
	ScanDuration  time.Duration  `json:"scan_duration"`
}

func (s *LivingStats) AddResult(r *LivingResult) {
	s.TotalScanned++

	if r.IsAlive && !r.IsFakeAlive {
		s.TotalAlive++
		s.AliveIPs = append(s.AliveIPs, r.Target.IP)
	} else if r.IsFakeAlive {
		s.TotalFiltered++
		s.FilteredIPs = append(s.FilteredIPs, r.Target.IP)
	}

	if r.WAFType != WAFNone {
		s.TotalWAF++
		wafName := string(r.WAFType)
		if s.WAFBreakdown == nil {
			s.WAFBreakdown = make(map[string]int)
		}
		s.WAFBreakdown[wafName]++
	}
}

func (s *LivingStats) String() string {
	return fmt.Sprintf(`扫描统计:
  总扫描目标: %d
  存活目标: %d
  过滤目标: %d (WAF/假死)
  WAF检测: %d
  相似页面组: %d
  扫描耗时: %v`,
		s.TotalScanned,
		s.TotalAlive,
		s.TotalFiltered,
		s.TotalWAF,
		s.SimilarGroups,
		s.ScanDuration)
}

type DetectOptions struct {
	Target       string
	Ports        string
	Threads      int
	Timeout      int
	EnableWAF    bool
	EnableSim    bool
	SimThreshold int
	WAFThreshold float64
	Output       string
	JSONOutput   bool
	Verbose      bool
}

func (o *DetectOptions) ToConfig() *LivingConfig {
	timeout := time.Duration(o.Timeout) * time.Second
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	threads := o.Threads
	if threads <= 0 {
		threads = 10
	}

	simThreshold := o.SimThreshold
	if simThreshold <= 0 {
		simThreshold = 10
	}

	wafThreshold := o.WAFThreshold
	if wafThreshold <= 0 {
		wafThreshold = 0.4
	}

	return &LivingConfig{
		Timeout:          timeout,
		Threads:          threads,
		EnableWAFDetect:  o.EnableWAF,
		EnableSimHash:    o.EnableSim,
		SimHashThreshold: simThreshold,
		WAFThreshold:     wafThreshold,
	}
}

var _ = fmt.Sprintf
var _ = time.Duration(0)
