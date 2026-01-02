package honeypot

import (
	"time"
)

type ScanMode string

const (
	QuickScan ScanMode = "quick"
	DeepScan  ScanMode = "deep"
)

type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Config struct {
	Target       string
	Ports        string
	Mode         ScanMode
	OutputFormat OutputFormat
	Threads      int
	Timeout      int
	ConfigPath   string
	Verbose      bool
}

type DetectionResult struct {
	Target           string            `json:"target"`
	Port             int               `json:"port"`
	Service          string            `json:"service"`
	Confidence       int               `json:"confidence"`
	RiskLevel        RiskLevel         `json:"risk_level"`
	HoneypotType     string            `json:"honeypot_type"`
	IsHoneypot       bool              `json:"is_honeypot"`
	MatchedFeatures  []MatchedFeature  `json:"matched_features"`
	Suggestion       string            `json:"suggestion"`
	ScanDuration     time.Duration     `json:"scan_duration"`
	ScanMode         ScanMode          `json:"scan_mode"`
	ServiceInfo      *ServiceInfo      `json:"service_info,omitempty"`
	BehaviorAnalysis *BehaviorAnalysis `json:"behavior_analysis,omitempty"`
}

type MatchedFeature struct {
	Name        string `json:"name"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

type ServiceInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner"`
	Version  string `json:"version"`
	OS       string `json:"os,omitempty"`
}

type BehaviorAnalysis struct {
	ResponseTimeFixed    bool   `json:"response_time_fixed"`
	OperationRestricted  bool   `json:"operation_restricted"`
	ProtocolInconsistent bool   `json:"protocol_inconsistent"`
	Details              string `json:"details"`
}

type Signature struct {
	Name        string           `json:"name"`
	Category    string           `json:"category"`
	Service     string           `json:"service"`
	Patterns    []Pattern        `json:"patterns"`
	Weight      int              `json:"weight"`
	Description string           `json:"description"`
}

type Pattern struct {
	Type      string `json:"type"`
	Pattern   string `json:"pattern"`
	Field     string `json:"field"`
	Condition string `json:"condition"`
}

type SignatureSet struct {
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Signatures  []Signature `json:"signatures"`
	UpdatedTime time.Time   `json:"updated_time"`
}

type ScanState struct {
	TotalTargets   int
	ScannedTargets int
	CurrentTarget  string
	StartTime      time.Time
	Results        []*DetectionResult
}

func NewDetectionResult(target string, port int) *DetectionResult {
	return &DetectionResult{
		Target:          target,
		Port:            port,
		MatchedFeatures: make([]MatchedFeature, 0),
	}
}

func CalculateRiskLevel(confidence int) RiskLevel {
	switch {
	case confidence >= 80:
		return RiskCritical
	case confidence >= 60:
		return RiskHigh
	case confidence >= 40:
		return RiskMedium
	default:
		return RiskLow
	}
}
