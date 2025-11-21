package waf

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// WAF特征定义
type WAF struct {
	Name                string   `json:"name"`
	Vendor              string   `json:"vendor"`
	ConfidenceThreshold int      `json:"confidence_threshold"`
	Features            []Feature `json:"features"`
}


// 特征定义
type Feature struct {
	Type       string      `json:"type"` // response_header, ssl_certificate, response_content, active_detect
	Key        string      `json:"key,omitempty"`
	Field      string      `json:"field,omitempty"`
	Value      string      `json:"value,omitempty"`
	MatchType  string      `json:"match_type,omitempty"` // exists, contains, exact, regex
	Weight     int         `json:"weight"`
	Request    *Request    `json:"request,omitempty"`
	RespCheck  *RespCheck  `json:"response_check,omitempty"`
}


// 请求定义
type Request struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	UserAgent string `json:"user_agent"`
}

// 响应检查定义
type RespCheck struct {
	StatusCode     int    `json:"status_code,omitempty"`
	ContentContains string `json:"content_contains,omitempty"`
	HeaderExists   string `json:"header_exists,omitempty"`
}

// WAF规则配置
type WAFConfig struct {
	WAFList []WAF `json:"waf_list"`
}

// 探测结果
type WAFResult struct {
	Target       string `json:"target"`        // 检测目标
	Detected     bool   `json:"detected"`      // 是否检测到WAF
	WAFName      string `json:"waf_name"`      // WAF名称
	Vendor       string `json:"vendor"`        // 厂商
	Confidence   int    `json:"confidence"`    // 置信度
	Description  string `json:"description"`   // 描述
	ErrorMessage string `json:"error_message"` // 错误信息
}

// 采集的信息
type TargetInfo struct {
	URL            string
	Headers        http.Header
	StatusCode     int
	ResponseBody   string
	CertIssuer     string
	CertSubject    string
	CertSerial     string
	TTL            int
	TCPWindowSize  int
}

// WAF识别器接口
type WAFDetector interface {
	LoadRules(rulesPath string) error
	DetectTarget(target string) (*WAFResult, error)
	DetectTargets(targets []string, concurrency int) []*WAFResult
}

// 默认HTTP客户端配置
func NewHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 1 * time.Second,
		}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
}