package webfp

import "time"

type WebfpConfig struct {
	URL         string
	Timeout     time.Duration
	Verbose     bool
	Output      string
	UserAgent   string
	NoRedirect  bool
	MaxBodySize int64
}

type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence float64  `json:"confidence"`
	DetectedBy []string `json:"detected_by"`
}

type FingerprintRule struct {
	Name     string        `json:"name"`
	Category string        `json:"category"`
	Headers  []HeaderRule  `json:"headers,omitempty"`
	HTML     []ContentRule `json:"html,omitempty"`
	Scripts  []URLRule     `json:"scripts,omitempty"`
	CSS      []URLRule     `json:"css,omitempty"`
	Meta     []MetaRule    `json:"meta,omitempty"`
	Cookies  []CookieRule  `json:"cookies,omitempty"`
}

type HeaderRule struct {
	Header  string `json:"header"`
	Pattern string `json:"pattern"`
	Version string `json:"version,omitempty"`
}

type ContentRule struct {
	Selector string `json:"selector,omitempty"`
	Pattern  string `json:"pattern"`
	Version  string `json:"version,omitempty"`
}

type URLRule struct {
	Pattern string `json:"pattern"`
	Version string `json:"version,omitempty"`
}

type MetaRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Version string `json:"version,omitempty"`
}

type CookieRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern,omitempty"`
	Version string `json:"version,omitempty"`
}

type WebfpResult struct {
	URL          string            `json:"url"`
	Technologies []Technology      `json:"technologies"`
	Headers      map[string]string `json:"headers"`
	StatusCode   int               `json:"status_code"`
	Server       string            `json:"server,omitempty"`
	ResponseTime time.Duration     `json:"response_time"`
	Error        string            `json:"error,omitempty"`
}

type DetectionContext struct {
	Headers map[string]string
	Body    string
	Scripts []string
	CSS     []string
	Meta    map[string]string
	Cookies map[string]string
}
