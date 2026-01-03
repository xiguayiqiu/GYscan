package patchcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/streadway/amqp"
)

type ComponentType string

const (
	TypeWebServer    ComponentType = "webserver"
	TypeDatabase     ComponentType = "database"
	TypeMiddleware   ComponentType = "middleware"
	TypeCacheMessage ComponentType = "cachemessage"
)

type ComponentInfo struct {
	Name            string            `json:"name"`
	Type            ComponentType     `json:"type"`
	Version         string            `json:"version"`
	Port            int               `json:"port"`
	Protocol        string            `json:"protocol"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	PatchStatus     PatchStatus       `json:"patch_status"`
	Fingerprints    []Fingerprint     `json:"fingerprints"`
	Headers         map[string]string `json:"headers,omitempty"`
	HTMLTitle       string            `json:"html_title,omitempty"`
	Technologies    []string          `json:"technologies,omitempty"`
}

type Fingerprint struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
}

type Vulnerability struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	CVE          string `json:"cve"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixed_version"`
	Description  string `json:"description"`
}

type PatchStatus struct {
	IsPatched       bool     `json:"is_patched"`
	LastCheck       string   `json:"last_check"`
	RiskLevel       string   `json:"risk_level"`
	Recommendations []string `json:"recommendations"`
}

type WebFingerprint struct {
	Name        string
	Category    string
	Patterns    []FingerprintPattern
	VersionRE   string
	Description string
}

type FingerprintPattern struct {
	Type  string
	Value string
	Field string
}

var FingerprintDB []WebFingerprint

type Scanner struct {
	Timeout        time.Duration
	Verbose        bool
	Threads        int
	RateLimit      int
	Aggression     int
	UserAgent      string
	Headers        []string
	Cookies        string
	Proxy          string
	FollowRedirect string
	MaxRedirects   int
}

func NewScanner(timeout time.Duration, verbose bool, threads, rateLimit int) *Scanner {
	return NewScannerWithOptions(timeout, verbose, threads, rateLimit, 1, "", []string{}, "", "", "always", 10)
}

func NewScannerWithOptions(timeout time.Duration, verbose bool, threads, rateLimit int,
	aggression int, userAgent string, headers []string, cookies string,
	proxy string, followRedirect string, maxRedirects int) *Scanner {
	scanner := &Scanner{
		Timeout:        timeout,
		Verbose:        verbose,
		Threads:        threads,
		RateLimit:      rateLimit,
		Aggression:     aggression,
		UserAgent:      userAgent,
		Headers:        headers,
		Cookies:        cookies,
		Proxy:          proxy,
		FollowRedirect: followRedirect,
		MaxRedirects:   maxRedirects,
	}
	initFingerprintDB()
	AddWhatWebFingerprintsToDB()
	return scanner
}

func initFingerprintDB() {
	FingerprintDB = []WebFingerprint{
		{
			Name:     "Nginx",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "nginx", Field: "Server"},
				{Type: "header", Value: "nginx", Field: "X-Powered-By"},
			},
			VersionRE: `nginx[/\s]?([\d.]+)`,
		},
		{
			Name:     "Apache",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "apache", Field: "Server"},
				{Type: "header", Value: "Apache", Field: "Server"},
			},
			VersionRE: `Apache[/\s]?([\d.]+)`,
		},
		{
			Name:     "Microsoft IIS",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "microsoft-iis", Field: "Server"},
			},
			VersionRE: `Microsoft-IIS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Tomcat",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "tomcat", Field: "Server"},
				{Type: "header", Value: "Apache-Coyote", Field: "Server"},
			},
			VersionRE: `Tomcat[/\s]?([\d.]+)`,
		},
		{
			Name:     "Jetty",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "jetty", Field: "Server"},
			},
			VersionRE: `Jetty[/\s]?([\d.]+)`,
		},
		{
			Name:     "WebLogic",
			Category: "Application Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "weblogic", Field: "Server"},
				{Type: "header", Value: "WebLogic", Field: "X-Powered-By"},
			},
			VersionRE: `WebLogic[/\s]?([\d.]+)`,
		},
		{
			Name:     "Resin",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "resin", Field: "Server"},
			},
			VersionRE: `Resin[/\s]?([\d.]+)`,
		},
		{
			Name:     "Lighttpd",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "lighttpd", Field: "Server"},
			},
			VersionRE: `lighttpd[/\s]?([\d.]+)`,
		},
		{
			Name:     "PHP",
			Category: "Scripting Language",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "php", Field: "X-Powered-By"},
				{Type: "cookie", Value: "PHPSESSID"},
			},
			VersionRE: `PHP[/\s]?([\d.]+)`,
		},
		{
			Name:     "ASP.NET",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "asp.net", Field: "X-Powered-By"},
				{Type: "header", Value: "ASP.NET", Field: "X-Powered-By"},
			},
			VersionRE: `ASP.NET[/\s]?([\d.]+)`,
		},
		{
			Name:     "Java Servlet",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "servlet", Field: "X-Powered-By"},
				{Type: "header", Value: "JSP", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Node.js",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "node", Field: "X-Powered-By"},
			},
			VersionRE: `Node\.js[/\s]?([\d.]+)`,
		},
		{
			Name:     "Python",
			Category: "Runtime Environment",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "python", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Ruby on Rails",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rails", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "React",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "react"},
				{Type: "html", Value: "_reactRootContainer"},
			},
		},
		{
			Name:     "Vue.js",
			Category: "JavaScript Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vue"},
				{Type: "html", Value: "__vue__"},
			},
		},
		{
			Name:     "jQuery",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "jquery"},
				{Type: "html", Value: "jQuery"},
				{Type: "html", Value: "/jquery"},
				{Type: "html", Value: "jquery-ui"},
				{Type: "html", Value: "jquery.js"},
				{Type: "html", Value: "jquery.min.js"},
				{Type: "html", Value: "cdn.jquery"},
			},
			VersionRE: `jquery[/-]?([\d.]+)`,
		},
		{
			Name:     "Bootstrap",
			Category: "CSS Framework",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "bootstrap"},
				{Type: "html", Value: "bootstrap.min.css"},
			},
			VersionRE: `bootstrap[/\s]?([\d.]+)`,
		},
		{
			Name:     "WordPress",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wordpress"},
				{Type: "meta", Value: "wordpress"},
				{Type: "cookie", Value: "wordpress"},
			},
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drupal"},
				{Type: "meta", Value: "drupal"},
			},
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "joomla"},
				{Type: "meta", Value: "joomla"},
			},
		},
		{
			Name:     "ThinkPHP",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "thinkphp", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Struts",
			Category: "Java Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "struts", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Spring",
			Category: "Java Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "spring", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "OpenResty",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "openresty", Field: "Server"},
			},
			VersionRE: `openresty[/\s]?([\d.]+)`,
		},
		{
			Name:     "Caddy",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "caddy", Field: "Server"},
			},
			VersionRE: `Caddy[/\s]?([\d.]+)`,
		},
		{
			Name:     "Cloudflare",
			Category: "CDN/WAF",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cloudflare", Field: "Server"},
				{Type: "header", Value: "cf-ray", Field: ""},
			},
		},
		{
			Name:     "Akamai",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "akamai", Field: "Server"},
			},
		},
		{
			Name:     "BWS",
			Category: "Web Server",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "bws", Field: "Server"},
			},
			VersionRE: `BWS[/\s]?([\d.]+)`,
		},
		{
			Name:     "Baidu",
			Category: "Search Engine",
			Patterns: []FingerprintPattern{
				{Type: "cookie", Value: "BAIDUID"},
				{Type: "cookie", Value: "BIDUPSID"},
				{Type: "cookie", Value: "PSTM"},
				{Type: "cookie", Value: "BDSVRTM"},
				{Type: "cookie", Value: "BD_HOME"},
			},
		},
		{
			Name:     "HTML5",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "<!DOCTYPE html"},
				{Type: "html", Value: "<!doctype html"},
			},
		},
		{
			Name:     "OpenSearch",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "opensearch"},
				{Type: "html", Value: "application/opensearchdescription+xml"},
			},
		},
		{
			Name:     "X-UA-Compatible",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-ua-compatible", Field: ""},
				{Type: "html", Value: "x-ua-compatible"},
			},
		},
		{
			Name:     "X-XSS-Protection",
			Category: "Security Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-xss-protection", Field: ""},
			},
		},
		{
			Name:     "CDN-Cache-Server",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "cdn cache server", Field: "Server"},
				{Type: "header", Value: "cdn cache", Field: "X-Via"},
			},
			VersionRE: `CDN[/\s]?Cache[/\s]?Server[/\s]?V?([\d.]+)`,
		},
		{
			Name:     "X-Cache",
			Category: "CDN",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-cache", Field: ""},
			},
		},
		{
			Name:     "PasswordField",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<input type="password"`},
				{Type: "html", Value: `type="password"`},
			},
		},
		{
			Name:     "Script",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<script`},
				{Type: "html", Value: `text/javascript`},
				{Type: "html", Value: `text/x-handlebars-template`},
			},
		},
		{
			Name:     "X-Via",
			Category: "Proxy Header",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-via", Field: ""},
			},
		},
		{
			Name:     "UncommonHeaders",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "x-ws-request-id", Field: ""},
			},
		},
		{
			Name:     "Handlebars",
			Category: "JavaScript Template",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "handlebars"},
				{Type: "html", Value: "x-handlebars-template"},
			},
		},
		{
			Name:     "Prototype",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "prototype.js"},
				{Type: "html", Value: "prototype-"},
			},
			VersionRE: `prototype[/-]?([\d.]+)`,
		},
		{
			Name:     "MooTools",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "mootools"},
				{Type: "html", Value: "mootools-core"},
			},
			VersionRE: `mootools[/\s]?([\d.]+)`,
		},
		{
			Name:     "Modernizr",
			Category: "JavaScript Library",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "modernizr"},
				{Type: "html", Value: "modernizr.js"},
			},
			VersionRE: `modernizr[/\s]?([\d.]+)`,
		},
		{
			Name:     "Moodle",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "moodle"},
				{Type: "html", Value: "mod Moodle"},
				{Type: "header", Value: "moodle", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "phpBB",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "phpbb"},
				{Type: "cookie", Value: "phpbb"},
			},
		},
		{
			Name:     "vBulletin",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "vbulletin"},
				{Type: "cookie", Value: "bb"},
			},
		},
		{
			Name:     "Discuz",
			Category: "Forum",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "discuz"},
				{Type: "html", Value: "comsenz"},
			},
		},
		{
			Name:     "WordPress",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "wordpress"},
				{Type: "meta", Value: "wordpress"},
				{Type: "cookie", Value: "wordpress"},
				{Type: "header", Value: "wordpress", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "drupal"},
				{Type: "meta", Value: "drupal"},
				{Type: "cookie", Value: "drupal"},
			},
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "joomla"},
				{Type: "meta", Value: "joomla"},
				{Type: "cookie", Value: "joomla"},
			},
		},
		{
			Name:     "Magento",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "magento"},
				{Type: "cookie", Value: "magento"},
			},
		},
		{
			Name:     "Shopify",
			Category: "E-Commerce",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "shopify"},
				{Type: "header", Value: "shopify", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Django",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "django", Field: "X-Powered-By"},
				{Type: "html", Value: "csrfmiddlewaretoken"},
			},
		},
		{
			Name:     "Laravel",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "laravel", Field: "X-Powered-By"},
				{Type: "html", Value: "laravel"},
			},
		},
		{
			Name:     "CodeIgniter",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "codeigniter", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "ThinkPHP",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "thinkphp", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Yii",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "yii", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Rails",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "rails", Field: "X-Powered-By"},
				{Type: "cookie", Value: "_rails"},
			},
		},
		{
			Name:     "Express",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "express", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "Flask",
			Category: "Web Framework",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "werkzeug", Field: "X-Powered-By"},
			},
		},
		{
			Name:     "WebSocket",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "upgrade", Field: ""},
			},
		},
		{
			Name:     "GZIP",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "gzip", Field: "Content-Encoding"},
			},
		},
		{
			Name:     "Deflate",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "deflate", Field: "Content-Encoding"},
			},
		},
		{
			Name:     "Vary",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "vary", Field: ""},
			},
		},
		{
			Name:     "ETag",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "header", Value: "etag", Field: ""},
			},
		},
		{
			Name:     "Meta-Refresh",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<meta[^>]*http-equiv=["']?refresh["']?`},
			},
		},
		{
			Name:     "Favicon",
			Category: "Web Technology",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: `<link[^>]*rel=["']?icon["']?`},
				{Type: "html", Value: `<link[^>]*href=["']?[^>]*\.ico["']?`},
			},
		},
		{
			Name:     "Google-Analytics",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "google-analytics.com"},
				{Type: "html", Value: "ga.js"},
				{Type: "html", Value: "gtag"},
			},
		},
		{
			Name:     "Baidu-Tongji",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "hm.js"},
				{Type: "html", Value: "tongji.baidu.com"},
			},
		},
		{
			Name:     "CNZZ",
			Category: "Analytics",
			Patterns: []FingerprintPattern{
				{Type: "html", Value: "cnzz.com"},
				{Type: "html", Value: "z5.cnzz.com"},
			},
		},
	}
}

func (s *Scanner) ScanTarget(target string, ports []int) []ComponentInfo {
	var components []ComponentInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout*time.Duration(len(ports)))
	defer cancel()

	resultChan := make(chan *ComponentInfo, len(ports))

	host := extractHost(target)
	isHTTPS := strings.HasPrefix(strings.ToLower(target), "https")

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if comp := s.scanPort(host, p, isHTTPS); comp != nil {
				select {
				case resultChan <- comp:
				case <-ctx.Done():
				}
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for comp := range resultChan {
		mu.Lock()
		components = append(components, *comp)
		mu.Unlock()
		if s.Verbose {
			fmt.Printf("[+] 发现组件: %s %s (端口: %d)\n", comp.Name, comp.Version, comp.Port)
		}
	}

	return components
}

func (s *Scanner) scanPort(target string, port int, isHTTPS bool) *ComponentInfo {
	var component *ComponentInfo

	scheme := "http"
	if isHTTPS || port == 443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, target, port)

	switch port {
	case 80, 443, 8080, 8009, 7001, 7002:
		component = s.detectWebServer(url, port)
	case 3306:
		component = s.detectMySQL(target, port)
	case 5432:
		component = s.detectPostgreSQL(target, port)
	case 1433:
		component = s.detectSQLServer(target, port)
	case 1521:
		component = s.detectOracle(target, port)
	case 6379:
		component = s.detectRedis(target, port)
	case 5672:
		component = s.detectRabbitMQ(target, port)
	case 11211:
		component = s.detectMemcached(target, port)
	}

	if component != nil {
		component.Port = port
		s.analyzePatchStatus(component)
	}

	return component
}

func (s *Scanner) detectWebServer(url string, port int) *ComponentInfo {
	resp, err := s.sendHTTPRequest(url)
	if err != nil {
		return nil
	}

	fingerprints := s.fingerprintWebServer(resp)
	if len(fingerprints) == 0 {
		return nil
	}

	fingerprints = deduplicateFingerprints(fingerprints)

	name := fingerprints[0].Name
	version := s.extractVersion(resp.Header.Get("Server"), "")

	for _, fp := range fingerprints {
		if fp.Category == "Web Server" || fp.Category == "Application Server" {
			name = fp.Name
			for _, wf := range FingerprintDB {
				if wf.Name == fp.Name && wf.VersionRE != "" {
					version = s.extractVersion(resp.Header.Get("Server"), wf.VersionRE)
					break
				}
			}
			break
		}
	}

	var technologies []string
	techSet := make(map[string]bool)
	for _, fp := range fingerprints {
		if fp.Category != "Web Server" && fp.Category != "Application Server" {
			key := fmt.Sprintf("%s (%d%%)", fp.Name, fp.Confidence)
			if !techSet[key] {
				techSet[key] = true
				technologies = append(technologies, key)
			}
		}
	}

	scheme := "http"
	if strings.HasPrefix(strings.ToLower(url), "https") || port == 443 {
		scheme = "https"
	}

	return &ComponentInfo{
		Name:         name,
		Type:         TypeWebServer,
		Version:      version,
		Protocol:     scheme,
		Fingerprints: fingerprints,
		Headers:      resp.Header,
		HTMLTitle:    resp.Title,
		Technologies: technologies,
	}
}

func (s *Scanner) sendHTTPRequest(url string) (*WebResponse, error) {
	resp, err := s.sendHTTPRequestRaw(url, 0)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Scanner) sendHTTPRequestRaw(url string, redirectCount int) (*WebResponse, error) {
	if redirectCount > s.MaxRedirects {
		return nil, fmt.Errorf("too many redirects (max: %d)", s.MaxRedirects)
	}

	shouldFollow := s.shouldFollowRedirect()
	if !shouldFollow {
		redirectCount = s.MaxRedirects + 1
	}

	conn, err := s.createConnection(url)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.Timeout))

	path := extractPath(url)
	reqStr := s.buildHTTPRequest(url, path)

	conn.Write([]byte(reqStr))

	reader := bufio.NewReader(conn)

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(statusLine, "HTTP/") {
		return nil, fmt.Errorf("invalid HTTP response: %s", strings.TrimSpace(statusLine))
	}

	statusCode := 0
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) >= 2 {
		statusCode, _ = strconv.Atoi(parts[1])
	}

	tp := textproto.NewReader(reader)
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("malformed MIME header: %v", err)
	}

	httpResp := &WebResponse{
		Header: make(map[string]string),
	}
	for k, v := range header {
		if len(v) > 0 {
			httpResp.Header[k] = v[0]
		}
	}

	if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308) && redirectCount < s.MaxRedirects {
		if location, ok := httpResp.Header["Location"]; ok {
			newURL := s.resolveRedirect(url, location)
			return s.sendHTTPRequestRaw(newURL, redirectCount+1)
		}
	}

	var title string
	bodyReader := io.LimitReader(reader, 16384)
	bodyBytes, _ := io.ReadAll(bodyReader)
	body := string(bodyBytes)

	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	if match := re.FindStringSubmatch(body); len(match) > 1 {
		title = strings.TrimSpace(match[1])
		if len(title) > 100 {
			title = title[:100]
		}
	}
	httpResp.Title = title
	httpResp.Body = body

	return httpResp, nil
}

func (s *Scanner) shouldFollowRedirect() bool {
	switch s.FollowRedirect {
	case "never":
		return false
	case "http-only":
		return false
	case "same-site":
		return false
	case "always":
		return true
	default:
		return true
	}
}

func (s *Scanner) createConnection(url string) (net.Conn, error) {
	hostPort := extractHostPort(url)
	isHTTPS := strings.HasPrefix(url, "https://")

	if s.Proxy != "" {
		parts := strings.Split(s.Proxy, ":")
		proxyHost := parts[0]
		proxyPort := "8080"
		if len(parts) > 1 {
			proxyPort = parts[1]
		}
		return net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyHost, proxyPort), s.Timeout)
	}

	conn, err := net.DialTimeout("tcp", hostPort, s.Timeout)
	if err != nil {
		return nil, err
	}

	if isHTTPS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %v", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

func (s *Scanner) buildHTTPRequest(url string, path string) string {
	host := extractHost(url)

	ua := s.UserAgent
	if ua == "" {
		ua = "GYscan/2.7"
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n", path, host)
	req += fmt.Sprintf("User-Agent: %s\r\n", ua)
	req += "Accept: */*\r\n"
	req += "Accept-Language: en-US,en;q=0.9\r\n"
	req += "Connection: close\r\n"

	if s.Cookies != "" {
		req += fmt.Sprintf("Cookie: %s\r\n", s.Cookies)
	}

	for _, h := range s.Headers {
		if h != "" {
			req += h + "\r\n"
		}
	}

	req += "\r\n"
	return req
}

func (s *Scanner) resolveRedirect(baseURL string, location string) string {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}

	scheme := "http"
	if strings.HasPrefix(baseURL, "https") {
		scheme = "https"
	}

	if strings.HasPrefix(location, "/") {
		host := extractHost(baseURL)
		return fmt.Sprintf("%s://%s%s", scheme, host, location)
	}

	basePath := ""
	if idx := strings.LastIndex(baseURL, "/"); idx > 0 {
		basePath = baseURL[:idx]
	}
	return basePath + "/" + location
}

type WebResponse struct {
	Header HTTPHeader
	Title  string
	Body   string
}

type HTTPHeader map[string]string

func (h HTTPHeader) Get(key string) string {
	if v, ok := h[key]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func deduplicateFingerprints(fps []Fingerprint) []Fingerprint {
	seen := make(map[string]bool)
	var result []Fingerprint
	for _, fp := range fps {
		if !seen[fp.Name] {
			seen[fp.Name] = true
			result = append(result, fp)
		}
	}
	return result
}

func (s *Scanner) fingerprintWebServer(resp *WebResponse) []Fingerprint {
	var fingerprints []Fingerprint

	for _, fp := range FingerprintDB {
		confidence := 0
		for _, pattern := range fp.Patterns {
			switch pattern.Type {
			case "header":
				if pattern.Field == "" {
					for _, v := range resp.Header {
						if strings.Contains(strings.ToLower(v), strings.ToLower(pattern.Value)) {
							confidence += 100
						}
					}
				} else if value := resp.Header.Get(pattern.Field); value != "" {
					if strings.Contains(strings.ToLower(value), strings.ToLower(pattern.Value)) {
						confidence += 100
					}
				}
			case "cookie":
				for _, v := range resp.Header {
					if strings.Contains(strings.ToLower(v), strings.ToLower(pattern.Value)) {
						confidence += 50
					}
				}
			case "html":
				if strings.Contains(strings.ToLower(resp.Body), strings.ToLower(pattern.Value)) {
					confidence += 80
				}
			case "meta":
				re := regexp.MustCompile(`(?i)<meta[^>]*name=["']?` + pattern.Value + `["']?[^>]*>`)
				if re.MatchString(resp.Body) {
					confidence += 70
				}
			}
		}

		if confidence > 0 {
			fingerprints = append(fingerprints, Fingerprint{
				Name:        fp.Name,
				Category:    fp.Category,
				Confidence:  min(confidence, 100),
				Description: fmt.Sprintf("基于响应特征识别 (%d%%置信度)", min(confidence, 100)),
			})
		}
	}

	return fingerprints
}

func (s *Scanner) extractVersion(header string, versionRE string) string {
	if header == "" {
		return ""
	}

	if versionRE != "" {
		re := regexp.MustCompile(`(?i)` + versionRE)
		if match := re.FindStringSubmatch(header); len(match) > 1 {
			return match[1]
		}
	}

	patterns := map[string]string{
		"nginx":  `nginx[/\s]?([\d.]+)`,
		"apache": `Apache[/\s]?([\d.]+)`,
		"iis":    `Microsoft-IIS[/\s]?([\d.]+)`,
		"tomcat": `Tomcat[/\s]?([\d.]+)`,
		"jetty":  `Jetty[/\s]?([\d.]+)`,
	}

	for name, reStr := range patterns {
		if strings.Contains(strings.ToLower(header), name) {
			re := regexp.MustCompile(`(?i)` + reStr)
			if match := re.FindStringSubmatch(header); len(match) > 1 {
				return match[1]
			}
		}
	}

	return ""
}

func (s *Scanner) detectMySQL(target string, port int) *ComponentInfo {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), s.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	response := string(buf[:n])
	if !strings.Contains(response, "MySQL") && !strings.HasPrefix(response, "\x0a") {
		return nil
	}

	version := extractMySQLVersion(response)
	return &ComponentInfo{
		Name:     "MySQL",
		Type:     TypeDatabase,
		Version:  version,
		Protocol: "tcp",
	}
}

func (s *Scanner) detectPostgreSQL(target string, port int) *ComponentInfo {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), s.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	pgStartup := []byte{
		0x00, 0x00, 0x00, 0x13, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73,
		0x65, 0x72, 0x00, 0x00, 0x70, 0x6F, 0x73, 0x74, 0x67, 0x72,
		0x65,
	}

	conn.Write(pgStartup)

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	response := string(buf[:n])
	if !strings.Contains(response, "PostgreSQL") {
		return nil
	}

	ver := extractPostgreSQLVersion(response)
	return &ComponentInfo{
		Name:     "PostgreSQL",
		Type:     TypeDatabase,
		Version:  ver,
		Protocol: "tcp",
	}
}

func (s *Scanner) detectSQLServer(target string, port int) *ComponentInfo {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), s.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	tdsPreLogin := []byte{
		0x04, 0x01, 0x00, 0x25, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x1A, 0x00, 0x02, 0x02, 0x00, 0x4D, 0x53, 0x54, 0x44, 0x42,
		0x4C, 0x49, 0x42, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	conn.Write(tdsPreLogin)

	buf := make([]byte, 1024)
	_, _ = conn.Read(buf)

	return &ComponentInfo{
		Name:     "SQL Server",
		Type:     TypeDatabase,
		Version:  "unknown",
		Protocol: "tcp",
	}
}

func (s *Scanner) detectOracle(target string, port int) *ComponentInfo {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), s.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	response := string(buf[:n])
	if !strings.Contains(response, "Oracle") {
		return nil
	}

	ver := extractOracleVersion(response)
	return &ComponentInfo{
		Name:     "Oracle Database",
		Type:     TypeDatabase,
		Version:  ver,
		Protocol: "tcp",
	}
}

func (s *Scanner) detectRedis(target string, port int) *ComponentInfo {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", target, port),
		Password: "",
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	info, err := client.Info(ctx, "server").Result()
	if err != nil {
		client.Close()
		return nil
	}
	client.Close()

	version := extractRedisVersion(info)
	return &ComponentInfo{
		Name:     "Redis",
		Type:     TypeCacheMessage,
		Version:  version,
		Protocol: "tcp",
	}
}

func (s *Scanner) detectRabbitMQ(target string, port int) *ComponentInfo {
	connStr := fmt.Sprintf("amqp://%s:%d/", target, port)
	conn, err := amqp.Dial(connStr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	version := conn.Properties["version"]
	ver := ""
	if v, ok := version.(string); ok {
		ver = v
	}

	return &ComponentInfo{
		Name:     "RabbitMQ",
		Type:     TypeCacheMessage,
		Version:  ver,
		Protocol: "amqp",
	}
}

func (s *Scanner) detectMemcached(target string, port int) *ComponentInfo {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), s.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	fmt.Fprintf(conn, "version\r\n")

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	response := string(buf[:n])
	if !strings.HasPrefix(response, "VERSION") {
		return nil
	}

	version := strings.TrimSpace(strings.TrimPrefix(response, "VERSION"))
	return &ComponentInfo{
		Name:     "Memcached",
		Type:     TypeCacheMessage,
		Version:  version,
		Protocol: "tcp",
	}
}

func extractMySQLVersion(response string) string {
	fields := strings.Fields(response)
	for i, field := range fields {
		if strings.Contains(strings.ToLower(field), "mysql") {
			if i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

func extractPostgreSQLVersion(response string) string {
	re := regexp.MustCompile(`PostgreSQL\s+(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractOracleVersion(response string) string {
	re := regexp.MustCompile(`Oracle\s+(?:Database\s+)?(?:Enterprise\s+)?(\d+(?:\.\d+)*)`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractRedisVersion(response string) string {
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimPrefix(line, "redis_version:")
		}
	}
	return ""
}

func (s *Scanner) analyzePatchStatus(component *ComponentInfo) {
	patchDatabase := GetPatchDatabase()
	vulns := patchDatabase[component.Name]

	var missingPatches []Vulnerability
	riskLevel := "Low"

	for _, vuln := range vulns {
		if s.isVersionAffected(component.Version, vuln.FixedVersion) {
			missingPatches = append(missingPatches, vuln)
			switch vuln.Severity {
			case "Critical":
				riskLevel = "Critical"
			case "High":
				if riskLevel != "Critical" {
					riskLevel = "High"
				}
			case "Medium":
				if riskLevel == "Low" {
					riskLevel = "Medium"
				}
			}
		}
	}

	component.Vulnerabilities = missingPatches
	component.PatchStatus = PatchStatus{
		IsPatched:       len(missingPatches) == 0,
		LastCheck:       time.Now().Format("2006-01-02 15:04:05"),
		RiskLevel:       riskLevel,
		Recommendations: s.generateRecommendations(component, missingPatches),
	}
}

func (s *Scanner) isVersionAffected(currentVersion, fixedVersion string) bool {
	if currentVersion == "" || fixedVersion == "" {
		return false
	}

	current := parseVersion(currentVersion)
	fixed := parseVersion(fixedVersion)

	for i := 0; i < len(current) && i < len(fixed); i++ {
		if current[i] > fixed[i] {
			return false
		}
		if current[i] < fixed[i] {
			return true
		}
	}

	return false
}

func parseVersion(version string) []int {
	var nums []int
	for _, part := range strings.Split(version, ".") {
		if num, err := strconv.Atoi(part); err == nil {
			nums = append(nums, num)
		}
	}
	return nums
}

func (s *Scanner) generateRecommendations(component *ComponentInfo, vulns []Vulnerability) []string {
	var recommendations []string

	if len(vulns) == 0 {
		recommendations = append(recommendations, "当前版本暂无已知漏洞，建议定期检查更新")
		return recommendations
	}

	for _, vuln := range vulns {
		recommendations = append(recommendations,
			fmt.Sprintf("建议升级 %s 到 %s 或更高版本以修复 %s (%s)",
				component.Name, vuln.FixedVersion, vuln.Name, vuln.CVE))
	}

	return recommendations
}

func GetPatchDatabase() map[string][]Vulnerability {
	return map[string][]Vulnerability{
		"Nginx": {
			{"NGINX-001", "Nginx范围处理整数溢出", "CVE-2019-20372", "High", "1.20.1", "Nginx 1.17.5-1.17.6"},
			{"NGINX-002", "Nginx DNS解析漏洞", "CVE-2021-23017", "Medium", "1.21.0", "Nginx 0.6.18-1.20.1"},
		},
		"Apache": {
			{"APACHE-001", "Apache HTTP Server路径遍历", "CVE-2021-41773", "High", "2.4.50", "Apache 2.4.49"},
			{"APACHE-002", "Apache HTTP Server模块漏洞", "CVE-2021-42013", "High", "2.4.51", "Apache 2.4.49-2.4.50"},
		},
		"Tomcat": {
			{"TOMCAT-001", "Tomcat AJP文件包含", "CVE-2020-1938", "High", "9.0.31", "Tomcat 9.0.0-9.0.30"},
		},
		"Microsoft IIS": {
			{"IIS-001", "IIS远程代码执行", "CVE-2021-31166", "Critical", "10.0.19043", "Windows 10 1909之前版本"},
		},
		"MySQL": {
			{"MYSQL-001", "MySQL认证绕过", "CVE-2019-2631", "Critical", "5.7.28", "MySQL 5.7.27及以下"},
			{"MYSQL-002", "MySQL权限提升", "CVE-2020-2752", "High", "5.7.29", "MySQL 5.7.28及以下"},
		},
		"PostgreSQL": {
			{"POSTGRES-001", "PostgreSQL权限提升", "CVE-2021-3677", "High", "13.3", "PostgreSQL 9.6-13.2"},
		},
		"Oracle Database": {
			{"ORACLE-001", "Oracle Database拒绝服务", "CVE-2021-2154", "Medium", "19c", "Oracle Database 19c"},
		},
		"Redis": {
			{"REDIS-001", "Redis未授权访问", "CVE-2015-4335", "Critical", "3.2.4", "所有版本"},
			{"REDIS-002", "Redis远程代码执行", "CVE-2021-32761", "High", "6.2.4", "Redis 6.0-6.2.3"},
		},
		"Memcached": {
			{"MEMCACHED-001", "Memcached拒绝服务", "CVE-2021-23841", "Medium", "1.6.9", "Memcached 1.6.0-1.6.8"},
		},
		"RabbitMQ": {
			{"RABBITMQ-001", "RabbitMQ凭证泄露", "CVE-2021-22116", "High", "3.8.16", "RabbitMQ 3.8.0-3.8.15"},
		},
		"WebLogic": {
			{"WEBLOGIC-001", "WebLogic反序列化", "CVE-2017-10271", "Critical", "12.2.1.3.0", "WebLogic 10.3.6, 12.1.3, 12.2.1"},
		},
		"PHP": {
			{"PHP-001", "PHP远程代码执行", "CVE-2021-21703", "High", "7.4.24", "PHP 7.4.x < 7.4.24"},
		},
	}
}

func extractHostPort(url string) string {
	host := extractHost(url)
	parts := strings.Split(host, ":")
	if len(parts) == 2 {
		return host
	}
	if strings.HasPrefix(strings.ToLower(url), "https://") {
		return host + ":443"
	}
	return host + ":80"
}

func extractHost(url string) string {
	parts := strings.Split(url, "://")
	if len(parts) > 1 {
		url = parts[1]
	}
	parts = strings.SplitN(url, "/", 2)
	return parts[0]
}

func extractPath(url string) string {
	parts := strings.Split(url, "://")
	if len(parts) > 1 {
		url = parts[1]
	}
	parts = strings.SplitN(url, "/", 2)
	if len(parts) > 1 {
		return "/" + parts[1]
	}
	return "/"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
