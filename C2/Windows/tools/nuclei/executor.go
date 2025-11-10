package nuclei

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ScanResult represents the result of a vulnerability scan
type ScanResult struct {
	TemplateID    string            `json:"template_id"`
	TemplateName  string            `json:"template_name"`
	Severity      string            `json:"severity"`
	Target        string            `json:"target"`
	Matched       bool              `json:"matched"`
	MatchedString string            `json:"matched_string,omitempty"`
	ExtractedData map[string]string `json:"extracted_data,omitempty"`
	Error         string            `json:"error,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// Executor handles the execution of Nuclei templates against targets
type Executor struct {
	engine      *Engine
	verbose     bool
	httpClient  *http.Client
	dnsClient   *dns.Client
	mu          sync.RWMutex
}

// NewExecutor creates a new executor instance
func NewExecutor(engine *Engine, verbose bool) *Executor {
	// Configure HTTP client with reasonable timeouts
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Allow self-signed certs
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Configure DNS client
	dnsClient := &dns.Client{
		Timeout: 10 * time.Second,
	}

	return &Executor{
		engine:     engine,
		verbose:    verbose,
		httpClient: httpClient,
		dnsClient:  dnsClient,
		mu:         sync.RWMutex{},
	}
}

// ExecuteTemplate executes a specific template against a target
func (e *Executor) ExecuteTemplate(templateID, target string) (*ScanResult, error) {
	template := e.engine.GetTemplateByID(templateID)
	if template == nil {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	result := &ScanResult{
		TemplateID:   template.ID,
		TemplateName: template.Info.Name,
		Severity:     template.Info.Severity,
		Target:       target,
		Timestamp:    time.Now(),
	}

	// Execute based on template type
	if len(template.HTTP) > 0 {
		return e.executeHTTPTemplate(template, target, result)
	} else if len(template.DNS) > 0 {
		return e.executeDNSTemplate(template, target, result)
	} else if len(template.Network) > 0 {
		return e.executeNetworkTemplate(template, target, result)
	}

	result.Error = "unsupported template type"
	return result, nil
}

// ExecuteAllTemplates executes all loaded templates against a target
func (e *Executor) ExecuteAllTemplates(target string) ([]*ScanResult, error) {
	templates := e.engine.GetTemplates()
	results := make([]*ScanResult, 0, len(templates))

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, template := range templates {
		wg.Add(1)
		go func(t *Template) {
			defer wg.Done()
			
			result, err := e.ExecuteTemplate(t.ID, target)
			if err != nil {
				if e.verbose {
					log.Printf("Error executing template %s: %v", t.ID, err)
				}
				return
			}
			
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(template)
	}

	wg.Wait()
	return results, nil
}

// executeHTTPTemplate executes HTTP-based templates
func (e *Executor) executeHTTPTemplate(template *Template, target string, result *ScanResult) (*ScanResult, error) {
	for _, httpReq := range template.HTTP {
		// Build the request
		req, err := e.buildHTTPRequest(httpReq, target)
		if err != nil {
			result.Error = fmt.Sprintf("failed to build request: %v", err)
			return result, nil
		}

		// Send the request
		resp, err := e.httpClient.Do(req)
		if err != nil {
			result.Error = fmt.Sprintf("request failed: %v", err)
			return result, nil
		}
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("failed to read response: %v", err)
			return result, nil
		}

		// Check matchers
		if e.checkMatchers(template.Matchers, string(body), resp) {
			result.Matched = true
			
			// Extract data if matchers passed
			if len(template.Extractors) > 0 {
				result.ExtractedData = e.extractData(template.Extractors, string(body), resp)
			}
			
			break
		}
	}

	return result, nil
}

// executeDNSTemplate executes DNS-based templates
func (e *Executor) executeDNSTemplate(template *Template, target string, result *ScanResult) (*ScanResult, error) {
	for _, dnsReq := range template.DNS {
		// Create DNS message
		msg := new(dns.Msg)
		
		// Use DNS request configuration if available
		queryName := target
		if dnsReq.Name != "" {
			queryName = dnsReq.Name
		}
		
		queryType := dns.TypeA
		if dnsReq.Type != "" {
			switch strings.ToUpper(dnsReq.Type) {
			case "A":
				queryType = dns.TypeA
			case "AAAA":
				queryType = dns.TypeAAAA
			case "CNAME":
				queryType = dns.TypeCNAME
			case "MX":
				queryType = dns.TypeMX
			case "TXT":
				queryType = dns.TypeTXT
			default:
				queryType = dns.TypeA
			}
		}
		
		msg.SetQuestion(dns.Fqdn(queryName), queryType)

		// Send DNS query
		resp, _, err := e.dnsClient.Exchange(msg, target+":53")
		if err != nil {
			result.Error = fmt.Sprintf("DNS query failed: %v", err)
			return result, nil
		}

		// Convert response to string for matching
		respStr := resp.String()

		// Check matchers
		if e.checkMatchers(template.Matchers, respStr, nil) {
			result.Matched = true
			
			// Extract data if matchers passed
			if len(template.Extractors) > 0 {
				result.ExtractedData = e.extractData(template.Extractors, respStr, nil)
			}
			
			break
		}
	}

	return result, nil
}

// executeNetworkTemplate executes network-based templates
func (e *Executor) executeNetworkTemplate(template *Template, target string, result *ScanResult) (*ScanResult, error) {
	for _, netReq := range template.Network {
		// Connect to target
		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			result.Error = fmt.Sprintf("connection failed: %v", err)
			return result, nil
		}
		defer conn.Close()

		// Send input if specified
		if netReq.Input != "" {
			_, err = conn.Write([]byte(netReq.Input))
			if err != nil {
				result.Error = fmt.Sprintf("failed to send data: %v", err)
				return result, nil
			}
		}

		// Read response
		var response []byte
		if netReq.ReadSize > 0 {
			response = make([]byte, netReq.ReadSize)
			_, err = conn.Read(response)
		} else {
			response, err = io.ReadAll(conn)
		}

		if err != nil && err != io.EOF {
			result.Error = fmt.Sprintf("failed to read response: %v", err)
			return result, nil
		}

		// Check matchers
		if e.checkMatchers(template.Matchers, string(response), nil) {
			result.Matched = true
			
			// Extract data if matchers passed
			if len(template.Extractors) > 0 {
				result.ExtractedData = e.extractData(template.Extractors, string(response), nil)
			}
			
			break
		}
	}

	return result, nil
}

// buildHTTPRequest builds an HTTP request from template definition
func (e *Executor) buildHTTPRequest(httpReq HTTPRequest, target string) (*http.Request, error) {
	var req *http.Request
	var err error

	// Handle raw requests
	if len(httpReq.Raw) > 0 {
		req, err = e.buildRawHTTPRequest(httpReq.Raw[0], target)
		if err != nil {
			return nil, err
		}
	} else {
		// Build request from components
		method := "GET"
		if httpReq.Method != "" {
			method = httpReq.Method
		}

		path := "/"
		if len(httpReq.Path) > 0 {
			path = httpReq.Path[0]
		}

		fullURL := target + path
		if !strings.HasPrefix(target, "http") {
			fullURL = "http://" + target + path
		}

		req, err = http.NewRequest(method, fullURL, nil)
		if err != nil {
			return nil, err
		}

		// Set headers
		for key, value := range httpReq.Headers {
			req.Header.Set(key, value)
		}

		// Set body if specified
		if httpReq.Body != "" {
			req.Body = io.NopCloser(strings.NewReader(httpReq.Body))
		}
	}

	return req, nil
}

// buildRawHTTPRequest builds an HTTP request from raw request string
func (e *Executor) buildRawHTTPRequest(rawRequest, target string) (*http.Request, error) {
	reader := bufio.NewReader(strings.NewReader(rawRequest))
	
	// Read first line (method and path)
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid raw request format")
	}

	method := parts[0]
	path := parts[1]

	// Build URL
	fullURL := target + path
	if !strings.HasPrefix(target, "http") {
		fullURL = "http://" + target + path
	}

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Parse headers
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF || strings.TrimSpace(line) == "" {
			break
		}
		if err != nil {
			return nil, err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			header := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			req.Header.Set(header, value)
		}
	}

	return req, nil
}

// checkMatchers checks if the response matches the template's matchers
func (e *Executor) checkMatchers(matchers []Matcher, response string, httpResp *http.Response) bool {
	if len(matchers) == 0 {
		return true // No matchers means always match
	}

	allMatch := true
	anyMatch := false

	for _, matcher := range matchers {
		matched := false

		switch matcher.Type {
		case "word":
			for _, word := range matcher.Words {
				if strings.Contains(response, word) {
					matched = true
					break
				}
			}
		case "regex":
			for _, pattern := range matcher.Regex {
				re, err := regexp.Compile(pattern)
				if err == nil && re.MatchString(response) {
					matched = true
					break
				}
			}
		case "status":
			if httpResp != nil {
				for _, word := range matcher.Words {
					if fmt.Sprintf("%d", httpResp.StatusCode) == word {
						matched = true
						break
					}
				}
			}
		}

		if matcher.Condition == "or" {
			if matched {
				anyMatch = true
			}
		} else { // "and" is default
			if !matched {
				allMatch = false
			}
		}
	}

	if len(matchers) > 0 && matchers[0].Condition == "or" {
		return anyMatch
	}
	return allMatch
}

// extractData extracts data from the response using extractors
func (e *Executor) extractData(extractors []Extractor, response string, httpResp *http.Response) map[string]string {
	result := make(map[string]string)

	for _, extractor := range extractors {
		switch extractor.Type {
		case "regex":
			for _, pattern := range extractor.Regex {
				re, err := regexp.Compile(pattern)
				if err == nil {
					matches := re.FindStringSubmatch(response)
					if len(matches) > 1 {
						result[extractor.Part] = matches[1]
					}
				}
			}
		case "kval":
			// Key-value extraction (simplified implementation)
			for key := range extractor.KVal {
				// This would need more sophisticated parsing
				result[key] = "extracted_value"
			}
		}
	}

	return result
}

// SetHTTPClient allows custom HTTP client configuration
func (e *Executor) SetHTTPClient(client *http.Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.httpClient = client
}

// SetDNSClient allows custom DNS client configuration
func (e *Executor) SetDNSClient(client *dns.Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dnsClient = client
}