package webfp

import (
	"bytes"
	"io"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/go-resty/resty/v2"
)

var defaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

type HTTPClient struct {
	client *resty.Client
	config *WebfpConfig
}

func NewHTTPClient(config *WebfpConfig) *HTTPClient {
	client := resty.New()
	client.SetTimeout(config.Timeout)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	client.SetHeader("User-Agent", config.UserAgent)
	client.SetHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	client.SetHeader("Accept-Language", "en-US,en;q=0.5")

	return &HTTPClient{
		client: client,
		config: config,
	}
}

func (c *HTTPClient) Fetch(targetURL string) (*HTTPResponse, error) {
	startTime := time.Now()

	utils.LogInfo("正在获取目标: %s", targetURL)

	resp, err := c.client.R().Get(targetURL)
	if err != nil {
		utils.LogError("请求失败: %v", err)
		return nil, err
	}

	responseTime := time.Since(startTime)

	response := &HTTPResponse{
		StatusCode:   resp.StatusCode(),
		Headers:      make(map[string]string),
		Body:         string(resp.Body()),
		BodyBytes:    resp.Body(),
		ContentType:  resp.Header().Get("Content-Type"),
		ResponseTime: responseTime,
	}

	for k, v := range resp.Header() {
		response.Headers[k] = strings.Join(v, ", ")
	}

	if c.config.Verbose {
		utils.LogDebug("响应状态: %d", response.StatusCode)
		utils.LogDebug("响应时间: %v", response.ResponseTime)
		utils.LogDebug("内容类型: %s", response.ContentType)
		utils.LogDebug("响应体大小: %d 字节", len(response.Body))
	}

	return response, nil
}

func (c *HTTPClient) GetClient() *resty.Client {
	return c.client
}

type HTTPResponse struct {
	StatusCode   int
	Headers      map[string]string
	Body         string
	BodyBytes    []byte
	ContentType  string
	ResponseTime time.Duration
}

func (r *HTTPResponse) IsHTML() bool {
	return strings.Contains(r.ContentType, "text/html")
}

func (r *HTTPResponse) IsJSON() bool {
	return strings.Contains(r.ContentType, "application/json")
}

func (r *HTTPResponse) GetServer() string {
	return r.Headers["Server"]
}

func (r *HTTPResponse) GetPoweredBy() string {
	return r.Headers["X-Powered-By"]
}

func (r *HTTPResponse) GetGenerator() string {
	return r.Headers["X-Generator"]
}

func (r *HTTPResponse) ExtractCookies() map[string]string {
	cookies := make(map[string]string)
	setCookie := r.Headers["Set-Cookie"]
	if setCookie != "" {
		for _, cookie := range strings.Split(setCookie, ",") {
			parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
			if len(parts) == 2 {
				cookies[parts[0]] = parts[1]
			}
		}
	}
	return cookies
}

func (r *HTTPResponse) GetLimitedBody(limit int64) string {
	if int64(len(r.BodyBytes)) <= limit {
		return r.Body
	}
	return string(r.BodyBytes[:limit])
}

func (c *HTTPClient) FetchWithRedirects(targetURL string, maxRedirects int) (*HTTPResponse, error) {
	client := c.client.Clone()
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(maxRedirects))

	resp, err := client.R().Get(targetURL)
	if err != nil {
		return nil, err
	}

	response := &HTTPResponse{
		StatusCode:  resp.StatusCode(),
		Headers:     make(map[string]string),
		Body:        string(resp.Body()),
		BodyBytes:   resp.Body(),
		ContentType: resp.Header().Get("Content-Type"),
	}

	for k, v := range resp.Header() {
		response.Headers[k] = strings.Join(v, ", ")
	}

	return response, nil
}

func (c *HTTPClient) FetchWithCustomHeaders(targetURL string, headers map[string]string) (*HTTPResponse, error) {
	request := c.client.R()

	for k, v := range headers {
		request.SetHeader(k, v)
	}

	resp, err := request.Get(targetURL)
	if err != nil {
		return nil, err
	}

	response := &HTTPResponse{
		StatusCode:  resp.StatusCode(),
		Headers:     make(map[string]string),
		Body:        string(resp.Body()),
		BodyBytes:   resp.Body(),
		ContentType: resp.Header().Get("Content-Type"),
	}

	for k, v := range resp.Header() {
		response.Headers[k] = strings.Join(v, ", ")
	}

	return response, nil
}

func (c *HTTPClient) HeadRequest(targetURL string) (*HTTPResponse, error) {
	resp, err := c.client.R().Head(targetURL)
	if err != nil {
		return nil, err
	}

	response := &HTTPResponse{
		StatusCode:  resp.StatusCode(),
		Headers:     make(map[string]string),
		ContentType: resp.Header().Get("Content-Type"),
	}

	for k, v := range resp.Header() {
		response.Headers[k] = strings.Join(v, ", ")
	}

	return response, nil
}

func (c *HTTPClient) GetResponseBodyReader(response *HTTPResponse) io.Reader {
	return bytes.NewReader(response.BodyBytes)
}

func GetDefaultUserAgent() string {
	return defaultUserAgents[0]
}

func GetRandomUserAgent() string {
	return defaultUserAgents[time.Now().Unix()%int64(len(defaultUserAgents))]
}
