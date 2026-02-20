package api

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/go-resty/resty/v2"
)

type ApiConfig struct {
	TargetURL     string
	Threads       int
	Timeout       time.Duration
	Output        string
	Verbose       bool
	IncludeParams bool
	Depth         int
	Headers       map[string]string
	Crawl         bool
	MaxPages      int
	AutoLook      bool
	Headless      bool
	WaitTime      time.Duration
	BrowserPort   int
	BrowserPath   string
	NoSandbox     bool
	VerifyAPI     bool
}

type ApiResult struct {
	Method   string
	Path     string
	FullURL  string
	Source   string
	Category string
	Status   string
	Valid    bool
	Response string
}

type ApiResults struct {
	Results []ApiResult
	Summary ApiSummary
	mu      sync.Mutex
}

type ApiSummary struct {
	TotalAPIs    int
	GETCount     int
	POSTCount    int
	PUTCount     int
	DELETECount  int
	PATCHCount   int
	OtherCount   int
	ScanTime     time.Duration
	PagesScanned int
}

var endpointPatterns = []string{
	`fetch\s*\(\s*['"](/[^"']+)['"]`,
	`fetch\s*\(\s*['"](https?://[^"']+)['"]`,
	`axios\.[a-z]+\s*\(\s*['"](/[^"']+)['"]`,
	`axios\.[a-z]+\s*\(\s*['"](https?://[^"']+)['"]`,
	`\$.(get|post|put|delete|patch|ajax)\s*\(\s*['"](/[^"']+)['"]`,
	`\$.ajax\s*\(\s*\{[^}]*url\s*:\s*['"](/[^"']+)['"]`,
	`\$.ajax\s*\(\s*\{[^}]*url\s*:\s*['"](https?://[^"']+)['"]`,
	`url\s*:\s*['"](/[^"']+)['"]`,
	`url\s*:\s*['"](https?://[^"']+/[^"']+)['"]`,
	`apiUrl\s*[:=]\s*['"](/[^"']+)['"]`,
	`apiUrl\s*[:=]\s*['"](https?://[^"']+)['"]`,
	`baseURL\s*[:=]\s*['"](/[^"']+)['"]`,
	`baseURL\s*[:=]\s*['"](https?://[^"']+)['"]`,
	`baseApi\s*[:=]\s*['"](/[^"']+)['"]`,
	`endpoint\s*:\s*['"](/[^"']+)['"]`,
	`apiEndpoint\s*[:=]\s*['"](/[^"']+)['"]`,
	`requestURL\s*[:=]\s*['"](/[^"']+)['"]`,
	`XHR\.open\s*\(\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"](/[^"']+)['"]`,
	`new\s+XMLHttpRequest\s*\(\s*\)\s*[\s\S]{0,100}\.open\s*\(\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"](/[^"']+)['"]`,
	`http\.(get|post|put|delete|patch)\s*\(\s*['"](/[^"']+)['"]`,
	`router\.(get|post|put|delete|push)\s*\(\s*['"](/[^"']+)['"]`,
	`Route\s*\(\s*\{[^}]*path\s*:\s*['"](/[^"']+)['"]`,
	`path\s*:\s*['"](/[^"']+)['"]`,
	`location\.href\s*=\s*['"](/[^"']+)['"]`,
	`window\.open\s*\(\s*['"](/[^"']+)['"]`,
	`action\s*=\s*["'](/[^"']+)["']`,
	`href\s*=\s*["'](/[^"']+)["']`,
	`useRoute\s*\(\s*['"](/[^"']+)['"]`,
	`navigateTo\s*\(\s*['"](/[^"']+)['"]`,
	`router\.push\s*\(\s*['"](/[^"']+)['"]`,
	`router\.replace\s*\(\s*['"](/[^"']+)['"]`,
	`history\.pushState\s*\(\s*[^,)]*,\s*[^,)]*,\s*['"](/[^"']+)['"]`,
	`createWebHistory\s*\(\s*\)\s*,?\s*[^)]*['"](/[^"']+)['"]`,
	`routes\s*:\s*\[[\s\S]{0,500}path\s*:\s*['"](/[^"']+)['"]`,
	`getStaticPaths\s*\(\s*\)\s*=>\s*\{[\s\S]{0,500}path\s*:\s*['"](/[^"']+)['"]`,
	`definePageMeta\s*\(\s*\{[^}]*path\s*:\s*['"](/[^"']+)['"]`,
}

var methodPatterns = map[string]*regexp.Regexp{
	"GET":    regexp.MustCompile(`(?i)(?:method|type|requestType)\s*[:=]\s*['"]?(?:GET|get)['"]?`),
	"POST":   regexp.MustCompile(`(?i)(?:method|type|requestType)\s*[:=]\s*['"]?(?:POST|post)['"]?`),
	"PUT":    regexp.MustCompile(`(?i)(?:method|type|requestType)\s*[:=]\s*['"]?(?:PUT|put)['"]?`),
	"DELETE": regexp.MustCompile(`(?i)(?:method|type|requestType)\s*[:=]\s*['"]?(?:DELETE|delete|del)['"]?`),
	"PATCH":  regexp.MustCompile(`(?i)(?:method|type|requestType)\s*[:=]\s*['"]?(?:PATCH|patch)['"]?`),
}

func RunApiScan(config ApiConfig) ApiResults {
	results := ApiResults{
		Results: make([]ApiResult, 0),
		Summary: ApiSummary{},
	}

	startTime := time.Now()

	client := resty.New()
	client.SetTimeout(config.Timeout)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))

	for k, v := range config.Headers {
		client.SetHeader(k, v)
	}

	baseURL := config.TargetURL
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Printf("[GYscan-API] URL解析错误: %v\n", err)
		return results
	}

	domain := parsedURL.Host

	if config.Verbose {
		fmt.Printf("[GYscan-API] 开始扫描目标: %s\n", baseURL)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	visited := make(map[string]bool)
	crawled := make(map[string]bool)
	pagesScanned := 0
	var wg sync.WaitGroup
	urlChan := make(chan string, config.Threads*10)
	var countMu sync.Mutex

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pageURL, ok := <-urlChan:
					if !ok {
						return
					}
					if !visited[pageURL] {
						visited[pageURL] = true
						extractApisFromPage(pageURL, baseURL, client, &results, config)

						countMu.Lock()
						pagesScanned++
						countMu.Unlock()
					}

					if config.Crawl && (config.MaxPages == 0 || pagesScanned < config.MaxPages) {
						extractLinksFromPage(ctx, pageURL, baseURL, domain, client, urlChan, crawled, config)
					}
				}
			}
		}()
	}

	urlChan <- baseURL

	time.Sleep(100 * time.Millisecond)
	close(urlChan)

	wg.Wait()

	results.Summary.ScanTime = time.Since(startTime)
	results.Summary.PagesScanned = pagesScanned
	results.Summary.TotalAPIs = len(results.Results)

	for _, api := range results.Results {
		switch api.Method {
		case "GET":
			results.Summary.GETCount++
		case "POST":
			results.Summary.POSTCount++
		case "PUT":
			results.Summary.PUTCount++
		case "DELETE":
			results.Summary.DELETECount++
		case "PATCH":
			results.Summary.PATCHCount++
		default:
			results.Summary.OtherCount++
		}
	}

	results.Results = deduplicateResults(results.Results)

	return results
}

func extractLinksFromPage(ctx context.Context, pageURL, baseURL, domain string, client *resty.Client, urlChan chan<- string, crawled map[string]bool, config ApiConfig) {
	defer func() {
		recover()
	}()

	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := client.R().Get(pageURL)
	if err != nil {
		return
	}

	contentType := resp.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(resp.Body())))
	if err != nil {
		return
	}

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists || href == "" {
			return
		}

		fullURL := resolveURL(href, baseURL)
		if fullURL == "" {
			return
		}

		parsed, err := url.Parse(fullURL)
		if err != nil || parsed.Host != domain {
			return
		}

		if !crawled[fullURL] && !strings.HasPrefix(fullURL, "mailto:") && !strings.HasPrefix(fullURL, "tel:") && !strings.HasPrefix(fullURL, "javascript:") {
			crawled[fullURL] = true
			defer func() {
				recover()
			}()
			select {
			case urlChan <- fullURL:
			default:
			}
		}
	})

	doc.Find("button, [role=button], .btn, button[class], input[type=submit], input[type=button]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("onclick")
		if href != "" {
			jsUrls := extractUrlsFromJavascript(href, baseURL)
			for _, jsURL := range jsUrls {
				parsed, err := url.Parse(jsURL)
				if err == nil && (parsed.Host == domain || parsed.Host == "") {
					jsURL = resolveURL(jsURL, baseURL)
					if jsURL != "" && !crawled[jsURL] {
						crawled[jsURL] = true
						select {
						case urlChan <- jsURL:
						default:
						}
					}
				}
			}
		}

		dataUrl, _ := s.Attr("data-url")
		if dataUrl != "" {
			fullURL := resolveURL(dataUrl, baseURL)
			if fullURL != "" && !crawled[fullURL] {
				crawled[fullURL] = true
				select {
				case urlChan <- fullURL:
				default:
				}
			}
		}

		dataApi, _ := s.Attr("data-api")
		if dataApi != "" {
			fullURL := resolveURL(dataApi, baseURL)
			if fullURL != "" && !crawled[fullURL] {
				crawled[fullURL] = true
				select {
				case urlChan <- fullURL:
				default:
				}
			}
		}
	})

	doc.Find("form[action]").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		if action != "" {
			fullURL := resolveURL(action, baseURL)
			if fullURL != "" {
				parsed, err := url.Parse(fullURL)
				if err == nil && (parsed.Host == domain || parsed.Host == "") {
					if !crawled[fullURL] {
						crawled[fullURL] = true
						select {
						case urlChan <- fullURL:
						default:
						}
					}
				}
			}
		}
	})

	doc.Find("[data-href], [data-link], [data-redirect]").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"data-href", "data-link", "data-redirect"} {
			val, _ := s.Attr(attr)
			if val != "" {
				fullURL := resolveURL(val, baseURL)
				if fullURL != "" && !crawled[fullURL] {
					parsed, err := url.Parse(fullURL)
					if err == nil && (parsed.Host == domain || parsed.Host == "") {
						crawled[fullURL] = true
						select {
						case urlChan <- fullURL:
						default:
						}
					}
				}
			}
		}
	})
}

func extractUrlsFromJavascript(jsCode, baseURL string) []string {
	var urls []string

	re := regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]|axios\.[a-z]+\s*\(\s*['"]([^'"]+)['"]|\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]|window\.location\s*=\s*['"]([^'"]+)['"]|location\.href\s*=\s*['"]([^'"]+)['"]|open\s*\(\s*['"]([^'"]+)['"]`)

	matches := re.FindAllStringSubmatch(jsCode, -1)
	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				urls = append(urls, match[i])
			}
		}
	}

	return urls
}

func extractApisFromPage(pageURL, baseURL string, client *resty.Client, results *ApiResults, config ApiConfig) {
	if client == nil {
		return
	}

	resp, err := client.R().Get(pageURL)
	if err != nil {
		if config.Verbose {
			fmt.Printf("[GYscan-API] 请求失败: %s - %v\n", pageURL, err)
		}
		return
	}

	contentType := resp.Header().Get("Content-Type")
	body := string(resp.Body())

	if !strings.Contains(contentType, "text/html") {
		if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") {
			extractApisFromJS(resp.Body(), baseURL, pageURL, results, config)
		}
		return
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return
	}

	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && src != "" {
			fullURL := resolveURL(src, baseURL)
			if fullURL != "" {
				jsResp, err := client.R().Get(fullURL)
				if err == nil {
					extractApisFromJS(jsResp.Body(), baseURL, fullURL, results, config)
				}
			}
		} else {
			content := s.Text()
			extractApisFromJS([]byte(content), baseURL, pageURL, results, config)
		}
	})

	doc.Find("link[rel]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		rel, _ := s.Attr("rel")
		if exists && href != "" && (strings.Contains(strings.ToLower(href), "swagger") || strings.Contains(strings.ToLower(href), "api-docs") || strings.Contains(strings.ToLower(rel), "api")) {
			fullURL := resolveURL(href, baseURL)
			if fullURL != "" {
				jsResp, err := client.R().Get(fullURL)
				if err == nil {
					extractApisFromJS(jsResp.Body(), baseURL, fullURL, results, config)
				}
			}
		}
	})

	doc.Find("[data-api], [data-url], [data-endpoint], [data-path], [ajax-url], [api-url]").Each(func(i int, s *goquery.Selection) {
		attrs := []string{"data-api", "data-url", "data-endpoint", "data-path", "ajax-url", "api-url"}
		for _, attr := range attrs {
			val, exists := s.Attr(attr)
			if exists && val != "" {
				fullURL := resolveURL(val, baseURL)
				result := ApiResult{
					Method:   "GET",
					Path:     val,
					FullURL:  fullURL,
					Source:   pageURL,
					Category: categorizeAPI(val),
				}
				results.mu.Lock()
				results.Results = append(results.Results, result)
				results.mu.Unlock()
			}
		}
	})

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if isAPIEndpoint(href) {
			fullURL := resolveURL(href, baseURL)
			result := ApiResult{
				Method:   "GET",
				Path:     href,
				FullURL:  fullURL,
				Source:   pageURL,
				Category: categorizeAPI(href),
			}
			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()
		}
	})

	doc.Find("form[action]").Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		method, _ := s.Attr("method")
		if exists && action != "" {
			fullURL := resolveURL(action, baseURL)
			result := ApiResult{
				Method:   strings.ToUpper(method),
				Path:     action,
				FullURL:  fullURL,
				Source:   pageURL,
				Category: categorizeAPI(action),
			}
			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()
		}
	})

	extractApisFromJS([]byte(body), baseURL, pageURL, results, config)

	importScripts := regexp.MustCompile(`import\s+.*\s+from\s+['"]([^'"]+)['"]|import\s*\(['"]([^'"]+)['"]\)`)
	matches := importScripts.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			importPath := match[1]
			if importPath == "" && len(match) >= 3 {
				importPath = match[2]
			}
			if importPath != "" && (strings.Contains(importPath, "api") || strings.Contains(importPath, "/")) {
				fullURL := resolveURL(importPath, baseURL)
				if fullURL != "" {
					jsResp, err := client.R().Get(fullURL)
					if err == nil {
						extractApisFromJS(jsResp.Body(), baseURL, fullURL, results, config)
					}
				}
			}
		}
	}

	axiosImports := regexp.MustCompile(`from\s+['"]([^'"]*axios[^'"]*)['"]|from\s+['"]([^'"]*fetch[^'"]*)['"]|from\s+['"]([^'"]*request[^'"]*)['"]`)
	matches = axiosImports.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				fullURL := resolveURL(match[i], baseURL)
				if fullURL != "" {
					jsResp, err := client.R().Get(fullURL)
					if err == nil {
						extractApisFromJS(jsResp.Body(), baseURL, fullURL, results, config)
					}
				}
			}
		}
	}
}

func extractApisFromJS(content []byte, baseURL, source string, results *ApiResults, config ApiConfig) {
	contentStr := string(content)

	for _, pattern := range endpointPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(contentStr, -1)

		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			path := match[1]
			if path == "" {
				continue
			}

			path = cleanPath(path)

			if !isValidAPI(path) {
				continue
			}

			method := detectMethod(contentStr, path)

			fullURL := resolveURL(path, baseURL)

			result := ApiResult{
				Method:   method,
				Path:     path,
				FullURL:  fullURL,
				Source:   source,
				Category: categorizeAPI(path),
			}

			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()

			if config.Verbose {
				fmt.Printf("[GYscan-API] 发现API: %s %s (来源: %s)\n", method, path, source)
			}
		}
	}

	extractFromJSONEndpoints(content, baseURL, source, results, config)
}

func extractApisFromHTML(htmlContent, baseURL, source string, results *ApiResults) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return
	}

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		method, _ := s.Attr("method")

		if exists && action != "" && isValidAPI(action) && isLikelyAPIPath(action) {
			fullURL := resolveURL(action, baseURL)
			result := ApiResult{
				Method:   strings.ToUpper(method),
				Path:     action,
				FullURL:  fullURL,
				Source:   source,
				Category: categorizeAPI(action),
			}

			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()
		}
	})

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if isValidAPI(href) && isLikelyAPIPath(href) {
			fullURL := resolveURL(href, baseURL)
			result := ApiResult{
				Method:   "GET",
				Path:     href,
				FullURL:  fullURL,
				Source:   source,
				Category: categorizeAPI(href),
			}

			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()
		}
	})

	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		content := s.Text()
		if content != "" {
			extractApisFromJS([]byte(content), baseURL, source, results, ApiConfig{Verbose: false})
		}
	})

	doc.Find("[data-api], [data-endpoint], [data-url], [data-href], [data-link], [data-action], [data-route]").Each(func(i int, s *goquery.Selection) {
		attrs := []string{"data-api", "data-endpoint", "data-url", "data-href", "data-link", "data-action", "data-route"}
		for _, attr := range attrs {
			if val, exists := s.Attr(attr); exists && val != "" {
				if isValidAPI(val) && isLikelyAPIPath(val) {
					fullURL := resolveURL(val, baseURL)
					result := ApiResult{
						Method:   "GET",
						Path:     val,
						FullURL:  fullURL,
						Source:   source,
						Category: categorizeAPI(val),
					}

					results.mu.Lock()
					results.Results = append(results.Results, result)
					results.mu.Unlock()
				}
			}
		}
	})

	re := regexp.MustCompile(`window\.__([A-Z_]+)__\s*=\s*(\{[\s\S]*?\});`)
	matches := re.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			extractApisFromJS([]byte(match[0]), baseURL, source, results, ApiConfig{Verbose: false})
		}
	}

	re = regexp.MustCompile(`window\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\{[\s\S]*?\{[\s\S]*?\}[\s\S]*?\})`)
	matches = re.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			extractApisFromJS([]byte(match[0]), baseURL, source, results, ApiConfig{Verbose: false})
		}
	}

	re = regexp.MustCompile(`data\s*[:=]\s*(\{[\s\S]*?\})`)
	matches = re.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			extractApisFromJS([]byte(match[1]), baseURL, source, results, ApiConfig{Verbose: false})
		}
	}

	doc.Find("link[rel=alternate][type=application/json]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && href != "" {
			if isValidAPI(href) {
				fullURL := resolveURL(href, baseURL)
				result := ApiResult{
					Method:   "GET",
					Path:     href,
					FullURL:  fullURL,
					Source:   source,
					Category: "API",
				}

				results.mu.Lock()
				results.Results = append(results.Results, result)
				results.mu.Unlock()
			}
		}
	})

	doc.Find("meta[itemprop=url], link[itemprop=url]").Each(func(i int, s *goquery.Selection) {
		if content, exists := s.Attr("content"); exists && content != "" {
			if isValidAPI(content) && isLikelyAPIPath(content) {
				fullURL := resolveURL(content, baseURL)
				result := ApiResult{
					Method:   "GET",
					Path:     content,
					FullURL:  fullURL,
					Source:   source,
					Category: categorizeAPI(content),
				}

				results.mu.Lock()
				results.Results = append(results.Results, result)
				results.mu.Unlock()
			}
		}
	})

	reAPI := regexp.MustCompile(`["'](/api[^"'\s]*)["']`)
	apiMatches := reAPI.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range apiMatches {
		if len(match) >= 2 {
			path := match[1]
			if isValidAPI(path) && isLikelyAPIPath(path) {
				fullURL := resolveURL(path, baseURL)
				result := ApiResult{
					Method:   "GET",
					Path:     path,
					FullURL:  fullURL,
					Source:   source,
					Category: categorizeAPI(path),
				}

				results.mu.Lock()
				results.Results = append(results.Results, result)
				results.mu.Unlock()
			}
		}
	}
}

func extractJsFilesFromHTML(htmlContent, baseURL string, results *ApiResults, config ApiConfig) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return
	}

	jsFiles := make(map[string]bool)

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, _ := s.Attr("src")
		if src != "" {
			fullURL := resolveURL(src, baseURL)
			if fullURL != "" && !jsFiles[fullURL] {
				jsFiles[fullURL] = true
			}
		}
	})

	doc.Find("link[rel=stylesheet]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if href != "" && (strings.Contains(href, ".js") || strings.Contains(href, "javascript")) {
			fullURL := resolveURL(href, baseURL)
			if fullURL != "" && !jsFiles[fullURL] {
				jsFiles[fullURL] = true
			}
		}
	})

	for jsURL := range jsFiles {
		if config.Verbose {
			fmt.Printf("[GYscan-API] 分析JS文件: %s\n", jsURL)
		}

		client := resty.New()
		client.SetTimeout(10 * time.Second)

		resp, err := client.R().Get(jsURL)
		if err != nil {
			continue
		}

		extractApisFromJS(resp.Body(), baseURL, jsURL, results, config)
	}
}

func guessCommonAPIPaths(baseURL, domain string, results *ApiResults, config ApiConfig) {
	commonPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/api/v1/",
		"/api/v2/",
		"/api/v3/",
		"/api/users",
		"/api/user",
		"/api/projects",
		"/api/project",
		"/api/search",
		"/api/auth",
		"/api/login",
		"/api/logout",
		"/api/register",
		"/api/token",
		"/api/data",
		"/api/info",
		"/api/health",
		"/api/status",
		"/api/config",
		"/api/settings",
		"/api/version",
		"/api/versions",
		"/api/files",
		"/api/upload",
		"/api/download",
		"/api/categories",
		"/api/tags",
		"/api/mods",
		"/api/modpacks",
		"/api/shaders",
		"/api/plugins",
		"/docs",
		"/docs/api",
		"/swagger",
		"/swagger-ui",
		"/openapi",
		"/api-docs",
		"/graphql",
		"/api/graphql",
		"/rest",
		"/rest/api",
		"/wp-json",
		"/json",
		"/ajax",
		"/api/ajax",
		"/backend",
		"/backend/api",
		"/admin",
		"/admin/api",
		"/manage",
		"/manage/api",
		"/internal",
		"/internal/api",
		"/mobile",
		"/mobile/api",
		"/api/mobile",
		"/webapi",
		"/webservices",
		"/rpc",
		"/json-rpc",
		"/api/rpc",
		"/gateway",
		"/api/gateway",
		"/hooks",
		"/api/hooks",
		"/webhooks",
		"/api/webhooks",
		"/pusher",
		"/api/pusher",
	}

	client := resty.New()
	client.SetTimeout(10 * time.Second)

	for _, path := range commonPaths {
		fullURL := resolveURL(path, baseURL)

		resp, err := client.R().Get(fullURL)
		if err == nil && resp.StatusCode() < 400 {
			if config.Verbose {
				fmt.Printf("[GYscan-API] 发现API端点: %s (状态码: %d)\n", fullURL, resp.StatusCode())
			}

			result := ApiResult{
				Method:   "GET",
				Path:     path,
				FullURL:  fullURL,
				Source:   "guess",
				Category: categorizeAPI(path),
			}

			results.mu.Lock()
			results.Results = append(results.Results, result)
			results.mu.Unlock()
		}
	}
}

func extractFromJSONEndpoints(content []byte, baseURL, source string, results *ApiResults, config ApiConfig) {
	re := regexp.MustCompile(`["']((?:https?:)?/?/api/[^"'\s]+)["']`)
	matches := re.FindAllStringSubmatch(string(content), -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		path := match[1]
		if path == "" {
			continue
		}

		path = cleanPath(path)

		if !isValidAPI(path) {
			continue
		}

		fullURL := resolveURL(path, baseURL)

		result := ApiResult{
			Method:   "GET",
			Path:     path,
			FullURL:  fullURL,
			Source:   source,
			Category: categorizeAPI(path),
		}

		results.mu.Lock()
		results.Results = append(results.Results, result)
		results.mu.Unlock()
	}
}

func detectMethod(content, path string) string {
	contextStart := strings.Index(content, path)
	if contextStart == -1 {
		return "GET"
	}

	contextEnd := contextStart + len(path)
	if contextEnd > len(content) {
		contextEnd = len(content)
	}

	contextStart = contextStart - 200
	if contextStart < 0 {
		contextStart = 0
	}

	context := content[contextStart:contextEnd]

	for method, pattern := range methodPatterns {
		if pattern.MatchString(context) {
			return method
		}
	}

	return inferMethodFromPath(path)
}

func inferMethodFromPath(path string) string {
	lowerPath := strings.ToLower(path)

	pathMethods := map[string]string{
		"/add":     "POST",
		"/create":  "POST",
		"/new":     "POST",
		"/update":  "PUT",
		"/edit":    "PUT",
		"/modify":  "PUT",
		"/delete":  "DELETE",
		"/remove":  "DELETE",
		"/get":     "GET",
		"/fetch":   "GET",
		"/list":    "GET",
		"/search":  "GET",
		"/query":   "GET",
		"/filter":  "GET",
		"/detail":  "GET",
		"/info":    "GET",
		"/status":  "GET",
		"/sync":    "POST",
		"/submit":  "POST",
		"/execute": "POST",
		"/run":     "POST",
		"/batch":   "POST",
	}

	for pattern, method := range pathMethods {
		if strings.Contains(lowerPath, pattern) {
			return method
		}
	}

	return "GET"
}

func isValidAPI(path string) bool {
	if len(path) < 2 {
		return false
	}

	if strings.HasPrefix(path, "//") {
		return false
	}

	if strings.Contains(path, " ") {
		return false
	}

	if strings.HasPrefix(path, "#") {
		return false
	}

	invalidPrefixes := []string{"data:", "javascript:", "mailto:", "tel:", "blob:"}
	for _, prefix := range invalidPrefixes {
		if strings.HasPrefix(strings.ToLower(path), prefix) {
			return false
		}
	}

	if strings.Contains(path, "=") || strings.Contains(path, "&") || strings.Contains(path, "?") {
		return false
	}

	if strings.HasPrefix(path, "!") || strings.HasPrefix(path, "(") || strings.HasPrefix(path, "{") {
		return false
	}

	if strings.Contains(path, "=>") || strings.Contains(path, "function") {
		return false
	}

	if len(path) > 200 {
		return false
	}

	cleanPath := strings.TrimSpace(path)
	if !strings.HasPrefix(cleanPath, "/") && !strings.HasPrefix(cleanPath, "http") {
		return false
	}

	invalidPaths := []string{"/403", "/404", "/500", "/400", "/401", "/302", "/301"}
	for _, invalid := range invalidPaths {
		if cleanPath == invalid || strings.HasSuffix(cleanPath, invalid) {
			return false
		}
	}

	if !isLikelyAPIPath(cleanPath) {
		return false
	}

	return true
}

func isAPIEndpoint(href string) bool {
	if !isValidAPI(href) {
		return false
	}

	lowerHref := strings.ToLower(href)

	invalidSuffixes := []string{".html", ".htm", ".css", ".jpg", ".jpeg", ".png", ".svg", ".ico", ".js", ".json", ".xml", ".txt", ".md", ".woff", ".woff2", ".ttf", ".eot"}
	for _, suffix := range invalidSuffixes {
		if strings.HasSuffix(lowerHref, suffix) {
			return false
		}
	}

	return true
}

var routeParamPatterns = []string{
	":id()",
	":slug()",
	":pathMatch",
	":",
}

var staticPagePatterns = []string{
	"/assets/",
	"/images/",
	"/img/",
	"/static/",
	"/fonts/",
	"/_next/static/",
	"/_nuxt/",
	"/__pycache__/",
	"/node_modules/",
	".css",
	".js",
	".webp",
	".png",
	".jpg",
	".jpeg",
	".gif",
	".svg",
	".ico",
	".woff",
	".woff2",
	".ttf",
	".eot",
	"/app",
	"/frog",
	"/plus",
	"/settings",
	"/discover",
	"/hosting",
	"/auth/sign-in",
	"/auth/sign-up",
	"/auth/logout",
	"/auth/",
	"/mod/",
	"/modpack/",
	"/plugin/",
	"/resourcepack/",
	"/shader/",
	"/datapack/",
	"/user/",
	"/organization/",
	"/collection/",
	"/dashboard/",
	"/moderation/",
	"/email/",
	"/flags",
	"/legal",
	"/report",
	"/mural/",
	"/payout/",
	"/billing/",
	"/fs/",
}

func isLikelyAPIPath(path string) bool {
	lowerPath := strings.ToLower(path)

	for _, pattern := range routeParamPatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	for _, pattern := range staticPagePatterns {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	if strings.HasPrefix(path, "/_") || strings.HasPrefix(path, "/.") {
		return false
	}

	if strings.Count(path, "/") >= 1 {
		return true
	}

	return false
}

func resolveURL(path, baseURL string) string {
	if path == "" {
		return ""
	}

	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	if strings.HasPrefix(path, "//") {
		return "https:" + path
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(path, "/") {
		base.Path = path
	} else {
		currentPath := base.Path
		if currentPath == "" || currentPath == "/" {
			currentPath = "/"
		}

		lastSlash := strings.LastIndex(currentPath, "/")
		if lastSlash > 0 {
			currentPath = currentPath[:lastSlash+1]
		} else {
			currentPath = "/"
		}

		base.Path = currentPath + path
	}

	return base.String()
}

func cleanPath(path string) string {
	path = strings.TrimSpace(path)

	path = strings.Trim(path, "\"'")

	path = strings.ReplaceAll(path, "\\/", "/")

	path = strings.ReplaceAll(path, "&amp;", "&")

	return path
}

func categorizeAPI(path string) string {
	lowerPath := strings.ToLower(path)

	categories := map[string][]string{
		"认证":  {"/auth", "/login", "/logout", "/register", "/signup", "/token", "/oauth"},
		"用户":  {"/user", "/profile", "/account", "/member"},
		"管理":  {"/admin", "/manage", "/dashboard", "/console"},
		"数据":  {"/data", "/file", "/upload", "/download", "/media", "/image"},
		"查询":  {"/search", "/query", "/filter", "/list", "/find"},
		"API": {"/api", "/rest", "/graphql", "/rpc", "/endpoint"},
		"配置":  {"/config", "/settings", "/option", "/preference"},
		"监控":  {"/monitor", "/health", "/status", "/metrics", "/stats", "/log"},
		"业务":  {"/order", "/product", "/payment", "/transaction", "/shop"},
		"系统":  {"/system", "/service", "/job", "/task", "/queue", "/worker"},
		"文档":  {"/doc", "/swagger", "/openapi", "/docs", "/nuclei"},
		"其他":  {},
	}

	for category, keywords := range categories {
		for _, keyword := range keywords {
			if strings.Contains(lowerPath, keyword) {
				return category
			}
		}
	}

	return "其他"
}

func deduplicateResults(results []ApiResult) []ApiResult {
	seen := make(map[string]bool)
	uniqueResults := make([]ApiResult, 0)

	for _, result := range results {
		key := result.Method + ":" + result.Path
		if !seen[key] {
			seen[key] = true
			uniqueResults = append(uniqueResults, result)
		}
	}

	return uniqueResults
}

func verifyApiEndpoint(api ApiResult, config ApiConfig) ApiResult {
	client := resty.New()
	client.SetTimeout(config.Timeout)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(3))

	for k, v := range config.Headers {
		client.SetHeader(k, v)
	}
	client.SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	result := api
	result.Valid = false
	result.Status = "未验证"

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	if api.Method != "" && api.Method != "未知" {
		methods = []string{api.Method}
	}

	for _, method := range methods {
		urlToCheck := api.FullURL
		if urlToCheck == "" {
			urlToCheck = api.Path
		}

		if !strings.HasPrefix(urlToCheck, "http") {
			continue
		}

		var resp *resty.Response
		var err error

		switch method {
		case "GET":
			resp, err = client.R().Get(urlToCheck)
		case "POST":
			resp, err = client.R().SetBody(map[string]interface{}{}).Post(urlToCheck)
		case "PUT":
			resp, err = client.R().SetBody(map[string]interface{}{}).Put(urlToCheck)
		case "DELETE":
			resp, err = client.R().Delete(urlToCheck)
		case "PATCH":
			resp, err = client.R().SetBody(map[string]interface{}{}).Patch(urlToCheck)
		}

		if err == nil && resp != nil {
			statusCode := resp.StatusCode()
			result.Status = fmt.Sprintf("%d", statusCode)

			if statusCode >= 200 && statusCode < 400 {
				result.Valid = true
				result.Response = fmt.Sprintf("OK (%d)", statusCode)
				result.Method = method
				return result
			} else if statusCode >= 400 && statusCode < 500 {
				result.Response = fmt.Sprintf("客户端错误 (%d)", statusCode)
			} else if statusCode >= 500 {
				result.Response = fmt.Sprintf("服务器错误 (%d)", statusCode)
			}
		}
	}

	return result
}

func VerifyApiEndpoints(results *ApiResults, config ApiConfig) {
	fmt.Printf("\n[GYscan-API] 开始验证 %d 个API端点...\n", len(results.Results))

	client := resty.New()
	client.SetTimeout(config.Timeout)

	validCount := 0
	verifiedCount := 0

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.Threads)

	for i := range results.Results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			api := results.Results[idx]
			verified := verifyApiEndpoint(api, config)

			results.mu.Lock()
			results.Results[idx] = verified
			results.mu.Unlock()

			verifiedCount++
			if verified.Valid {
				validCount++
				fmt.Printf("[GYscan-API] ✓ 有效API: %s %s [%s]\n", verified.Method, verified.Path, verified.Status)
			} else if config.Verbose && verified.Status != "未验证" {
				fmt.Printf("[GYscan-API] ✗ 无效API: %s %s [%s]\n", api.Method, api.Path, verified.Status)
			}
		}(i)
	}

	wg.Wait()

	fmt.Printf("[GYscan-API] 验证完成: %d/%d 个API可用\n", validCount, verifiedCount)
}

func PrintApiResults(results ApiResults) {
	fmt.Println("\n[GYscan-API] ==============================")
	fmt.Printf("[GYscan-API] API扫描结果\n")
	fmt.Println("[GYscan-API] ==============================")

	validCount := 0
	for _, r := range results.Results {
		if r.Valid {
			validCount++
		}
	}

	fmt.Printf("[GYscan-API] 总计发现API端点: %d\n", results.Summary.TotalAPIs)
	if validCount > 0 {
		fmt.Printf("[GYscan-API] 有效API端点: %d\n", validCount)
	}
	fmt.Printf("[GYscan-API] GET: %d | POST: %d | PUT: %d | DELETE: %d | PATCH: %d | 其他: %d\n",
		results.Summary.GETCount, results.Summary.POSTCount, results.Summary.PUTCount,
		results.Summary.DELETECount, results.Summary.PATCHCount, results.Summary.OtherCount)
	if results.Summary.PagesScanned > 0 {
		fmt.Printf("[GYscan-API] 扫描页面数: %d\n", results.Summary.PagesScanned)
	}
	fmt.Printf("[GYscan-API] 扫描耗时: %.2f秒\n", results.Summary.ScanTime.Seconds())
	fmt.Println("[GYscan-API] ==============================")
	fmt.Println()

	if len(results.Results) > 0 {
		hasVerification := results.Results[0].Status != ""

		fmt.Println("发现的API端点:")
		if hasVerification {
			fmt.Printf("%-8s %-12s %-10s %s\n", "Method", "Category", "Status", "URL")
		} else {
			fmt.Printf("%-8s %-12s %s\n", "Method", "Category", "URL")
		}

		for _, result := range results.Results {
			url := result.Path
			if hasVerification {
				status := result.Status
				if result.Valid {
					status = "✓ OK"
				} else if result.Status != "" && result.Status != "未验证" {
					status = "✗ " + result.Status
				}
				fmt.Printf("%-8s %-12s %-10s %s\n", result.Method, result.Category, status, url)
			} else {
				fmt.Printf("%-8s %-12s %s\n", result.Method, result.Category, url)
			}
		}
	}

	fmt.Println()
}

func TestApiDetection() {
	fmt.Println("\n[GYscan-API] 开始测试API检测功能...")

	testCases := []struct {
		Name     string
		Content  string
		Expected int
	}{
		{"基础API路径", `fetch('/api/users')`, 1},
		{"RESTful API", `axios.get('/api/v1/users')`, 1},
		{"GraphQL端点", `'/api/graphql'`, 1},
		{"Swagger路径", `'/api/swagger'`, 1},
		{"多API端点", `fetch('/api/login'); fetch('/api/logout');`, 2},
		{"带参数API", `$.get('/api/user/123/profile')`, 1},
		{"内嵌URL", `"https://api.example.com/v1/data"`, 1},
		{"表单action", `<form action="/api/submit" method="POST">`, 1},
		{"非API内容", `This is just some regular text content`, 0},
	}

	passed := 0

	for _, tc := range testCases {
		re := regexp.MustCompile(`["']([^"']*(?:api|endpoint|route|path)[^"']*)['"]`)
		matches := re.FindAllStringSubmatch(tc.Content, -1)

		count := 0
		for _, match := range matches {
			if len(match) >= 2 && isValidAPI(match[1]) {
				count++
			}
		}

		if count == tc.Expected {
			passed++
			fmt.Printf("[GYscan-API] ✓ 通过: %s (发现: %d, 期望: %d)\n", tc.Name, count, tc.Expected)
		} else {
			fmt.Printf("[GYscan-API] ✗ 失败: %s (发现: %d, 期望: %d)\n", tc.Name, count, tc.Expected)
		}
	}

	fmt.Printf("\n[GYscan-API] 测试结果: %d/%d 通过\n", passed, len(testCases))
}

func CheckAndInstallChromium(verbose bool) error {
	if runtime.GOOS != "linux" {
		if verbose {
			fmt.Printf("[GYscan-API] 非Linux系统，跳过Chromium检查\n")
		}
		return nil
	}

	chromiumPaths := []string{
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
	}

	for _, path := range chromiumPaths {
		if _, err := exec.LookPath(path); err == nil {
			if verbose {
				fmt.Printf("[GYscan-API] 已找到浏览器: %s\n", path)
			}
			return nil
		}
	}

	fmt.Printf("[GYscan-API] 未检测到Chromium/Chrome，正在尝试安装...\n")

	distro := detectLinuxDistro()
	if distro == "" {
		return fmt.Errorf("无法检测Linux发行版，请手动安装Chromium")
	}

	var installCmd []string
	switch distro {
	case "debian", "ubuntu", "linuxmint", "kali":
		installCmd = []string{"sudo", "apt", "update", "&&", "sudo", "apt", "install", "-y", "chromium"}
	case "fedora", "rhel", "centos":
		installCmd = []string{"sudo", "dnf", "install", "-y", "chromium"}
	case "arch", "manjaro", "endeavouros":
		installCmd = []string{"sudo", "pacman", "-S", "--noconfirm", "chromium"}
	case "alpine":
		installCmd = []string{"sudo", "apk", "add", "chromium"}
	case "opensuse":
		installCmd = []string{"sudo", "zypper", "install", "-y", "chromium"}
	default:
		return fmt.Errorf("不支持的发行版: %s，请手动安装Chromium", distro)
	}

	fmt.Printf("[GYscan-API] 使用 %s 安装Chromium...\n", distro)
	fmt.Printf("[GYscan-API] 执行命令: %s\n", strings.Join(installCmd, " "))

	cmd := exec.Command("sh", "-c", strings.Join(installCmd, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装Chromium失败: %v", err)
	}

	for _, path := range chromiumPaths {
		if _, err := exec.LookPath(path); err == nil {
			fmt.Printf("[GYscan-API] Chromium安装成功: %s\n", path)
			return nil
		}
	}

	return fmt.Errorf("安装后仍未找到Chromium，请手动安装")
}

func detectLinuxDistro() string {
	files := []string{
		"/etc/os-release",
		"/etc/lsb-release",
		"/etc/debian_version",
		"/etc/fedora-release",
		"/etc/centos-release",
		"/etc/redhat-release",
		"/etc/arch-release",
		"/etc/manjaro-release",
		"/etc/alpine-release",
		"/etc/opensuse-release",
	}

	for _, file := range files {
		if data, err := os.ReadFile(file); err == nil {
			content := string(data)

			if strings.Contains(content, "ID=debian") || strings.Contains(content, "ID=ubuntu") ||
				strings.Contains(content, "ID=kali") || strings.Contains(content, "ID_LIKE=debian") {
				return "debian"
			}
			if strings.Contains(content, "ID=fedora") || strings.Contains(content, "ID=rhel") ||
				strings.Contains(content, "ID=centos") || strings.Contains(content, "ID_LIKE=fedora") {
				return "fedora"
			}
			if strings.Contains(content, "ID=arch") || strings.Contains(content, "ID_LIKE=arch") {
				return "arch"
			}
			if strings.Contains(content, "ID=manjaro") {
				return "manjaro"
			}
			if strings.Contains(content, "ID=alpine") {
				return "alpine"
			}
			if strings.Contains(content, "ID=opensuse") || strings.Contains(content, "ID=opensuse") {
				return "opensuse"
			}
			if strings.Contains(content, "ID=linuxmint") {
				return "linuxmint"
			}
		}
	}

	cmd := exec.Command("sh", "-c", "lsb_release -is 2>/dev/null || echo \"\"")
	output, _ := cmd.Output()
	distro := strings.TrimSpace(string(output))

	switch strings.ToLower(distro) {
	case "debian", "ubuntu", "linuxmint", "kali", "fedora", "rhel", "centos",
		"arch", "manjaro", "alpine", "opensuse":
		return strings.ToLower(distro)
	}

	return ""
}

func RunBrowserApiScan(config ApiConfig) ApiResults {
	if err := CheckAndInstallChromium(config.Verbose); err != nil {
		fmt.Printf("[GYscan-API] 错误: %v\n", err)
		return ApiResults{}
	}

	results := ApiResults{
		Results: make([]ApiResult, 0),
		Summary: ApiSummary{},
	}

	baseURL := config.TargetURL
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Printf("[GYscan-API] URL解析错误: %v\n", err)
		return results
	}

	domain := parsedURL.Host

	if config.Verbose {
		fmt.Printf("[GYscan-API] 启动浏览器扫描目标: %s\n", baseURL)
		if config.Headless {
			fmt.Printf("[GYscan-API] 浏览器模式: 无头模式\n")
		} else {
			fmt.Printf("[GYscan-API] 浏览器模式: 可视化模式\n")
		}
	}

	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		os.Setenv("WAYLAND_DISPLAY", "wayland-0")
	}

	if config.Headless {
		return runBrowserCrawl(config, baseURL, domain)
	}

	return runVisualCrawl(config, baseURL, domain)
}

func runVisualCrawl(config ApiConfig, baseURL, domain string) ApiResults {
	results := ApiResults{
		Results: make([]ApiResult, 0),
		Summary: ApiSummary{},
	}

	startTime := time.Now()

	ctx := context.Background()

	fmt.Printf("[GYscan-API] 主浏览器打开首页并提取链接...\n")

	mainOpts := []chromedp.ExecAllocatorOption{
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("start-maximized", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
	}

	if config.BrowserPath != "" {
		mainOpts = append(mainOpts, chromedp.ExecPath(config.BrowserPath))
	}

	mainAllocCtx, cancelMainAlloc := chromedp.NewExecAllocator(ctx, mainOpts...)
	defer cancelMainAlloc()

	mainBrowserCtx, cancelMainBrowser := chromedp.NewContext(mainAllocCtx)
	defer cancelMainBrowser()

	var mainLinks []string
	var mainHtmlContent string

	mainCtx, cancelMain := context.WithTimeout(mainBrowserCtx, 60*time.Second)
	defer cancelMain()

	err := chromedp.Run(mainCtx,
		chromedp.Navigate(baseURL),
		chromedp.Sleep(3*time.Second),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(config.WaitTime),
		chromedp.EvaluateAsDevTools(`document.documentElement.outerHTML`, &mainHtmlContent),
		chromedp.EvaluateAsDevTools(`
			(function() {
				var urls = [];
				document.querySelectorAll('a[href]').forEach(function(el) {
					if (el.href && (el.href.startsWith('/') || el.href.startsWith(window.location.origin))) {
						urls.push(el.href);
					}
				});
				document.querySelectorAll('button[data-url], button[data-href], button[data-link], button[data-action], [role=button][data-url], [role=button][data-href]').forEach(function(el) {
					var url = el.dataset.url || el.dataset.href || el.dataset.link || el.dataset.action;
					if (url) {
						if (url.startsWith('http')) {
							urls.push(url);
						} else if (url.startsWith('/')) {
							urls.push(window.location.origin + url);
						}
					}
				});
				document.querySelectorAll('form[action]').forEach(function(el) {
					var action = el.action;
					if (action && action.startsWith('/')) {
						urls.push(window.location.origin + action);
					} else if (action && action.startsWith('http')) {
						urls.push(action);
					}
				});
				document.querySelectorAll('[data-api], [data-endpoint], [data-url], [ajax-url], [api-url]').forEach(function(el) {
					var url = el.dataset.api || el.dataset.endpoint || el.dataset.url || el.dataset.ajaxUrl || el.dataset.apiUrl;
					if (url) {
						if (url.startsWith('http')) {
							urls.push(url);
						} else if (url.startsWith('/')) {
							urls.push(window.location.origin + url);
						}
					}
				});
				document.querySelectorAll('[onclick]').forEach(function(el) {
					var onclick = el.getAttribute('onclick');
					if (onclick) {
						var match = onclick.match(/['"]([^'"]+)['"]/);
						if (match && match[1]) {
							var url = match[1];
							if (url.startsWith('http')) {
								urls.push(url);
							} else if (url.startsWith('/')) {
								urls.push(window.location.origin + url);
							}
						}
					}
				});
				return urls;
			})()
		`, &mainLinks),
	)

	if err != nil {
		fmt.Printf("[GYscan-API] 首页访问失败: %v\n", err)
		return results
	}

	if config.Verbose {
		fmt.Printf("[GYscan-API] 首页内容长度: %d 字节\n", len(mainHtmlContent))
	}

	extractApisFromJS([]byte(mainHtmlContent), baseURL, baseURL, &results, config)
	extractApisFromHTML(mainHtmlContent, baseURL, baseURL, &results)

	extractJsFilesFromHTML(mainHtmlContent, baseURL, &results, config)

	if config.Verbose {
		fmt.Printf("[GYscan-API] 首页提取到 %d 个API\n", len(results.Results))
	}

	visited := make(map[string]bool)
	var visitedMu sync.Mutex
	queue := []string{baseURL}

	visited[baseURL] = true

	for _, link := range mainLinks {
		parsed, _ := url.Parse(link)
		if parsed != nil && (parsed.Host == "" || parsed.Host == domain) {
			fullURL := resolveURL(link, baseURL)
			if fullURL != "" && fullURL != baseURL {
				queue = append(queue, fullURL)
			}
		}
	}

	pagesScanned := 0
	fmt.Printf("[GYscan-API] 首页扫描完成，发现 %d 个链接，开始并行分析...\n", len(queue)-1)

	threadCount := config.Threads
	if threadCount < 2 {
		threadCount = 2
	}
	if threadCount > 10 {
		threadCount = 10
	}

	fmt.Printf("[GYscan-API] 启动顺序任务...\n")

	queueIndex := 0
	for queueIndex < len(queue) {
		link := queue[queueIndex]
		queueIndex++

		if link == baseURL {
			continue
		}

		visitedMu.Lock()
		if visited[link] {
			visitedMu.Unlock()
			continue
		}
		visited[link] = true
		visitedMu.Unlock()

		pagesScanned++

		if config.Verbose {
			fmt.Printf("[%d/%d] 打开页面: %s\n", queueIndex, len(queue), link)
		} else if queueIndex%10 == 0 {
			fmt.Printf("[GYscan-API] 已处理 %d/%d 页...\n", queueIndex, len(queue))
		}

		var htmlContent string
		var links []string

		pageCtx, cancelPage := context.WithTimeout(ctx, 60*time.Second)
		pageErr := chromedp.Run(pageCtx,
			chromedp.Navigate(link),
			chromedp.Sleep(3*time.Second),
			chromedp.WaitReady("body", chromedp.ByQuery),
			chromedp.Sleep(config.WaitTime),
			chromedp.EvaluateAsDevTools(`document.documentElement.outerHTML`, &htmlContent),
			chromedp.EvaluateAsDevTools(`
				(function() {
					var urls = [];
					document.querySelectorAll('a[href]').forEach(function(el) {
						if (el.href && (el.href.startsWith('/') || el.href.startsWith(window.location.origin))) {
							urls.push(el.href);
						}
					});
					document.querySelectorAll('button[data-url], button[data-href], button[data-link], button[data-action], [role=button][data-url], [role=button][data-href]').forEach(function(el) {
						var url = el.dataset.url || el.dataset.href || el.dataset.link || el.dataset.action;
						if (url) {
							if (url.startsWith('http')) {
								urls.push(url);
							} else if (url.startsWith('/')) {
								urls.push(window.location.origin + url);
							}
						}
					});
					document.querySelectorAll('form[action]').forEach(function(el) {
						var action = el.action;
						if (action && action.startsWith('/')) {
							urls.push(window.location.origin + action);
						} else if (action && action.startsWith('http')) {
							urls.push(action);
						}
					});
					document.querySelectorAll('[data-api], [data-endpoint], [data-url], [ajax-url], [api-url]').forEach(function(el) {
						var url = el.dataset.api || el.dataset.endpoint || el.dataset.url || el.dataset.ajaxUrl || el.dataset.apiUrl;
						if (url) {
							if (url.startsWith('http')) {
								urls.push(url);
							} else if (url.startsWith('/')) {
								urls.push(window.location.origin + url);
							}
						}
					});
					document.querySelectorAll('[onclick]').forEach(function(el) {
						var onclick = el.getAttribute('onclick');
						if (onclick) {
							var match = onclick.match(/['"]([^'"]+)['"]/);
							if (match && match[1]) {
								var url = match[1];
								if (url.startsWith('http')) {
									urls.push(url);
								} else if (url.startsWith('/')) {
									urls.push(window.location.origin + url);
								}
							}
						}
					});
					return urls;
				})()
			`, &links),
		)
		cancelPage()

		if pageErr != nil {
			if config.Verbose {
				fmt.Printf("[GYscan-API] 页面访问失败: %s\n", link)
			}
			continue
		}

		extractApisFromJS([]byte(htmlContent), baseURL, link, &results, config)
		extractApisFromHTML(htmlContent, baseURL, link, &results)

		for _, newLink := range links {
			parsed, _ := url.Parse(newLink)
			if parsed != nil && (parsed.Host == "" || parsed.Host == domain) {
				fullURL := resolveURL(newLink, baseURL)
				if fullURL != "" {
					visitedMu.Lock()
					if !visited[fullURL] {
						visited[fullURL] = true
						visitedMu.Unlock()
						queue = append(queue, fullURL)
					} else {
						visitedMu.Unlock()
					}
				}
			}
		}

		if config.MaxPages > 0 && pagesScanned >= config.MaxPages {
			fmt.Printf("[GYscan-API] 已达到最大页面数: %d\n", config.MaxPages)
			break
		}
	}

	results.Results = deduplicateResults(results.Results)

	results.Summary.ScanTime = time.Since(startTime)
	results.Summary.PagesScanned = pagesScanned
	results.Summary.TotalAPIs = len(results.Results)

	for _, api := range results.Results {
		switch api.Method {
		case "GET":
			results.Summary.GETCount++
		case "POST":
			results.Summary.POSTCount++
		case "PUT":
			results.Summary.PUTCount++
		case "DELETE":
			results.Summary.DELETECount++
		case "PATCH":
			results.Summary.PATCHCount++
		default:
			results.Summary.OtherCount++
		}
	}

	return results
}

func runBrowserCrawl(config ApiConfig, baseURL, domain string) ApiResults {
	results := ApiResults{
		Results: make([]ApiResult, 0),
		Summary: ApiSummary{},
	}

	startTime := time.Now()

	opts := []chromedp.ExecAllocatorOption{
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable_gpu", false),
		chromedp.Flag("enable-features", "UseOzonePlatform"),
		chromedp.Flag("ozone-platform-hint", "auto"),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	}

	if config.NoSandbox {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
		opts = append(opts, chromedp.Flag("disable-setuid-sandbox", true))
	}

	if config.BrowserPath != "" {
		opts = append(opts, chromedp.ExecPath(config.BrowserPath))
	}

	if config.Headless {
		opts = append(opts, chromedp.Headless)
	} else {
		opts = append(opts, chromedp.Flag("start-maximized", true))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	pagesVisited := make(map[string]bool)
	pagesScanned := 0
	var visitedMu sync.Mutex

	fmt.Printf("[GYscan-API] 浏览器打开首页...\n")

	extractApisWithBrowser(browserCtx, baseURL, baseURL, domain, &results, config)
	pagesScanned++
	pagesVisited[baseURL] = true

	if config.Verbose {
		fmt.Printf("[GYscan-API] 首页扫描完成，发现 %d 个API\n", len(results.Results))
	}

	queue := []string{baseURL}
	extractLinksWithBrowserSlice(browserCtx, baseURL, baseURL, domain, &queue, pagesVisited, &visitedMu, config)

	queueIndex := 0
	for queueIndex < len(queue) {
		link := queue[queueIndex]
		queueIndex++

		if link == baseURL {
			continue
		}

		visitedMu.Lock()
		if pagesVisited[link] {
			visitedMu.Unlock()
			continue
		}
		pagesVisited[link] = true
		visitedMu.Unlock()

		pagesScanned++

		if config.Verbose {
			fmt.Printf("[%d/%d] 访问页面: %s\n", queueIndex, len(queue), link)
		}

		extractApisWithBrowser(browserCtx, link, baseURL, domain, &results, config)
		extractLinksWithBrowserSlice(browserCtx, link, baseURL, domain, &queue, pagesVisited, &visitedMu, config)

		if config.MaxPages > 0 && pagesScanned >= config.MaxPages {
			fmt.Printf("[GYscan-API] 已达到最大页面数: %d\n", config.MaxPages)
			break
		}
	}

	results.Summary.ScanTime = time.Since(startTime)
	results.Summary.PagesScanned = pagesScanned
	results.Summary.TotalAPIs = len(results.Results)

	for _, api := range results.Results {
		switch api.Method {
		case "GET":
			results.Summary.GETCount++
		case "POST":
			results.Summary.POSTCount++
		case "PUT":
			results.Summary.PUTCount++
		case "DELETE":
			results.Summary.DELETECount++
		case "PATCH":
			results.Summary.PATCHCount++
		default:
			results.Summary.OtherCount++
		}
	}

	results.Results = deduplicateResults(results.Results)

	return results
}

func extractApisWithBrowser(browserCtx context.Context, pageURL, baseURL, domain string, results *ApiResults, config ApiConfig) {
	var htmlContent string

	pageCtx, cancel := context.WithTimeout(browserCtx, 30*time.Second)
	defer cancel()

	err := chromedp.Run(pageCtx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(2*time.Second),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(config.WaitTime),
		chromedp.EvaluateAsDevTools(`document.documentElement.outerHTML`, &htmlContent),
	)

	if err != nil {
		if config.Verbose {
			fmt.Printf("[GYscan-API] 浏览器访问失败: %s - %v\n", pageURL, err)
		}
		return
	}

	if config.Verbose {
		fmt.Printf("[GYscan-API] 浏览器成功访问: %s\n", pageURL)
	}

	if htmlContent != "" {
		extractApisFromJS([]byte(htmlContent), baseURL, pageURL, results, config)
		extractApisFromHTML(htmlContent, baseURL, pageURL, results)
	}
}

func extractLinksWithBrowserSlice(browserCtx context.Context, pageURL, baseURL, domain string, queue *[]string, visited map[string]bool, visitedMu *sync.Mutex, config ApiConfig) {
	defer func() {
		recover()
	}()

	var links []string

	linkCtx, cancel := context.WithTimeout(browserCtx, 15*time.Second)
	defer cancel()

	err := chromedp.Run(linkCtx,
		chromedp.EvaluateAsDevTools(`
			Array.from(document.querySelectorAll('a[href], button[data-url], button[data-href], button[data-link], form[action], [data-api], [data-endpoint]')).map(el => {
				if (el.tagName === 'A') return el.href;
				if (el.tagName === 'BUTTON' || el.dataset.url || el.dataset.href || el.dataset.link) return el.dataset.url || el.dataset.href || el.dataset.link || '';
				if (el.tagName === 'FORM') return el.action || '';
				return el.dataset.api || el.dataset.endpoint || '';
			}).filter(h => h && h.startsWith('http') || (h && h.startsWith('/')))
		`, &links),
	)

	if err != nil {
		if config.Verbose {
			fmt.Printf("[GYscan-API] 提取链接失败: %s - %v\n", pageURL, err)
		}
		return
	}

	if config.Verbose {
		fmt.Printf("[GYscan-API] 从 %s 提取到 %d 个链接\n", pageURL, len(links))
	}

	for _, link := range links {
		if link == "" {
			continue
		}

		parsed, err := url.Parse(link)
		if err != nil {
			continue
		}

		if parsed.Host != "" && parsed.Host != domain {
			continue
		}

		fullURL := resolveURL(link, baseURL)
		if fullURL == "" {
			continue
		}

		visitedMu.Lock()
		if !visited[fullURL] {
			visited[fullURL] = true
			visitedMu.Unlock()
			*queue = append(*queue, fullURL)
		} else {
			visitedMu.Unlock()
		}
	}
}

func extractLinksWithBrowser(browserCtx context.Context, pageURL, baseURL, domain string, pageChan chan<- string, visited map[string]bool, visitedMu *sync.Mutex, config ApiConfig) {
	defer func() {
		recover()
	}()

	var links []string

	err := chromedp.Run(browserCtx,
		chromedp.EvaluateAsDevTools(`
			Array.from(document.querySelectorAll('a[href], button[data-url], button[data-href], button[data-link], form[action], [data-api], [data-endpoint]')).map(el => {
				if (el.tagName === 'A') return el.href;
				if (el.tagName === 'BUTTON' || el.dataset.url || el.dataset.href || el.dataset.link) return el.dataset.url || el.dataset.href || el.dataset.link || '';
				if (el.tagName === 'FORM') return el.action || '';
				return el.dataset.api || el.dataset.endpoint || '';
			}).filter(h => h && h.startsWith('http') || (h && h.startsWith('/')))
		`, &links),
	)

	if err != nil {
		if config.Verbose {
			fmt.Printf("[GYscan-API] 提取链接失败: %s - %v\n", pageURL, err)
		}
		return
	}

	if config.Verbose {
		fmt.Printf("[GYscan-API] 从 %s 提取到 %d 个链接\n", pageURL, len(links))
	}

	for _, link := range links {
		if link == "" {
			continue
		}

		parsed, err := url.Parse(link)
		if err != nil {
			continue
		}

		if parsed.Host != "" && parsed.Host != domain {
			continue
		}

		if strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "tel:") || strings.HasPrefix(link, "javascript:") {
			continue
		}

		fullURL := resolveURL(link, baseURL)
		if fullURL == "" {
			continue
		}

		visitedMu.Lock()
		if visited[fullURL] {
			visitedMu.Unlock()
			continue
		}
		visited[fullURL] = true
		visitedMu.Unlock()

		if config.Verbose {
			fmt.Printf("[GYscan-API] 发现新页面: %s\n", fullURL)
		}

		select {
		case pageChan <- fullURL:
		default:
		}
	}
}

func CDPGetDocument(ctx context.Context) (string, error) {
	var html string
	err := chromedp.EvaluateAsDevTools(`document.documentElement.outerHTML`, &html).Do(ctx)
	if err != nil {
		return "", err
	}
	return html, nil
}
