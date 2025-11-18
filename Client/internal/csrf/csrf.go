package csrf

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/valyala/fasttemplate"
)

// RunScan 执行CSRF漏洞扫描
func RunScan(config Config) Results {
	results := Results{
		Summary: Summary{
			TotalURLs: 1,
		},
		Items: []Result{},
	}

	// 初始化HTTP客户端
	client := initHTTPClient(config)

	// 如果需要登录，先执行登录
	if config.LoginURL != "" {
		if err := login(client, config); err != nil {
			if config.Verbose {
				fmt.Printf("[GYscan-CSRF] 登录失败: %v\n", err)
			}
			return results
		}
	}

	// 获取原始页面内容，用于提取CSRF Token
	originalResp, err := client.R().Get(config.URL)
	if err != nil {
		if config.Verbose {
			fmt.Printf("[GYscan-CSRF] 获取目标页面失败: %v\n", err)
		}
		return results
	}

	// 提取页面中的CSRF Token
	tokens := extractCSRFTokens(originalResp.String())

	// 解析原始表单数据
	originalFormData := parseFormData(config.Data)

	// 解析URL参数
	originalParams := parseParams(config.Params)

	// 执行各种CSRF检测场景
	results = appendResults(results, testNoTokenScenario(client, config, originalFormData, originalParams, originalResp.StatusCode()))
	results = appendResults(results, testInvalidTokenScenario(client, config, originalFormData, originalParams, originalResp.StatusCode(), tokens))
	results = appendResults(results, testTamperedTokenScenario(client, config, originalFormData, originalParams, originalResp.StatusCode(), tokens))
	results = appendResults(results, testFakeRefererScenario(client, config, originalFormData, originalParams, originalResp.StatusCode(), tokens))
	results = appendResults(results, testEmptyRefererScenario(client, config, originalFormData, originalParams, originalResp.StatusCode(), tokens))
	results = appendResults(results, testCrossOriginRefererScenario(client, config, originalFormData, originalParams, originalResp.StatusCode(), tokens))
	results = appendResults(results, checkCookieSameSite(client, config))

	// 更新总结信息
	results.Summary.TotalTests = len(results.Items)
	for _, result := range results.Items {
		if result.IsVulnerable {
			results.Summary.VulnerableTests++
			results.Summary.TotalVulnerabilities++
		}
	}

	return results
}

// initHTTPClient 初始化HTTP客户端
func initHTTPClient(config Config) *resty.Client {
	client := resty.New()

	// 基本配置
	client.SetTimeout(time.Duration(config.Timeout) * time.Second)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	// 设置默认User-Agent
	if config.UserAgent == "" {
		// 使用预定义的User-Agent，避免依赖user_agent库的复杂API
		client.SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	} else {
		client.SetHeader("User-Agent", config.UserAgent)
	}

	// 设置代理
	if config.Proxy != "" {
		client.SetProxy(config.Proxy)
	}

	// 设置Cookies
	if config.Cookies != "" {
		client.SetCookies(parseCookies(config.Cookies))
	}

	// 设置其他头信息
	if config.Headers != "" {
		for _, header := range strings.Split(config.Headers, "&") {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				client.SetHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// 设置Referer
	if config.Referer != "" {
		client.SetHeader("Referer", config.Referer)
	}

	return client
}

// login 执行登录操作
func login(client *resty.Client, config Config) error {
	loginData := url.Values{}

	// 如果提供了登录数据模板，使用模板渲染
	if config.LoginData != "" {
		tpl := fasttemplate.New(config.LoginData, "{{", "}}")
		renderedData := tpl.ExecuteString(map[string]interface{}{
			"username": config.LoginUsername,
			"password": config.LoginPassword,
		})
		for _, param := range strings.Split(renderedData, "&") {
			parts := strings.SplitN(param, "=", 2)
			if len(parts) == 2 {
				loginData.Add(parts[0], parts[1])
			}
		}
	} else {
		// 否则使用默认的用户名密码字段
		loginData.Add("username", config.LoginUsername)
		loginData.Add("password", config.LoginPassword)
	}

	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.LoginMethod) {
	case "POST":
		resp, err = client.R().SetFormDataFromValues(loginData).Post(config.LoginURL)
	case "GET":
		resp, err = client.R().SetQueryParamsFromValues(loginData).Get(config.LoginURL)
	default:
		resp, err = client.R().SetFormDataFromValues(loginData).Post(config.LoginURL)
	}

	if err != nil {
		return err
	}

	// 检查登录是否成功
	if config.LoginSuccess != "" && !strings.Contains(resp.String(), config.LoginSuccess) {
		return fmt.Errorf("登录成功标识未找到")
	}

	return nil
}

// extractCSRFTokens 从HTML页面中提取CSRF Token
func extractCSRFTokens(html string) []string {
	var tokens []string
	reader := strings.NewReader(html)
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return tokens
	}

	// 提取常见的CSRF Token字段
	selectors := []string{
		"input[name='csrf_token']",
		"input[name='_csrf_token']",
		"input[name='csrfmiddlewaretoken']",
		"input[name='anticsrf']",
		"input[name='__RequestVerificationToken']",
		"input[name='token']",
		"meta[name='csrf-token']",
	}

	for _, selector := range selectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			var token string
			if strings.HasPrefix(selector, "meta") {
				token, _ = s.Attr("content")
			} else {
				token, _ = s.Attr("value")
			}
			if token != "" {
				tokens = append(tokens, token)
			}
		})
	}

	return tokens
}

// testNoTokenScenario 测试无CSRF Token的请求场景
func testNoTokenScenario(client *resty.Client, config Config, formData map[string]string, params map[string]string, expectedStatus int) Results {
	results := Results{
		Items: []Result{},
	}

	// 移除所有可能的CSRF Token字段
	cleanFormData := cleanCSRFTokenFields(formData)
	cleanParams := cleanCSRFTokenFields(params)

	startTime := time.Now()
	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.Method) {
	case "POST":
		resp, err = client.R().SetFormData(cleanFormData).Post(config.URL)
	case "GET":
		resp, err = client.R().SetQueryParams(cleanParams).Get(config.URL)
	default:
		resp, err = client.R().SetFormData(cleanFormData).Post(config.URL)
	}

	responseTime := time.Since(startTime).Seconds()

	if err != nil {
		return results
	}

	result := Result{
		URL:              config.URL,
		Method:           config.Method,
		VulnerabilityType: "无CSRF Token保护",
		Payload:          "移除所有CSRF Token字段",
		StatusCode:       resp.StatusCode(),
		ResponseTime:     responseTime,
		Evidence:         fmt.Sprintf("响应状态码: %d (预期: %d)", resp.StatusCode(), expectedStatus),
		IsVulnerable:     resp.StatusCode() == expectedStatus,
	}

	results.Items = append(results.Items, result)
	return results
}

// testInvalidTokenScenario 测试无效CSRF Token的请求场景
func testInvalidTokenScenario(client *resty.Client, config Config, formData map[string]string, params map[string]string, expectedStatus int, validTokens []string) Results {
	results := Results{
		Items: []Result{},
	}

	// 如果没有有效的Token，跳过此测试
	if len(validTokens) == 0 {
		return results
	}

	// 使用随机UUID作为无效Token
	invalidToken := uuid.New().String()

	// 在表单数据和参数中添加无效Token
	for field := range getCommonCSRFTokenFields() {
		formData[field] = invalidToken
		params[field] = invalidToken
	}

	startTime := time.Now()
	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.Method) {
	case "POST":
		resp, err = client.R().SetFormData(formData).Post(config.URL)
	case "GET":
		resp, err = client.R().SetQueryParams(params).Get(config.URL)
	default:
		resp, err = client.R().SetFormData(formData).Post(config.URL)
	}

	responseTime := time.Since(startTime).Seconds()

	if err != nil {
		return results
	}

	result := Result{
		URL:              config.URL,
		Method:           config.Method,
		VulnerabilityType: "无效CSRF Token接受",
		Payload:          fmt.Sprintf("使用无效Token: %s", invalidToken),
		StatusCode:       resp.StatusCode(),
		ResponseTime:     responseTime,
		Evidence:         fmt.Sprintf("响应状态码: %d (预期: %d)", resp.StatusCode(), expectedStatus),
		IsVulnerable:     resp.StatusCode() == expectedStatus,
	}

	results.Items = append(results.Items, result)
	return results
}

// testTamperedTokenScenario 测试篡改CSRF Token的请求场景
func testTamperedTokenScenario(client *resty.Client, config Config, formData map[string]string, params map[string]string, expectedStatus int, validTokens []string) Results {
	results := Results{
		Items: []Result{},
	}

	// 如果没有有效的Token，跳过此测试
	if len(validTokens) == 0 {
		return results
	}

	// 篡改第一个有效的Token
	validToken := validTokens[0]
	tamperedToken := validToken + "_tampered"

	// 在表单数据和参数中添加篡改后的Token
	for field := range getCommonCSRFTokenFields() {
		formData[field] = tamperedToken
		params[field] = tamperedToken
	}

	startTime := time.Now()
	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.Method) {
	case "POST":
		resp, err = client.R().SetFormData(formData).Post(config.URL)
	case "GET":
		resp, err = client.R().SetQueryParams(params).Get(config.URL)
	default:
		resp, err = client.R().SetFormData(formData).Post(config.URL)
	}

	responseTime := time.Since(startTime).Seconds()

	if err != nil {
		return results
	}

	result := Result{
		URL:              config.URL,
		Method:           config.Method,
		VulnerabilityType: "篡改CSRF Token接受",
		Payload:          fmt.Sprintf("篡改Token: %s", tamperedToken),
		StatusCode:       resp.StatusCode(),
		ResponseTime:     responseTime,
		Evidence:         fmt.Sprintf("响应状态码: %d (预期: %d)", resp.StatusCode(), expectedStatus),
		IsVulnerable:     resp.StatusCode() == expectedStatus,
	}

	results.Items = append(results.Items, result)
	return results
}

// testFakeRefererScenario 测试伪造Referer的请求场景
func testFakeRefererScenario(client *resty.Client, config Config, formData map[string]string, params map[string]string, expectedStatus int, tokens []string) Results {
	results := Results{
		Items: []Result{},
	}

	// 添加有效的Token
	for field := range getCommonCSRFTokenFields() {
		if len(tokens) > 0 {
			formData[field] = tokens[0]
			params[field] = tokens[0]
		}
	}

	// 使用跨域Referer
	fakeReferer := "https://evil.com"

	startTime := time.Now()
	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.Method) {
	case "POST":
		resp, err = client.R().SetFormData(formData).SetHeader("Referer", fakeReferer).Post(config.URL)
	case "GET":
		resp, err = client.R().SetQueryParams(params).SetHeader("Referer", fakeReferer).Get(config.URL)
	default:
		resp, err = client.R().SetFormData(formData).SetHeader("Referer", fakeReferer).Post(config.URL)
	}

	responseTime := time.Since(startTime).Seconds()

	if err != nil {
		return results
	}

	result := Result{
		URL:              config.URL,
		Method:           config.Method,
		VulnerabilityType: "Referer头伪造",
		Payload:          fmt.Sprintf("伪造Referer: %s", fakeReferer),
		StatusCode:       resp.StatusCode(),
		ResponseTime:     responseTime,
		Evidence:         fmt.Sprintf("响应状态码: %d (预期: %d)", resp.StatusCode(), expectedStatus),
		IsVulnerable:     resp.StatusCode() == expectedStatus,
	}

	results.Items = append(results.Items, result)
	return results
}

// testEmptyRefererScenario 测试空Referer的请求场景
func testEmptyRefererScenario(client *resty.Client, config Config, formData map[string]string, params map[string]string, expectedStatus int, tokens []string) Results {
	results := Results{
		Items: []Result{},
	}

	// 添加有效的Token
	for field := range getCommonCSRFTokenFields() {
		if len(tokens) > 0 {
			formData[field] = tokens[0]
			params[field] = tokens[0]
		}
	}

	// 使用空Referer
	startTime := time.Now()
	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.Method) {
	case "POST":
		resp, err = client.R().SetFormData(formData).SetHeader("Referer", "").Post(config.URL)
	case "GET":
		resp, err = client.R().SetQueryParams(params).SetHeader("Referer", "").Get(config.URL)
	default:
		resp, err = client.R().SetFormData(formData).SetHeader("Referer", "").Post(config.URL)
	}

	responseTime := time.Since(startTime).Seconds()

	if err != nil {
		return results
	}

	result := Result{
		URL:              config.URL,
		Method:           config.Method,
		VulnerabilityType: "空Referer接受",
		Payload:          "空Referer头",
		StatusCode:       resp.StatusCode(),
		ResponseTime:     responseTime,
		Evidence:         fmt.Sprintf("响应状态码: %d (预期: %d)", resp.StatusCode(), expectedStatus),
		IsVulnerable:     resp.StatusCode() == expectedStatus,
	}

	results.Items = append(results.Items, result)
	return results
}

// testCrossOriginRefererScenario 测试跨域Origin的请求场景
func testCrossOriginRefererScenario(client *resty.Client, config Config, formData map[string]string, params map[string]string, expectedStatus int, tokens []string) Results {
	results := Results{
		Items: []Result{},
	}

	// 添加有效的Token
	for field := range getCommonCSRFTokenFields() {
		if len(tokens) > 0 {
			formData[field] = tokens[0]
			params[field] = tokens[0]
		}
	}

	// 使用跨域Origin
	fakeOrigin := "https://attacker.com"

	startTime := time.Now()
	var resp *resty.Response
	var err error

	switch strings.ToUpper(config.Method) {
	case "POST":
		resp, err = client.R().SetFormData(formData).SetHeader("Origin", fakeOrigin).Post(config.URL)
	case "GET":
		resp, err = client.R().SetQueryParams(params).SetHeader("Origin", fakeOrigin).Get(config.URL)
	default:
		resp, err = client.R().SetFormData(formData).SetHeader("Origin", fakeOrigin).Post(config.URL)
	}

	responseTime := time.Since(startTime).Seconds()

	if err != nil {
		return results
	}

	result := Result{
		URL:              config.URL,
		Method:           config.Method,
		VulnerabilityType: "Origin头伪造",
		Payload:          fmt.Sprintf("伪造Origin: %s", fakeOrigin),
		StatusCode:       resp.StatusCode(),
		ResponseTime:     responseTime,
		Evidence:         fmt.Sprintf("响应状态码: %d (预期: %d)", resp.StatusCode(), expectedStatus),
		IsVulnerable:     resp.StatusCode() == expectedStatus,
	}

	results.Items = append(results.Items, result)
	return results
}

// checkCookieSameSite 检查Cookie的SameSite配置
func checkCookieSameSite(client *resty.Client, config Config) Results {
	results := Results{
		Items: []Result{},
	}

	// 发送请求获取Cookie
	resp, err := client.R().Get(config.URL)
	if err != nil {
		return results
	}

	// 检查所有Cookie
	for _, cookie := range resp.Cookies() {
		// 解析Cookie的SameSite属性
		cookieStr := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
		if cookie.Path != "" {
			cookieStr += fmt.Sprintf("; Path=%s", cookie.Path)
		}
		if cookie.Domain != "" {
			cookieStr += fmt.Sprintf("; Domain=%s", cookie.Domain)
		}
		if cookie.Secure {
			cookieStr += "; Secure"
		}
		if cookie.HttpOnly {
			cookieStr += "; HttpOnly"
		}
		if cookie.SameSite != http.SameSiteDefaultMode {
			// 手动转换SameSite类型为字符串
			var sameSiteStr string
			switch cookie.SameSite {
			case http.SameSiteStrictMode:
				sameSiteStr = "Strict"
			case http.SameSiteLaxMode:
				sameSiteStr = "Lax"
			case http.SameSiteNoneMode:
				sameSiteStr = "None"
			default:
				sameSiteStr = "Default"
			}
			cookieStr += fmt.Sprintf("; SameSite=%s", sameSiteStr)
		}

		// 简化Cookie检查，直接使用标准库解析

		// 检查SameSite配置
		isVulnerable := false
		vulnerabilityType := ""

		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			// SameSite=None必须配合Secure使用
			isVulnerable = true
			vulnerabilityType = "SameSite=None缺少Secure标志"
		} else if cookie.SameSite == http.SameSiteDefaultMode {
			// 默认模式可能不安全
			isVulnerable = true
			vulnerabilityType = "缺少SameSite配置"
		} else if !cookie.HttpOnly {
			// Cookie可被JavaScript读取，增加CSRF风险
			isVulnerable = true
			vulnerabilityType = "Cookie缺少HttpOnly标志"
		}

		if isVulnerable {
			result := Result{
				URL:              config.URL,
				Method:           "GET",
				VulnerabilityType: vulnerabilityType,
				Payload:          fmt.Sprintf("Cookie: %s", cookie.Name),
				StatusCode:       resp.StatusCode(),
				ResponseTime:     0,
				Evidence:         fmt.Sprintf("Cookie配置: %s", cookieStr),
				IsVulnerable:     true,
			}

			results.Items = append(results.Items, result)
		}
	}

	return results
}

// getCommonCSRFTokenFields 获取常见的CSRF Token字段名
func getCommonCSRFTokenFields() map[string]bool {
	return map[string]bool{
		"csrf_token":              true,
		"_csrf_token":             true,
		"csrfmiddlewaretoken":     true,
		"anticsrf":               true,
		"__RequestVerificationToken": true,
		"token":                  true,
	}
}

// cleanCSRFTokenFields 清理表单数据和参数中的CSRF Token字段
func cleanCSRFTokenFields(data map[string]string) map[string]string {
	cleaned := make(map[string]string)
	csrfFields := getCommonCSRFTokenFields()

	for key, value := range data {
		if !csrfFields[key] {
			cleaned[key] = value
		}
	}

	return cleaned
}

// parseFormData 解析表单数据
func parseFormData(data string) map[string]string {
	formData := make(map[string]string)
	for _, param := range strings.Split(data, "&") {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 {
			formData[parts[0]] = parts[1]
		}
	}
	return formData
}

// parseParams 解析URL参数
func parseParams(params string) map[string]string {
	parsedParams := make(map[string]string)
	for _, param := range strings.Split(params, "&") {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 {
			parsedParams[parts[0]] = parts[1]
		}
	}
	return parsedParams
}

// parseCookies 解析Cookie字符串
func parseCookies(cookiesStr string) []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookieStr := range strings.Split(cookiesStr, ";") {
		cookieStr = strings.TrimSpace(cookieStr)
		if cookieStr == "" {
			continue
		}

		parts := strings.SplitN(cookieStr, "=", 2)
		if len(parts) != 2 {
			continue
		}

		cookies = append(cookies, &http.Cookie{
			Name:  strings.TrimSpace(parts[0]),
			Value: strings.TrimSpace(parts[1]),
		})
	}
	return cookies
}

// appendResults 合并结果
func appendResults(results1, results2 Results) Results {
	results1.Summary.TotalTests += len(results2.Items)
	results1.Summary.VulnerableTests += countVulnerableResults(results2)
	results1.Summary.TotalVulnerabilities += countVulnerableResults(results2)
	results1.Items = append(results1.Items, results2.Items...)
	return results1
}

// countVulnerableResults 计算漏洞数量
func countVulnerableResults(results Results) int {
	count := 0
	for _, result := range results.Items {
		if result.IsVulnerable {
			count++
		}
	}
	return count
}