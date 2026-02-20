package living

import (
	"fmt"
	"regexp"
	"strings"
)

type WAFType string

const (
	WAFNone        WAFType = "none"
	WAFUnknown     WAFType = "unknown"
	WAFAliyun      WAFType = "aliyun"
	WAF腾讯云         WAFType = "tencent"
	WAF华为云         WAFType = "huawei"
	WAFAWS         WAFType = "aws"
	WAFAzure       WAFType = "azure"
	WAFCloudflare  WAFType = "cloudflare"
	WAFAkamai      WAFType = "akamai"
	WAFImperva     WAFType = "imperva"
	WAFFortinet    WAFType = "fortinet"
	WAFPaloAlto    WAFType = "paloalto"
	WAFSucuri      WAFType = "sucuri"
	WAFModSecurity WAFType = "modsecurity"
	WAFNginx       WAFType = "nginx"
	WAFApache      WAFType = "apache"
	WAFIIS         WAFType = "iis"
	WAF403         WAFType = "403_forbidden"
	WAF429         WAFType = "rate_limit"
)

type WAFSignature struct {
	Name        WAFType
	Patterns    []*regexp.Regexp
	Headers     []string
	StatusCodes []int
	Keywords    []string
}

var wafSignatures = []WAFSignature{
	{
		Name: WAFAliyun,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aliyundun`),
			regexp.MustCompile(`(?i)aliyun\.com`),
			regexp.MustCompile(`(?i)error\.aliyun`),
			regexp.MustCompile(`(?i)waf\.aliyun`),
		},
		Headers: []string{
			"X-Swift-Cache-Time",
			"X-Swift-Save-Time",
			"Aliyun-OSS-TOKEN",
		},
		StatusCodes: []int{403, 405},
		Keywords: []string{
			"aliyundun",
			"security.aliyun.com",
			"waf.aliyun.com",
			"ipblacklist",
		},
	},
	{
		Name: WAF腾讯云,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)tencentcloud`),
			regexp.MustCompile(`(?i)waf\.qcloud`),
			regexp.MustCompile(`(?i)waf\.tencent`),
			regexp.MustCompile(`(?i)cdn\.twms`),
		},
		Headers: []string{
			"X-Cdn-From",
			"X-Gw-Cdn-Type",
			"Server",
		},
		StatusCodes: []int{403, 405},
		Keywords: []string{
			"tencentcloud",
			"waf.qcloud",
			"waf.tencent",
			"DNSPOD",
		},
	},
	{
		Name: WAF华为云,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)huaweicloud`),
			regexp.MustCompile(`(?i)waf\.huawei`),
			regexp.MustCompile(`(?i)hwclouds`),
		},
		Headers: []string{
			"HuaweiCloud-Request-ID",
			"HuaweiCloud-TRC",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"huaweicloud",
			"hwclouds.com",
			"hwcloud.cn",
		},
	},
	{
		Name: WAFAWS,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)aws\.waf`),
			regexp.MustCompile(`(?i)amazon-aws`),
			regexp.MustCompile(`(?i)amazonaws`),
		},
		Headers: []string{
			"X-Amzn-Requestid",
			"Server",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"aws-waf",
			"Amazon-CloudFront",
			"Amazon-CloudFront-Request-ID",
		},
	},
	{
		Name: WAFAzure,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)azure-waf`),
			regexp.MustCompile(`(?i)azure\.microsoft`),
			regexp.MustCompile(`(?i)azureedge`),
		},
		Headers: []string{
			"X-Correlation-Context",
			"X-Azure-Ref",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"azure-waf",
			"Microsoft-Azure-WAF",
		},
	},
	{
		Name: WAFCloudflare,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)cloudflare`),
			regexp.MustCompile(`(?i)cf-ray`),
			regexp.MustCompile(`(?i)cloudflare-nginx`),
		},
		Headers: []string{
			"cf-ray",
			"cf-cache-status",
			"cf-request-id",
			"Server",
		},
		StatusCodes: []int{403, 405, 503},
		Keywords: []string{
			"cloudflare",
			"cf-error-details",
			"Attention Required! | Cloudflare",
		},
	},
	{
		Name: WAFAkamai,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)akamai`),
			regexp.MustCompile(`(?i)akamaighost`),
			regexp.MustCompile(`(?i)akamai-origin`),
		},
		Headers: []string{
			"X-Akamai-Transformed",
			"X-Cache",
			"X-CDN",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"akamai",
			"Reference #",
			"Access Denied",
		},
	},
	{
		Name: WAFImperva,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)imperva`),
			regexp.MustCompile(`(?i)incapsula`),
			regexp.MustCompile(`(?i)incapsula-cdi`),
		},
		Headers: []string{
			"X-CDN",
			"X-Iinfo",
			"X-Cdn-Type",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"incapsula",
			"Imperva",
			"Reference #",
			"Incapsula incident ID",
		},
	},
	{
		Name: WAFFortinet,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)fortigate`),
			regexp.MustCompile(`(?i)fortinet`),
			regexp.MustCompile(`(?i)fortiweb`),
		},
		Headers: []string{
			"Fortigate",
			"FortiWeb",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"FortiGuard",
			"FortiWeb",
			"FortiGate",
		},
	},
	{
		Name: WAFPaloAlto,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)paloalto`),
			regexp.MustCompile(`(?i)pan-os`),
			regexp.MustCompile(`(?i)firewall`),
		},
		Headers: []string{
			"Server",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"PaloAlto",
			"PA-Series",
		},
	},
	{
		Name: WAFSucuri,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)sucuri`),
			regexp.MustCompile(`(?i)sucuricloud`),
		},
		Headers: []string{
			"X-Sucuri-ID",
			"X-Sucuri-Cache-Control",
			"X-Server",
		},
		StatusCodes: []int{403},
		Keywords: []string{
			"Sucuri",
			"sucuri.net",
			"Proxy Detection",
		},
	},
	{
		Name: WAFModSecurity,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)mod_security`),
			regexp.MustCompile(`(?i)modsecurity`),
			regexp.MustCompile(`(?i)mod_security`),
		},
		Headers: []string{
			"Server",
		},
		StatusCodes: []int{403, 406},
		Keywords: []string{
			"mod_security",
			"ModSecurity",
			"ModSecurity NGNIX",
			"ruleId",
		},
	},
	{
		Name: WAFNginx,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)nginx`),
		},
		Headers: []string{
			"Server",
		},
		StatusCodes: []int{403, 404, 500, 502, 503},
		Keywords: []string{
			"nginx",
			"50x.html",
			"nginx!",
		},
	},
	{
		Name: WAFApache,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)apache`),
		},
		Headers: []string{
			"Server",
		},
		StatusCodes: []int{403, 404, 500, 503},
		Keywords: []string{
			"Apache",
			"Forbidden",
			"Not Found",
		},
	},
	{
		Name: WAFIIS,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)iis`),
			regexp.MustCompile(`(?i)internet information`),
		},
		Headers: []string{
			"Server",
			"X-Powered-By",
		},
		StatusCodes: []int{403, 404, 500, 503},
		Keywords: []string{
			"IIS",
			"Microsoft-IIS",
			"404 Not Found",
			"403 Forbidden",
		},
	},
	{
		Name: WAF403,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)403.*forbidden`),
			regexp.MustCompile(`(?i)access.*denied`),
			regexp.MustCompile(`(?i)forbidden`),
		},
		Headers:     []string{},
		StatusCodes: []int{403},
		Keywords: []string{
			"403 Forbidden",
			"Access Denied",
			"forbidden",
		},
	},
	{
		Name: WAF429,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)429.*too.*many`),
			regexp.MustCompile(`(?i)rate.*limit`),
			regexp.MustCompile(`(?i)too.*many.*request`),
		},
		Headers:     []string{},
		StatusCodes: []int{429},
		Keywords: []string{
			"429 Too Many Requests",
			"rate limit",
			"Too Many Requests",
		},
	},
}

type WAFResult struct {
	WAFType    WAFType
	Confidence float64
	Details    string
}

func DetectWAF(headers map[string]string, body string, statusCode int) *WAFResult {
	var bestMatch *WAFResult

	for _, sig := range wafSignatures {
		score := 0.0

		for _, header := range sig.Headers {
			if _, ok := headers[strings.ToLower(header)]; ok {
				score += 0.3
			}
		}

		headerValue := ""
		for k, v := range headers {
			headerValue += k + ": " + v + " "
		}
		headerValue = strings.ToLower(headerValue)
		for _, pattern := range sig.Patterns {
			if pattern.MatchString(headerValue) {
				score += 0.4
			}
		}

		bodyLower := strings.ToLower(body)
		for _, keyword := range sig.Keywords {
			if strings.Contains(bodyLower, strings.ToLower(keyword)) {
				score += 0.2
			}
		}

		for _, code := range sig.StatusCodes {
			if statusCode == code {
				score += 0.3
				break
			}
		}

		if score >= 0.3 {
			if bestMatch == nil || score > bestMatch.Confidence {
				confidence := score
				if confidence > 1.0 {
					confidence = 1.0
				}
				bestMatch = &WAFResult{
					WAFType:    sig.Name,
					Confidence: confidence,
					Details: fmt.Sprintf("Matched %d patterns, %d headers, status code %d",
						len(sig.Patterns), len(sig.Headers), statusCode),
				}
			}
		}
	}

	if bestMatch != nil && bestMatch.Confidence >= 0.4 {
		return bestMatch
	}

	return &WAFResult{
		WAFType:    WAFNone,
		Confidence: 0,
		Details:    "No WAF detected",
	}
}

func IsWAFBlocked(statusCode int, headers map[string]string, body string) bool {
	blockCodes := []int{403, 405, 406, 429, 503, 504}

	for _, code := range blockCodes {
		if statusCode == code {
			wafResult := DetectWAF(headers, body, statusCode)
			if wafResult.WAFType != WAFNone {
				return true
			}
		}
	}

	return false
}

func GetWAFTypeName(wafType WAFType) string {
	switch wafType {
	case WAFNone:
		return "No WAF"
	case WAFAliyun:
		return "阿里云WAF"
	case WAF腾讯云:
		return "腾讯云WAF"
	case WAF华为云:
		return "华为云WAF"
	case WAFAWS:
		return "AWS WAF"
	case WAFAzure:
		return "Azure WAF"
	case WAFCloudflare:
		return "Cloudflare"
	case WAFAkamai:
		return "Akamai"
	case WAFImperva:
		return "Imperva/Incapsula"
	case WAFFortinet:
		return "Fortinet/FortiWeb"
	case WAFPaloAlto:
		return "Palo Alto"
	case WAFSucuri:
		return "Sucuri"
	case WAFModSecurity:
		return "ModSecurity"
	case WAFNginx:
		return "Nginx"
	case WAFApache:
		return "Apache"
	case WAFIIS:
		return "IIS"
	case WAF403:
		return "403 Forbidden"
	case WAF429:
		return "Rate Limit (429)"
	default:
		return "Unknown"
	}
}

type CommonPages struct {
	LoginPage    *regexp.Regexp
	ErrorPage    *regexp.Regexp
	DefaultPage  *regexp.Regexp
	RedirectPage *regexp.Regexp
}

var commonPages = &CommonPages{
	LoginPage:    regexp.MustCompile(`(?i)(login|signin|password|username|登录|注册)`),
	ErrorPage:    regexp.MustCompile(`(?i)(error|exception|404|500|403|denied|forbidden|拒绝|错误|异常)`),
	DefaultPage:  regexp.MustCompile(`(?i)(default|index|welcome|首页|主页)`),
	RedirectPage: regexp.MustCompile(`(?i)(redirect|url=|location\.href|window\.location)`),
}

func IsCommonPage(body string, statusCode int) bool {
	if statusCode >= 300 && statusCode < 400 {
		return true
	}

	bodyLower := strings.ToLower(body)

	matchCount := 0
	if commonPages.LoginPage.MatchString(bodyLower) {
		matchCount++
	}
	if commonPages.ErrorPage.MatchString(bodyLower) {
		matchCount++
	}
	if commonPages.DefaultPage.MatchString(bodyLower) {
		matchCount++
	}

	return matchCount >= 2
}

func AnalyzeResponse(statusCode int, headers map[string]string, body string) *WAFResult {
	wafResult := DetectWAF(headers, body, statusCode)

	if wafResult.WAFType == WAFNone && statusCode == 403 {
		wafResult.WAFType = WAF403
		wafResult.Confidence = 0.5
		wafResult.Details = "403 Forbidden - likely blocked"
	}

	if wafResult.WAFType == WAFNone && statusCode == 429 {
		wafResult.WAFType = WAF429
		wafResult.Confidence = 0.8
		wafResult.Details = "Rate limit detected"
	}

	return wafResult
}
