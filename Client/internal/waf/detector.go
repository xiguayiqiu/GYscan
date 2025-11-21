package waf

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// WAFDetectorImpl 实现WAFDetector接口
type WAFDetectorImpl struct {
	Rules       []WAF
	Client      *http.Client
	rulesLoaded bool
}

// NewWAFDetector 创建新的WAF检测器
func NewWAFDetector() *WAFDetectorImpl {
	return &WAFDetectorImpl{
		Client:      NewHTTPClient(),
		Rules:       make([]WAF, 0), // 初始化Rules切片
		rulesLoaded: false,
	}
}

// LoadRules 加载WAF规则配置文件
func (d *WAFDetectorImpl) LoadRules(rulesPath string) error {
	if rulesPath == "" {
		rulesPath = "internal/waf/waf_rules.json"
	}
	
	file, err := os.ReadFile(rulesPath)
	if err != nil {
		return fmt.Errorf("读取规则文件失败: %v", err)
	}
	
	var config WAFConfig
	err = json.Unmarshal(file, &config)
	if err != nil {
		return fmt.Errorf("解析规则文件失败: %v", err)
	}
	
	d.Rules = config.WAFList
	d.rulesLoaded = true
	return nil
}

// WAFMatchInfo WAF匹配信息，用于去重和误报控制
type WAFMatchInfo struct {
	WAF                    *WAF
	Score                  int
	FeatureCount           int
	HighWeightFeatureCount int
}

// DetectTarget 检测目标网站是否使用WAF
func (d *WAFDetectorImpl) DetectTarget(target string) (*WAFResult, error) {
	// 确保目标格式正确
	target = normalizeTarget(target)
	
	result := &WAFResult{
		Target:       target,
		Detected:     false,
		Description:  "未检测到已知WAF",
		WAFName:      "",
		Vendor:       "",
		Confidence:   0,
		ErrorMessage: "",
	}
	
	// 采集被动信息
	info, err := d.collectPassiveInfo(target)
	if err != nil {
		result.Description = fmt.Sprintf("采集信息失败: %v", err)
		return result, err
	}
	
	// 进行被动特征匹配
	var matches []WAFMatchInfo
	
	for _, waf := range d.Rules {
		score := d.matchPassiveFeatures(&waf, info)
		if score > 0 {
			// 统计匹配到的特征数量和高权重特征数量
			featureCount := 0
			highWeightFeatureCount := 0
			for _, feature := range waf.Features {
				if feature.Type != "active_detect" && d.matchFeature(feature, info) {
					featureCount++
					if feature.Weight >= 80 {
						highWeightFeatureCount++
					}
				}
			}
			matches = append(matches, WAFMatchInfo{
				WAF:                    &waf,
				Score:                  score,
				FeatureCount:           featureCount,
				HighWeightFeatureCount: highWeightFeatureCount,
			})
		}
	}
	
	// 特征冲突处理：当有多个可能的WAF匹配时，进行更智能的选择
	if len(matches) > 1 {
		// 过滤出所有超过置信度阈值的匹配
		validMatches := []WAFMatchInfo{}
		for _, match := range matches {
			if match.Score >= match.WAF.ConfidenceThreshold {
				validMatches = append(validMatches, match)
			}
		}
		
		// 如果有多个有效匹配，进行冲突解决
		if len(validMatches) > 1 {
			// 优先选择高权重特征匹配数量多的
			bestMatch := &validMatches[0]
			for i := 1; i < len(validMatches); i++ {
				currentMatch := &validMatches[i]
				// 如果高权重特征匹配数更多，直接选择
				if currentMatch.HighWeightFeatureCount > bestMatch.HighWeightFeatureCount {
					bestMatch = currentMatch
				} else if currentMatch.HighWeightFeatureCount == bestMatch.HighWeightFeatureCount {
					// 如果高权重特征匹配数相同，选择总体得分更高的
					if currentMatch.Score > bestMatch.Score {
						bestMatch = currentMatch
					} else if currentMatch.Score == bestMatch.Score {
						// 如果得分也相同，选择置信度阈值更高的（更严格的规则）
						if currentMatch.WAF.ConfidenceThreshold > bestMatch.WAF.ConfidenceThreshold {
							bestMatch = currentMatch
						}
					}
				}
			}
			
			return &WAFResult{
				Target:     target,
				WAFName:    bestMatch.WAF.Name,
				Vendor:     bestMatch.WAF.Vendor,
				Confidence: bestMatch.Score,
				Detected:   true,
			}, nil
		}
	}
	
	// 去重和误报控制：选择最佳匹配
	bestMatch := d.selectBestMatch(matches)
	
	// 如果被动匹配失败，进行主动探测
	if bestMatch == nil {
		activeScore, activeWAF := d.performActiveDetection(target)
		if activeScore > 0 && activeWAF.ConfidenceThreshold > 0 && activeScore >= activeWAF.ConfidenceThreshold {
			result.Detected = true
			result.WAFName = activeWAF.Name
			result.Vendor = activeWAF.Vendor
			result.Confidence = activeScore
			result.Description = fmt.Sprintf("通过主动探测检测到WAF: %s (厂商: %s)", activeWAF.Name, activeWAF.Vendor)
			return result, nil
		}
		return result, nil
	}
	
	// 检测到WAF
	result.Detected = true
	result.WAFName = bestMatch.WAF.Name
	result.Vendor = bestMatch.WAF.Vendor
	result.Confidence = bestMatch.Score
	result.Description = fmt.Sprintf("检测到WAF: %s (厂商: %s)，置信度: %d%%", bestMatch.WAF.Name, bestMatch.WAF.Vendor, bestMatch.Score)
	return result, nil
}

// selectBestMatch 选择最佳匹配，实现去重和误报控制
func (d *WAFDetectorImpl) selectBestMatch(matches []WAFMatchInfo) *WAFMatchInfo {
	if len(matches) == 0 {
		return nil
	}
	
	// 过滤掉低置信度的匹配结果
	validMatches := []WAFMatchInfo{}
	for _, match := range matches {
		// 只有置信度超过阈值的匹配结果才被视为有效
		if match.Score >= match.WAF.ConfidenceThreshold {
			validMatches = append(validMatches, match)
		}
	}
	
	// 如果没有有效匹配，返回nil
	if len(validMatches) == 0 {
		return nil
	}
	
	bestMatch := &validMatches[0]
	for i := 1; i < len(validMatches); i++ {
		match := &validMatches[i]
		// 优先考虑高权重特征数量
		if match.HighWeightFeatureCount > bestMatch.HighWeightFeatureCount {
			bestMatch = match
		} else if match.HighWeightFeatureCount == bestMatch.HighWeightFeatureCount {
			// 高权重特征数量相同时，选择得分高的
			if match.Score > bestMatch.Score {
				bestMatch = match
			} else if match.Score == bestMatch.Score {
				// 得分相同时，选择匹配特征数量多的
				if match.FeatureCount > bestMatch.FeatureCount {
					bestMatch = match
				} else if match.FeatureCount == bestMatch.FeatureCount {
					// 如果分数和特征数量都相同，选择置信度阈值高的
					if match.WAF.ConfidenceThreshold > bestMatch.WAF.ConfidenceThreshold {
						bestMatch = match
					}
				}
			}
		}
	}
	
	return bestMatch
}

// collectPassiveInfo 采集被动信息
func (d *WAFDetectorImpl) collectPassiveInfo(target string) (*TargetInfo, error) {
	info := &TargetInfo{
		URL:          target,
		Headers:      make(http.Header),
		ResponseBody: "",
		CertIssuer:   "",
		CertSubject:  "",
		CertSerial:   "",
	}
	
	// 发送HTTP请求
	resp, err := d.Client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	// 收集响应头和状态码
	info.Headers = resp.Header
	info.StatusCode = resp.StatusCode
	
	// 收集响应体（限制大小为10KB）
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	info.ResponseBody = string(body)
	
	// 如果是HTTPS，收集证书信息
	if strings.HasPrefix(target, "https://") {
		certInfo, err := d.getCertInfo(target)
		if err == nil {
			info.CertIssuer = certInfo.Issuer
			info.CertSubject = certInfo.Subject
			info.CertSerial = certInfo.Serial
		}
	}
	
	return info, nil
}

// getCertInfo 获取证书信息
func (d *WAFDetectorImpl) getCertInfo(target string) (*CertInfo, error) {
	// 从URL中提取主机名和端口
	host := target
	host = strings.TrimPrefix(host, "https://")
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("未获取到证书")
	}
	
	cert := state.PeerCertificates[0]
	return &CertInfo{
		Issuer:  cert.Issuer.String(),
		Subject: cert.Subject.String(),
		Serial:  cert.SerialNumber.String(),
	}, nil
}

// CertInfo 证书信息
type CertInfo struct {
	Issuer  string
	Subject string
	Serial  string
}

// normalizeTarget 规范化目标URL格式
func normalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// 尝试HTTPS
		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			if parts[1] == "443" {
				target = "https://" + target
			} else {
				target = "http://" + target
			}
		} else {
			// 默认尝试HTTPS
			target = "https://" + target
		}
	}
	return target
}

// matchPassiveFeatures 匹配被动特征，计算匹配得分
func (d *WAFDetectorImpl) matchPassiveFeatures(waf *WAF, info *TargetInfo) int {
	score := 0
	matchedFeatureCount := 0
	highConfidenceMatch := false
	highWeightMatched := 0
	
	// 对特征按权重从高到低排序
	sortedFeatures := make([]Feature, len(waf.Features))
	copy(sortedFeatures, waf.Features)
	
	// 排序：权重从高到低
	sort.Slice(sortedFeatures, func(i, j int) bool {
		return sortedFeatures[i].Weight > sortedFeatures[j].Weight
	})
	
	// 优先匹配高权重特征，并进行早期判断
	for _, feature := range sortedFeatures {
		if feature.Type == "active_detect" {
			continue // 跳过主动探测特征
		}
		
		if d.matchFeature(feature, info) {
			score += feature.Weight
			matchedFeatureCount++
			// 标记是否有高权重特征匹配（权重≥80）
			if feature.Weight >= 80 {
				highConfidenceMatch = true
				highWeightMatched++
				// 如果匹配到两个或更多高权重特征，可以提前判断
				if highWeightMatched >= 2 && score > 70 {
					// 至少已经匹配到2个高权重特征，提前返回较高的得分
					return 85 + rand.Intn(15) // 返回85-99的随机值
				}
			}
		}
	}
	
	// 改进的加权逻辑：只有当有高权重特征匹配且匹配特征数≥2时才额外加分
	if matchedFeatureCount >= 2 && highConfidenceMatch && score > 60 {
		score += 10
	}
	
	// 如果匹配到高权重特征，适当提高分数
	if highWeightMatched > 0 {
		score = score + highWeightMatched*3
		if score > 100 {
			score = 100
		}
	}
	
	// 确保置信度不超过100%
	if score > 100 {
		score = 100
	}
	
	return score
}

// matchFeature 匹配单个特征
func (d *WAFDetectorImpl) matchFeature(feature Feature, info *TargetInfo) bool {
	switch feature.Type {
	case "response_header":
		return d.matchHeader(feature, info.Headers)
	case "ssl_certificate":
		return d.matchCertificate(feature, info)
	case "response_content":
		return d.matchContent(feature, info.ResponseBody)
	}
	return false
}

// matchHeader 匹配响应头
func (d *WAFDetectorImpl) matchHeader(feature Feature, headers http.Header) bool {
	headerValue := headers.Get(feature.Key)
	if feature.MatchType == "exists" {
		return headerValue != ""
	} else if feature.MatchType == "contains" {
		return strings.Contains(strings.ToLower(headerValue), strings.ToLower(feature.Value))
	} else if feature.MatchType == "exact" {
		return strings.EqualFold(headerValue, feature.Value)
	} else if feature.MatchType == "regex" {
		matched, _ := regexp.MatchString(feature.Value, headerValue)
		return matched
	}
	return false
}

// matchCertificate 匹配证书
func (d *WAFDetectorImpl) matchCertificate(feature Feature, info *TargetInfo) bool {
	var value string
	switch feature.Field {
	case "issuer":
		value = info.CertIssuer
	case "subject":
		value = info.CertSubject
	case "serial":
		value = info.CertSerial
	default:
		return false
	}
	
	switch feature.MatchType {
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(feature.Value))
	case "exact":
		return strings.EqualFold(value, feature.Value)
	case "regex":
		matched, _ := regexp.MatchString(feature.Value, value)
		return matched
	}
	return false
}

// matchContent 匹配响应内容
func (d *WAFDetectorImpl) matchContent(feature Feature, content string) bool {
	switch feature.MatchType {
	case "contains":
		return strings.Contains(strings.ToLower(content), strings.ToLower(feature.Value))
	case "exact":
		return strings.EqualFold(content, feature.Value)
	case "regex":
		matched, _ := regexp.MatchString(feature.Value, content)
		return matched
	}
	return false
}

// performActiveDetection 执行主动探测
func (d *WAFDetectorImpl) performActiveDetection(target string) (int, *WAF) {
	highestScore := 0
	bestMatch := &WAF{}
	
	for _, waf := range d.Rules {
		score := d.activeDetect(&waf, target)
		if score > highestScore {
			highestScore = score
			bestMatch = &waf
		}
	}
	
	return highestScore, bestMatch
}

// activeDetect 对单个WAF进行主动探测
func (d *WAFDetectorImpl) activeDetect(waf *WAF, target string) int {
	score := 0
	matchedFeatureCount := 0
	highConfidenceMatch := false

	for _, feature := range waf.Features {
		if feature.Type != "active_detect" {
			continue
		}

		if d.executeActiveRequest(target, feature) {
			score += feature.Weight
			matchedFeatureCount++
			// 标记是否有高权重特征匹配（权重≥80）
			if feature.Weight >= 80 {
				highConfidenceMatch = true
			}
		}
	}

	// 改进的加权逻辑：只有当有高权重特征匹配且匹配特征数≥2时才额外加分
	if matchedFeatureCount >= 2 && highConfidenceMatch && score > 60 {
		score += 10
	}

	// 确保置信度不超过100%
	if score > 100 {
		score = 100
	}

	return score
}

// executeActiveRequest 执行主动探测请求
func (d *WAFDetectorImpl) executeActiveRequest(target string, feature Feature) bool {
	// 构建请求URL
	var url string
	if feature.Request != nil && feature.Request.Path != "" {
		baseURL := strings.TrimSuffix(target, "/")
		path := strings.TrimPrefix(feature.Request.Path, "/")
		url = baseURL + "/" + path
	} else {
		// 使用默认的轻微异常路径
		url = target + "/?test='123"
	}
	
	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	
	// 设置User-Agent
	if feature.Request != nil && feature.Request.UserAgent != "" {
		req.Header.Set("User-Agent", feature.Request.UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	}
	
	// 发送请求
	resp, err := d.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// 检查响应
	if feature.RespCheck != nil {
		// 检查状态码
		if feature.RespCheck.StatusCode > 0 && resp.StatusCode != feature.RespCheck.StatusCode {
			return false
		}
		
		// 检查响应头
		if feature.RespCheck.HeaderExists != "" && resp.Header.Get(feature.RespCheck.HeaderExists) == "" {
			return false
		}
		
		// 检查响应内容
		if feature.RespCheck.ContentContains != "" {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
			if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(feature.RespCheck.ContentContains)) {
				return false
			}
		}
	} else {
		// 默认检查：如果返回403/406/503状态码，认为可能被WAF拦截
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 503 {
			return true
		}
	}
	
	return true
}

// DetectTargets 并发探测多个目标
func (d *WAFDetectorImpl) DetectTargets(targets []string, concurrency int) []*WAFResult {
	// 控制并发数量
	if concurrency <= 0 {
		concurrency = 20 // 默认并发数
	}
	if concurrency > 100 {
		concurrency = 100 // 最大并发数
	}

	// 创建结果通道和错误通道
	results := make(chan *WAFResult, len(targets))
	sem := make(chan struct{}, concurrency) // 信号量控制并发
	wg := &sync.WaitGroup{}

	// 启动goroutine处理每个目标
	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			
			// 获取信号量
			sem <- struct{}{}
			defer func() { <-sem }()

			// 探测目标
			result, err := d.DetectTarget(t)
			if err != nil {
				// 如果出错，创建错误结果
				result = &WAFResult{
					Target:       t,
					Detected:     false,
					Description:  "探测失败",
					ErrorMessage: err.Error(),
				}
			}

			// 发送结果
			results <- result
		}(target)
	}

	// 等待所有goroutine完成并关闭结果通道
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集所有结果
	var allResults []*WAFResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults
}