package dirscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ScanConfig 目录扫描配置
type ScanConfig struct {
	URL              string
	Wordlist         string
	Threads          int
	Timeout          time.Duration
	UserAgent        string
	Extensions       []string
	Recursive        bool
	FollowRedirects  bool
	OutputFile       string
	ShowAll          bool
	StatusCodeFilter []int
	Proxy            string
}

// ScanResult 扫描结果
type ScanResult struct {
	URL        string
	StatusCode int
	Size       int64
	Title      string
	Error      error
}

// Scanner 目录扫描器
type Scanner struct {
	config      *ScanConfig
	client      *http.Client
	wordlist    []string
	results     chan ScanResult
	wg          sync.WaitGroup
	mutex       sync.Mutex
	foundCount  int
	scannedCount int
	totalWords  int
	allResults []ScanResult
}

// NewScanner 创建新的扫描器
func NewScanner(config *ScanConfig) (*Scanner, error) {
	scanner := &Scanner{
		config:  config,
		results: make(chan ScanResult, 100),
	}

	// 配置HTTP客户端
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 设置代理
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return nil, fmt.Errorf("无效的代理地址: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	scanner.client = &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// 加载字典文件或内置字典
	if err := scanner.loadWordlist(); err != nil {
		return nil, err
	}

	scanner.totalWords = len(scanner.wordlist)

	return scanner, nil
}

// loadWordlist 加载字典文件或内置字典
func (s *Scanner) loadWordlist() error {
	// 检查是否是内置字典选择 (1或2)
	if s.config.Wordlist == "1" || s.config.Wordlist == "2" {
		// 加载内置字典
		wordlist, err := GetBuiltinWordlist(s.config.Wordlist)
		if err != nil {
			return err
		}
		s.wordlist = wordlist
		return nil
	}

	// 加载外部字典文件
	file, err := os.Open(s.config.Wordlist)
	if err != nil {
		return fmt.Errorf("无法打开字典文件: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			s.wordlist = append(s.wordlist, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取字典文件错误: %v", err)
	}

	if len(s.wordlist) == 0 {
		return fmt.Errorf("字典文件为空")
	}

	return nil
}

// Start 开始扫描
func (s *Scanner) Start() error {
	fmt.Printf("开始目录扫描...\n")
	fmt.Printf("目标: %s\n", s.config.URL)
	fmt.Printf("字典: %s (%d 个条目)\n", s.config.Wordlist, len(s.wordlist))
	fmt.Printf("线程: %d\n", s.config.Threads)
	fmt.Printf("超时: %v\n", s.config.Timeout)
	fmt.Println(strings.Repeat("-", 50))

	// 创建输出文件
	var outputFile *os.File
	if s.config.OutputFile != "" {
		var err error
		outputFile, err = os.Create(s.config.OutputFile)
		if err != nil {
			return fmt.Errorf("创建输出文件失败: %v", err)
		}
		defer outputFile.Close()
	}

	// 启动结果处理器
	go s.processResults(outputFile)

	// 创建工作池
	jobs := make(chan string, len(s.wordlist))

	// 启动工作线程
	for i := 0; i < s.config.Threads; i++ {
		s.wg.Add(1)
		go s.worker(jobs)
	}

	// 分发任务
	for _, word := range s.wordlist {
		jobs <- word
	}
	close(jobs)

	// 等待所有工作完成
	s.wg.Wait()
	close(s.results)

	// 等待结果处理器完成
	time.Sleep(100 * time.Millisecond)

	// 显示扫描完成进度
	fmt.Printf("\r扫描进度: %d/%d (100.0%%)\n", s.totalWords, s.totalWords)

	// 显示排序后的结果
	s.displaySortedResults()

	fmt.Printf("\n扫描完成! 找到 %d 个有效路径\n", s.foundCount)
	if s.config.OutputFile != "" {
		fmt.Printf("结果已保存到: %s\n", s.config.OutputFile)
	}

	return nil
}

// worker 工作线程
func (s *Scanner) worker(jobs <-chan string) {
	defer s.wg.Done()

	for word := range jobs {
		s.scanPath(word)
	}
}

// scanPath 扫描单个路径
func (s *Scanner) scanPath(path string) {
	// 处理扩展名
	if len(s.config.Extensions) > 0 {
		for _, ext := range s.config.Extensions {
			s.scanWithExtension(path, ext)
		}
	} else {
		s.scanURL(path)
	}
}

// scanWithExtension 扫描带扩展名的路径
func (s *Scanner) scanWithExtension(path, extension string) {
	var pathsToScan []string

	// 处理路径中的占位符
	if strings.Contains(path, "%EXT%") {
		pathsToScan = append(pathsToScan, strings.Replace(path, "%EXT%", extension, -1))
	} else {
		pathsToScan = append(pathsToScan, path+"."+extension)
	}

	for _, p := range pathsToScan {
		s.scanURL(p)
	}
}

// scanURL 扫描URL
func (s *Scanner) scanURL(path string) {
	targetURL := s.normalizeURL(path)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		s.results <- ScanResult{URL: targetURL, Error: err}
		s.updateProgress()
		return
	}

	// 设置User-Agent
	if s.config.UserAgent != "" {
		req.Header.Set("User-Agent", s.config.UserAgent)
	} else {
		req.Header.Set("User-Agent", "GYscan DirScanner/1.0")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.results <- ScanResult{URL: targetURL, Error: err}
		s.updateProgress()
		return
	}
	defer resp.Body.Close()

	// 读取响应体大小
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.results <- ScanResult{URL: targetURL, Error: err}
		s.updateProgress()
		return
	}

	// 提取页面标题
	title := extractTitle(string(body))

	result := ScanResult{
		URL:        targetURL,
		StatusCode: resp.StatusCode,
		Size:       int64(len(body)),
		Title:      title,
	}

	s.results <- result
	s.updateProgress()
}

// updateProgress 更新扫描进度
func (s *Scanner) updateProgress() {
	s.mutex.Lock()
	s.scannedCount++
	s.mutex.Unlock()
}

// normalizeURL 标准化URL
func (s *Scanner) normalizeURL(path string) string {
	baseURL := strings.TrimSuffix(s.config.URL, "/")
	path = strings.TrimPrefix(path, "/")
	return baseURL + "/" + path
}

// processResults 处理扫描结果
func (s *Scanner) processResults(outputFile *os.File) {
	for result := range s.results {
		// 存储所有结果用于后续排序显示
		s.mutex.Lock()
		s.allResults = append(s.allResults, result)
		s.mutex.Unlock()

		if result.Error != nil {
			if s.config.ShowAll {
				fmt.Printf("[ERROR] %s: %v\n", result.URL, result.Error)
			}
			continue
		}

		// 状态码过滤
		if len(s.config.StatusCodeFilter) > 0 {
			found := false
			for _, code := range s.config.StatusCodeFilter {
				if result.StatusCode == code {
					found = true
					break
				}
			}
			if !found && !s.config.ShowAll {
				continue
			}
		}

		// 显示所有扫描结果
		s.displayResult(result)

		// 保存到文件
		if outputFile != nil {
			s.saveResult(outputFile, result)
		}

		if result.StatusCode >= 200 && result.StatusCode < 400 {
			s.mutex.Lock()
			s.foundCount++
			s.mutex.Unlock()
		}
	}
}

// displayResult 显示扫描结果
func (s *Scanner) displayResult(result ScanResult) {
	statusColor := getStatusCodeColor(result.StatusCode)
	
	fmt.Printf("[%s] %-8d %s", 
		statusColor.Sprintf("%3d", result.StatusCode),
		result.Size,
		result.URL)
	
	if result.Title != "" {
		fmt.Printf(" - %s", result.Title)
	}
	fmt.Println()
}

// displaySortedResults 显示排序后的结果
func (s *Scanner) displaySortedResults() {
	// 过滤出200和301状态码的结果
	var successResults []ScanResult
	for _, result := range s.allResults {
		if result.Error == nil && (result.StatusCode == 200 || result.StatusCode == 301) {
			successResults = append(successResults, result)
		}
	}

	// 如果没有成功结果，直接返回
	if len(successResults) == 0 {
		return
	}

	// 按状态码排序：200在前，301在后
	for i := 0; i < len(successResults)-1; i++ {
		for j := i + 1; j < len(successResults); j++ {
			if successResults[i].StatusCode > successResults[j].StatusCode {
				successResults[i], successResults[j] = successResults[j], successResults[i]
			}
		}
	}

	fmt.Println("\n=== 成功路径 (200/301) ===")
	for _, result := range successResults {
		s.displayResult(result)
	}
}

// saveResult 保存结果到文件
func (s *Scanner) saveResult(file *os.File, result ScanResult) {
	line := fmt.Sprintf("%d\t%d\t%s\t%s\n", 
		result.StatusCode, result.Size, result.URL, result.Title)
	file.WriteString(line)
}

// extractTitle 从HTML中提取标题
func extractTitle(html string) string {
	titleStart := strings.Index(html, "<title>")
	if titleStart == -1 {
		return ""
	}
	titleStart += 7

	titleEnd := strings.Index(html[titleStart:], "</title>")
	if titleEnd == -1 {
		return ""
	}

	title := html[titleStart:titleStart+titleEnd]
	title = strings.TrimSpace(title)
	title = strings.ReplaceAll(title, "\n", " ")
	title = strings.ReplaceAll(title, "\t", " ")
	
	// 限制标题长度
	if len(title) > 50 {
		title = title[:47] + "..."
	}
	
	return title
}

// getStatusCodeColor 根据状态码获取颜色
func getStatusCodeColor(statusCode int) *color.Color {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return color.New(color.FgGreen)
	case statusCode >= 300 && statusCode < 400:
		return color.New(color.FgBlue)
	case statusCode >= 400 && statusCode < 500:
		return color.New(color.FgYellow)
	case statusCode >= 500:
		return color.New(color.FgRed)
	default:
		return color.New(color.FgWhite)
	}
}

// BuiltinWordlists 内置字典列表
var BuiltinWordlists = map[string]string{
	"1": "dirmap/dicc.txt",    // 大型字典 (9756个条目)
	"2": "dirmap/medium.txt", // 中型字典 (2762个条目)
}

// DefaultWordlist 返回默认字典路径
func DefaultWordlist() string {
	return BuiltinWordlists["2"] // 默认使用中型字典
}

// GetBuiltinWordlist 获取内置字典内容
func GetBuiltinWordlist(choice string) ([]string, error) {
	wordlistPath, exists := BuiltinWordlists[choice]
	if !exists {
		return nil, fmt.Errorf("无效的内置字典选择: %s", choice)
	}

	// 检查字典文件是否存在
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("内置字典文件不存在: %s", wordlistPath)
	}

	// 读取字典文件内容
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("无法打开内置字典文件: %v", err)
	}
	defer file.Close()

	var wordlist []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			wordlist = append(wordlist, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取内置字典文件错误: %v", err)
	}

	if len(wordlist) == 0 {
		return nil, fmt.Errorf("内置字典文件为空: %s", wordlistPath)
	}

	return wordlist, nil
}