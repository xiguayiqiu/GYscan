package dirscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
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
	Show404403       bool
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
	config       *ScanConfig
	client       *http.Client
	wordlist     []string
	results      chan ScanResult
	wg           sync.WaitGroup
	mutex        sync.Mutex
	foundCount   int
	scannedCount int
	totalWords   int
	allResults   []ScanResult
	ctx          context.Context
	cancel       context.CancelFunc
	interrupted  bool
}

// NewScanner 创建新的扫描器
func NewScanner(config *ScanConfig) (*Scanner, error) {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &Scanner{
		config:  config,
		results: make(chan ScanResult, 100),
		ctx:     ctx,
		cancel:  cancel,
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

// clearScreen 跨平台清屏函数
func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		// Windows清屏命令
		cmd := "cls"
		runCommand(cmd)
	default:
		// Linux/Mac清屏命令
		cmd := "clear"
		runCommand(cmd)
	}
}

// runCommand 执行系统命令
func runCommand(cmd string) {
	var execCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		execCmd = exec.Command("cmd", "/c", cmd)
	} else {
		execCmd = exec.Command("sh", "-c", cmd)
	}
	execCmd.Stdout = os.Stdout
	execCmd.Run()
}

// loadWordlist 加载字典文件
func (s *Scanner) loadWordlist() error {
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

	// 显示扩展名配置
	if len(s.config.Extensions) > 0 {
		fmt.Printf("扩展名: %s\n", strings.Join(s.config.Extensions, ", "))
	}

	fmt.Println(strings.Repeat("-", 50))

	// 设置Ctrl+C信号处理
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

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
	go func() {
		for _, word := range s.wordlist {
			select {
			case jobs <- word:
			case <-s.ctx.Done():
				return
			}
		}
		close(jobs)

		// 所有任务分发完成后，等待工作线程完成，然后取消上下文
		s.wg.Wait()
		s.cancel()
	}()

	// 实时显示进度，直到扫描完成
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-signalChan:
			// Ctrl+C被按下
			s.handleInterrupt()
			return nil
		case <-s.ctx.Done():
			// 扫描完成
			goto scanComplete
		case <-ticker.C:
			// 定期更新进度显示
			s.mutex.Lock()
			progress := float64(s.scannedCount) / float64(s.totalWords) * 100
			fmt.Printf("\r\033[K扫描进度: %d/%d (%.1f%%)", s.scannedCount, s.totalWords, progress)
			s.mutex.Unlock()
		}
	}

scanComplete:
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

// handleInterrupt 处理中断信号
func (s *Scanner) handleInterrupt() {
	s.mutex.Lock()
	s.interrupted = true
	s.mutex.Unlock()

	// 取消上下文
	s.cancel()

	// 等待工作线程完成
	s.wg.Wait()
	close(s.results)

	// 清屏并显示整理后的结果
	clearScreen()

	fmt.Println("\n=== 扫描被中断 ===")
	fmt.Printf("已扫描: %d/%d (%.1f%%)\n", s.scannedCount, s.totalWords,
		float64(s.scannedCount)/float64(s.totalWords)*100)
	fmt.Printf("找到有效路径: %d\n\n", s.foundCount)

	// 显示整理后的结果
	s.displayOrganizedResults()

	fmt.Println("\n按任意键退出...")
	bufio.NewReader(os.Stdin).ReadByte()
}

// worker 工作线程
func (s *Scanner) worker(jobs <-chan string) {
	defer s.wg.Done()

	for {
		select {
		case word, ok := <-jobs:
			if !ok {
				return
			}
			s.scanPath(word)
		case <-s.ctx.Done():
			return
		}
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
		// 如果没有设置扩展名，但路径中包含%EXT%，则跳过该路径
		if strings.Contains(path, "%EXT%") {
			// 不扫描包含未替换占位符的路径
			s.updateProgress()
			return
		}
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

	// 每扫描10个路径或扫描完成时显示进度
	if s.scannedCount%10 == 0 || s.scannedCount == s.totalWords {
		progress := float64(s.scannedCount) / float64(s.totalWords) * 100
		fmt.Printf("\r扫描进度: %d/%d (%.1f%%)", s.scannedCount, s.totalWords, progress)
	}

	s.mutex.Unlock()
}

// normalizeURL 标准化URL
func (s *Scanner) normalizeURL(path string) string {
	baseURL := strings.TrimSuffix(s.config.URL, "/")
	path = strings.TrimPrefix(path, "/")

	// 检查基础URL是否包含协议，如果没有则添加默认协议
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	return baseURL + "/" + path
}

// processResults 处理扫描结果
func (s *Scanner) processResults(outputFile *os.File) {
	for result := range s.results {
		// 过滤掉错误结果，不存储错误路径
		if result.Error != nil {
			// 不显示错误信息，直接跳过
			continue
		}

		// 存储有效结果用于后续排序显示
		s.mutex.Lock()
		s.allResults = append(s.allResults, result)
		s.mutex.Unlock()

		// 状态码过滤 - 默认只显示有效状态码（200, 301, 302, 100, 101）
		validStatusCodes := map[int]bool{
			200: true,
			301: true,
			302: true,
			100: true,
			101: true,
		}

		// 检查是否为有效状态码
		isValidStatusCode := validStatusCodes[result.StatusCode]

		// 检查是否为404/403状态码
		is404403 := result.StatusCode == 404 || result.StatusCode == 403

		// 如果启用了显示404/403，则允许显示这些状态码
		allow404403 := s.config.Show404403 && is404403

		// 如果启用了显示所有状态码，或者有自定义的状态码过滤器，则使用原有逻辑
		if s.config.ShowAll || len(s.config.StatusCodeFilter) > 0 {
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
		} else {
			// 默认情况下，只显示有效状态码或允许的404/403状态码
			if !isValidStatusCode && !allow404403 {
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

	// 保存光标位置，显示结果，然后恢复光标位置
	fmt.Printf("\033[s") // 保存光标位置

	fmt.Printf("[%s] %-8d %s",
		statusColor.Sprintf("%3d", result.StatusCode),
		result.Size,
		result.URL)

	if result.Title != "" {
		fmt.Printf(" - %s", result.Title)
	}
	fmt.Println()

	// 恢复光标位置并显示进度
	fmt.Printf("\033[u") // 恢复光标位置
	s.mutex.Lock()
	progress := float64(s.scannedCount) / float64(s.totalWords) * 100
	fmt.Printf("\r\033[K扫描进度: %d/%d (%.1f%%)", s.scannedCount, s.totalWords, progress)
	s.mutex.Unlock()
}

// displaySortedResults 显示排序后的结果
func (s *Scanner) displaySortedResults() {
	s.displayOrganizedResults()
}

// displayOrganizedResults 显示整理后的结果
func (s *Scanner) displayOrganizedResults() {
	if len(s.allResults) == 0 {
		fmt.Println("没有找到任何有效路径")
		return
	}

	// 定义有效状态码
	validStatusCodes := map[int]bool{
		200: true,
		301: true,
		302: true,
		100: true,
		101: true,
	}

	// 按状态码分类结果
	resultsByStatus := make(map[int][]ScanResult)
	var allStatusCodes []int

	for _, result := range s.allResults {
		if result.Error != nil {
			continue
		}

		// 应用与实时扫描相同的过滤逻辑
		isValidStatusCode := validStatusCodes[result.StatusCode]
		is404403 := result.StatusCode == 404 || result.StatusCode == 403
		allow404403 := s.config.Show404403 && is404403

		// 如果启用了显示所有状态码，或者有自定义的状态码过滤器，则使用原有逻辑
		if s.config.ShowAll || len(s.config.StatusCodeFilter) > 0 {
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
		} else {
			// 默认情况下，只处理有效状态码或允许的404/403状态码
			if !isValidStatusCode && !allow404403 {
				continue
			}
		}

		if _, exists := resultsByStatus[result.StatusCode]; !exists {
			resultsByStatus[result.StatusCode] = []ScanResult{}
			allStatusCodes = append(allStatusCodes, result.StatusCode)
		}
		resultsByStatus[result.StatusCode] = append(resultsByStatus[result.StatusCode], result)
	}

	// 按状态码排序
	sort.Ints(allStatusCodes)

	// 显示每个状态码的结果
	for _, statusCode := range allStatusCodes {
		results := resultsByStatus[statusCode]

		// 按URL长度排序，便于阅读
		sort.Slice(results, func(i, j int) bool {
			return len(results[i].URL) < len(results[j].URL)
		})

		// 显示状态码标题
		statusColor := getStatusCodeColor(statusCode)
		title := fmt.Sprintf("=== 状态码 %d (%d 个路径) ===", statusCode, len(results))
		fmt.Println()
		statusColor.Println(title)

		// 显示结果
		for _, result := range results {
			s.displayResult(result)
		}
	}

	// 显示错误结果（如果存在）
	var errorResults []ScanResult
	for _, result := range s.allResults {
		if result.Error != nil {
			errorResults = append(errorResults, result)
		}
	}

	if len(errorResults) > 0 {
		fmt.Printf("\n=== 错误结果 (%d 个) ===\n", len(errorResults))
		for _, result := range errorResults {
			fmt.Printf("[ERROR] %s: %v\n", result.URL, result.Error)
		}
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

	title := html[titleStart : titleStart+titleEnd]
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
