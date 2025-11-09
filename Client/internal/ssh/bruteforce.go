package ssh

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	
	"GYscan/internal/utils"
)

// SSHBruteforcer SSH爆破器主类
type SSHBruteforcer struct {
	config         *SSHConfig
	authenticator  *SSHAuthenticator
	results        []*SSHResult
	mutex          sync.Mutex
	stopChan       chan bool
	progress       *ProgressTracker
	// 资源管理
	cleanupDone    chan bool
}

// NewSSHBruteforcer 创建新的SSH爆破器
func NewSSHBruteforcer(config *SSHConfig) *SSHBruteforcer {
	authenticator := NewSSHAuthenticator(config)
	
	return &SSHBruteforcer{
		config:        config,
		authenticator: authenticator,
		results:       make([]*SSHResult, 0),
		stopChan:      make(chan bool),
		progress:      NewProgressTracker(),
		cleanupDone:   make(chan bool),
	}
}

// Bruteforce 执行SSH爆破
func (s *SSHBruteforcer) Bruteforce() ([]*SSHResult, error) {
	startTime := time.Now()

	// 验证配置
	if err := s.ValidateConfig(); err != nil {
		return nil, err
	}

	// 检查目标是否可达
	if !s.IsTargetReachable() {
		return nil, fmt.Errorf("目标不可达: %s:%d", s.config.Target, s.config.Port)
	}

	// 打印配置信息
	s.PrintConfig()

	// 生成凭证组合
	credentials, err := s.authenticator.GenerateCredentials(s.config)
	if err != nil {
		return nil, fmt.Errorf("生成凭证组合失败: %v", err)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("没有可用的凭证组合")
	}

	if s.config.Verbose || s.config.VeryVerbose {
		utils.InfoPrint("[+] 总共 %d 个凭证组合需要测试", len(credentials))
	}

	// 初始化进度跟踪器
	s.progress.Init(len(credentials))

	// 执行并发爆破
	results := s.executeBruteforce(credentials)

	// 计算总耗时
	totalTime := time.Since(startTime)
	
	if s.config.Verbose || s.config.VeryVerbose {
		utils.InfoPrint("[+] 爆破完成，总耗时: %v", totalTime)
	}

	return results, nil
}

// executeBruteforce 执行并发爆破
func (s *SSHBruteforcer) executeBruteforce(credentials []Credentials) []*SSHResult {
	var wg sync.WaitGroup
	var successCount int32
	
	// 创建凭证通道，使用固定大小的缓冲区避免内存压力
	credChan := make(chan Credentials, min(1000, len(credentials)))
	
	// 启动工作线程
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go s.worker(i, credChan, &wg, &successCount)
	}

	// 在单独的goroutine中填充凭证通道
	go func() {
		for _, cred := range credentials {
			// 检查是否应该停止
			select {
			case <-s.stopChan:
				close(credChan)
				return
			default:
				credChan <- cred
			}
		}
		close(credChan)
	}()

	// 等待所有工作线程完成
	wg.Wait()

	return s.results
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// worker 工作线程
func (s *SSHBruteforcer) worker(id int, credChan chan Credentials, wg *sync.WaitGroup, successCount *int32) {
	defer wg.Done()

	// 失败计数器，用于检测服务器安全机制
	consecutiveFailures := 0
	maxConsecutiveFailures := 5
	
	// 线程本地连接计数器，避免单个线程创建过多连接
	localConnectionCount := 0
	maxConnectionsPerThread := 50
	
	for cred := range credChan {
		// 检查是否应该停止（在关键点都检查）
		select {
		case <-s.stopChan:
			return
		default:
		}

		// 检查是否已经找到匹配且设置了停止标志
		if s.config.StopOnFirst && atomic.LoadInt32(successCount) > 0 {
			return
		}

		// 检查线程本地连接计数，避免单个线程创建过多连接
		if localConnectionCount >= maxConnectionsPerThread {
			if s.config.VeryVerbose {
				utils.Debug("[线程%d] 连接数达到限制(%d)，等待清理...", id, maxConnectionsPerThread)
			}
			time.Sleep(5 * time.Second)
			localConnectionCount = 0
		}

		// 添加尝试间隔，避免触发服务器安全机制
		if s.config.AttemptDelay > 0 {
			time.Sleep(time.Duration(s.config.AttemptDelay) * time.Millisecond)
			
			// 再次检查停止信号，避免长时间等待
			select {
			case <-s.stopChan:
				return
			default:
			}
		}

		// 记录当前时间用于结果统计
		attemptStartTime := time.Now()
		
		// 测试凭证
		result, err := s.authenticator.TestCredentials(
			s.config.Target,
			s.config.Port,
			cred.Username,
			cred.Password,
		)

		if err != nil {
			if s.config.VeryVerbose {
				utils.Debug("[线程%d] 测试失败: %v", id, err)
			}
			
			// 处理服务器安全机制导致的错误
			securityHandled := s.handleSecurityMechanism(err, &consecutiveFailures, maxConsecutiveFailures)
			
			// 即使处理了安全机制，也要记录失败结果
			if securityHandled {
				// 创建失败结果记录
				result = &SSHResult{
					Target:     s.config.Target,
					Port:       s.config.Port,
					Username:   cred.Username,
					Password:   cred.Password,
					Success:    false,
					Error:      "服务器安全机制触发，凭证被跳过",
					Attempts:   1,
					ElapsedTime: time.Since(attemptStartTime),
				}
			} else {
				// 非安全机制错误，创建正常的失败结果记录
				result = &SSHResult{
					Target:     s.config.Target,
					Port:       s.config.Port,
					Username:   cred.Username,
					Password:   cred.Password,
					Success:    false,
					Error:      s.authenticator.ParseSSHError(err),
					Attempts:   1,
					ElapsedTime: time.Since(attemptStartTime),
				}
			}
		} else {
			// 成功连接，增加本地连接计数
			localConnectionCount++
		}

		// 保存结果
		s.mutex.Lock()
		s.results = append(s.results, result)
		s.mutex.Unlock()

		// 更新进度
		s.progress.Increment()

		// 如果成功且设置了停止标志，发送停止信号
		if result.Success {
			atomic.AddInt32(successCount, 1)
			
			if s.config.StopOnFirst {
				close(s.stopChan)
				return
			}
		}
		
		// 重置连续失败计数
		if result.Success {
			consecutiveFailures = 0
		}
	}
}

// handleSecurityMechanism 处理服务器安全机制
func (s *SSHBruteforcer) handleSecurityMechanism(err error, consecutiveFailures *int, maxFailures int) bool {
	errorStr := err.Error()
	
	// 检测服务器安全机制触发的错误
	if strings.Contains(errorStr, "connection closed") || 
	   strings.Contains(errorStr, "too many authentication failures") ||
	   strings.Contains(errorStr, "connection reset") ||
	   strings.Contains(errorStr, "EOF") ||
	   strings.Contains(errorStr, "wsarecv") ||
	   strings.Contains(errorStr, "handshake failed") {
		
		*consecutiveFailures++
		
		if *consecutiveFailures >= maxFailures {
			// 服务器可能已锁定，等待一段时间
			if s.config.VeryVerbose {
				utils.WarningPrint("[!] 检测到服务器安全机制，等待%d秒后继续...", 30+(*consecutiveFailures-5)*10)
			}
			
			// 动态调整等待时间，避免无限等待
			waitTime := 30 + (*consecutiveFailures-5)*10
			if waitTime > 300 { // 最大等待5分钟
				waitTime = 300
			}
			
			time.Sleep(time.Duration(waitTime) * time.Second)
			
			// 重新检查目标是否可达
			if !s.IsTargetReachable() {
				if s.config.VeryVerbose {
					utils.WarningPrint("[!] 目标仍然不可达，继续等待%d秒...", 60)
				}
				time.Sleep(60 * time.Second)
			}
			
			// 重置失败计数，但保留部分历史以检测持续问题
			if *consecutiveFailures > 10 {
				*consecutiveFailures = 5 // 保留部分历史
			}
		}
		
		return true
	}
	
	return false
}

// Stop 停止爆破
func (s *SSHBruteforcer) Stop() {
	select {
	case <-s.stopChan:
		// 已经关闭
	default:
		close(s.stopChan)
	}
}

// ValidateConfig 验证配置
func (s *SSHBruteforcer) ValidateConfig() error {
	if s.config.Target == "" {
		return fmt.Errorf("目标地址不能为空")
	}

	if s.config.Port < 1 || s.config.Port > 65535 {
		return fmt.Errorf("端口号必须在1-65535范围内")
	}

	if s.config.Threads < 1 || s.config.Threads > 100 {
		return fmt.Errorf("线程数必须在1-100范围内")
	}

	if s.config.Timeout < 1 || s.config.Timeout > 300 {
		return fmt.Errorf("超时时间必须在1-300秒范围内")
	}

	if s.config.AttemptDelay < 0 || s.config.AttemptDelay > 60000 {
		return fmt.Errorf("尝试间隔必须在0-60000毫秒范围内")
	}

	if s.config.Username == "" && s.config.UsernameFile == "" {
		return fmt.Errorf("必须指定用户名或用户名字典文件")
	}

	if s.config.Password == "" && s.config.PasswordFile == "" {
		return fmt.Errorf("必须指定密码或密码字典文件")
	}

	return nil
}

// IsTargetReachable 检查目标是否可达
func (s *SSHBruteforcer) IsTargetReachable() bool {
	err := s.authenticator.TestConnection(s.config.Target, s.config.Port)
	if err != nil {
		if s.config.Verbose || s.config.VeryVerbose {
			fmt.Printf("[!] 目标不可达: %v\n", err)
		}
		return false
	}
	return true
}

// PrintConfig 打印配置信息
func (s *SSHBruteforcer) PrintConfig() {
	if !s.config.Verbose && !s.config.VeryVerbose {
		return
	}

	utils.BannerPrint("==============================================")
	utils.BannerPrint("GYscan SSH爆破工具 (Hydra风格)")
	utils.InfoPrint("目标: %s:%d", s.config.Target, s.config.Port)
	utils.InfoPrint("线程数: %d", s.config.Threads)
	utils.InfoPrint("超时时间: %d秒", s.config.Timeout)
	utils.WarningPrint("如果看见连续多个失败，可能会触发服务器安全机制导致强制关闭连接！")
	utils.WarningPrint("建议: 增加尝试间隔(2000毫秒一次发包)，或使用字典文件时注意服务器安全设置!")
	utils.WarningPrint("注意: 增加尝试间隔可能会增加破解时间，建议根据目标响应时间调整")
	utils.WarningPrint("不是没想过在开发时使用并发加速破解，而是根据openssh最新的安全更新，得知opensssh")
	utils.WarningPrint("添加了一个并发请求会被强制断连的安全更新！")

	if s.config.AttemptDelay > 0 {
		utils.WarningPrint("尝试间隔: %d毫秒", s.config.AttemptDelay)
	}
	
	if s.config.Username != "" {
		utils.InfoPrint("用户名: %s", s.config.Username)
	} else {
		utils.InfoPrint("用户名字典: %s", s.config.UsernameFile)
	}
	
	if s.config.Password != "" {
		utils.InfoPrint("密码: %s", "********")
	} else {
		utils.InfoPrint("密码字典: %s", s.config.PasswordFile)
	}
	
	if s.config.ExtraChecks != "" {
		utils.InfoPrint("额外检查: %s", s.config.ExtraChecks)
	}
	
	if s.config.StopOnFirst {
		utils.WarningPrint("模式: 找到第一个匹配后停止")
	}
	
	utils.BannerPrint("==============================================")
}

// PrintResults 打印结果（Hydra风格）
func (s *SSHBruteforcer) PrintResults(results []*SSHResult) {
	successCount := 0
	totalAttempts := 0

	// Hydra风格的标题
	utils.BannerPrint("\n[HYDRA] starting at %s", time.Now().Format("2006-01-02 15:04:05"))
	utils.BannerPrint("[DATA] max %d tasks per 1 server, overall max %d tasks", s.config.Threads, s.config.Threads)
	utils.BannerPrint("[INFO] Reduced number of tasks to %d because there are not enough hosts", s.config.Threads)
	
	// 打印成功的结果（Hydra风格）
	for _, result := range results {
		totalAttempts += result.Attempts
		
		if result.Success {
			successCount++
			// Hydra风格的成功显示 - 使用更醒目的格式
			utils.SuccessPrint("\n[%d][ssh] host: %s:%d login: %s password: %s [SUCCESS]", 
				successCount, result.Target, result.Port, result.Username, result.Password)
			// 在成功时立即显示详细信息，不依赖详细模式
			utils.SuccessPrint("    认证成功！耗时: %v", result.ElapsedTime)
		} else if s.config.VeryVerbose {
			// 详细模式下的失败显示
			utils.ErrorPrint("[%d][ssh] host: %s:%d login: %s password: %s [FAILED] (%s)", 
				totalAttempts, result.Target, result.Port, result.Username, result.Password, result.Error)
		}
	}

	// Hydra风格的统计信息
	utils.BannerPrint("\n[STATUS] attack finished for %s:%d (%s)", 
		s.config.Target, s.config.Port, time.Now().Format("2006-01-02 15:04:05"))
	
	if successCount > 0 {
		utils.SuccessPrint("[SUCCESS] Found %d valid password(s) for %d host(s)", successCount, 1)
		utils.SuccessPrint("[HOST] %s:%d [ssh]\n[LOGIN] %s\n[PASSWORD] %s", 
			s.config.Target, s.config.Port, s.config.Username, getSuccessPassword(results))
	} else {
		utils.ErrorPrint("[ERROR] No valid passwords found")
	}
	
	// 详细的统计信息
	utils.InfoPrint("\n[统计摘要]")
	utils.InfoPrint("服务器: %s:%d", s.config.Target, s.config.Port)
	utils.InfoPrint("服务: ssh")
	utils.InfoPrint("成功数: %d", successCount)
	utils.InfoPrint("尝试次数: %d", totalAttempts)
	
	if len(results) > 0 {
		utils.InfoPrint("耗时: %v", results[0].ElapsedTime)
	}
	
	if successCount == 0 {
		utils.WarningPrint("[警告] 未找到有效的凭据")
	} else {
		utils.SuccessPrint("[完成] SSH暴力破解攻击成功完成")
	}
}

// getSuccessPassword 获取成功的密码
func getSuccessPassword(results []*SSHResult) string {
	for _, result := range results {
		if result.Success {
			return result.Password
		}
	}
	return ""
}

// Close 关闭爆破器，释放所有资源
func (s *SSHBruteforcer) Close() {
	// 关闭认证器
	if s.authenticator != nil {
		s.authenticator.Close()
	}
	
	// 发送清理完成信号
	close(s.cleanupDone)
}

// ProgressTracker 进度跟踪器
type ProgressTracker struct {
	total     int
	completed int32
	startTime time.Time
}

// NewProgressTracker 创建新的进度跟踪器
func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{}
}

// Init 初始化进度跟踪器
func (p *ProgressTracker) Init(total int) {
	p.total = total
	p.completed = 0
	p.startTime = time.Now()
}

// Increment 增加完成计数
func (p *ProgressTracker) Increment() {
	atomic.AddInt32(&p.completed, 1)
	
	// 每完成10%或每100个任务打印一次进度
	completed := atomic.LoadInt32(&p.completed)
	if completed%100 == 0 || completed == int32(p.total) {
		p.printProgress()
	}
}

// printProgress 打印进度
func (p *ProgressTracker) printProgress() {
	completed := atomic.LoadInt32(&p.completed)
	percentage := float64(completed) / float64(p.total) * 100
	elapsed := time.Since(p.startTime)
	
	// 计算预计剩余时间
	var remaining time.Duration
	if completed > 0 {
		avgTimePerTask := elapsed / time.Duration(completed)
		remainingTasks := p.total - int(completed)
		remaining = avgTimePerTask * time.Duration(remainingTasks)
	}
	
	utils.ProgressPrint("[进度] %.1f%% (%d/%d) 耗时: %v 剩余: %v", 
		percentage, completed, p.total, elapsed.Round(time.Second), remaining.Round(time.Second))
}

// getVerboseLevel 获取详细级别
func getVerboseLevel(config *SSHConfig) int {
	if config.VeryVerbose {
		return 2
	}
	if config.Verbose {
		return 1
	}
	return 0
}