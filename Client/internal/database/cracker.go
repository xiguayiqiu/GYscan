package database

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CrackResult 破解结果
type CrackResult struct {
	Username string
	Password string
	Success  bool
	Error    error
	Duration time.Duration
}

// ProgressCallback 进度回调函数
type ProgressCallback func(current, total, found int)

// DatabaseCracker 数据库破解器接口
type DatabaseCracker interface {
	Name() string
	TestConnection(ctx context.Context, config *DatabaseConfig) error
	Crack(ctx context.Context, config *DatabaseConfig, usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error)
}

// BaseCracker 基础破解器
type BaseCracker struct {
	name string
}

// NewBaseCracker 创建基础破解器
func NewBaseCracker(name string) *BaseCracker {
	return &BaseCracker{name: name}
}

func (b *BaseCracker) Name() string {
	return b.name
}

// CrackWorker 破解工作器
type CrackWorker struct {
	config    *DatabaseConfig
	cracker   DatabaseCracker
	usernames []string
	passwords []string
	results   chan CrackResult
	progress  ProgressCallback
	wg        *sync.WaitGroup
}

// NewCrackWorker 创建工作器
func NewCrackWorker(config *DatabaseConfig, cracker DatabaseCracker, 
	usernames, passwords []string, progress ProgressCallback) *CrackWorker {
	return &CrackWorker{
		config:    config,
		cracker:   cracker,
		usernames: usernames,
		passwords: passwords,
		results:   make(chan CrackResult, 100),
		progress:  progress,
		wg:        &sync.WaitGroup{},
	}
}

// Run 运行破解工作器
func (w *CrackWorker) Run(ctx context.Context, threads int) []CrackResult {
	total := len(w.usernames) * len(w.passwords)
	current := 0
	found := 0
	
	// 创建结果收集器
	results := make([]CrackResult, 0)
	resultMutex := &sync.Mutex{}
	
	// 启动结果收集器
	go func() {
		for result := range w.results {
			resultMutex.Lock()
			results = append(results, result)
			if result.Success {
				found++
			}
			current++
			
			// 更新进度
			if w.progress != nil {
				w.progress(current, total, found)
			}
			
			resultMutex.Unlock()
		}
	}()
	
	// 创建工作队列
	jobs := make(chan [2]string, total)
	
	// 填充工作队列
	go func() {
		defer close(jobs)
		for _, username := range w.usernames {
			for _, password := range w.passwords {
				select {
				case jobs <- [2]string{username, password}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	
	// 启动工作线程
	for i := 0; i < threads; i++ {
		w.wg.Add(1)
		go w.worker(ctx, jobs)
	}
	
	// 等待所有工作完成
	w.wg.Wait()
	close(w.results)
	
	return results
}

// worker 工作线程
func (w *CrackWorker) worker(ctx context.Context, jobs chan [2]string) {
	defer w.wg.Done()
	
	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			username, password := job[0], job[1]
			
			// 创建临时配置
			tempConfig := *w.config
			tempConfig.Username = username
			tempConfig.Password = password
			
			start := time.Now()
			success := false
			var err error
			
			// 尝试连接
			if w.cracker != nil {
				err = w.cracker.TestConnection(ctx, &tempConfig)
				success = (err == nil)
			}
			
			duration := time.Since(start)
			
			result := CrackResult{
				Username: username,
				Password: password,
				Success:  success,
				Error:    err,
				Duration: duration,
			}
			
			select {
			case w.results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// CrackManager 破解管理器
type CrackManager struct {
	crackers map[DatabaseType]DatabaseCracker
}

// NewCrackManager 创建破解管理器
func NewCrackManager() *CrackManager {
	return &CrackManager{
		crackers: make(map[DatabaseType]DatabaseCracker),
	}
}

// RegisterCracker 注册破解器
func (m *CrackManager) RegisterCracker(dbType DatabaseType, cracker DatabaseCracker) {
	m.crackers[dbType] = cracker
}

// GetCracker 获取破解器
func (m *CrackManager) GetCracker(dbType DatabaseType) (DatabaseCracker, error) {
	cracker, exists := m.crackers[dbType]
	if !exists {
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
	return cracker, nil
}

// Crack 执行破解
func (m *CrackManager) Crack(ctx context.Context, config *DatabaseConfig,
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	cracker, err := m.GetCracker(config.Type)
	if err != nil {
		return nil, err
	}
	
	// 验证配置
	if err := config.Validate(); err != nil {
		return nil, err
	}
	
	// 创建破解工作器
	worker := NewCrackWorker(config, cracker, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// PrintResults 打印破解结果
func PrintResults(results []CrackResult) {
	total := len(results)
	successCount := 0
	totalDuration := time.Duration(0)
	
	// 使用map去重，避免重复显示相同的成功破解结果
	uniqueResults := make(map[string]CrackResult)
	successResults := make([]CrackResult, 0)
	
	for _, result := range results {
		totalDuration += result.Duration
		if result.Success {
			successCount++
			// 使用用户名+密码作为唯一键
			key := result.Username + "|" + result.Password
			// 只保留第一个成功的结果，避免重复显示
			if _, exists := uniqueResults[key]; !exists {
				uniqueResults[key] = result
				successResults = append(successResults, result)
			}
		}
	}
	
	// 打印结果摘要
	fmt.Println("=== 数据库密码破解结果 ===")
	fmt.Printf("总尝试次数: %d\n", total)
	fmt.Printf("成功破解: %d\n", len(successResults))
	fmt.Printf("成功率: %.2f%%\n", float64(len(successResults))/float64(total)*100)
	fmt.Printf("总耗时: %v\n", totalDuration)
	
	// 打印成功破解的详细信息
	if len(successResults) > 0 {
		fmt.Println("\n破解成功的账户:")
		for _, result := range successResults {
			fmt.Printf("  - 用户名: %s\n", result.Username)
			fmt.Printf("    密码: %s\n", result.Password)
			fmt.Printf("    耗时: %v\n", result.Duration)
			fmt.Println()
		}
	} else {
		fmt.Println("\n[!] 未找到有效的用户名/密码组合")
	}
	
	fmt.Println("======================")
}