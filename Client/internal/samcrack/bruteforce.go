package samcrack

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// BruteForceCracker 暴力破解器
type BruteForceCracker struct {
	charset      string
	minLength    int
	maxLength    int
	workers      int
	results      chan *CrackResult
	stopChan     chan struct{}
}

// NewBruteForceCracker 创建新的暴力破解器
func NewBruteForceCracker(charset string, minLength, maxLength int) *BruteForceCracker {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	
	return &BruteForceCracker{
		charset:   charset,
		minLength: minLength,
		maxLength: maxLength,
		workers:   workers,
		results:   make(chan *CrackResult, 100),
		stopChan:  make(chan struct{}),
	}
}



// Crack 使用暴力破解NTLM哈希
func (b *BruteForceCracker) Crack(targetHash, username string) (*CrackResult, error) {
	// 验证参数
	if b.minLength < 1 || b.maxLength < b.minLength {
		return nil, fmt.Errorf("无效的长度参数: min=%d, max=%d", b.minLength, b.maxLength)
	}
	
	if len(b.charset) == 0 {
		return nil, fmt.Errorf("字符集不能为空")
	}
	
	// 创建NTLM哈希计算器
	hasher := NewNTLMHasher()
	
	// 启动破解
	return b.crackWithWorkers(targetHash, username, hasher)
}

// crackWithWorkers 使用多协程破解
func (b *BruteForceCracker) crackWithWorkers(targetHash, username string, hasher *NTLMHasher) (*CrackResult, error) {
	var wg sync.WaitGroup
	var found bool
	var foundPassword string
	var attempts int64
	var mu sync.Mutex
	
	startTime := time.Now()
	
	// 创建密码通道
	passwordChan := make(chan string, 1000)
	
	// 启动生产者协程
	go b.producePasswords(passwordChan)
	
	// 启动消费者协程
	for i := 0; i < b.workers; i++ {
		wg.Add(1)
		go b.worker(passwordChan, targetHash, &found, &foundPassword, &attempts, &mu, &wg, hasher)
	}
	
	// 等待所有协程完成
	wg.Wait()
	
	elapsedTime := time.Since(startTime)
	
	result := &CrackResult{
		Username:    username,
		NTLMHash:    targetHash,
		ElapsedTime: elapsedTime,
		Attempts:    attempts,
	}
	
	if found {
		result.Password = foundPassword
		result.Found = true
	}
	
	return result, nil
}

// producePasswords 生成密码组合到通道
func (b *BruteForceCracker) producePasswords(passwordChan chan<- string) {
	defer close(passwordChan)
	
	// 为每个长度生成密码
	for length := b.minLength; length <= b.maxLength; length++ {
		b.generatePasswordsOfLength("", length, passwordChan)
	}
}

// generatePasswordsOfLength 生成长度为length的所有密码组合
func (b *BruteForceCracker) generatePasswordsOfLength(prefix string, length int, passwordChan chan<- string) {
	if length == 0 {
		select {
		case <-b.stopChan:
			return
		case passwordChan <- prefix:
		}
		return
	}
	
	for _, char := range b.charset {
		select {
		case <-b.stopChan:
			return
		default:
			b.generatePasswordsOfLength(prefix+string(char), length-1, passwordChan)
		}
	}
}

// worker 工作协程
func (b *BruteForceCracker) worker(passwordChan <-chan string, targetHash string, 
	found *bool, foundPassword *string, attempts *int64, mu *sync.Mutex, 
	wg *sync.WaitGroup, hasher *NTLMHasher) {
	
	defer wg.Done()
	
	for password := range passwordChan {
		select {
		case <-b.stopChan:
			return
		default:
			// 原子性增加尝试计数
			mu.Lock()
			*attempts++
			mu.Unlock()
			
			// 验证密码
			if hasher.VerifyPassword(password, targetHash) {
				mu.Lock()
				if !*found {
					*found = true
					*foundPassword = password
					close(b.stopChan) // 通知其他协程停止
				}
				mu.Unlock()
				return
			}
		}
	}
}

// CrackMultiple 破解多个哈希
func (b *BruteForceCracker) CrackMultiple(userHashes []*UserHash) ([]*CrackResult, error) {
	var results []*CrackResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 为每个用户哈希启动破解协程
	for _, userHash := range userHashes {
		wg.Add(1)
		go func(hash *UserHash) {
			defer wg.Done()
			
			result, err := b.Crack(hash.NTLMHash, hash.Username)
			if err != nil {
				fmt.Printf("暴力破解用户 %s 失败: %v\n", hash.Username, err)
				return
			}
			
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(userHash)
	}
	
	wg.Wait()
	
	return results, nil
}

// GetBruteForceStats 获取暴力破解统计信息
func (b *BruteForceCracker) GetBruteForceStats() *BruteForceStats {
	stats := &BruteForceStats{
		Charset:   b.charset,
		MinLength: b.minLength,
		MaxLength: b.maxLength,
		Workers:   b.workers,
	}
	
	// 计算总组合数
	totalCombinations := int64(0)
	charsetLength := len(b.charset)
	
	for length := b.minLength; length <= b.maxLength; length++ {
		combinations := int64(1)
		for i := 0; i < length; i++ {
			combinations *= int64(charsetLength)
		}
		totalCombinations += combinations
	}
	
	stats.TotalCombinations = totalCombinations
	
	return stats
}

// BruteForceStats 暴力破解统计信息
type BruteForceStats struct {
	Charset           string
	MinLength         int
	MaxLength         int
	Workers           int
	TotalCombinations int64
}

// Stop 停止破解
func (b *BruteForceCracker) Stop() {
	select {
	case <-b.stopChan:
		// 已经关闭
	default:
		close(b.stopChan)
	}
}

// EstimateTime 估算破解时间
func (b *BruteForceCracker) EstimateTime(hashRatePerSecond int64) time.Duration {
	stats := b.GetBruteForceStats()
	
	if hashRatePerSecond <= 0 {
		hashRatePerSecond = 100000 // 默认10万次/秒
	}
	
	totalSeconds := float64(stats.TotalCombinations) / float64(hashRatePerSecond)
	
	return time.Duration(totalSeconds * float64(time.Second))
}