package samcrack

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

// DictionaryCracker 字典破解器
type DictionaryCracker struct {
	dictionaryPath string
	workers         int
	results         chan *CrackResult
	stopChan        chan struct{}
}

// NewDictionaryCracker 创建新的字典破解器
func NewDictionaryCracker(dictionaryPath string) *DictionaryCracker {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	
	return &DictionaryCracker{
		dictionaryPath: dictionaryPath,
		workers:         workers,
		results:         make(chan *CrackResult, 100),
		stopChan:        make(chan struct{}),
	}
}



// Crack 使用字典破解NTLM哈希
func (d *DictionaryCracker) Crack(targetHash, username string) (*CrackResult, error) {
	// 检查字典文件是否存在
	if _, err := os.Stat(d.dictionaryPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("字典文件不存在: %s", d.dictionaryPath)
	}

	// 打开字典文件
	file, err := os.Open(d.dictionaryPath)
	if err != nil {
		return nil, fmt.Errorf("打开字典文件失败: %v", err)
	}
	defer file.Close()

	// 创建NTLM哈希计算器
	hasher := NewNTLMHasher()

	// 启动破解
	return d.crackWithWorkers(file, targetHash, username, hasher)
}

// crackWithWorkers 使用多协程破解
func (d *DictionaryCracker) crackWithWorkers(file *os.File, targetHash, username string, hasher *NTLMHasher) (*CrackResult, error) {
	var wg sync.WaitGroup
	var found bool
	var foundPassword string
	var attempts int64
	var mu sync.Mutex
	
	startTime := time.Now()
	
	// 创建密码通道
	passwordChan := make(chan string, 1000)
	
	// 启动生产者协程
	go d.producePasswords(file, passwordChan)
	
	// 启动消费者协程
	for i := 0; i < d.workers; i++ {
		wg.Add(1)
		go d.worker(passwordChan, targetHash, &found, &foundPassword, &attempts, &mu, &wg, hasher)
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

// producePasswords 生产密码到通道
func (d *DictionaryCracker) producePasswords(file *os.File, passwordChan chan<- string) {
	defer close(passwordChan)
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-d.stopChan:
			return
		default:
			password := scanner.Text()
			if password != "" {
				passwordChan <- password
			}
		}
	}
}

// worker 工作协程
func (d *DictionaryCracker) worker(passwordChan <-chan string, targetHash string, 
	found *bool, foundPassword *string, attempts *int64, mu *sync.Mutex, 
	wg *sync.WaitGroup, hasher *NTLMHasher) {
	
	defer wg.Done()
	
	for password := range passwordChan {
		select {
		case <-d.stopChan:
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
					close(d.stopChan) // 通知其他协程停止
				}
				mu.Unlock()
				return
			}
		}
	}
}

// CrackMultiple 破解多个哈希
func (d *DictionaryCracker) CrackMultiple(userHashes []*UserHash) ([]*CrackResult, error) {
	var results []*CrackResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 为每个用户哈希启动破解协程
	for _, userHash := range userHashes {
		wg.Add(1)
		go func(hash *UserHash) {
			defer wg.Done()
			
			result, err := d.Crack(hash.NTLMHash, hash.Username)
			if err != nil {
				fmt.Printf("破解用户 %s 失败: %v\n", hash.Username, err)
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

// GetDictionaryStats 获取字典统计信息
func (d *DictionaryCracker) GetDictionaryStats() (*DictionaryStats, error) {
	file, err := os.Open(d.dictionaryPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	stats := &DictionaryStats{
		FilePath: d.dictionaryPath,
	}
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			stats.TotalPasswords++
			if len(line) < 6 {
				stats.ShortPasswords++
			}
		}
	}
	
	// 获取文件大小
	fileInfo, err := file.Stat()
	if err == nil {
		stats.FileSize = fileInfo.Size()
	}
	
	return stats, nil
}

// DictionaryStats 字典统计信息
type DictionaryStats struct {
	FilePath       string
	TotalPasswords int64
	ShortPasswords int64
	FileSize       int64
}

// Stop 停止破解
func (d *DictionaryCracker) Stop() {
	select {
	case <-d.stopChan:
		// 已经关闭
	default:
		close(d.stopChan)
	}
}