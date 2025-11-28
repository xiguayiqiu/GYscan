package ftp

import (
	"fmt"
	"time"
)

// CrackFTP 执行FTP破解
func CrackFTP(target string, usernames, passwords []string, threads, timeout int) ([]CrackResult, error) {
	// 解析目标地址
	host, port, err := ParseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("解析目标地址失败: %v", err)
	}

	// 创建配置
	config := &FTPConfig{
		Host:     host,
		Port:     port,
		Username: usernames,
		Password: passwords,
		Threads:  threads,
		Timeout:  timeout,
	}

	// 验证配置
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	// 开始破解
	fmt.Println("开始破解...")

	// 创建破解工作器
	worker := NewCrackWorker(config)

	// 启动进度监控和实时结果显示
	go func() {
		total := len(config.Username) * len(config.Password)
		completed := 0
		
		for {
			select {
			case progress, ok := <-worker.GetProgress():
				if !ok {
					return
				}
				completed += progress
				progressPercent := float64(completed) / float64(total) * 100
				// 直接输出进度
				fmt.Printf("\r进度: %d/%d (%.2f%%)", completed, total, progressPercent)
				
			case _, ok := <-worker.GetSuccessResults():
				if !ok {
					continue
				}
				// 成功结果将在最终结果中统一显示，这里不再单独输出
			}
		}
	}()

	// 运行破解
	startTime := time.Now()
	results := worker.Run()
	duration := time.Since(startTime)

	// 确保进度行有换行，避免影响后续输出
	fmt.Printf("\n破解完成，总耗时: %v\n\n", duration)

	return results, nil
}

// CrackFTPWithConfig 使用配置执行FTP破解
func CrackFTPWithConfig(config *FTPConfig) ([]CrackResult, error) {
	// 验证配置
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	// 开始破解
	fmt.Println("开始破解...")

	// 创建破解工作器
	worker := NewCrackWorker(config)

	// 启动进度监控和实时结果显示
	go func() {
		total := len(config.Username) * len(config.Password)
		completed := 0
		
		for {
			select {
			case progress, ok := <-worker.GetProgress():
				if !ok {
					return
				}
				completed += progress
				progressPercent := float64(completed) / float64(total) * 100
				// 直接输出进度
				fmt.Printf("\r进度: %d/%d (%.2f%%)", completed, total, progressPercent)
				
			case _, ok := <-worker.GetSuccessResults():
				if !ok {
					continue
				}
				// 成功结果将在最终结果中统一显示，这里不再单独输出
			}
		}
	}()

	// 运行破解
	startTime := time.Now()
	results := worker.Run()
	duration := time.Since(startTime)

	// 确保进度行有换行，避免影响后续输出
	fmt.Printf("\n破解完成，总耗时: %v\n\n", duration)

	return results, nil
}
