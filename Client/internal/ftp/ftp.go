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

	fmt.Printf("开始FTP破解...\n")
	fmt.Printf("目标: %s:%d\n", config.Host, config.Port)
	fmt.Printf("用户数: %d, 密码数: %d\n", len(config.Username), len(config.Password))
	fmt.Printf("线程数: %d, 超时: %d秒\n", config.Threads, config.Timeout)
	fmt.Printf("总尝试次数: %d\n", len(config.Username)*len(config.Password))
	fmt.Println()

	// 创建破解工作器
	worker := NewCrackWorker(config)

	// 启动进度监控和实时结果显示
	go func() {
		total := len(config.Username) * len(config.Password)
		completed := 0
		successCount := 0
		lastProgressLine := ""
		
		for {
			select {
			case progress, ok := <-worker.GetProgress():
				if !ok {
					return
				}
				completed += progress
				progressPercent := float64(completed) / float64(total) * 100
				// 保存当前进度行，用于成功信息后重新显示
				lastProgressLine = fmt.Sprintf("进度: %d/%d (%.2f%%)", completed, total, progressPercent)
				fmt.Printf("\r%s", lastProgressLine)
				
			case successResult, ok := <-worker.GetSuccessResults():
				if !ok {
					continue
				}
				successCount++
				// 先换行显示成功信息
				fmt.Printf("\n✅ 成功破解: 用户名: %s, 密码: %s, 耗时: %v\n", 
					successResult.Username, successResult.Password, successResult.Duration)
				// 然后在新行显示当前进度
				fmt.Printf("%s\n", lastProgressLine)
			}
		}
	}()

	// 运行破解
	startTime := time.Now()
	results := worker.Run()
	duration := time.Since(startTime)

	fmt.Printf("\n破解完成，总耗时: %v\n", duration)

	return results, nil
}

// CrackFTPWithConfig 使用配置执行FTP破解
func CrackFTPWithConfig(config *FTPConfig) ([]CrackResult, error) {
	// 验证配置
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	fmt.Printf("开始FTP破解...\n")
	fmt.Printf("目标: %s:%d\n", config.Host, config.Port)
	fmt.Printf("用户数: %d, 密码数: %d\n", len(config.Username), len(config.Password))
	fmt.Printf("线程数: %d, 超时: %d秒\n", config.Threads, config.Timeout)
	fmt.Printf("总尝试次数: %d\n", len(config.Username)*len(config.Password))
	fmt.Println()

	// 创建破解工作器
	worker := NewCrackWorker(config)

	// 启动进度监控和实时结果显示
	go func() {
		total := len(config.Username) * len(config.Password)
		completed := 0
		successCount := 0
		lastProgressLine := ""
		
		for {
			select {
			case progress, ok := <-worker.GetProgress():
				if !ok {
					return
				}
				completed += progress
				progressPercent := float64(completed) / float64(total) * 100
				// 保存当前进度行，用于成功信息后重新显示
				lastProgressLine = fmt.Sprintf("进度: %d/%d (%.2f%%)", completed, total, progressPercent)
				fmt.Printf("\r%s", lastProgressLine)
				
			case successResult, ok := <-worker.GetSuccessResults():
				if !ok {
					continue
				}
				successCount++
				// 先换行显示成功信息
				fmt.Printf("\n✅ 成功破解: 用户名: %s, 密码: %s, 耗时: %v\n", 
					successResult.Username, successResult.Password, successResult.Duration)
				// 然后在新行显示当前进度
				fmt.Printf("%s\n", lastProgressLine)
			}
		}
	}()

	// 运行破解
	startTime := time.Now()
	results := worker.Run()
	duration := time.Since(startTime)

	fmt.Printf("\n破解完成，总耗时: %v\n", duration)

	return results, nil
}
