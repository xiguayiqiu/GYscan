package main

import (
	"fmt"
	"os"
	"runtime"
	"GYscan/internal/cli"
	"GYscan/internal/logging"
)

func main() {
	// 设置Windows环境下的UTF-8编码支持
	setupWindowsEncoding()

	// 初始化日志系统
	if err := logging.InitLoggingSystem(); err != nil {
		fmt.Printf("初始化日志系统失败: %v\n", err)
		os.Exit(1)
	}
	defer logging.CloseLoggingSystem()

	// 记录系统信息
	logging.LogSystemInfo()

	// 无论是否有命令行参数，都直接执行命令
	cli.Execute()
}

// setupWindowsEncoding 设置Windows环境下的UTF-8编码支持
func setupWindowsEncoding() {
	if runtime.GOOS == "windows" {
		// 设置控制台输出编码为UTF-8
		os.Setenv("PYTHONIOENCODING", "utf-8")
		// 对于Windows系统，可能需要额外的编码设置
		// 这里可以根据需要添加更多Windows特定的编码设置
	}
}
