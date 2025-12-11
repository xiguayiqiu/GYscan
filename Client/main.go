package main

import (
	"GYscan/internal/cli"
	"os"
	"runtime"
)

func main() {
	// 设置Windows环境下的UTF-8编码支持
	setupWindowsEncoding()

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
