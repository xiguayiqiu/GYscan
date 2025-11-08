package main

import (
	"GYscan/internal/cli"
	"fmt"
	"os"
)

func main() {
	// 创建调试文件
	debugFile, err := os.Create("debug.log")
	if err != nil {
		fmt.Fprintln(os.Stderr, "创建调试文件失败:", err)
	} else {
		defer debugFile.Close()
		fmt.Fprintf(debugFile, "=== GYscan程序开始执行 ===\n")
		fmt.Fprintf(debugFile, "=== 命令行参数数量: %d\n", len(os.Args))
		fmt.Fprintf(debugFile, "=== 命令行参数: %v\n", os.Args)
	}
	
	fmt.Fprintln(os.Stderr, "=== GYscan程序开始执行 ===")
	fmt.Fprintf(os.Stderr, "=== 命令行参数数量: %d\n", len(os.Args))
	fmt.Fprintf(os.Stderr, "=== 命令行参数: %v\n", os.Args)
	os.Stdout.Sync() // 强制刷新输出缓冲区
	cli.Execute()
	
	if debugFile != nil {
		fmt.Fprintf(debugFile, "=== GYscan程序执行结束 ===\n")
	}
	fmt.Fprintln(os.Stderr, "=== GYscan程序执行结束 ===")
}