package xss

import (
	"fmt"

	"github.com/spf13/cobra"
)

var XssCmd = &cobra.Command{
	Use:   "xss [目标URL] [help]",
	Short: "XSS漏洞检测工具，支持反射型、存储型、DOM型XSS检测",
	Args:  cobra.MaximumNArgs(1),
	Long: `GYscan XSS模块 - XSS漏洞检测工具

支持功能:
- 反射型XSS检测 (多参数、混合编码、WAF绕过)
- 存储型XSS检测 (登录态保持、双回调验证)
- DOM型XSS检测 (JS语法解析、浏览器渲染验证)
- 高级WAF绕过 (Payload变异、参数污染)
- 并发扫描控制 (避免目标防护阈值)

用法:
  1. 直接传递目标URL: GYscan xss 目标URL [选项]
  2. 使用--url标志: GYscan xss --url 目标URL [选项]
  3. 获取帮助: GYscan xss help

示例用法:
  ./GYscan xss https://example.com/vuln.php --type reflected
  ./GYscan xss https://example.com/profile.php --type stored --login-url https://example.com/login.php
  ./GYscan xss https://example.com --type dom
  ./GYscan xss https://example.com --type all --threads 20 --waf-bypass`,
}

// init 初始化xss命令
func init() {
	// 将变量定义在init函数内部，避免参数残留
	var (
		targetURL    string
		xssType      string
		loginURL     string
		username     string
		password     string
		threads      int
		wafBypass    bool
		payloadLevel string
		output       string
		verbose      bool
		testMode     bool
	)

	// 配置命令运行函数
	XssCmd.Run = func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}
		
		// 优先使用命令行参数中的URL，如果没有则使用--url标志
		if len(args) > 0 && args[0] != "help" {
			targetURL = args[0]
		}
		
		if targetURL == "" {
			fmt.Println("请指定检测目标URL (直接传递URL参数或使用 --url 标志)")
			fmt.Println("用法: GYscan xss 目标URL [选项] 或 GYscan xss --url 目标URL [选项]")
			return
		}

		// 创建XSS检测配置
		config := XssConfig{
			URL:          targetURL,
			Type:         xssType,
			LoginURL:     loginURL,
			Username:     username,
			Password:     password,
			Threads:      threads,
			WafBypass:    wafBypass,
			PayloadLevel: payloadLevel,
			Verbose:      verbose,
			TestMode:     testMode,
		}

		// 执行XSS检测
		fmt.Printf("[GYscan-XSS] 开始检测目标: %s\n", targetURL)
		fmt.Printf("[GYscan-XSS] 检测类型: %s\n", xssType)
		
		results := RunXssScan(config)
		
		// 打印结果
		PrintXssResults(results)

		// 保存结果
		if output != "" {
			if err := SaveXssResults(results, output); err != nil {
				fmt.Printf("保存结果失败: %v\n", err)
			}
		}
	}
	
	// 定义命令行标志
	XssCmd.Flags().StringVarP(&targetURL, "url", "u", "", "检测目标URL")
	XssCmd.Flags().StringVarP(&xssType, "type", "t", "reflected", "XSS检测类型 (reflected/stored/dom/all)")
	XssCmd.Flags().StringVarP(&loginURL, "login-url", "l", "", "登录页面URL (用于存储型XSS)")
	XssCmd.Flags().StringVarP(&username, "username", "U", "", "登录用户名 (用于存储型XSS)")
	XssCmd.Flags().StringVarP(&password, "password", "P", "", "登录密码 (用于存储型XSS)")
	XssCmd.Flags().IntVarP(&threads, "threads", "n", 10, "并发线程数")
	XssCmd.Flags().BoolVarP(&wafBypass, "waf-bypass", "w", false, "启用WAF绕过模式")
	XssCmd.Flags().StringVarP(&payloadLevel, "payload-level", "p", "medium", "Payload级别 (low/medium/high)")
	XssCmd.Flags().StringVarP(&output, "output", "o", "", "结果输出文件")
	XssCmd.Flags().BoolVarP(&verbose, "verbose", "V", false, "显示详细测试过程")
	XssCmd.Flags().BoolVarP(&testMode, "test", "T", false, "启用XSS检测测试模式")
	
	// 添加help子命令
	XssCmd.AddCommand(&cobra.Command{
		Use:   "help",
		Short: "显示xss模块详细帮助信息",
		Run: func(cmd *cobra.Command, args []string) {
			XssHelp()
		},
	})
}

// XssHelp 显示xss帮助信息
func XssHelp() {
	helpText := `
GYscan XSS模块使用说明

基本用法:
  1. 直接传递目标URL: GYscan xss 目标URL [选项]
  2. 使用--url标志: GYscan xss --url 目标URL [选项]

检测类型:
  - reflected: 反射型XSS检测 (默认)
  - stored: 存储型XSS检测
  - dom: DOM型XSS检测
  - all: 检测所有类型的XSS漏洞

常用选项:
  -u, --url: 检测目标URL
  -t, --type: XSS检测类型 (reflected/stored/dom/all)
  -l, --login-url: 登录页面URL (用于存储型XSS)
  -U, --username: 登录用户名 (用于存储型XSS)
  -P, --password: 登录密码 (用于存储型XSS)
  -n, --threads: 并发线程数
  -w, --waf-bypass: 启用WAF绕过模式
  -p, --payload-level: Payload级别 (low/medium/high)
  -o, --output: 结果输出文件
  -V, --verbose: 显示详细测试过程

Payload级别说明:
  low: 基础Payload，适合无防护的目标
  medium: 包含编码和混淆的Payload，适合基础防护
  high: 高级绕过Payload，适合复杂WAF防护

示例:
  ./GYscan xss https://example.com/vuln.php --type reflected
  ./GYscan xss https://example.com/profile.php --type stored --login-url https://example.com/login.php --username admin --password 123456
  ./GYscan xss https://example.com --type dom --waf-bypass
  ./GYscan xss https://example.com --type all --threads 20 --payload-level high
  ./GYscan xss https://example.com/test.php?id=1 -V
`
	fmt.Println(helpText)
}