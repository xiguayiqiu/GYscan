package csrf

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Cmd 定义CSRF漏洞检测命令
var Cmd = &cobra.Command{
	Use:   "csrf [目标URL] [help]",
	Short: "CSRF漏洞检测 [测试阶段]",
	Args:  cobra.MaximumNArgs(1),
	Long: `
[GYscan-CSRF] CSRF漏洞检测模块
用于检测目标URL的CSRF漏洞，支持多种检测场景：
无Token请求检测、无效Token请求检测、伪造Referer/Origin请求检测、Cookie SameSite配置检测等。

使用示例：
  GYscan.exe csrf http://example.com/vul/csrf.php
  GYscan.exe csrf -u http://example.com/vul/csrf.php -X POST -d "action=delete&id=1"
  GYscan.exe csrf -u http://example.com/vul/csrf.php --cookies "session=xxx"
  GYscan.exe csrf -u http://example.com/vul/csrf.php --headers "X-Custom: value"
  GYscan.exe csrf -u http://example.com/vul/csrf.php -V
  GYscan.exe csrf --test
`,
	Example: "GYscan.exe csrf http://example.com/submit -X POST -d 'name=test'",

	Run: func(cmd *cobra.Command, args []string) {
		// 处理help参数
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 处理直接传递的URL参数
		if len(args) > 0 {
			cmd.Flags().Set("url", args[0])
		}

		// 解析配置
		config := parseConfig(cmd)

		// 检查是否提供了URL（非测试模式下）
		if !config.TestMode && config.URL == "" {
			fmt.Println("请指定目标URL")
			fmt.Println("用法: gyscan csrf 目标URL [选项] 或 gyscan csrf --url 目标URL [选项]")
			return
		}

		// 执行CSRF漏洞扫描
		results := RunScan(config)

		// 输出结果
		printResults(results, config)
	},
}

// 初始化命令行参数
func init() {
	// 基本选项
	Cmd.Flags().StringP("url", "u", "", "目标URL")
	Cmd.Flags().StringP("method", "X", "GET", "HTTP请求方法 (GET/POST)")
	Cmd.Flags().StringP("data", "d", "", "POST数据 (key=value格式)")
	Cmd.Flags().StringP("params", "p", "", "自定义参数 (key=value格式，多个参数用&分隔)")
	Cmd.Flags().StringP("headers", "H", "", "自定义HTTP头 (key:value格式，多个头用&分隔)")
	Cmd.Flags().IntP("timeout", "T", 10, "请求超时时间(秒)")
	Cmd.Flags().IntP("threads", "j", 5, "并发线程数")
	Cmd.Flags().BoolP("verbose", "V", false, "显示详细信息")
	Cmd.Flags().BoolP("test", "", false, "启用测试模式")
	Cmd.Flags().StringP("proxy", "", "", "代理服务器")
	Cmd.Flags().StringP("cookies", "", "", "Cookie信息")
	Cmd.Flags().StringP("referer", "", "", "Referer头")
	Cmd.Flags().StringP("user-agent", "", "", "User-Agent头")
	Cmd.Flags().StringP("login-url", "", "", "登录URL")
	Cmd.Flags().StringP("login-username", "", "", "登录用户名")
	Cmd.Flags().StringP("login-password", "", "", "登录密码")
	Cmd.Flags().StringP("login-method", "", "POST", "登录方法")
	Cmd.Flags().StringP("login-data", "", "", "登录数据")
	Cmd.Flags().StringP("login-success", "", "", "登录成功标识")
}

// parseConfig 解析命令行参数到配置结构体
func parseConfig(cmd *cobra.Command) Config {
	url, _ := cmd.Flags().GetString("url")
	method, _ := cmd.Flags().GetString("method")
	data, _ := cmd.Flags().GetString("data")
	params, _ := cmd.Flags().GetString("params")
	headers, _ := cmd.Flags().GetString("headers")
	timeout, _ := cmd.Flags().GetInt("timeout")
	threads, _ := cmd.Flags().GetInt("threads")
	verbose, _ := cmd.Flags().GetBool("verbose")
	testMode, _ := cmd.Flags().GetBool("test")
	proxy, _ := cmd.Flags().GetString("proxy")
	cookies, _ := cmd.Flags().GetString("cookies")
	referer, _ := cmd.Flags().GetString("referer")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	loginURL, _ := cmd.Flags().GetString("login-url")
	loginUsername, _ := cmd.Flags().GetString("login-username")
	loginPassword, _ := cmd.Flags().GetString("login-password")
	loginMethod, _ := cmd.Flags().GetString("login-method")
	loginData, _ := cmd.Flags().GetString("login-data")
	loginSuccess, _ := cmd.Flags().GetString("login-success")

	return Config{
		URL:           url,
		Method:        method,
		Params:        params,
		Headers:       headers,
		Data:          data,
		Threads:       threads,
		Verbose:       verbose,
		TestMode:      testMode,
		Timeout:       timeout,
		Proxy:         proxy,
		Cookies:       cookies,
		Referer:       referer,
		UserAgent:     userAgent,
		LoginURL:      loginURL,
		LoginUsername: loginUsername,
		LoginPassword: loginPassword,
		LoginMethod:   loginMethod,
		LoginData:     loginData,
		LoginSuccess:  loginSuccess,
	}
}

// printResults 输出CSRF漏洞检测结果
func printResults(results Results, config Config) {
	fmt.Println("\n[GYscan-CSRF] 检测结果总结")
	fmt.Println("=================================")
	fmt.Printf("总测试数: %d\n", results.Summary.TotalTests)
	fmt.Printf("发现漏洞数: %d\n", results.Summary.VulnerableTests)
	fmt.Println("=================================")

	if config.Verbose || results.Summary.VulnerableTests > 0 {
		fmt.Println("\n[GYscan-CSRF] 详细检测结果")
		fmt.Println("=================================")

		for i, result := range results.Items {
			fmt.Printf("\n[%d] 检测结果\n", i+1)
			fmt.Printf("URL: %s\n", result.URL)
			fmt.Printf("方法: %s\n", result.Method)
			fmt.Printf("漏洞类型: %s\n", result.VulnerabilityType)
			fmt.Printf("Payload: %s\n", result.Payload)
			fmt.Printf("响应状态码: %d\n", result.StatusCode)
			fmt.Printf("响应时间: %.2f秒\n", result.ResponseTime)
			fmt.Printf("漏洞证据: %s\n", result.Evidence)
			if result.IsVulnerable {
				fmt.Printf("状态: [高危] 存在CSRF漏洞\n")
			} else {
				fmt.Printf("状态: 不存在CSRF漏洞\n")
			}
			fmt.Println("---------------------------------")
		}
	}

	if results.Summary.VulnerableTests > 0 {
		fmt.Println("\n[GYscan-CSRF] 建议")
		fmt.Println("=================================")
		fmt.Println("1. 为所有敏感操作添加有效的CSRF Token验证")
		fmt.Println("2. 正确配置Cookie的SameSite属性")
		fmt.Println("3. 实现Referer/Origin头的严格验证")
		fmt.Println("4. 对敏感操作添加二次验证机制")
	}
}
