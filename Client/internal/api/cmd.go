package api

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var ApiCmd = &cobra.Command{
	Use:   "api [目标URL] [help]",
	Short: "API端点抓取工具，从网页中提取隐藏的API节点",
	Args:  cobra.MaximumNArgs(1),
	Long: `GYscan API模块 - API端点抓取工具

支持功能:
- 从HTML页面中提取JavaScript文件
- 分析JavaScript代码中的API端点
- 识别常见API模式 (REST, GraphQL, Swagger等)
- 自动识别HTTP方法
- 并发扫描控制
- 结果去重和分类
- 网站爬取功能 (-c, --crawl) 推荐使用
- 浏览器自动化扫描 (-a, --autolook) 部分环境可能不兼容

用法:
  1. 直接传递目标URL: GYscan api 目标URL [选项]
  2. 使用--url标志: GYscan api --url 目标URL [选项]
  3. 获取帮助: GYscan api help

示例用法:
  ./GYscan api https://example.com
  ./GYscan api https://example.com -c -m 20
  ./GYscan api https://example.com -c -e
  ./GYscan api https://example.com -o result.txt`,
}

func init() {
	var (
		targetURL   string
		threads     int
		timeout     int
		output      string
		verbose     bool
		headers     []string
		testMode    bool
		crawl       bool
		maxPages    int
		autoLook    bool
		headless    bool
		waitTime    int
		browserPath string
		noSandbox   bool
		verifyAPI   bool
		proxy       string
	)

	ApiCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		if testMode {
			TestApiDetection()
			return
		}

		if len(args) > 0 && args[0] != "help" {
			targetURL = args[0]
		}

		if targetURL == "" {
			fmt.Println("请指定检测目标URL (直接传递URL参数或使用 --url 标志)")
			fmt.Println("用法: GYscan api 目标URL [选项] 或 GYscan api --url 目标URL [选项]")
			return
		}

		headerMap := make(map[string]string)
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		config := ApiConfig{
			TargetURL:     targetURL,
			Threads:       threads,
			Timeout:       time.Duration(timeout) * time.Second,
			Output:        output,
			Verbose:       verbose,
			IncludeParams: true,
			Headers:       headerMap,
			Crawl:         crawl,
			MaxPages:      maxPages,
			AutoLook:      autoLook,
			Headless:      headless,
			WaitTime:      time.Duration(waitTime) * time.Second,
			BrowserPath:   browserPath,
			NoSandbox:     noSandbox,
			VerifyAPI:     verifyAPI,
			Proxy:         proxy,
		}

		fmt.Printf("[GYscan-API] 开始扫描目标: %s\n", targetURL)
		fmt.Printf("[GYscan-API] 并发线程数: %d\n", threads)
		fmt.Printf("[GYscan-API] 超时时间: %d秒\n", timeout)
		if verifyAPI {
			fmt.Printf("[GYscan-API] API验证: 启用\n")
		}
		if autoLook {
			fmt.Printf("[GYscan-API] 浏览器自动化: 启用\n")
			if headless {
				fmt.Printf("[GYscan-API] 浏览器模式: 无头模式 (推荐用于爬取)\n")
			} else {
				fmt.Printf("[GYscan-API] 浏览器模式: 可视化模式 (适合观察单页)\n")
			}
			if browserPath != "" {
				fmt.Printf("[GYscan-API] 浏览器路径: %s\n", browserPath)
			}
			fmt.Printf("[GYscan-API] 等待渲染时间: %d秒\n", waitTime)
		} else if crawl {
			fmt.Printf("[GYscan-API] 启用网站爬取: 是 (最大页面数: %d)\n", maxPages)
		}

		var results *ApiResults

		if autoLook {
			results = RunBrowserApiScan(config)
		} else {
			results = RunApiScan(config)
		}

		if verifyAPI && len(results.Results) > 0 {
			VerifyApiEndpoints(results, config)
		}

		PrintApiResults(results)

		if output != "" {
			if err := saveResults(results, output); err != nil {
				fmt.Printf("保存结果失败: %v\n", err)
			} else {
				fmt.Printf("[GYscan-API] 结果已保存到: %s\n", output)
			}
		}
	}

	ApiCmd.Flags().StringVarP(&targetURL, "url", "u", "", "检测目标URL")
	ApiCmd.Flags().IntVarP(&threads, "threads", "n", 5, "并发线程数")
	ApiCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "请求超时时间(秒)")
	ApiCmd.Flags().StringVarP(&output, "output", "o", "", "结果输出文件")
	ApiCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "显示详细扫描过程")
	ApiCmd.Flags().StringArrayVarP(&headers, "header", "H", []string{}, "自定义请求头 (格式: Key:Value)")
	ApiCmd.Flags().BoolVarP(&testMode, "test", "T", false, "启用测试模式")
	ApiCmd.Flags().BoolVarP(&crawl, "crawl", "c", false, "启用网站爬取，自动遍历所有页面")
	ApiCmd.Flags().IntVarP(&maxPages, "max-pages", "m", 0, "爬取最大页面数 (0表示无限制)")
	ApiCmd.Flags().BoolVarP(&autoLook, "autolook", "a", false, "启用浏览器自动化扫描(模拟真实用户访问，部分环境可能不兼容)")
	ApiCmd.Flags().BoolVar(&headless, "headless", true, "无头模式运行浏览器")
	ApiCmd.Flags().IntVarP(&waitTime, "wait", "w", 2, "浏览器等待渲染时间(秒)")
	ApiCmd.Flags().StringVarP(&browserPath, "browser-path", "p", "", "指定浏览器可执行文件路径")
	ApiCmd.Flags().BoolVarP(&noSandbox, "no-sandbox", "s", false, "禁用沙箱模式(用于root用户)")
	ApiCmd.Flags().BoolVarP(&verifyAPI, "verify", "e", false, "验证发现的API端点是否可用")
	ApiCmd.Flags().StringVar(&proxy, "proxy", "", "代理服务器地址 (如: socks5://127.0.0.1:1080)")

	ApiCmd.AddCommand(&cobra.Command{
		Use:   "help",
		Short: "显示API模块详细帮助信息",
		Run: func(cmd *cobra.Command, args []string) {
			ApiHelp()
		},
	})
}

func ApiHelp() {
	helpText := `
GYscan API模块使用说明

基本用法:
  1. 直接传递目标URL: GYscan api 目标URL [选项]
  2. 使用--url标志: GYscan api --url 目标URL [选项]

常用选项:
  -u, --url:       检测目标URL
  -n, --threads:   并发线程数 (默认: 5)
  -t, --timeout:   请求超时时间(秒) (默认: 30)
  -o, --output:    结果输出文件
  -v, --verbose:   显示详细扫描过程
  -H, --header:    自定义请求头 (可多次使用)
  -T, --test:      启用测试模式
  -c, --crawl:     启用网站爬取，自动遍历所有页面
  -m, --max-pages: 爬取最大页面数 (0表示无限制)
  -a, --autolook:  启用浏览器自动化扫描(模拟真实用户访问)
  -H, --headless:  无头模式运行浏览器 (默认: true)
  -w, --wait:      浏览器等待渲染时间(秒) (默认: 2)

支持的功能:
  - API模式识别: /api/, /rest/, /graphql, /swagger 等
  - HTTP方法识别: GET, POST, PUT, DELETE, PATCH
  - 自动分类: 认证、用户、管理、数据、查询等
  - JavaScript分析: 提取JS文件中的API端点
  - 表单分析: 提取HTML表单中的API路径
  - 网站爬取: 自动遍历网站所有页面发现更多API

检测类别:
  - 认证: /auth, /login, /logout, /register, /token
  - 用户: /user, /profile, /account, /member
  - 管理: /admin, /manage, /dashboard
  - 数据: /data, /file, /upload, /download
  - 查询: /search, /query, /filter, /list
  - API: /api, /rest, /graphql, /rpc

示例:
  ./GYscan api https://example.com
  ./GYscan api https://example.com --threads 10 --verbose
  ./GYscan api https://example.com -o apis.txt
  ./GYscan api https://example.com -H "Cookie: session=xxx"
  ./GYscan api https://example.com -T
`
	fmt.Println(helpText)
}

func saveResults(results *ApiResults, output string) error {
	var sb strings.Builder

	sb.WriteString("GYscan API扫描结果\n")
	sb.WriteString("==================\n\n")
	sb.WriteString(fmt.Sprintf("总计发现API端点: %d\n", results.Summary.TotalAPIs))
	sb.WriteString(fmt.Sprintf("GET: %d | POST: %d | PUT: %d | DELETE: %d | PATCH: %d\n\n",
		results.Summary.GETCount, results.Summary.POSTCount, results.Summary.PUTCount,
		results.Summary.DELETECount, results.Summary.PATCHCount))

	sb.WriteString(fmt.Sprintf("发现的API端点数量: %d\n", len(results.Results)))
	sb.WriteString("发现的API端点:\n")
	sb.WriteString(fmt.Sprintf("%-10s %-80s %-15s %s\n", "Method", "Path", "Category", "Source"))
	sb.WriteString(strings.Repeat("-", 150) + "\n")

	for _, result := range results.Results {
		sb.WriteString(fmt.Sprintf("%-10s %-80s %-15s %s\n",
			result.Method, result.Path, result.Category, result.Source))
	}

	return os.WriteFile(output, []byte(sb.String()), 0644)
}
