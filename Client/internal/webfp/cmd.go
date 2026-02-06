package webfp

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var WebfpCmd = &cobra.Command{
	Use:   "webfp [目标URL] [flags]",
	Short: "网站技术指纹识别工具",
	Long: `GYscan WebFP模块 - 网站技术指纹识别工具

基于HTTP响应头、HTML内容、资源文件路径等多维度识别网站使用的技术栈。

支持识别:
- Web服务器 (Nginx, Apache, IIS, LiteSpeed)
- 编程语言 (PHP, Node.js, Python, Ruby)
- Web框架 (Laravel, Django, Express, Rails)
- 前端框架 (React, Vue, Angular, Next.js)
- CMS系统 (WordPress, Drupal, Joomla)
- JavaScript库 (jQuery, Lodash)
- UI框架 (Bootstrap, Tailwind CSS)
- CDN与安全服务 (Cloudflare)

用法:
  1. 直接传递目标URL: GYscan webfp 目标URL [选项]
  2. 使用--url标志: GYscan webfp --url 目标URL [选项]
  3. 获取帮助: GYscan webfp help

示例:
  ./GYscan webfp https://example.com
  ./GYscan webfp https://example.com -v
  ./GYscan webfp https://example.com -o json
  ./GYscan webfp https://example.com -t 30s`,
}

func init() {
	var (
		targetURL  string
		timeout    time.Duration
		verbose    bool
		output     string
		userAgent  string
		noRedirect bool
		category   string
	)

	WebfpCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		if len(args) > 0 && args[0] != "help" {
			targetURL = args[0]
		}

		if targetURL == "" {
			fmt.Println("请指定目标URL (直接传递URL参数或使用 --url 标志)")
			fmt.Println("用法: GYscan webfp 目标URL [选项] 或 GYscan webfp --url 目标URL [选项]")
			return
		}

		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "https://" + targetURL
		}

		config := WebfpConfig{
			URL:         targetURL,
			Timeout:     timeout,
			Verbose:     verbose,
			Output:      output,
			UserAgent:   userAgent,
			NoRedirect:  noRedirect,
			MaxBodySize: 512 * 1024,
		}

		utils.LogBanner("开始网站技术指纹识别")
		utils.LogInfo("目标: %s", targetURL)

		result := RunWebfpScan(config, category)

		PrintResults(result, verbose, category)

		if output != "" {
			if err := SaveResults(result, output); err != nil {
				utils.LogError("保存结果失败: %v", err)
			} else {
				utils.LogSuccess("结果已保存到: %s", output)
			}
		}
	}

	WebfpCmd.Flags().StringVarP(&targetURL, "url", "u", "", "目标URL")
	WebfpCmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "请求超时时间")
	WebfpCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "显示详细输出")
	WebfpCmd.Flags().StringVarP(&output, "output", "o", "", "结果输出文件 (JSON格式)")
	WebfpCmd.Flags().StringVarP(&userAgent, "user-agent", "U", GetDefaultUserAgent(), "自定义User-Agent")
	WebfpCmd.Flags().BoolVarP(&noRedirect, "no-redirect", "n", false, "禁止重定向")
	WebfpCmd.Flags().StringVarP(&category, "category", "c", "", "只显示指定类别的结果")

	WebfpCmd.AddCommand(&cobra.Command{
		Use:   "help",
		Short: "显示webfp模块详细帮助信息",
		Run: func(cmd *cobra.Command, args []string) {
			WebfpHelp()
		},
	})
}

func RunWebfpScan(config WebfpConfig, categoryFilter string) WebfpResult {
	result := WebfpResult{
		URL:     config.URL,
		Headers: make(map[string]string),
	}

	httpClient := NewHTTPClient(&config)

	response, err := httpClient.Fetch(config.URL)
	if err != nil {
		result.Error = err.Error()
		utils.LogError("请求失败: %v", err)
		return result
	}

	result.StatusCode = response.StatusCode
	result.Headers = response.Headers
	result.Server = response.GetServer()
	result.ResponseTime = response.ResponseTime

	if config.Verbose {
		utils.LogDebug("状态码: %d", result.StatusCode)
		utils.LogDebug("服务器: %s", result.Server)
	}

	if !response.IsHTML() && !response.IsJSON() {
		utils.LogWarning("响应类型不是HTML或JSON，可能无法进行完整识别")
	}

	parser, err := NewHTMLParser(response.Body)
	if err != nil {
		utils.LogWarning("HTML解析失败: %v", err)
	} else {
		if config.Verbose {
			utils.LogDebug("HTML解析成功")
		}
	}

	ctx := &DetectionContext{
		Headers: response.Headers,
		Body:    response.Body,
		Scripts: parser.ExtractScripts(),
		CSS:     parser.ExtractCSS(),
		Meta:    parser.ExtractMetaTags(),
		Cookies: response.ExtractCookies(),
	}

	frameworkIndicators := ExtractFrameworkIndicators(response.Body)
	if len(frameworkIndicators) > 0 && config.Verbose {
		utils.LogDebug("检测到框架特征: %v", frameworkIndicators)
	}

	engine, err := NewFingerprintEngine()
	if err != nil {
		utils.LogError("初始化指纹引擎失败: %v", err)
		result.Error = err.Error()
		return result
	}

	if config.Verbose {
		utils.LogDebug("指纹规则总数: %d", engine.GetTotalRules())
	}

	technologies := engine.Detect(ctx)

	if categoryFilter != "" {
		var filtered []Technology
		for _, tech := range technologies {
			if tech.Category == categoryFilter {
				filtered = append(filtered, tech)
			}
		}
		technologies = filtered
	}

	result.Technologies = technologies

	return result
}

func PrintResults(result WebfpResult, verbose bool, categoryFilter string) {
	fmt.Println()
	utils.LogBanner("识别结果")
	fmt.Printf("目标: %s\n", result.URL)
	fmt.Printf("状态码: %d\n", result.StatusCode)
	fmt.Printf("响应时间: %v\n", result.ResponseTime)

	if result.Server != "" {
		fmt.Printf("服务器: %s\n", result.Server)
	}

	fmt.Println()
	fmt.Println("识别到的技术栈:")
	fmt.Println(strings.Repeat("=", 60))

	if len(result.Technologies) == 0 {
		fmt.Println("未识别到任何技术栈")
		if verbose {
			fmt.Println("\n可能原因:")
			fmt.Println("1. 网站返回了非HTML内容")
			fmt.Println("2. 技术栈未被当前规则覆盖")
			fmt.Println("3. 需要使用 -v 标志查看详细输出")
		}
	} else {
		categories := make(map[string][]Technology)
		for _, tech := range result.Technologies {
			categories[tech.Category] = append(categories[tech.Category], tech)
		}

		for cat, techs := range categories {
			fmt.Printf("\n[%s]\n", cat)
			for _, tech := range techs {
				versionInfo := ""
				if tech.Version != "" {
					versionInfo = fmt.Sprintf(" (v%s)", tech.Version)
				}
				confidence := int(tech.Confidence)
				confidenceStr := ""
				if confidence >= 80 {
					confidenceStr = " [高置信度]"
				} else if confidence >= 50 {
					confidenceStr = " [中置信度]"
				} else {
					confidenceStr = " [低置信度]"
				}
				fmt.Printf("  - %s%s%s\n", tech.Name, versionInfo, confidenceStr)
				if verbose && len(tech.DetectedBy) > 0 {
					fmt.Printf("    检测依据: %v\n", tech.DetectedBy)
				}
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("总计识别: %d 个技术组件\n", len(result.Technologies))

	if result.Error != "" {
		fmt.Printf("\n警告: %s\n", result.Error)
	}
}

func SaveResults(result WebfpResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func WebfpHelp() {
	helpText := `
GYscan WebFP模块使用说明

基本用法:
  1. 直接传递目标URL: GYscan webfp 目标URL [选项]
  2. 使用--url标志: GYscan webfp --url 目标URL [选项]

识别范围:
  - Web服务器: Nginx, Apache, Microsoft IIS, LiteSpeed, Caddy
  - 前端框架: React, Vue.js, Angular, Svelte, SolidJS, Qwik
  - 元框架: Next.js, Nuxt.js, SvelteKit, Gatsby
  - 后端框架: Express, NestJS, Fastify, Django, Flask, FastAPI
  - 后端框架: Spring Boot, Quarkus, Gin, Echo, Fiber, Laravel, Symfony
  - CMS系统: WordPress, Drupal, Joomla, Shopify, Wix, Squarespace
  - 静态站点: Hugo, Jekyll, Docusaurus, Hexo, Eleventy
  - UI框架: Bootstrap, Tailwind CSS, Bulma, Ant Design, Element Plus, Vuetify
  - JavaScript库: jQuery, Lodash, Underscore, Axios, Moment.js, Chart.js
  - 状态管理: Redux, Pinia, Zustand, MobX, Recoil
  - 构建工具: Webpack, Vite, esbuild, Babel, TypeScript
  - CDN与安全: Cloudflare, Akamai, Fastly
  - 托管平台: Vercel, Netlify, AWS Amplify
  - 分析工具: Google Analytics, Hotjar, Meta Pixel, Matomo
  - 认证服务: Auth0, Firebase, Okta, NextAuth, Supabase
  - 支付服务: Stripe, PayPal

命令行选项:
  -u, --url:        目标URL
  -t, --timeout:   请求超时时间 (默认10秒)
  -v, --verbose:   显示详细输出
  -o, --output:    结果输出文件 (JSON格式)
  -U, --user-agent: 自定义User-Agent
  -n, --no-redirect: 禁止重定向
  -c, --category:   只显示指定类别

输出格式:
  默认以简洁文本格式输出
  使用 -o json 可输出JSON格式供其他工具解析

示例:
  ./GYscan webfp https://example.com
  ./GYscan webfp https://example.com -v
  ./GYscan webfp https://example.com -o result.json
  ./GYscan webfp https://example.com -c "Frontend Frameworks"
  ./GYscan webfp https://example.com -t 30s

注意事项:
  1. 识别结果基于特征匹配，可能存在误报或漏报
  2. 某些技术可能无法通过被动方式识别
  3. 建议结合其他侦察工具使用以获得更完整的信息
`
	fmt.Println(helpText)
}
