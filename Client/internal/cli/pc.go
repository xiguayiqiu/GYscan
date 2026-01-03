package cli

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/patchcheck"
	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	aggressionLevel int
	userAgent       string
	httpHeaders     []string
	cookies         string
	proxy           string
	followRedirect  string
	maxRedirects    int
	pluginFilter    string
	grepPattern     string
	inputFile       string
	quietMode       bool
	noErrors        bool
)

var pcCmd = &cobra.Command{
	Use:   "pc",
	Short: "远程补丁探测工具，探测目标系统的中间层组件版本与补丁状态",
	Long: `pc命令 - 远程补丁探测工具

无需登录即可远程查询目标系统的中间层组件版本与补丁状态。
基于 WhatWeb 指纹识别技术，支持 1999+ 个 Web 指纹识别。

支持的组件类型:
  - Web服务器: Nginx, Apache, Tomcat, IIS
  - 数据库: MySQL, SQL Server, Oracle, PostgreSQL
  - 缓存/消息: Redis, Memcached, RabbitMQ
  - 中间件: WebLogic, JBoss, GlassFish
  - CMS系统: WordPress, Drupal, Joomla
  - JavaScript框架: React, Vue.js, jQuery

探测原理:
  - 响应头解析 (Server, X-Powered-By)
  - HTML内容指纹匹配
  - Cookie识别
  - 协议握手包分析
  - 默认端口指纹识别
  - 组件版本与官方漏洞库关联分析

侵略级别 (--aggression):
  1. Stealthy    - 每个目标发送一次HTTP请求，跟随重定向
  3. Aggressive  - 如果级别1插件匹配，发送额外请求
  4. Heavy       - 大量HTTP请求，尝试所有插件URL

示例用法:
  ./GYscan pc --target 192.168.1.100
  ./GYscan pc -t 192.168.1.100 -p 80,443,8080
  ./GYscan pc -t 192.168.1.100 --timeout 5 -o results.json
  ./GYscan pc -l  查看所有支持的指纹
  ./GYscan pc -t example.com -a 3  侵略性扫描
  ./GYscan pc -t example.com --grep nginx  搜索nginx相关结果
  ./GYscan pc -i targets.txt  从文件读取目标列表`,
	Run: func(cmd *cobra.Command, args []string) {
		listFingerprints, _ := cmd.Flags().GetBool("list")
		if listFingerprints {
			showFingerprintList()
			return
		}

		target, _ := cmd.Flags().GetString("target")
		portsStr, _ := cmd.Flags().GetString("ports")
		timeout, _ := cmd.Flags().GetInt("timeout")
		output, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")
		allPorts, _ := cmd.Flags().GetBool("all")

		if target == "" && inputFile == "" {
			utils.ErrorPrint("错误: 必须指定目标(--target 或 -t) 或输入文件(-i/--input-file)")
			cmd.Help()
			return
		}

		utils.SuccessPrint("[+] 远程补丁探测工具启动")
		if target != "" {
			utils.InfoPrint("[*] 目标: %s", target)
		}
		if inputFile != "" {
			utils.InfoPrint("[*] 输入文件: %s", inputFile)
		}
		utils.InfoPrint("[*] 超时时间: %d秒", timeout)
		utils.InfoPrint("[*] 侵略级别: %d", aggressionLevel)
		if userAgent != "" {
			utils.InfoPrint("[*] User-Agent: %s", userAgent)
		}
		if proxy != "" {
			utils.InfoPrint("[*] 代理: %s", proxy)
		}
		if followRedirect != "" {
			utils.InfoPrint("[*] 重定向策略: %s", followRedirect)
		}
		if verbose {
			utils.InfoPrint("[*] 详细输出模式: 启用")
		}
		utils.InfoPrint("")

		var targets []string
		if inputFile != "" {
			targets = loadTargetsFromFile(inputFile)
			if len(targets) == 0 {
				utils.ErrorPrint("错误: 无法读取目标文件或文件为空")
				return
			}
			utils.InfoPrint("[*] 从文件加载 %d 个目标", len(targets))
		} else {
			targets = []string{target}
		}

		var ports []int
		if allPorts {
			ports = getDefaultPorts()
			utils.InfoPrint("[*] 使用全端口扫描模式")
		} else if portsStr != "" {
			ports = parsePorts(portsStr)
			utils.InfoPrint("[*] 扫描端口: %s", portsStr)
		} else {
			ports = []int{80, 443, 8080, 7001, 3306, 5432, 6379}
			utils.InfoPrint("[*] 使用默认端口列表")
		}

		threads, _ := cmd.Flags().GetInt("threads")
		rate, _ := cmd.Flags().GetInt("rate")
		utils.InfoPrint("[*] 并发线程数: %d", threads)
		utils.InfoPrint("[*] 速率限制: %d/秒", rate)
		utils.InfoPrint("")

		parseHTTPHeaders()

		scanner := patchcheck.NewScannerWithOptions(
			time.Duration(timeout)*time.Second,
			verbose,
			threads,
			rate,
			aggressionLevel,
			userAgent,
			httpHeaders,
			cookies,
			proxy,
			followRedirect,
			maxRedirects,
		)

		var allComponents []patchcheck.ComponentInfo

		for _, t := range targets {
			utils.InfoPrint("[*] 扫描目标: %s", t)
			startTime := time.Now()

			components := scanner.ScanTarget(t, ports)

			duration := time.Since(startTime)
			utils.InfoPrint("[*] 扫描完成，耗时: %v", duration)

			if len(components) == 0 {
				if !quietMode {
					utils.WarningPrint("[-] 未发现任何中间层组件")
				}
				if !noErrors {
					utils.InfoPrint("提示: 目标系统可能未开放常用端口，或需要使用全端口扫描(--all)")
				}
				continue
			}

			utils.SuccessPrint("[+] 发现 %d 个中间层组件", len(components))
			utils.InfoPrint("")

			if grepPattern != "" {
				components = filterByGrep(components, grepPattern)
				utils.InfoPrint("[*] grep过滤后: %d 个组件", len(components))
			}

			printResults(t, components)
			allComponents = append(allComponents, components...)
		}

		if len(allComponents) == 0 {
			utils.WarningPrint("[-] 所有目标均未发现中间层组件")
			return
		}

		if output != "" {
			saveResults(allComponents, output, targets)
			utils.SuccessPrint("[+] 结果已保存到: %s", output)
		}

		if pluginFilter != "" {
			utils.InfoPrint("[*] 插件过滤: %s", pluginFilter)
		}

		summary := generateSummary(allComponents)
		utils.InfoPrint("\n" + strings.Repeat("=", 60))
		utils.BoldInfo("补丁状态汇总")
		utils.InfoPrint(strings.Repeat("=", 60))
		fmt.Println(summary)
	},
}

func init() {
	pcCmd.Flags().StringP("target", "t", "", "目标主机IP或域名 (必需，除非使用-i指定文件)")
	pcCmd.Flags().StringP("ports", "p", "", "扫描端口 (默认: 80,443,8080,7001,3306,5432,6379)")
	pcCmd.Flags().Int("timeout", 3, "连接超时时间(秒)")
	pcCmd.Flags().StringP("output", "o", "", "结果输出文件 (JSON格式)")
	pcCmd.Flags().Bool("verbose", false, "详细输出模式")
	pcCmd.Flags().Bool("all", false, "全端口扫描模式")
	pcCmd.Flags().BoolP("list", "l", false, "显示所有支持的指纹列表")
	pcCmd.Flags().Int("threads", 10, "并发扫描线程数")
	pcCmd.Flags().Int("rate", 100, "每秒扫描速率限制")

	pcCmd.Flags().IntVarP(&aggressionLevel, "aggression", "a", 1, "侵略级别: 1=Stealthy, 3=Aggressive, 4=Heavy")
	pcCmd.Flags().StringVarP(&userAgent, "user-agent", "U", "", "HTTP User-Agent头 (默认: GYscan/v2.7)")
	pcCmd.Flags().StringArrayVarP(&httpHeaders, "header", "H", []string{}, "添加HTTP头, 如 -H 'Foo:Bar'")
	pcCmd.Flags().StringVarP(&cookies, "cookie", "c", "", "HTTP Cookies, 如 'name=value; name2=value2'")
	pcCmd.Flags().StringVarP(&proxy, "proxy", "", "", "代理服务器 <hostname:port>")
	pcCmd.Flags().StringVarP(&followRedirect, "follow-redirect", "", "", "重定向策略: never, http-only, same-site, always (默认: always)")
	pcCmd.Flags().IntVarP(&maxRedirects, "max-redirects", "", 10, "最大重定向次数")
	pcCmd.Flags().StringVarP(&pluginFilter, "plugins", "", "", "插件过滤: +启用, -禁用, 如 'nginx,+apache,-tomcat'")
	pcCmd.Flags().StringVarP(&grepPattern, "grep", "g", "", "搜索匹配的结果 (支持正则表达式)")
	pcCmd.Flags().StringVarP(&inputFile, "input-file", "i", "", "从文件读取目标列表 (每行一个目标)")
	pcCmd.Flags().BoolVar(&quietMode, "quiet", false, "安静模式，减少输出")
	pcCmd.Flags().BoolVar(&noErrors, "no-errors", false, "不显示错误信息")

	pcCmd.Flags().SetInterspersed(true)
}

func getDefaultPorts() []int {
	return []int{
		80, 443, 8080, 8009, 7001, 7002,
		3306, 1433, 1521, 5432,
		6379, 11211, 5672, 15672,
	}
}

func parsePorts(portsStr string) []int {
	var ports []int

	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else if num, err := strconv.Atoi(part); err == nil {
			ports = append(ports, num)
		}
	}

	return ports
}

func printResults(target string, components []patchcheck.ComponentInfo) {
	colorHiBlue := color.New(color.FgHiBlue)
	colorHiYellow := color.New(color.FgHiYellow)
	colorHiRed := color.New(color.FgHiRed)
	colorHiGreen := color.New(color.FgHiGreen)
	colorCyan := color.New(color.FgCyan)
	colorMagenta := color.New(color.FgMagenta)

	sort.Slice(components, func(i, j int) bool {
		return components[i].Type < components[j].Type
	})

	for _, comp := range components {
		fmt.Println("")
		colorHiBlue.Println(strings.Repeat("=", 60))
		scheme := "http"
		if comp.Protocol == "https" || comp.Port == 443 {
			scheme = "https"
		}
		hostname := extractHostname(target)
		portStr := ""
		if comp.Port != 80 && comp.Port != 443 {
			portStr = fmt.Sprintf(":%d", comp.Port)
		}
		colorHiBlue.Printf("GYscan Report for %s://%s%s/\n", scheme, hostname, portStr)
		colorHiBlue.Println(strings.Repeat("=", 60))

		colorCyan.Printf("Status    : %s\n", getStatusDescription(comp))
		if comp.HTMLTitle != "" {
			colorCyan.Printf("Title     : %s\n", truncateString(comp.HTMLTitle, 60))
		}

		if redirectURL := getHeader(comp.Headers, "Location"); redirectURL != "" {
			colorCyan.Printf("Redirect  : %s\n", redirectURL)
		}

		fmt.Println("")
		colorHiYellow.Println("Summary   :")
		summary := buildSummary(comp)
		for _, line := range strings.Split(summary, "\n") {
			if line != "" {
				colorHiYellow.Printf("  %s\n", truncateString(line, 55))
			}
		}

		fmt.Println("")
		colorHiBlue.Println("Detected Fingerprints:")
		colorHiBlue.Println(strings.Repeat("-", 40))

		for _, fp := range comp.Fingerprints {
			printFingerprintDetail(fp, colorHiBlue, colorHiYellow, colorCyan, colorMagenta, colorHiGreen)
		}

		fmt.Println("")
		colorCyan.Println("HTTP Headers:")
		colorCyan.Println(strings.Repeat("-", 40))
		printHTTPHeaders(comp.Headers, colorCyan)

		if len(comp.Technologies) > 0 {
			fmt.Println("")
			colorHiGreen.Println("Technology Stack:")
			colorHiGreen.Println(strings.Repeat("-", 40))
			for _, tech := range comp.Technologies {
				colorHiGreen.Printf("  * %s\n", tech)
			}
		}

		fmt.Println("")
		colorCyan.Println("Patch Status:")
		colorCyan.Println(strings.Repeat("-", 40))
		printPatchStatus(comp, colorHiRed, colorHiYellow, colorHiGreen, colorHiYellow)

		fmt.Println("")
	}
}

func getStatusDescription(comp patchcheck.ComponentInfo) string {
	switch comp.Type {
	case "webserver":
		if comp.Version != "" {
			return fmt.Sprintf("%s [%s]", comp.Name, comp.Version)
		}
		return comp.Name
	default:
		return fmt.Sprintf("%s %s", comp.Name, comp.Version)
	}
}

func buildSummary(comp patchcheck.ComponentInfo) string {
	seen := make(map[string]bool)
	var items []string

	for _, fp := range comp.Fingerprints {
		if seen[fp.Name] {
			continue
		}
		seen[fp.Name] = true

		if fp.Category == "Web Server" || fp.Category == "Application Server" {
			if comp.Version != "" {
				items = append(items, fmt.Sprintf("%s[%s]", fp.Name, comp.Version))
			} else {
				items = append(items, fp.Name)
			}
		} else if fp.Category == "Search Engine" {
			items = append(items, fp.Name)
		} else if fp.Category == "JavaScript Library" {
			items = append(items, fp.Name)
		} else if fp.Category == "JavaScript Framework" {
			items = append(items, fp.Name)
		} else if fp.Category == "JavaScript Template" {
			items = append(items, fp.Name)
		} else if fp.Category == "Web Technology" {
			items = append(items, fp.Name)
		} else if fp.Category == "Security Header" {
			items = append(items, fp.Name)
		} else if fp.Category == "Scripting Language" {
			items = append(items, fp.Name)
		} else if fp.Category == "Web Framework" {
			items = append(items, fp.Name)
		} else if fp.Category == "CSS Framework" {
			items = append(items, fp.Name)
		} else if fp.Category == "CMS" {
			items = append(items, fp.Name)
		} else if fp.Category == "Forum" {
			items = append(items, fp.Name)
		} else if fp.Category == "E-Commerce" {
			items = append(items, fp.Name)
		} else if fp.Category == "CDN" || fp.Category == "CDN/WAF" {
			items = append(items, fp.Name)
		} else if fp.Category == "Runtime Environment" {
			items = append(items, fp.Name)
		} else if fp.Category == "Proxy Header" {
			items = append(items, fp.Name)
		} else if fp.Category == "Analytics" {
			items = append(items, fp.Name)
		} else if fp.Category == "Code Editor" {
			items = append(items, fp.Name)
		} else if fp.Category == "Rich Text Editor" {
			items = append(items, fp.Name)
		} else if fp.Category == "DevOps" {
			items = append(items, fp.Name)
		} else if fp.Category == "EdTech" {
			items = append(items, fp.Name)
		} else if fp.Category == "Gaming" {
			items = append(items, fp.Name)
		} else if fp.Category == "Developer Tools" {
			items = append(items, fp.Name)
		} else if fp.Category == "Infrastructure" {
			items = append(items, fp.Name)
		} else if fp.Category == "Mobile" {
			items = append(items, fp.Name)
		} else if fp.Category == "Protocol" {
			items = append(items, fp.Name)
		}
	}

	cookies := extractCookies(comp.Headers)
	if len(cookies) > 0 {
		items = append(items, fmt.Sprintf("Cookies[%s]", strings.Join(cookies, ",")))
	}

	if redirectURL := getHeader(comp.Headers, "Location"); redirectURL != "" {
		items = append(items, fmt.Sprintf("RedirectLocation[%s]", truncateString(redirectURL, 30)))
	}

	return strings.Join(items, ", ")
}

func extractCookies(headers map[string]string) []string {
	var cookies []string
	if cookie, ok := headers["Set-Cookie"]; ok {
		parts := strings.Split(cookie, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "BDID") || strings.HasPrefix(part, "BAID") ||
				strings.HasPrefix(part, "BIDUP") || strings.HasPrefix(part, "PSTM") ||
				strings.HasPrefix(part, "BDSVRTM") || strings.HasPrefix(part, "BD_HOME") {
				name := strings.Split(part, "=")[0]
				if name != "" && !contains(cookies, name) {
					cookies = append(cookies, name)
				}
			}
		}
	}
	return cookies
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getHeader(headers map[string]string, key string) string {
	if v, ok := headers[key]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func printFingerprintDetail(fp patchcheck.Fingerprint, colorHiBlue, colorHiYellow, colorCyan, colorMagenta, colorHiGreen *color.Color) {
	switch fp.Category {
	case "Web Server", "Application Server":
		colorHiBlue.Printf("[%s]\n", fp.Category)
		colorHiBlue.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Scripting Language", "Runtime Environment", "Web Framework":
		colorCyan.Printf("[%s]\n", fp.Category)
		colorCyan.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "JavaScript Framework", "JavaScript Library", "JavaScript Template", "CSS Framework":
		colorMagenta.Printf("[%s]\n", fp.Category)
		colorMagenta.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "CMS":
		colorHiYellow.Printf("[%s]\n", fp.Category)
		colorHiYellow.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "CDN", "CDN/WAF":
		colorHiGreen.Printf("[%s]\n", fp.Category)
		colorHiGreen.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Search Engine":
		colorHiBlue.Printf("[%s]\n", fp.Category)
		colorHiBlue.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Forum":
		colorMagenta.Printf("[%s]\n", fp.Category)
		colorMagenta.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "E-Commerce":
		colorHiYellow.Printf("[%s]\n", fp.Category)
		colorHiYellow.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Analytics":
		colorHiGreen.Printf("[%s]\n", fp.Category)
		colorHiGreen.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Proxy Header":
		colorCyan.Printf("[%s]\n", fp.Category)
		colorCyan.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Web Technology":
		colorCyan.Printf("[%s]\n", fp.Category)
		colorCyan.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	case "Security Header":
		colorHiGreen.Printf("[%s]\n", fp.Category)
		colorHiGreen.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	default:
		colorCyan.Printf("[%s]\n", fp.Category)
		colorCyan.Printf("  %s", fp.Name)
		if fp.Confidence < 100 {
			colorHiYellow.Printf(" [%d%%]", fp.Confidence)
		}
		fmt.Println("")
	}

	colorHiYellow.Printf("  %s\n", fp.Description)
	fmt.Println("")
}

func printHTTPHeaders(headers map[string]string, colorCyan *color.Color) {
	for k, v := range headers {
		key := strings.Title(strings.ToLower(k))
		colorCyan.Printf("  %-20s: %s\n", key, truncateString(v, 60))
	}
}

func printPatchStatus(comp patchcheck.ComponentInfo, colorHiRed, colorHiYellow, colorHiGreen, colorCyan *color.Color) {
	switch comp.PatchStatus.RiskLevel {
	case "Critical":
		colorHiRed.Printf("  Status: Unpatched [Risk: %s]\n", comp.PatchStatus.RiskLevel)
	case "High":
		colorHiRed.Printf("  Status: Unpatched [Risk: %s]\n", comp.PatchStatus.RiskLevel)
	case "Medium":
		colorHiYellow.Printf("  Status: Partially Patched [Risk: %s]\n", comp.PatchStatus.RiskLevel)
	case "Low":
		colorHiGreen.Printf("  Status: Patched [Risk: %s]\n", comp.PatchStatus.RiskLevel)
	}

	if len(comp.Vulnerabilities) > 0 {
		colorHiRed.Printf("\n  Found %d unpatched vulnerabilities:\n", len(comp.Vulnerabilities))
		for _, vuln := range comp.Vulnerabilities {
			colorHiRed.Printf("    - %s (%s) [%s]\n", vuln.Name, vuln.CVE, vuln.Severity)
			colorHiYellow.Printf("      Affected: %s\n", vuln.Description)
			colorHiGreen.Printf("      Fixed in: %s\n", vuln.FixedVersion)
		}
	} else {
		colorHiGreen.Printf("  No known vulnerabilities for current version\n")
	}

	if len(comp.PatchStatus.Recommendations) > 0 {
		fmt.Println("\n  Recommendations:")
		for _, rec := range comp.PatchStatus.Recommendations {
			colorHiYellow.Printf("    * %s\n", rec)
		}
	}
}

func generateSummary(components []patchcheck.ComponentInfo) string {
	var sb strings.Builder

	totalCount := len(components)
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	totalVulns := 0
	totalFingerprints := 0

	uniqueFingerprints := make(map[string]bool)
	for _, comp := range components {
		for _, fp := range comp.Fingerprints {
			if !uniqueFingerprints[fp.Name] {
				uniqueFingerprints[fp.Name] = true
				totalFingerprints++
			}
		}

		switch comp.PatchStatus.RiskLevel {
		case "Critical":
			criticalCount++
		case "High":
			highCount++
		case "Medium":
			mediumCount++
		case "Low":
			lowCount++
		}
		totalVulns += len(comp.Vulnerabilities)
	}

	sb.WriteString(fmt.Sprintf("  总计检测指纹: %d 个\n", totalFingerprints))
	sb.WriteString(fmt.Sprintf("  扫描端口数: %d 个\n", totalCount))
	sb.WriteString(fmt.Sprintf("  高危风险组件: %d 个\n", criticalCount+highCount))
	sb.WriteString(fmt.Sprintf("  中危风险组件: %d 个\n", mediumCount))
	sb.WriteString(fmt.Sprintf("  低危风险组件: %d 个\n", lowCount))
	sb.WriteString(fmt.Sprintf("  发现漏洞总数: %d 个\n", totalVulns))
	sb.WriteString("\n  风险分布:\n")

	if criticalCount > 0 {
		sb.WriteString(fmt.Sprintf("    🔴 Critical: %d 个\n", criticalCount))
	}
	if highCount > 0 {
		sb.WriteString(fmt.Sprintf("    🟠 High: %d 个\n", highCount))
	}
	if mediumCount > 0 {
		sb.WriteString(fmt.Sprintf("    🟡 Medium: %d 个\n", mediumCount))
	}
	if lowCount > 0 {
		sb.WriteString(fmt.Sprintf("    🟢 Low: %d 个\n", lowCount))
	}

	return sb.String()
}

func saveResults(components []patchcheck.ComponentInfo, filename string, targets []string) {
	var result struct {
		ScanTime   string                     `json:"scan_time"`
		Targets    []string                   `json:"targets"`
		Components []patchcheck.ComponentInfo `json:"components"`
		Summary    string                     `json:"summary"`
	}

	result.ScanTime = time.Now().Format("2006-01-02 15:04:05")
	result.Targets = targets
	result.Components = components
	result.Summary = generateSummary(components)

	utils.SaveJSON(filename, result)
}

func showFingerprintList() {
	patchcheck.AddWhatWebFingerprintsToDB()
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	utils.BoldInfo("GYscan Fingerprint List")
	utils.InfoPrint("WhatWeb Fingerprint Database")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	fingerprints := patchcheck.FingerprintDB

	categories := make(map[string][]string)
	for _, fp := range fingerprints {
		categories[fp.Category] = append(categories[fp.Category], fp.Name)
	}

	var categoryNames []string
	for name := range categories {
		categoryNames = append(categoryNames, name)
	}
	sort.Strings(categoryNames)

	totalCount := 0
	for _, category := range categoryNames {
		names := categories[category]
		sort.Strings(names)
		count := len(names)
		totalCount += count

		utils.BoldInfo("[%s] (%d)", category, count)
		fmt.Println(strings.Repeat("-", 60))
		for i, name := range names {
			num := fmt.Sprintf("%d.", i+1)
			spaces := 4 - len(num)
			fmt.Printf("  %s%s%s", num, strings.Repeat(" ", spaces), name)
			if (i+1)%3 == 0 {
				fmt.Println()
			} else if i != len(names)-1 {
				fmt.Print("  ")
			}
		}
		fmt.Println()
		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 80))
	utils.SuccessPrint("总计: %d 个指纹, %d 个分类", totalCount, len(categories))
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()
	fmt.Println("使用方式:")
	fmt.Println("  ./GYscan pc -l              显示所有指纹")
	fmt.Println("  ./GYscan pc -l | grep nginx  搜索特定指纹")
	fmt.Println("  ./GYscan pc -t example.com  开始扫描")
}

func loadTargetsFromFile(filename string) []string {
	var targets []string

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return targets
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}

	return targets
}

func parseHTTPHeaders() {
	for i, h := range httpHeaders {
		if strings.Contains(h, ":") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				httpHeaders[i] = strings.TrimSpace(parts[0]) + ": " + strings.TrimSpace(parts[1])
			}
		}
	}
}

func filterByGrep(components []patchcheck.ComponentInfo, pattern string) []patchcheck.ComponentInfo {
	var filtered []patchcheck.ComponentInfo

	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(pattern))
	}

	for _, comp := range components {
		match := false

		if re.MatchString(comp.Name) {
			match = true
		}
		if re.MatchString(comp.Version) {
			match = true
		}
		if re.MatchString(string(comp.Type)) {
			match = true
		}

		for _, fp := range comp.Fingerprints {
			if re.MatchString(fp.Name) || re.MatchString(fp.Category) {
				match = true
				break
			}
		}

		for _, tech := range comp.Technologies {
			if re.MatchString(tech) {
				match = true
				break
			}
		}

		for k, v := range comp.Headers {
			if re.MatchString(k) || re.MatchString(v) {
				match = true
				break
			}
		}

		if match {
			filtered = append(filtered, comp)
		}
	}

	return filtered
}

func extractHostname(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	slashIdx := strings.Index(url, "/")
	colonIdx := strings.Index(url, ":")
	if colonIdx > 0 && (slashIdx < 0 || colonIdx < slashIdx) {
		return url[:colonIdx]
	}
	if slashIdx > 0 {
		return url[:slashIdx]
	}
	return url
}
