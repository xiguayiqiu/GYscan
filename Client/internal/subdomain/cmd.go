package subdomain

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"GYscan/internal/utils"
)

var SubCmd = &cobra.Command{
	Use:   "sub [目标域名] [help]",
	Short: "子域名挖掘工具，支持字典爆破和DNS查询",
	Long: `GYscan Subdomain模块 - 子域名挖掘工具

支持功能:
- 字典爆破 (基于DNS查询)
- DNS记录查询 (A/CNAME/MX/TXT/NS)
- 并发扫描 (支持高并发)
- 自动通配符检测和过滤
- 实时进度显示

用法:
  1. 直接传递目标: GYscan sub 目标域名 [选项]
  2. 使用--domain标志: GYscan sub --domain 目标域名 [选项]
  3. 获取帮助: GYscan sub help

示例用法:
  ./GYscan sub example.com
  ./GYscan sub example.com -w subdomains.txt
  ./GYscan sub example.com -w subdomains.txt -t 100
  ./GYscan sub example.com -T CNAME`,
}

func init() {
	var (
		domain       string
		wordlist     string
		threads      int
		timeout      int
		output       string
		queryType    string
		verifyHTTP   bool
		noVerifyHTTP bool
	)

	SubCmd.Run = func(cmd *cobra.Command, args []string) {
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		if len(args) > 0 {
			domain = args[0]
		}

		if domain == "" {
			fmt.Println("请指定目标域名 (直接传递目标参数或使用 --domain 标志)")
			fmt.Println("用法: GYscan sub 目标域名 [选项] 或 GYscan sub --domain 目标域名 [选项]")
			return
		}

		domain = strings.ToLower(domain)
		if !IsValidDomain(domain) {
			fmt.Printf("域名格式无效: %s\n", domain)
			fmt.Println("支持格式: example.com, sub.example.com")
			return
		}

		config := SubdomainConfig{
			Domain:     domain,
			Wordlist:   wordlist,
			Threads:    threads,
			Timeout:    time.Duration(timeout) * time.Second,
			Output:     output,
			QueryType:  queryType,
			VerifyHTTP: verifyHTTP && !noVerifyHTTP,
		}

		utils.InfoPrint("[GYscan-Subdomain] 开始扫描目标: %s", domain)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		resultChan := make(chan []SubdomainResult, 1)

		go func() {
			results := SubdomainScan(ctx, config)
			resultChan <- results
		}()

		select {
		case results := <-resultChan:
			duration := time.Since(getStartTime())
			utils.InfoPrint("\n已发现的子域名:")
			for _, result := range results {
				var coloredStatus string
				if result.HTTPStatus > 0 {
					switch {
					case result.HTTPStatus >= 200 && result.HTTPStatus < 300:
						coloredStatus = utils.Success("%d", result.HTTPStatus)
					case result.HTTPStatus >= 300 && result.HTTPStatus < 400:
						coloredStatus = utils.Warning("%d", result.HTTPStatus)
					default:
						coloredStatus = utils.Error("%d", result.HTTPStatus)
					}
					fmt.Printf("%s %s\n", coloredStatus, utils.Highlight("%s", result.Subdomain))
				} else {
					fmt.Printf("%s -> %s\n", utils.Highlight("%s", result.Subdomain), result.IP)
				}
			}
			utils.SuccessPrint("\n扫描完成! 共发现 %d 个子域名 (耗时: %v)", len(results), duration)
		case sig := <-sigChan:
			cancel()
			utils.WarningPrint("\n\n[!] 检测到中断信号 (%v)", sig)
			utils.InfoPrint("等待扫描线程停止...")

			select {
			case results := <-resultChan:
				utils.InfoPrint("\n已发现的子域名:")
				for _, result := range results {
					if result.HTTPStatus > 0 {
						var coloredStatus string
						switch {
						case result.HTTPStatus >= 200 && result.HTTPStatus < 300:
							coloredStatus = utils.Success("%d", result.HTTPStatus)
						case result.HTTPStatus >= 300 && result.HTTPStatus < 400:
							coloredStatus = utils.Warning("%d", result.HTTPStatus)
						default:
							coloredStatus = utils.Error("%d", result.HTTPStatus)
						}
						fmt.Printf("%s %s\n", coloredStatus, utils.Highlight("%s", result.Subdomain))
					} else {
						fmt.Printf("%s -> %s\n", utils.Highlight("%s", result.Subdomain), result.IP)
					}
				}
				utils.SuccessPrint("\n扫描中断，共发现 %d 个子域名", len(results))
			case <-time.After(2 * time.Second):
				utils.ErrorPrint("扫描线程未能及时停止")
			}
		}
	}

	SubCmd.Flags().StringVarP(&domain, "domain", "d", "", "目标域名")
	SubCmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "子域名字典文件路径")
	SubCmd.Flags().IntVarP(&threads, "threads", "t", 50, "并发线程数")
	SubCmd.Flags().IntVarP(&timeout, "timeout", "o", 3, "超时时间(秒)")
	SubCmd.Flags().StringVarP(&output, "output", "f", "", "结果输出文件")
	SubCmd.Flags().StringVarP(&queryType, "type", "T", "A", "DNS查询类型 (A/CNAME)")
	SubCmd.Flags().BoolVarP(&verifyHTTP, "http", "H", true, "验证HTTP响应，过滤无效子域名")
	SubCmd.Flags().BoolVarP(&noVerifyHTTP, "no-http", "", false, "禁用HTTP验证")

	SubCmd.SetHelpTemplate(`{{.UsageString}}

DNS查询类型说明:
  A:     IPv4地址记录
  CNAME: 别名记录

选项说明:
  -H, --http:   验证HTTP响应，确认子域名是否真正可用
                 (默认启用，可使用 --no-http 禁用)

输出文件说明:
  -f, --output:  指定输出文件路径，保存扫描结果
`)

	SubCmd.AddCommand(&cobra.Command{
		Use:   "help",
		Short: "显示子域名模块详细帮助信息",
		Run: func(cmd *cobra.Command, args []string) {
			SubHelp()
		},
	})
}

func SubHelp() {
	helpText := `
GYscan Subdomain模块使用说明

基本用法:
  1. 直接传递目标: GYscan sub 目标域名 [选项]
  2. 使用--domain标志: GYscan sub --domain 目标域名 [选项]

目标格式:
  - 单个域名: example.com
  - 子域名: sub.example.com

常用选项:
  -d, --domain:   目标域名
  -w, --wordlist: 子域名字典文件路径
  -t, --threads:  并发线程数 (默认: 50)
  -o, --timeout:  超时时间(秒) (默认: 3)
  -f, --output:   结果输出文件
  -H, --http:     验证HTTP响应，过滤无效子域名 (默认启用)

DNS查询类型:
  -T, --type: DNS查询类型 (默认: A)
             A/CNAME

示例:
  ./GYscan sub example.com              # 默认启用HTTP验证
  ./GYscan sub example.com -w subdomains.txt
  ./GYscan sub example.com -w subdomains.txt -t 100
  ./GYscan sub example.com -T CNAME
  ./GYscan sub example.com -f results.txt
  ./GYscan sub example.com --no-http    # 禁用HTTP验证
`
	fmt.Println(helpText)
}
