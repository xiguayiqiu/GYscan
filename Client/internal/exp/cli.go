package exp

import (
	"fmt"
	"os"
	"strconv"

	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	query         string
	cve           string
	platform      string
	exploitType   string
	exactMatch    bool
	caseSensitive bool
	outputPath    string
	outputFormat  string
	verbose       bool
	target        string
	port          int
	ssl           bool
)

var searchCmd = &cobra.Command{
	Use:   "search [关键词]",
	Short: "搜索漏洞利用和Shellcode",
	Long: `搜索Exploit-DB漏洞数据库，支持多种搜索方式：

  1. 关键词搜索:
     ./GYscan exp search "apache"

  2. CVE编号搜索:
     ./GYscan exp search --cve CVE-2021-44228

  3. 平台搜索:
     ./GYscan exp search --platform windows

  4. 精确匹配:
     ./GYscan exp search --exact "Apache Struts 2.0.0"

  5. 保存结果到文件:
     ./GYscan exp search "mysql" -o results.json --format json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && query == "" {
			query = args[0]
		}

		if query == "" && cve == "" && platform == "" && exploitType == "" {
			return fmt.Errorf("请提供搜索关键词、--cve、--platform 或 --type 参数")
		}

		options := SearchOptions{
			Query:         query,
			CVE:           cve,
			Platform:      platform,
			Type:          exploitType,
			ExactMatch:    exactMatch,
			CaseSensitive: caseSensitive,
			OutputPath:    outputPath,
			Format:        outputFormat,
		}

		result, err := SearchExploits(options)
		if err != nil {
			return fmt.Errorf("搜索失败: %v", err)
		}

		PrintResults(result, verbose)
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list [platforms|types]",
	Short: "列出可用的平台和漏洞类型",
	Long: `列出Exploit-DB数据库中的所有平台和漏洞类型：

  1. 列出所有平台:
     ./GYscan exp list platforms

  2. 列出所有漏洞类型:
     ./GYscan exp list types`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请指定要列出的类型: platforms 或 types")
		}

		switch args[0] {
		case "platforms":
			platforms := ListPlatforms()
			utils.LogSuccess("可用平台 (%d 个):", len(platforms))
			for _, p := range platforms {
				fmt.Println("  - " + p)
			}

		case "types":
			types := ListExploitTypes()
			utils.LogSuccess("漏洞类型 (%d 种):", len(types))
			for _, t := range types {
				fmt.Println("  - " + t)
			}

		default:
			return fmt.Errorf("未知类型: %s", args[0])
		}

		return nil
	},
}

var infoCmd = &cobra.Command{
	Use:   "info <EDB-ID>",
	Short: "显示漏洞利用详细信息",
	Long: `显示指定EDB-ID的漏洞利用详细信息：

  ./GYscan exp info 40564
  ./GYscan exp info 39446 -v`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请提供EDB-ID")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("无效的EDB-ID: %s", args[0])
		}

		exploit, err := GetExploitDetails(id)
		if err != nil {
			return fmt.Errorf("获取漏洞信息失败: %v", err)
		}

		cyan := color.New(color.FgCyan)
		green := color.New(color.FgGreen)

		cyan.Printf("\n[EDB-ID: %d]\n", exploit.ID)
		utils.LogInfo("描述: %s", exploit.Description)
		utils.LogInfo("平台: %s", exploit.Platform)
		utils.LogInfo("类型: %s", exploit.Type)
		utils.LogInfo("作者: %s", exploit.Author)
		utils.LogInfo("发布日期: %s", exploit.DatePublished)
		utils.LogInfo("文件: %s", exploit.File)

		if exploit.Codes != "" {
			utils.LogInfo("CVE: %s", exploit.Codes)
		}

		if exploit.Verified {
			green.Println("状态: 已验证")
		} else {
			utils.LogWarning("状态: 未验证")
		}

		if verbose {
			if exploit.Tags != "" {
				utils.LogInfo("标签: %s", exploit.Tags)
			}
			if exploit.Aliases != "" {
				utils.LogInfo("别名: %s", exploit.Aliases)
			}
		}

		return nil
	},
}

var showCmd = &cobra.Command{
	Use:   "show <EDB-ID>",
	Short: "显示漏洞利用代码内容",
	Long: `显示指定EDB-ID的漏洞利用代码内容：

  ./GYscan exp show 40564

  支持输出重定向:
  ./GYscan exp show 40564 > poc.py`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请提供EDB-ID")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("无效的EDB-ID: %s", args[0])
		}

		exploit, err := GetExploitDetails(id)
		if err != nil {
			return fmt.Errorf("获取漏洞信息失败: %v", err)
		}

		PrintPOC(*exploit)
		return nil
	},
}

var copyCmd = &cobra.Command{
	Use:   "copy <EDB-ID> [输出目录]",
	Short: "复制漏洞利用代码到指定目录",
	Long: `复制指定EDB-ID的漏洞利用代码到指定目录：

  ./GYscan exp copy 40564
  ./GYscan exp copy 40564 /tmp/pocs
  ./GYscan exp copy 40564 ./my_pocs`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请提供EDB-ID")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("无效的EDB-ID: %s", args[0])
		}

		exploit, err := GetExploitDetails(id)
		if err != nil {
			return fmt.Errorf("获取漏洞信息失败: %v", err)
		}

		outputDir := "."
		if len(args) > 1 {
			outputDir = args[1]
		}

		if err := CopyPOC(*exploit, outputDir); err != nil {
			return fmt.Errorf("复制失败: %v", err)
		}

		return nil
	},
}

var generateCmd = &cobra.Command{
	Use:   "generate <EDB-ID>",
	Short: "生成可用的PoC代码",
	Long: `生成带有GYscan头部的PoC代码，支持自定义目标参数：

  1. 生成到当前目录:
     ./GYscan exp generate 40564

  2. 生成到指定目录:
     ./GYscan exp generate 40564 -o /tmp/pocs

  3. 指定目标参数:
     ./GYscan exp generate 40564 -t 192.168.1.100 -p 8080

  4. 生成简单模板PoC:
     ./GYscan exp generate 40564 --template`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请提供EDB-ID")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("无效的EDB-ID: %s", args[0])
		}

		exploit, err := GetExploitDetails(id)
		if err != nil {
			return fmt.Errorf("获取漏洞信息失败: %v", err)
		}

		options := POCOptions{
			Target:     target,
			Port:       port,
			SSL:        ssl,
			OutputFile: outputPath,
		}

		generator := NewPOCGenerator()
		content, err := generator.GeneratePOC(*exploit, options)
		if err != nil {
			return fmt.Errorf("生成PoC失败: %v", err)
		}

		if outputPath == "" {
			fmt.Println(string(content))
		}

		return nil
	},
}

var simpleCmd = &cobra.Command{
	Use:   "simple <EDB-ID>",
	Short: "生成简单的Python PoC模板",
	Long: `生成简单的Python PoC模板，适用于快速测试：

  ./GYscan exp simple 40564
  ./GYscan exp simple 40564 -t 192.168.1.100 -p 8080 -o poc.py`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请提供EDB-ID")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("无效的EDB-ID: %s", args[0])
		}

		exploit, err := GetExploitDetails(id)
		if err != nil {
			return fmt.Errorf("获取漏洞信息失败: %v", err)
		}

		poc := GenerateSimplePOC(*exploit, target, port)

		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(poc), 0644); err != nil {
				return fmt.Errorf("写入文件失败: %v", err)
			}
			utils.LogSuccess("PoC已保存到: %s", outputPath)
		} else {
			fmt.Println(poc)
		}

		return nil
	},
}

var nmapCmd = &cobra.Command{
	Use:   "nmap <EDB-ID>",
	Short: "生成Nmap NSE脚本",
	Long: `生成Nmap NSE漏洞检测脚本：

  ./GYscan exp nmap 40564
  ./GYscan exp nmap 40564 -o /usr/share/nmap/scripts/vuln-40564.nse`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("请提供EDB-ID")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("无效的EDB-ID: %s", args[0])
		}

		exploit, err := GetExploitDetails(id)
		if err != nil {
			return fmt.Errorf("获取漏洞信息失败: %v", err)
		}

		script := GenerateNmapScript(*exploit)

		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(script), 0644); err != nil {
				return fmt.Errorf("写入文件失败: %v", err)
			}
			utils.LogSuccess("NSE脚本已保存到: %s", outputPath)
		} else {
			fmt.Println(script)
		}

		return nil
	},
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "显示数据库统计信息",
	Long: `显示Exploit-DB数据库的统计信息：

  ./GYscan exp stats`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := LoadDatabase(); err != nil {
			return fmt.Errorf("加载数据库失败: %v", err)
		}

		exploitCount, shellcodeCount := GetDatabaseStats()

		utils.LogBanner("Exploit-DB 数据库统计")
		utils.LogInfo("漏洞利用: %d 条", exploitCount)
		utils.LogInfo("Shellcode: %d 条", shellcodeCount)
		utils.LogInfo("总计: %d 条", exploitCount+shellcodeCount)

		if IsLoaded() {
			utils.LogSuccess("数据库状态: 已加载")
		} else {
			utils.LogWarning("数据库状态: 未加载")
		}

		return nil
	},
}

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "重新加载数据库",
	Long: `重新加载Exploit-DB数据库：

  ./GYscan exp reload`,
	RunE: func(cmd *cobra.Command, args []string) error {
		utils.LogInfo("正在重新加载数据库...")
		if err := ReloadDatabase(); err != nil {
			return fmt.Errorf("重新加载数据库失败: %v", err)
		}
		utils.LogSuccess("数据库已重新加载")
		return nil
	},
}

var ExpCmd = &cobra.Command{
	Use:   "exp",
	Short: "Exploit-DB 漏洞利用搜索和PoC生成工具",
	Long: `GYscan Exploit-DB 集成模块，用于搜索漏洞利用和生成PoC代码。

子命令:
  search     搜索漏洞利用和Shellcode
  list       列出可用的平台和漏洞类型
  info       显示漏洞利用详细信息
  show       显示漏洞利用代码内容
  copy       复制漏洞利用代码到指定目录
  generate   生成带有GYscan头部的PoC代码
  simple     生成简单的Python PoC模板
  nmap       生成Nmap NSE脚本
  stats      显示数据库统计信息
  reload     重新加载数据库

示例:
  ./GYscan exp search "apache struts"
  ./GYscan exp search --cve CVE-2021-44228
  ./GYscan exp search --platform windows --type local
  ./GYscan exp info 40564
  ./GYscan exp show 40564 > poc.py
  ./GYscan exp copy 40564 /tmp/pocs
  ./GYscan exp generate 40564 -t 192.168.1.100
  ./GYscan exp simple 40564 -t 192.168.1.100 -o poc.py
  ./GYscan exp nmap 40564
  ./GYscan exp stats`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return nil
	},
}

func init() {
	searchCmd.Flags().StringVarP(&query, "keyword", "k", "", "搜索关键词")
	searchCmd.Flags().StringVar(&cve, "cve", "", "CVE编号")
	searchCmd.Flags().StringVar(&platform, "platform", "", "平台 (windows/linux/php/asp/etc)")
	searchCmd.Flags().StringVar(&exploitType, "type", "", "漏洞类型 (local/remote/dos/webapps)")
	searchCmd.Flags().BoolVar(&exactMatch, "exact", false, "精确匹配")
	searchCmd.Flags().BoolVarP(&caseSensitive, "case", "c", false, "大小写敏感")
	searchCmd.Flags().StringVarP(&outputPath, "output", "o", "", "输出文件路径")
	searchCmd.Flags().StringVar(&outputFormat, "format", "text", "输出格式 (text/json)")
	searchCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出")

	generateCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址或主机名")
	generateCmd.Flags().IntVarP(&port, "port", "p", 0, "目标端口")
	generateCmd.Flags().BoolVar(&ssl, "ssl", false, "使用SSL/HTTPS")
	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "", "输出目录")

	simpleCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址或主机名")
	simpleCmd.Flags().IntVarP(&port, "port", "p", 0, "目标端口")
	simpleCmd.Flags().StringVarP(&outputPath, "output", "o", "", "输出文件路径")

	nmapCmd.Flags().StringVarP(&outputPath, "output", "o", "", "输出文件路径")

	ExpCmd.AddCommand(searchCmd)
	ExpCmd.AddCommand(listCmd)
	ExpCmd.AddCommand(infoCmd)
	ExpCmd.AddCommand(showCmd)
	ExpCmd.AddCommand(copyCmd)
	ExpCmd.AddCommand(generateCmd)
	ExpCmd.AddCommand(simpleCmd)
	ExpCmd.AddCommand(nmapCmd)
	ExpCmd.AddCommand(statsCmd)
	ExpCmd.AddCommand(reloadCmd)
}
