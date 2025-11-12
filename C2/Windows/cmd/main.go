package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
	
	"GYscan-Win-C2/internal/userinfo"
	"GYscan-Win-C2/pkg/audit"
	"GYscan-Win-C2/pkg/scanners"
	"GYscan-Win-C2/tools/goss"
)

// Config 配置结构
type Config struct {
	Target    string
	Type      string
	Output    string
	Verbose   bool
	LocalScan bool
	
	UserinfoOutput string // Userinfo子命令的输出文件
	GossOutput   string // Goss子命令的输出文件
}

// PrintVersion 打印版本信息
func PrintVersion() {
	fmt.Println("GYscan-Win-C2 Windows安全审计工具")
	PrintVersionInfo()
	fmt.Println("作者: BiliBili-弈秋啊")
}



func main() {
	var config Config

	// 定义子命令
	userinfoCmd := flag.NewFlagSet("userinfo", flag.ExitOnError)
	gossCmd := flag.NewFlagSet("goss", flag.ExitOnError)
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)

	// 自定义Usage函数
	flag.Usage = func() {
		fmt.Println("==============================================")
		fmt.Println("GYscan-Win-C2 - Windows安全审计工具")
		fmt.Println("作者: BiliBili-弈秋啊")
		fmt.Printf("工具版本: %s\n", GetVersion())
		fmt.Println("描述: 专注Windows系统安全审计、漏洞扫描、配置检查")
		fmt.Println("")
		fmt.Println("警告: 仅用于授权测试，严禁未授权使用！")
		fmt.Println("==============================================")
		fmt.Println("")
		fmt.Println("主命令参数:")
		flag.PrintDefaults()
		fmt.Println("\n子命令:")
		fmt.Println("  userinfo  分析本地用户和组信息")
		fmt.Println("  goss      Windows系统配置审计")
		fmt.Println("  audit     Windows安全审计")
		fmt.Println("\n使用示例:")
		fmt.Println("  GYscan-Win-C2.exe userinfo -o user_report.txt")
		fmt.Println("  GYscan-Win-C2.exe goss -o goss_report.html")
		fmt.Println("  GYscan-Win-C2.exe audit -type all -o audit_report.json")
		fmt.Println("  GYscan-Win-C2.exe -target 192.168.1.1 -type all -o report.txt")
		fmt.Println("\n查看版本信息:")
		fmt.Println("  GYscan-Win-C2.exe --version")
		fmt.Println("  GYscan-Win-C2.exe -v")
		fmt.Println("\n查看子命令帮助:")
		fmt.Println("  GYscan-Win-C2.exe userinfo --help")
		fmt.Println("  GYscan-Win-C2.exe goss --help")
		fmt.Println("  GYscan-Win-C2.exe audit --help")
		fmt.Println("")
		fmt.Println("==============================================")
		fmt.Println("使用 \"GYscan-Win-C2.exe -h\" 获取帮助信息")
	}

	// 主命令参数
	flag.StringVar(&config.Target, "target", "", "扫描目标 (IP地址、域名或文件路径)")
	flag.StringVar(&config.Type, "type", "all", "扫描类型: all|system|services|programs|middleware|command_exec|privilege_escalation|sql_injection")
	flag.StringVar(&config.Output, "output", "GYscan-Win-C2_report.txt", "输出文件路径")
	flag.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// 版本信息参数
	versionFlag := flag.Bool("version", false, "显示版本信息")
	flag.BoolVar(versionFlag, "v", false, "显示版本信息 (简写)")



	// userinfo子命令参数
	userinfoCmd.StringVar(&config.UserinfoOutput, "o", "windows_userinfo_report.txt", "输出文件路径")
	userinfoCmd.StringVar(&config.UserinfoOutput, "output", "windows_userinfo_report.txt", "输出文件路径")
	userinfoCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")



	// goss子命令参数
	gossCmd.StringVar(&config.GossOutput, "o", "goss_report.html", "输出文件路径")
	gossCmd.StringVar(&config.GossOutput, "output", "goss_report.html", "输出文件路径")
	gossCmd.StringVar(&config.Target, "target", "localhost", "扫描目标（系统路径）")
	gossCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// audit子命令参数
	auditCmd.StringVar(&config.Output, "output", "windows_audit_report.json", "输出文件路径")
	auditCmd.StringVar(&config.Type, "type", "all", "审计类型: all|process|network|filesystem|registry|eventlog|account")
	auditCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// 检查版本参数和帮助参数
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "--v") {
		PrintVersion()
		os.Exit(0)
	}
	
	// 检查help参数
	if len(os.Args) > 1 && (os.Args[1] == "help" || os.Args[1] == "-help" || os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "--h") {
		flag.Usage()
		os.Exit(0)
	}

	// 检查子命令
	if len(os.Args) > 1 {
		switch os.Args[1] {

		case "userinfo":
			config.LocalScan = true
			config.Target = "localhost"
			userinfoCmd.Parse(os.Args[2:])
		case "goss":
			config.LocalScan = true
			config.Target = "localhost"
			gossCmd.Parse(os.Args[2:])
		case "audit":
			config.LocalScan = true
			config.Target = "localhost"
			auditCmd.Parse(os.Args[2:])
		default:
			flag.Parse()
		}
	} else {
		flag.Parse()
	}

	// 检查版本标志
	if *versionFlag {
		PrintVersion()
		os.Exit(0)
	}

	if !config.LocalScan && config.Target == "" {
		flag.Usage()
		os.Exit(1)
	}

	if runtime.GOOS != "windows" {
		fmt.Println("错误: 此程序只能在Windows系统上运行")
		os.Exit(1)
	}

	// 检查当前执行的子命令
	subcommand := ""
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "userinfo":
			subcommand = "userinfo"
		case "goss":
			subcommand = "goss"
		case "audit":
			subcommand = "audit"
		}
	}
	
	// 根据子命令选择正确的输出文件
	var outputFile string
	outputFile = config.Output
	if subcommand == "userinfo" {
		outputFile = config.UserinfoOutput
	} else if subcommand == "goss" {
		outputFile = config.GossOutput
	} else if subcommand == "audit" {
		outputFile = config.Output
	}
	
	// 根据子命令选择输出文件

	// 根据子命令执行不同的操作
	var scanType string
	
	startTime := time.Now()
	
	if subcommand == "userinfo" {
		// 执行用户信息分析
		scanType = "用户信息分析"
		
		// 导入userinfo包
		userResult, err := userinfo.AnalyzeLocalUsers()
		if err != nil {
			log.Fatalf("用户信息分析失败: %v", err)
		}
		
		// 生成用户信息报告
		err = GenerateUserInfoReport(userResult, outputFile)
		if err != nil {
			log.Fatalf("生成用户信息报告失败: %v", err)
		}

	} else if subcommand == "goss" {
		// 执行Goss扫描
		scanType = "Goss Windows配置审计"
		
		// 创建Goss配置
		gossConfig := goss.NewConfig()
		gossConfig.SetTarget(config.Target)
		gossConfig.SetOutput(config.GossOutput)
		gossConfig.SetVerbose(config.Verbose)
		
		// 创建Goss扫描器
		gossScanner := goss.NewScanner(gossConfig, config.Verbose)
		
		// 执行Goss扫描
		scanResult, err := gossScanner.Scan()
		if err != nil {
			log.Fatalf("Goss扫描失败: %v", err)
		}
		
		// 根据输出文件扩展名确定报告格式
		if strings.HasSuffix(strings.ToLower(config.GossOutput), ".html") {
			// 生成HTML报告
			err := gossScanner.GenerateHTMLReport(scanResult, config.GossOutput)
			if err != nil {
				log.Fatalf("生成Goss HTML报告失败: %v", err)
			}
		} else if strings.HasSuffix(strings.ToLower(config.GossOutput), ".json") {
			// 生成JSON报告
			err := gossScanner.GenerateJSONReport(scanResult, config.GossOutput)
			if err != nil {
				log.Fatalf("生成Goss JSON报告失败: %v", err)
			}
		} else {
			// 生成文本报告
			err := gossScanner.GenerateTextReport(scanResult, config.GossOutput)
			if err != nil {
				log.Fatalf("生成Goss报告失败: %v", err)
			}
		}
		
		// 打印摘要
		fmt.Printf("Goss扫描完成，报告已保存到: %s\n", config.GossOutput)
		fmt.Printf("扫描结果: 总测试数: %d, 失败: %d, 跳过: %d\n", 
			scanResult.Summary.TotalCount, 
			scanResult.Summary.FailedCount, 
			scanResult.Summary.SkippedCount)
	} else if subcommand == "audit" {
		// 检查audit子命令的help参数
		if len(os.Args) > 2 && (os.Args[2] == "help" || os.Args[2] == "-help" || os.Args[2] == "--help" || os.Args[2] == "-h" || os.Args[2] == "--h") {
			fmt.Println("Windows安全审计命令使用说明:")
			fmt.Println("用法: GYscan-Win-C2.exe audit [选项]")
			fmt.Println("")
			fmt.Println("选项:")
			fmt.Println("  -o, --output string     审计报告输出文件路径 (默认: windows_audit_report.html)")
			fmt.Println("  -type string            审计类型，可选值: all|process|network|filesystem|registry|eventlog|account (默认: all)")
			fmt.Println("  -verbose, -v            详细输出模式")
			fmt.Println("  -help, -h               显示帮助信息")
			fmt.Println("")
			fmt.Println("示例:")
			fmt.Println("  GYscan-Win-C2.exe audit -o audit_report.html")
			fmt.Println("  GYscan-Win-C2.exe audit -type process|network -verbose")
			fmt.Println("  GYscan-Win-C2.exe audit help")
			os.Exit(0)
		}
		
		// 执行Windows安全审计
		scanType = "Windows安全审计"
		
		// 解析audit子命令参数
		auditOutputFile := auditCmd.String("o", "windows_audit_report.html", "审计报告输出文件路径")
		
		auditCmd.Parse(os.Args[2:])
		
		// 设置输出文件
		if *auditOutputFile != "windows_audit_report.json" {
			outputFile = *auditOutputFile
		}
		
		// 创建审计配置
		auditConfig := &audit.Config{
			Verbose:        config.Verbose,
			OutputFile:     outputFile,
			IncludeDetails: true,
		}
		
		// 根据审计类型设置模块
		if config.Type != "all" {
			auditConfig.Modules = strings.Split(config.Type, "|")
		}
		
		// 创建审计管理器
		auditManager := audit.NewAuditManager(auditConfig)
		
		// 注册审计模块
		auditManager.RegisterModule(audit.NewProcessAudit(auditConfig))
		auditManager.RegisterModule(audit.NewNetworkAudit(auditConfig))
		auditManager.RegisterModule(audit.NewFileSystemAudit(auditConfig))
		auditManager.RegisterModule(audit.NewRegistryAudit(auditConfig))
		auditManager.RegisterModule(audit.NewEventLogAudit(auditConfig))
		auditManager.RegisterModule(audit.NewAccountAudit(auditConfig))
		
		// 执行审计
		auditReport, err := auditManager.RunAudit()
		if err != nil {
			log.Fatalf("Windows安全审计失败: %v", err)
		}
		
		// 生成审计报告
		err = audit.GenerateAuditReport(auditReport, outputFile)
		if err != nil {
			log.Fatalf("生成审计报告失败: %v", err)
		}
		
		// 打印摘要
		audit.PrintAuditSummary(auditReport)
		fmt.Printf("Windows安全审计完成，报告已保存到: %s\n", outputFile)
	} else {
		// 执行CVE扫描（默认或cve子命令）
		scanType = "漏洞扫描"
		
		// 创建扫描器
		scanner := scanners.NewVulnScanner(config.Verbose)

		// 执行扫描
		scanResult, err := scanner.Scan(config.Target, config.Type)
		if err != nil {
			log.Fatalf("扫描失败: %v", err)
		}

		// 生成报告
		reportGen := scanners.NewReportGenerator()
		err = reportGen.GenerateReport(scanResult, outputFile)
		if err != nil {
			log.Fatalf("生成报告失败: %v", err)
		}
		
		// 打印摘要
		scanners.PrintSummary(scanResult, time.Since(startTime))
	}

	scanDuration := time.Since(startTime)

	if config.LocalScan {
		fmt.Printf("本地%s完成! 耗时: %v\n", scanType, scanDuration)
	} else {
		fmt.Printf("%s完成! 耗时: %v\n", scanType, scanDuration)
	}
	fmt.Printf("报告已保存到: %s\n", outputFile)
}

// GenerateUserInfoReport 生成用户信息报告
func GenerateUserInfoReport(users interface{}, outputPath string) error {
	// 将interface{}转换为具体的用户信息类型
	userList, ok := users.([]userinfo.UserInfo)
	if !ok {
		return fmt.Errorf("无效的用户信息类型")
	}
	
	// 生成报告内容
	reportContent := "Windows用户信息报告\n"
	reportContent += "====================\n\n"
	
	for _, user := range userList {
		reportContent += fmt.Sprintf("用户名: %s\n", user.Name)
		reportContent += fmt.Sprintf("全名: %s\n", user.FullName)
		reportContent += fmt.Sprintf("注释: %s\n", user.Comment)
		reportContent += fmt.Sprintf("SID: %s\n", user.SID)
		reportContent += "---------------------\n"
	}
	
	// 写入文件
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建报告文件失败: %v", err)
	}
	defer file.Close()
	
	_, err = file.WriteString(reportContent)
	if err != nil {
		return fmt.Errorf("写入报告文件失败: %v", err)
	}
	
	return nil
}
