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
	"GYscan-Win-C2/pkg/scanners"
	"GYscan-Win-C2/tools/goss"
	"GYscan-Win-C2/tools/trivy"
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

func main() {
	var config Config

	// 定义子命令
	userinfoCmd := flag.NewFlagSet("userinfo", flag.ExitOnError)
	trivyCmd := flag.NewFlagSet("trivy", flag.ExitOnError)
	gossCmd := flag.NewFlagSet("goss", flag.ExitOnError)

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

	// trivy子命令参数
	trivyCmd.StringVar(&config.Output, "o", "trivy_report.json", "输出文件路径")
	trivyCmd.StringVar(&config.Output, "output", "trivy_report.json", "输出文件路径")
	trivyCmd.StringVar(&config.Target, "target", "", "扫描目标（镜像、文件系统路径等）")
	trivyCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// goss子命令参数
	gossCmd.StringVar(&config.GossOutput, "o", "goss_report.html", "输出文件路径")
	gossCmd.StringVar(&config.GossOutput, "output", "goss_report.html", "输出文件路径")
	gossCmd.StringVar(&config.Target, "target", "localhost", "扫描目标（系统路径）")
	gossCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// 检查版本参数
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "--v") {
		PrintVersion()
		os.Exit(0)
	}

	// 检查子命令
	if len(os.Args) > 1 {
		switch os.Args[1] {

		case "userinfo":
			config.LocalScan = true
			config.Target = "localhost"
			userinfoCmd.Parse(os.Args[2:])
		case "trivy":
			config.LocalScan = true
			trivyCmd.Parse(os.Args[2:])
		case "goss":
			config.LocalScan = true
			config.Target = "localhost"
			gossCmd.Parse(os.Args[2:])
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
		// 显示完整的帮助信息
		fmt.Println("Windows漏洞扫描工具")
		fmt.Println("====================")
		fmt.Printf("版本: %s\n\n", GetBuildInfo())
		fmt.Println("主命令参数:")
		flag.Usage()
		fmt.Println("\n子命令:")
		fmt.Println("  userinfo  分析本地用户和组信息")
		fmt.Println("  trivy     容器镜像漏洞扫描")
		fmt.Println("  goss      Windows系统配置审计")
		fmt.Println("\n使用示例:")
		fmt.Println("  GYscan-Win-C2.exe userinfo -o user_report.txt")
		fmt.Println("  GYscan-Win-C2.exe trivy -target image:latest -o trivy_report.json")
		fmt.Println("  GYscan-Win-C2.exe goss -o goss_report.html")
		fmt.Println("  GYscan-Win-C2.exe -target 192.168.1.1 -type all -o report.txt")
		fmt.Println("\n查看版本信息:")
		fmt.Println("  GYscan-Win-C2.exe --version")
		fmt.Println("  GYscan-Win-C2.exe -v")
		fmt.Println("\n查看子命令帮助:")
		fmt.Println("  GYscan-Win-C2.exe userinfo --help")
		fmt.Println("  GYscan-Win-C2.exe trivy --help")
		fmt.Println("  GYscan-Win-C2.exe goss --help")
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
		case "trivy":
			subcommand = "trivy"
		case "goss":
			subcommand = "goss"
		}
	}
	
	// 根据子命令选择正确的输出文件
	var outputFile string
	outputFile = config.Output
	if subcommand == "userinfo" {
		outputFile = config.UserinfoOutput
	} else if subcommand == "trivy" {
		outputFile = config.Output
	} else if subcommand == "goss" {
		outputFile = config.GossOutput
	}
	
	// 调试信息：显示当前配置
	fmt.Printf("调试信息: subcommand=%s, outputFile=%s\n", subcommand, outputFile)

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
	} else if subcommand == "trivy" {
		// 执行Trivy扫描
		scanType = "Trivy漏洞扫描"
		
		// 检查目标是否为空
		if config.Target == "" {
			log.Fatalf("错误: Trivy扫描需要指定目标，请使用 -target 参数")
		}
		
		// 创建Trivy配置
		trivyConfig := trivy.NewConfig()
		trivyConfig.SetTarget(config.Target)
		trivyConfig.SetOutput(config.Output)
		trivyConfig.SetQuiet(!config.Verbose)
		trivyConfig.SetDebug(config.Verbose)
		
		// 创建Trivy扫描器
		trivyScanner := trivy.NewScanner(trivyConfig, config.Verbose)
		
		// 执行Trivy扫描
		err := trivyScanner.Scan()
		if err != nil {
			log.Fatalf("Trivy扫描失败: %v", err)
		}
		
		// 根据输出文件扩展名确定报告格式
		if strings.HasSuffix(strings.ToLower(config.Output), ".html") {
			// 生成HTML报告
			err := trivyScanner.GenerateHTMLReport(config.Output)
			if err != nil {
				log.Fatalf("生成Trivy HTML报告失败: %v", err)
			}
		} else {
			// 生成JSON报告
			err := trivyScanner.GenerateReport(config.Output)
			if err != nil {
				log.Fatalf("生成Trivy报告失败: %v", err)
			}
		}
		
		// 打印摘要
		fmt.Printf("Trivy扫描完成，报告已保存到: %s\n", config.Output)
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
