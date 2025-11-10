package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
	
	"GYscan-linux-C2/internal/userinfo"
	"GYscan-linux-C2/pkg/scanners"
	"GYscan-linux-C2/tools/ssh"
	"GYscan-linux-C2/tools/trivy"
)

// Config 配置结构
type Config struct {
	Target    string
	Type      string
	Output    string
	Verbose   bool
	LocalScan bool

	UserinfoOutput string // Userinfo子命令的输出文件
	SSHOutput string // SSH子命令的输出文件
}

func main() {
	var config Config

	// 定义子命令
	userinfoCmd := flag.NewFlagSet("userinfo", flag.ExitOnError)
	trivyCmd := flag.NewFlagSet("trivy", flag.ExitOnError)
	sshCmd := flag.NewFlagSet("ssh", flag.ExitOnError)

	// 主命令参数
	flag.StringVar(&config.Target, "target", "", "扫描目标 (IP地址、域名或文件路径)")
	flag.StringVar(&config.Type, "type", "all", "扫描类型: all|kernel|services|programs|middleware|distro")
	flag.StringVar(&config.Output, "output", "GYscan-Linux-C2_report.txt", "输出文件路径")
	flag.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")
	
	// 版本信息参数
	versionFlag := flag.Bool("version", false, "显示版本信息")
	flag.BoolVar(versionFlag, "v", false, "显示版本信息 (简写)")



	// userinfo子命令参数
	userinfoCmd.StringVar(&config.UserinfoOutput, "o", "linux_userinfo_report.txt", "输出文件路径")
	userinfoCmd.StringVar(&config.UserinfoOutput, "output", "linux_userinfo_report.txt", "输出文件路径")
	userinfoCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// trivy子命令参数
	trivyCmd.StringVar(&config.Output, "o", "trivy_report.html", "输出文件路径")
	trivyCmd.StringVar(&config.Output, "output", "trivy_report.html", "输出文件路径")
	trivyCmd.StringVar(&config.Target, "target", "", "扫描目标 (镜像、文件或目录)")
	trivyCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")



	// ssh子命令参数
	sshCmd.StringVar(&config.SSHOutput, "o", "ssh_audit_report.html", "输出文件路径")
	sshCmd.StringVar(&config.SSHOutput, "output", "ssh_audit_report.html", "输出文件路径")
	sshCmd.StringVar(&config.Target, "target", "localhost:22", "SSH服务地址 (格式: host:port)")
	sshCmd.BoolVar(&config.Verbose, "verbose", false, "详细输出模式")

	// 首先检查帮助请求
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		// 显示完整的帮助信息
		fmt.Println("Linux漏洞扫描工具")
		fmt.Println("==================")
		fmt.Printf("版本: %s\n\n", GetBuildInfo())
		fmt.Println("主命令参数:")
		flag.Usage()
		fmt.Println("子命令:")

		fmt.Println("  userinfo  分析本地用户和组信息")
		fmt.Println("  trivy     使用Trivy进行容器/镜像扫描")
		fmt.Println("  ssh       使用ssh-audit进行SSH配置安全审计")
		fmt.Println("\n使用示例:")
		fmt.Println("  GYscan-Linux-C2.exe userinfo -o user_report.txt")
		fmt.Println("  GYscan-Linux-C2.exe trivy -target image:latest -o report.html")
		fmt.Println("  GYscan-Linux-C2.exe ssh -target 192.168.1.1:22 -o ssh_report.html")
		fmt.Println("  GYscan-Linux-C2.exe -target 192.168.1.1 -type all -o report.txt")
		fmt.Println("\n查看版本信息:")
		fmt.Println("  GYscan-Linux-C2.exe --version")
		fmt.Println("  GYscan-Linux-C2.exe -v")
		fmt.Println("\n查看子命令帮助:")
		fmt.Println("  GYscan-Linux-C2.exe userinfo --help")
		fmt.Println("  GYscan-Linux-C2.exe trivy --help")
		fmt.Println("  GYscan-Linux-C2.exe ssh --help")
		os.Exit(0)
	}

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
			trivyCmd.Parse(os.Args[2:])
		case "ssh":
			sshCmd.Parse(os.Args[2:])
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

	// 检查是否应该显示帮助信息（没有指定目标且不是子命令）
	shouldShowHelp := !config.LocalScan && config.Target == ""

	if shouldShowHelp {
		// 显示完整的帮助信息
		fmt.Println("Linux漏洞扫描工具")
		fmt.Println("==================")
		fmt.Printf("版本: %s\n\n", GetBuildInfo())
		fmt.Println("主命令参数:")
		flag.Usage()
		fmt.Println("\n子命令:")
		fmt.Println("  userinfo  分析本地用户和组信息")
		fmt.Println("  trivy     使用Trivy进行容器/镜像扫描")
		fmt.Println("  lynis     使用Lynis进行系统安全审计")
		fmt.Println("\n使用示例:")

		fmt.Println("  GYscan-Linux-C2.exe userinfo -o user_report.txt")
		fmt.Println("  GYscan-Linux-C2.exe trivy -target image:latest -o report.html")
		fmt.Println("  GYscan-Linux-C2.exe lynis -o lynis_report.html")
		fmt.Println("  GYscan-Linux-C2.exe -target 192.168.1.1 -type all -o report.txt")
		fmt.Println("\n查看版本信息:")
		fmt.Println("  GYscan-Linux-C2.exe --version")
		fmt.Println("  GYscan-Linux-C2.exe -v")
		fmt.Println("\n查看子命令帮助:")

		fmt.Println("  Yscan-Linux-C2.exe userinfo --help")
		fmt.Println("  GYscan-Linux-C2.exe trivy --help")
		fmt.Println("  GYscan-Linux-C2.exe lynis --help")
		os.Exit(1)
	}

	// 允许在Windows上进行测试
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		fmt.Println("错误: 此程序只能在Linux或Windows系统上运行")
		os.Exit(1)
	}

	// 根据子命令执行不同的操作
	var scanType string
	
	startTime := time.Now()
	
	// 检查当前执行的子命令
	subcommand := ""
	if len(os.Args) > 1 {
		switch os.Args[1] {

		case "userinfo":
			subcommand = "userinfo"
		case "trivy":
			subcommand = "trivy"
		case "ssh":
			subcommand = "ssh"
		}
	}

	// 检查是否需要root权限
	if runtime.GOOS == "linux" && !isRoot() {
		// 检查哪些操作需要root权限
		needsRoot := false
		reason := ""
		
		if subcommand == "" {
			needsRoot = true
			reason = "漏洞扫描需要访问系统敏感信息"
		} else if subcommand == "userinfo" {
			needsRoot = true
			reason = "用户信息分析需要访问系统用户数据"
		}
		
		if needsRoot {
			fmt.Printf("错误: %s需要root权限 (%s)\n", subcommand, reason)
			fmt.Println("请使用sudo运行此程序:")
			fmt.Printf("  sudo ./cmd.exe %s\n", strings.Join(os.Args[1:], " "))
			os.Exit(1)
		}
	}
	
	// 调试信息：显示当前配置
	var outputFile string
	outputFile = config.Output
	if subcommand == "userinfo" {
		outputFile = config.UserinfoOutput
	} else if subcommand == "trivy" {
		outputFile = config.Output
	} else if subcommand == "ssh" {
		outputFile = config.SSHOutput
	}
	fmt.Printf("调试信息: subcommand=%s, outputFile=%s\n", subcommand, outputFile)
	
	if subcommand == "userinfo" {
		// 执行用户信息分析
		scanType = "用户信息分析"
		userResult, err := userinfo.AnalyzeLocalUsers()
		if err != nil {
			log.Fatalf("用户信息分析失败: %v", err)
		}
		
		// 生成用户信息报告
		err = GenerateUserInfoReport(userResult, config.UserinfoOutput)
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

	} else if subcommand == "ssh" {
		// 执行SSH配置安全审计
		scanType = "SSH配置安全审计"
		
		// 检查目标是否为空
		if config.Target == "" {
			log.Fatalf("错误: SSH扫描需要指定目标，请使用 -target 参数")
		}
		
		// 创建SSH配置
		sshConfig := ssh.NewConfig()
		sshConfig.Target = config.Target
		sshConfig.OutputFile = config.SSHOutput
		sshConfig.Verbose = config.Verbose
		
		// 创建SSH扫描器
		sshScanner := ssh.NewScanner(sshConfig, config.Verbose)
		
		// 执行扫描
		result, err := sshScanner.Scan()
		if err != nil {
			log.Fatalf("SSH扫描失败: %v", err)
		}
		// 打印扫描结果
		sshScanner.PrintResult(result)
		
		// 保存扫描结果
		err = sshScanner.SaveResult(result)
		if err != nil {
			log.Fatalf("保存SSH扫描结果失败: %v", err)
		}
		
		fmt.Printf("SSH配置安全审计完成，报告已保存到: %s\n", config.SSHOutput)
	} else {
		// 执行CVE扫描（默认或cve子命令）
		scanType = "漏洞扫描"
		scanner := scanners.NewVulnScanner(config.Verbose)
		scanResult, err := scanner.Scan(config.Target, config.Type)
		if err != nil {
			log.Fatalf("扫描失败: %v", err)
		}
		// 生成报告
		reportGen := scanners.NewReportGenerator(scanResult)
		
		// 根据子命令选择正确的输出文件
		outputFile = config.Output
		
		// 根据输出文件扩展名确定报告格式
		outputFormat := "text"
		if strings.HasSuffix(strings.ToLower(outputFile), ".html") {
			outputFormat = "html"
		} else if strings.HasSuffix(strings.ToLower(outputFile), ".json") {
			outputFormat = "json"
		}
		
		err = reportGen.GenerateReport(outputFormat, outputFile)
		if err != nil {
			log.Fatalf("生成报告失败: %v", err)
		}
		
		// 打印摘要
		reportGen.PrintSummary()
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
	reportContent := userinfo.FormatUserInfo(userList)
	
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

// isRoot 检查当前用户是否为root权限
func isRoot() bool {
	// 在Windows系统上，总是返回true（不需要root检查）
	if runtime.GOOS == "windows" {
		return true
	}
	
	// 在Linux系统上检查当前用户ID
	return os.Geteuid() == 0
}
