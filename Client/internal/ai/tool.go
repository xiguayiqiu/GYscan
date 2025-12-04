package ai

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"

	"gopkg.in/yaml.v3"
)

// ToolInterface 定义工具执行的统一接口
type ToolInterface interface {
	// Name 返回工具名称
	Name() string
	// Run 执行工具命令
	Run(args ...string) (string, error)
	// ParseResult 解析工具输出结果
	ParseResult(output string) (string, error)
	// IsAvailable 检查工具是否可用
	IsAvailable() bool
	// GetPath 获取工具路径
	GetPath() string
}

// BaseTool 基础工具实现
type BaseTool struct {
	NameValue string
	Path      string
	Available bool
}

// Name 返回工具名称
func (t *BaseTool) Name() string {
	return t.NameValue
}

// IsAvailable 检查工具是否可用
func (t *BaseTool) IsAvailable() bool {
	return t.Available
}

// GetPath 获取工具路径
func (t *BaseTool) GetPath() string {
	return t.Path
}

// Run 执行工具命令
func (t *BaseTool) Run(args ...string) (string, error) {
	if !t.Available {
		return "", fmt.Errorf("工具 %s 不可用", t.Name())
	}

	// 构建命令
	cmd := exec.Command(t.Path, args...)

	// 捕获命令输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("执行命令 %s 失败: %v", t.Name(), err)
	}

	// 输出命令结果
	fmt.Println(string(output))

	return string(output), nil
}

// ParseResult 解析工具输出结果（默认实现）
func (t *BaseTool) ParseResult(output string) (string, error) {
	return output, nil
}

// ToolManager 工具管理器
type ToolManager struct {
	Tools        map[string]ToolInterface
	SmartManager *SmartToolManager
}

// NewToolManager 创建工具管理器
func NewToolManager() *ToolManager {
	return &ToolManager{
		Tools:        make(map[string]ToolInterface),
		SmartManager: nil,
	}
}

// SetSmartManager 设置智能工具管理器
func (tm *ToolManager) SetSmartManager(smartManager *SmartToolManager) {
	tm.SmartManager = smartManager
}

// GetTool 获取工具
func (tm *ToolManager) GetTool(name string) (ToolInterface, bool) {
	tool, exists := tm.Tools[name]
	return tool, exists
}

// GetAvailableTools 获取可用工具列表
func (tm *ToolManager) GetAvailableTools() map[string]bool {
	availableTools := make(map[string]bool)
	for name, tool := range tm.Tools {
		availableTools[name] = tool.IsAvailable()
	}
	return availableTools
}

// GetAvailableToolNames 获取可用工具名称列表
func (tm *ToolManager) GetAvailableToolNames() []string {
	var availableToolNames []string
	for name, tool := range tm.Tools {
		if tool.IsAvailable() {
			availableToolNames = append(availableToolNames, name)
		}
	}
	return availableToolNames
}

// ScanSystemTools 扫描系统中可用的工具 - 增强版，支持更多安全渗透工具
func ScanSystemTools(aiClient AIClientInterface) *ToolManager {
	toolManager := NewToolManager()

	// 扩展支持的安全渗透工具列表（增强版）
	supportedTools := []string{
		// 网络扫描工具
		"nmap", "masscan", "zmap", "unicornscan", "hping3",
		// 域名枚举工具
		"amass", "subfinder", "subjack", "assetfinder", "findomain", "dnsrecon", "dnsenum", "sublist3r", "httpx",
		// Web应用扫描工具
		"nikto", "dirb", "gobuster", "dirsearch", "ffuf", "wfuzz", "arjun", "nuclei",
		// 数据库安全工具
		"sqlmap", "sqlninja", "sqlsus", "bbqsql",
		// 漏洞扫描工具
		"nessus", "openvas", "nexpose", "metasploit-framework", "msfconsole", "exploitdb", "wpscan", "joomscan", "drupwn",
		// 信息收集工具
		"whatweb", "wafw00f", "theharvester", "recon-ng", "maltego", "shodan",
		// 密码破解工具
		"hydra", "medusa", "ncrack", "john", "hashcat", "ophcrack", "rainbowcrack",
		// 无线安全工具
		"aircrack-ng", "reaver", "wifite", "kismet", "airmon-ng", "airodump-ng",
		// 网络分析工具
		"wireshark", "tcpdump", "tshark", "ettercap", "driftnet", "nc", "netcat", "ncat", "socat",
		// 社会工程学工具
		"setoolkit", "social-engineer-toolkit", "beef", "phishing-frenzy",
		// 后渗透工具
		"meterpreter", "empire", "cobaltstrike", "pupy", "powersploit",
		// 开发工具
		"curl", "wget", "python3", "python", "perl", "ruby", "java", "node", "npm",
		"git", "docker", "kubectl", "ansible", "terraform", "vagrant",
		// 系统工具
		"ssh", "scp", "rsync", "tar", "gzip", "zip", "unzip", "find", "grep", "awk", "sed",
		"ftp", "rdp", "smbclient", "rpcclient",
		// 数据库工具
		"mysql", "psql", "sqlite3", "mssql-cli",
		// 其他安全工具
		"burpsuite", "zap", "gdb", "radare2", "ida", "ollydbg", "immunitydebugger",
		"volatility", "autopsy", "sleuthkit", "binwalk", "foremost", "scalpel",
	}

	// 并行扫描工具以提高效率
	toolChan := make(chan struct {
		name      string
		path      string
		available bool
	}, len(supportedTools))
	var wg sync.WaitGroup

	for _, toolName := range supportedTools {
		wg.Add(1)
		go func(toolName string) {
			defer wg.Done()

			path, available := findToolPath(toolName)
			toolChan <- struct {
				name      string
				path      string
				available bool
			}{name: toolName, path: path, available: available}
		}(toolName)
	}

	// 等待所有扫描完成
	go func() {
		wg.Wait()
		close(toolChan)
	}()

	// 收集结果
	for result := range toolChan {
		tool := &BaseTool{
			NameValue: result.name,
			Path:      result.path,
			Available: result.available,
		}

		// 直接添加到工具映射
		toolManager.Tools[result.name] = tool

		// 输出结果
		if result.available {
			utils.SuccessPrint("✓ 检测到工具: %s -> %s", result.name, result.path)
		} else {
			utils.WarningPrint("✗ 未检测到工具: %s", result.name)
		}
	}

	// 如果提供了AI客户端，创建智能工具管理器
	if aiClient != nil {
		smartManager := NewSmartToolManager(toolManager, aiClient)
		toolManager.SetSmartManager(smartManager)
		smartManager.InitializeCache()
		utils.SuccessPrint("智能工具管理器初始化完成")
	}

	// 生成工具扫描报告
	generateToolScanReport(toolManager)

	return toolManager
}

// generateToolScanReport 生成工具扫描报告
func generateToolScanReport(toolManager *ToolManager) {
	utils.InfoPrint("生成工具扫描报告...")

	// 按类别统计
	categories := map[string][]string{
		"网络扫描":    {"nmap", "masscan", "zmap", "unicornscan", "hping3"},
		"域名枚举":    {"amass", "subfinder", "subjack", "assetfinder", "findomain", "dnsrecon", "dnsenum", "sublist3r"},
		"Web应用扫描": {"nikto", "dirb", "gobuster", "dirsearch", "ffuf", "wfuzz", "arjun", "nuclei", "httpx"},
		"数据库安全":   {"sqlmap", "sqlninja", "sqlsus", "bbqsql"},
		"漏洞扫描":    {"nessus", "openvas", "nexpose", "metasploit-framework", "msfconsole", "exploitdb", "wpscan", "joomscan", "drupwn"},
		"信息收集":    {"whatweb", "wafw00f", "theharvester", "recon-ng", "maltego", "shodan"},
		"密码破解":    {"hydra", "medusa", "ncrack", "john", "hashcat", "ophcrack", "rainbowcrack"},
		"无线安全":    {"aircrack-ng", "reaver", "wifite", "kismet", "airmon-ng", "airodump-ng"},
		"网络分析":    {"wireshark", "tcpdump", "tshark", "ettercap", "driftnet", "nc", "netcat", "ncat", "socat"},
		"社会工程学":   {"setoolkit", "social-engineer-toolkit", "beef", "phishing-frenzy"},
		"后渗透工具":   {"meterpreter", "empire", "cobaltstrike", "pupy", "powersploit"},
		"开发工具":    {"curl", "wget", "python3", "python", "perl", "ruby", "java", "node", "npm", "git", "docker", "kubectl", "ansible", "terraform", "vagrant"},
		"系统工具":    {"ssh", "scp", "rsync", "tar", "gzip", "zip", "unzip", "find", "grep", "awk", "sed", "ftp", "rdp", "smbclient", "rpcclient"},
		"数据库工具":   {"mysql", "psql", "sqlite3", "mssql-cli"},
		"其他安全工具":  {"burpsuite", "zap", "gdb", "radare2", "ida", "ollydbg", "immunitydebugger", "volatility", "autopsy", "sleuthkit", "binwalk", "foremost", "scalpel"},
	}

	categoryCounts := make(map[string]int)
	totalFound := 0

	for category, toolList := range categories {
		count := 0
		for _, toolName := range toolList {
			if tool, exists := toolManager.GetTool(toolName); exists && tool.IsAvailable() {
				count++
				totalFound++
			}
		}
		categoryCounts[category] = count
	}

	// 输出报告
	utils.InfoPrint("=== 工具扫描报告 ===")
	utils.InfoPrint("总发现工具数: %d", totalFound)
	utils.InfoPrint("分类统计:")

	for category, count := range categoryCounts {
		if count > 0 {
			utils.SuccessPrint("  %s: %d个工具", category, count)
		}
	}

	utils.InfoPrint("=== 报告结束 ===")
}

// CheckToolMappingExists 检查配置文件中是否有工具记录
func CheckToolMappingExists(configPath string) (bool, error) {
	// 获取默认配置路径（如果未提供）
	if configPath == "" {
		configPath = config.GetDefaultConfigPath()
	}

	// 检查配置文件是否存在
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		return false, nil // 配置文件不存在，没有工具记录
	}

	// 加载现有配置
	cfgPtr, loadErr := config.LoadConfig(configPath)
	if loadErr != nil {
		return false, fmt.Errorf("加载配置失败: %v", loadErr)
	}

	cfg := *cfgPtr

	// 检查ToolMapping字段是否存在且有内容
	if cfg.ToolMapping == nil || len(cfg.ToolMapping) == 0 {
		return false, nil // 工具映射为空
	}

	// 检查是否有任何已记录的工具（值为true表示工具存在）
	hasTools := false
	for _, exists := range cfg.ToolMapping {
		if exists {
			hasTools = true
			break
		}
	}

	return hasTools, nil
}

// LoadToolManagerFromConfig 从配置文件加载工具管理器
func LoadToolManagerFromConfig(configPath string) *ToolManager {
	// 获取默认配置路径（如果未提供）
	if configPath == "" {
		configPath = config.GetDefaultConfigPath()
	}

	// 检查配置文件是否存在
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		utils.WarningPrint("配置文件不存在: %s", configPath)
		return nil
	}

	// 加载现有配置
	cfgPtr, loadErr := config.LoadConfig(configPath)
	if loadErr != nil {
		utils.WarningPrint("加载配置失败: %v", loadErr)
		return nil
	}

	cfg := *cfgPtr

	// 检查ToolMapping字段是否存在
	if cfg.ToolMapping == nil || len(cfg.ToolMapping) == 0 {
		utils.WarningPrint("配置文件中没有工具记录")
		return nil
	}

	// 创建工具管理器并设置可用工具
	toolManager := &ToolManager{
		Tools: make(map[string]ToolInterface),
	}

	// 根据配置中的工具映射创建工具对象
	for toolName, available := range cfg.ToolMapping {
		if available {
			// 工具可用，创建工具对象
			tool := &BaseTool{
				NameValue: toolName,
				Path:      "",    // 路径需要重新查找
				Available: false, // 初始化为不可用
			}

			// 尝试查找工具路径
			if path, found := findToolPath(toolName); found {
				tool.Path = path
				tool.Available = true
			} else {
				// 工具路径未找到，标记为不可用
				tool.Available = false
				utils.WarningPrint("工具 %s 在配置中标记为可用，但未找到路径", toolName)
			}

			toolManager.Tools[toolName] = tool
		}
	}

	utils.InfoPrint("从配置文件加载了 %d 个可用工具", len(toolManager.Tools))
	return toolManager
}

// SaveToolScanResults 保存工具扫描结果到配置
func SaveToolScanResults(toolManager *ToolManager, configPath string) error {
	// 获取可用工具列表
	availableTools := toolManager.GetAvailableTools()

	// 获取默认配置路径（如果未提供）
	if configPath == "" {
		configPath = config.GetDefaultConfigPath()
	}

	// 检查配置文件是否存在，如果不存在则创建默认配置
	var cfg config.AIConfig
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		// 使用默认配置
		cfg = config.GetDefaultConfig()
	} else {
		// 加载现有配置
		cfgPtr, loadErr := config.LoadConfig(configPath)
		if loadErr != nil {
			// 加载失败，尝试只更新工具映射而不覆盖provider设置
			utils.WarningPrint("加载配置失败，尝试仅更新工具映射: %v", loadErr)

			// 尝试读取原始配置文件内容，只更新工具映射部分
			if originalContent, readErr := os.ReadFile(configPath); readErr == nil {
				var originalConfig map[string]interface{}
				if yamlErr := yaml.Unmarshal(originalContent, &originalConfig); yamlErr == nil {
					// 保留原始配置，只更新工具映射
					originalConfig["tool_mapping"] = availableTools

					// 保存更新后的配置
					if updatedContent, marshalErr := yaml.Marshal(originalConfig); marshalErr == nil {
						if writeErr := os.WriteFile(configPath, updatedContent, 0644); writeErr == nil {
							utils.SuccessPrint("工具映射已更新到配置文件: %s", configPath)
							return nil
						}
					}
				}
			}

			// 如果上述方法失败，使用默认配置但记录警告
			utils.WarningPrint("无法更新工具映射，使用默认配置")
			cfg = config.GetDefaultConfig()
		} else {
			cfg = *cfgPtr
		}
	}

	// 更新工具映射
	cfg.ToolMapping = availableTools

	// 保存配置
	if saveErr := config.SaveConfig(cfg, configPath, true); saveErr != nil {
		return fmt.Errorf("保存配置失败: %v", saveErr)
	}

	utils.SuccessPrint("工具扫描结果已保存到配置文件: %s", configPath)
	return nil
}

// PerformInformationGathering 执行完整的信息收集
func PerformInformationGathering(target string, toolManager *ToolManager) (map[string]string, error) {
	utils.InfoPrint("=== 开始信息收集阶段 ===")
	results := make(map[string]string)

	// 1. 网络扫描 - 使用nmap进行完整端口扫描
	if nmap, exists := toolManager.GetTool("nmap"); exists && nmap.IsAvailable() {
		utils.InfoPrint("正在使用nmap进行端口扫描...")
		nmapArgs := []string{"-sV", "-sC", "-A", "-O", "-p-", "--script=default,vuln", target}
		nmapResult, err := RunTool(nmap, nmapArgs...)
		if err != nil {
			utils.ErrorPrint("nmap扫描失败: %v", err)
		} else {
			results["nmap"] = nmapResult
			utils.SuccessPrint("nmap扫描完成")
		}
	}

	// 2. Web 服务扫描 - 使用nikto扫描web服务
	if nikto, exists := toolManager.GetTool("nikto"); exists && nikto.IsAvailable() {
		utils.InfoPrint("正在使用nikto进行web服务扫描...")
		niktoArgs := []string{"-h", target}
		niktoResult, err := RunTool(nikto, niktoArgs...)
		if err != nil {
			utils.ErrorPrint("nikto扫描失败: %v", err)
		} else {
			results["nikto"] = niktoResult
			utils.SuccessPrint("nikto扫描完成")
		}
	}

	// 3. 目录扫描 - 使用dirb进行目录枚举
	if dirb, exists := toolManager.GetTool("dirb"); exists && dirb.IsAvailable() {
		utils.InfoPrint("正在使用dirb进行目录扫描...")
		dirbArgs := []string{fmt.Sprintf("http://%s", target), "/usr/share/wordlists/dirb/common.txt"}
		dirbResult, err := RunTool(dirb, dirbArgs...)
		if err != nil {
			utils.ErrorPrint("dirb扫描失败: %v", err)
		} else {
			results["dirb"] = dirbResult
			utils.SuccessPrint("dirb扫描完成")
		}
	}

	// 4. 子域名枚举 - 使用subfinder进行子域名发现
	if subfinder, exists := toolManager.GetTool("subfinder"); exists && subfinder.IsAvailable() {
		utils.InfoPrint("正在使用subfinder进行子域名枚举...")
		subfinderArgs := []string{"-d", target, "-recursive"}
		subfinderResult, err := RunTool(subfinder, subfinderArgs...)
		if err != nil {
			utils.ErrorPrint("subfinder枚举失败: %v", err)
		} else {
			results["subfinder"] = subfinderResult
			utils.SuccessPrint("subfinder枚举完成")
		}
	}

	// 5. 指纹识别 - 使用whatweb进行服务识别
	if whatweb, exists := toolManager.GetTool("whatweb"); exists && whatweb.IsAvailable() {
		utils.InfoPrint("正在使用whatweb进行服务指纹识别...")
		whatwebArgs := []string{target}
		whatwebResult, err := RunTool(whatweb, whatwebArgs...)
		if err != nil {
			utils.ErrorPrint("whatweb识别失败: %v", err)
		} else {
			results["whatweb"] = whatwebResult
			utils.SuccessPrint("whatweb识别完成")
		}
	}

	// 6. WAF 检测 - 使用wafw00f进行WAF识别
	if wafw00f, exists := toolManager.GetTool("wafw00f"); exists && wafw00f.IsAvailable() {
		utils.InfoPrint("正在使用wafw00f进行WAF检测...")
		wafw00fArgs := []string{target}
		wafw00fResult, err := RunTool(wafw00f, wafw00fArgs...)
		if err != nil {
			utils.ErrorPrint("wafw00f检测失败: %v", err)
		} else {
			results["wafw00f"] = wafw00fResult
			utils.SuccessPrint("wafw00f检测完成")
		}
	}

	utils.InfoPrint("=== 信息收集阶段完成 ===")
	return results, nil
}

// findToolPath 查找工具路径 - 增强版，支持全盘扫描
func findToolPath(toolName string) (string, bool) {
	// 获取当前操作系统
	currentOS := runtime.GOOS

	// 首先尝试系统命令查找（最快）
	if path, found := findToolBySystemCommand(toolName, currentOS); found {
		return path, true
	}

	// 然后尝试预定义的常见路径
	if path, found := findToolByCommonPaths(toolName, currentOS); found {
		return path, true
	}

	// 最后进行全盘扫描（最慢但最全面）
	if path, found := findToolByFullDiskScan(toolName, currentOS); found {
		return path, true
	}

	return "", false
}

// findToolBySystemCommand 使用系统命令查找工具
func findToolBySystemCommand(toolName string, osType string) (string, bool) {
	var cmd *exec.Cmd

	if osType == "windows" {
		cmd = exec.Command("where", toolName)
		// 在Windows上，也尝试查找带.exe扩展名的工具
		cmd2 := exec.Command("where", toolName+".exe")
		if output, err := cmd2.CombinedOutput(); err == nil {
			path := strings.TrimSpace(string(output))
			if path != "" {
				absPath, _ := filepath.Abs(path)
				return absPath, true
			}
		}
	} else {
		cmd = exec.Command("which", toolName)
	}

	output, err := cmd.CombinedOutput()
	if err == nil {
		path := strings.TrimSpace(string(output))
		if path != "" {
			absPath, _ := filepath.Abs(path)
			return absPath, true
		}
	}

	return "", false
}

// findToolByCommonPaths 在常见路径中查找工具
func findToolByCommonPaths(toolName string, osType string) (string, bool) {
	// 构建系统特定的工具路径映射（扩展版）
	toolPaths := map[string][]string{
		"linux": {
			// 标准系统路径
			"/usr/bin/%s",
			"/usr/local/bin/%s",
			"/bin/%s",
			"/usr/sbin/%s",
			"/sbin/%s",
			"/usr/local/sbin/%s",
			// 用户路径
			"$HOME/.local/bin/%s",
			"$HOME/bin/%s",
			"$HOME/.cargo/bin/%s",
			"$HOME/go/bin/%s",
			// 渗透测试系统常见路径（Kali、ParrotOS等）
			"/opt/%s/%s",
			"/opt/tools/%s",
			"/usr/share/%s/%s",
			"/usr/lib/%s/%s",
			// 特定工具常见路径
			"/usr/share/nmap/scripts/%s.nse",
			"/usr/share/metasploit-framework/tools/%s",
			"/usr/share/sqlmap/%s.py",
			"/usr/share/wordlists/%s",
			// 容器化工具路径
			"/snap/bin/%s",
			"/var/lib/snapd/snap/bin/%s",
			// 包管理器路径
			"/usr/libexec/%s",
			"/usr/lib/%s/bin/%s",
		},
		"windows": {
			// 系统路径
			"C:\\Windows\\System32\\%s.exe",
			"C:\\Windows\\%s.exe",
			"C:\\Windows\\SysWOW64\\%s.exe",
			// 程序文件路径
			"C:\\Program Files\\%s\\%s.exe",
			"C:\\Program Files (x86)\\%s\\%s.exe",
			// 用户路径
			"$USERPROFILE\\AppData\\Local\\Programs\\%s\\%s.exe",
			"$USERPROFILE\\AppData\\Roaming\\%s\\%s.exe",
			"$USERPROFILE\\%s.exe",
			// 工具专用路径
			"C:\\Tools\\%s\\%s.exe",
			"C:\\Pentest\\%s\\%s.exe",
			"D:\\Tools\\%s\\%s.exe",
			// 环境变量路径
			"%s.exe",
			// WSL路径
			"C:\\Users\\%s\\AppData\\Local\\Microsoft\\WindowsApps\\%s.exe",
			// Chocolatey路径
			"C:\\ProgramData\\chocolatey\\bin\\%s.exe",
		},
	}

	// 获取对应操作系统的路径列表
	paths, exists := toolPaths[osType]
	if !exists {
		return "", false
	}

	// 查找工具路径
	for _, pattern := range paths {
		path := fmt.Sprintf(pattern, toolName, toolName)

		// 处理环境变量
		if osType == "linux" {
			path = strings.ReplaceAll(path, "$HOME", os.Getenv("HOME"))
		} else if osType == "windows" {
			path = strings.ReplaceAll(path, "$USERPROFILE", os.Getenv("USERPROFILE"))
			// 处理用户名替换
			if strings.Contains(path, "%s") {
				username := os.Getenv("USERNAME")
				path = strings.ReplaceAll(path, "%s", username)
			}
		}

		// 检查路径是否存在
		if _, err := os.Stat(path); err == nil {
			absPath, _ := filepath.Abs(path)
			return absPath, true
		}
	}

	return "", false
}

// findToolByFullDiskScan 全盘扫描查找工具
func findToolByFullDiskScan(toolName string, osType string) (string, bool) {
	utils.InfoPrint("正在全盘扫描查找工具: %s", toolName)

	// 定义搜索模式
	var searchPatterns []string
	if osType == "windows" {
		searchPatterns = []string{
			"*" + toolName + "*.exe",
			"*" + toolName + "*.bat",
			"*" + toolName + "*.cmd",
		}
	} else {
		searchPatterns = []string{
			"*" + toolName + "*",
		}
	}

	// 定义搜索路径（根据操作系统）
	var searchRoots []string
	if osType == "windows" {
		searchRoots = []string{
			"C:\\",
			"D:\\",
			"E:\\",
			os.Getenv("USERPROFILE"),
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\Tools",
			"C:\\Pentest",
		}
	} else {
		searchRoots = []string{
			"/usr",
			"/opt",
			"/bin",
			"/sbin",
			"/usr/local",
			os.Getenv("HOME"),
			"/var",
			"/lib",
		}
	}

	// 限制搜索深度和文件数量，避免性能问题
	maxFiles := 1000
	foundFiles := 0

	for _, root := range searchRoots {
		if _, err := os.Stat(root); err != nil {
			continue // 跳过不存在的路径
		}

		for _, pattern := range searchPatterns {
			matches, err := filepath.Glob(filepath.Join(root, pattern))
			if err != nil {
				continue
			}

			for _, match := range matches {
				// 检查文件是否可执行
				if info, err := os.Stat(match); err == nil && !info.IsDir() {
					// 在Linux上检查文件权限
					if osType != "windows" {
						if info.Mode()&0111 != 0 { // 检查可执行权限
							absPath, _ := filepath.Abs(match)
							utils.SuccessPrint("全盘扫描发现工具: %s -> %s", toolName, absPath)
							return absPath, true
						}
					} else {
						// Windows上直接返回
						absPath, _ := filepath.Abs(match)
						utils.SuccessPrint("全盘扫描发现工具: %s -> %s", toolName, absPath)
						return absPath, true
					}
				}

				foundFiles++
				if foundFiles >= maxFiles {
					break
				}
			}
		}
	}

	return "", false
}

// RunTool 执行工具命令
func RunTool(tool ToolInterface, args ...string) (string, error) {
	if !tool.IsAvailable() {
		return "", fmt.Errorf("工具 %s 不可用", tool.Name())
	}

	// 构建命令
	cmd := exec.Command(tool.GetPath(), args...)

	// 捕获命令输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("执行命令 %s 失败: %v", tool.Name(), err)
	}

	// 输出命令结果
	fmt.Println(string(output))

	return string(output), nil
}

// RunCommand 执行系统命令，捕获命令输出
func RunCommand(cmdName string, args ...string) (string, error) {
	// 构建命令
	cmd := exec.Command(cmdName, args...)

	// 捕获命令输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("执行命令 %s 失败: %v", cmdName, err)
	}

	// 输出命令结果
	fmt.Println(string(output))

	return string(output), nil
}

// initResourceDir 初始化资源目录
func initResourceDir(resourceDir string) string {
	// 如果没有指定资源目录，使用默认路径
	if resourceDir == "" {
		// 获取用户主目录
		homeDir, err := os.UserHomeDir()
		if err != nil {
			utils.ErrorPrint("获取用户主目录失败: %v", err)
			// 如果获取失败，使用当前目录
			homeDir = "."
		}
		// 默认资源目录: 用户主目录/GYscan/Resources
		resourceDir = filepath.Join(homeDir, "GYscan", "Resources")
	}

	// 创建资源目录及其父目录
	if err := os.MkdirAll(resourceDir, 0755); err != nil {
		utils.ErrorPrint("创建资源目录失败: %v", err)
		// 如果创建失败，使用当前目录
		resourceDir = "."
	}

	return resourceDir
}
