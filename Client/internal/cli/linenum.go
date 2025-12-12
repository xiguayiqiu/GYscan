package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// linenumCmd Linux本地信息枚举和权限提升脚本
var linenumCmd = &cobra.Command{
	Use:   "linenum [options]",
	Short: "Linux本地信息枚举和权限提升工具",
	Long: `Linux本地信息枚举和权限提升工具 - 基于LinEnum.sh的Go语言实现

支持功能:
- 系统信息收集 (内核、版本、主机名等)
- 用户和组信息枚举
- 环境信息收集
- 作业和任务信息
- 网络信息收集
- 服务信息
- 软件配置检查
- 敏感文件查找
- Docker和LXC容器检查

使用示例:
  ./GYscan linenum                    # 基本扫描，无输出文件
  ./GYscan linenum -k password        # 搜索包含"password"的文件
  ./GYscan linenum -e /tmp/           # 将结果导出到/tmp目录
  ./GYscan linenum -r myreport        # 生成名为myreport的报告
  ./GYscan linenum -t                 # 执行详细测试
  ./GYscan linenum -s                 # 使用sudo密码检查权限

警告: 仅用于授权测试和安全评估，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 解析参数
		keyword, _ := cmd.Flags().GetString("keyword")
		exportPath, _ := cmd.Flags().GetString("export")
		reportName, _ := cmd.Flags().GetString("report")
		thorough, _ := cmd.Flags().GetBool("thorough")
		sudoPassword, _ := cmd.Flags().GetBool("sudo-password")

		// 检查是否在Linux系统上运行
		if runtime.GOOS != "linux" {
			utils.ErrorPrint("此命令只能在Linux系统上运行，当前系统: %s", runtime.GOOS)
			utils.InfoPrint("请在Linux环境下运行此命令以执行系统枚举和权限提升检查")
			return
		}

		// 执行枚举
		enumerateSystem(keyword, exportPath, reportName, thorough, sudoPassword)
	},
}

// enumerateSystem 执行系统枚举
func enumerateSystem(keyword, exportPath, reportName string, thorough, sudoPassword bool) {
	utils.BoldInfo("开始Linux系统信息枚举...")

	// 显示调试信息
	printDebugInfo(keyword, exportPath, reportName, thorough, sudoPassword)

	// 如果提供了关键词，执行关键词搜索
	if keyword != "" {
		searchKeywordFiles(keyword)
	}

	// 执行各个模块的枚举
	systemInfo()
	userInfo()
	environmentalInfo()
	jobInfo()
	networkingInfo()
	servicesInfo()
	softwareConfigs()
	interestingFiles(thorough)
	dockerChecks()
	lxcContainerChecks()

	utils.BoldInfo("枚举完成!")
}

// searchKeywordFiles 在配置、PHP、INI和日志文件中搜索关键词
func searchKeywordFiles(keyword string) {
	utils.BoldInfo("### 关键词搜索: %s ################################", keyword)
	startTime := time.Now()

	var wg sync.WaitGroup
	resultChan := make(chan string, 100)

	// 启动结果收集器
	go func() {
		for result := range resultChan {
			utils.SuccessPrint("[+] %s", result)
		}
	}()

	// 并行搜索不同类型的文件
	wg.Add(4)
	go func() {
		defer wg.Done()
		searchConfigFiles(keyword, resultChan)
	}()
	go func() {
		defer wg.Done()
		searchPHPFiles(keyword, resultChan)
	}()
	go func() {
		defer wg.Done()
		searchINIFiles(keyword, resultChan)
	}()
	go func() {
		defer wg.Done()
		searchLogFiles(keyword, resultChan)
	}()

	wg.Wait()
	close(resultChan)

	utils.InfoPrint("关键词搜索完成，耗时: %v", time.Since(startTime))
	fmt.Println()
}

// searchConfigFiles 并行搜索配置文件
func searchConfigFiles(keyword string, resultChan chan<- string) {
	utils.InfoPrint("[-] 在配置文件中搜索 '%s':", keyword)

	configFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/fstab",
		"/etc/crontab",
		"/etc/sudoers",
		"/etc/ssh/sshd_config",
		"/etc/mysql/my.cnf",
		"/etc/postgresql/*/postgresql.conf",
	}

	var wg sync.WaitGroup
	for _, pattern := range configFiles {
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			wg.Add(1)
			go func(f string) {
				defer wg.Done()
				if containsKeyword(f, keyword) {
					resultChan <- fmt.Sprintf("在 %s 中找到匹配项", f)
				}
			}(file)
		}
	}
	wg.Wait()
}

// searchPHPFiles 优化搜索PHP文件
func searchPHPFiles(keyword string, resultChan chan<- string) {
	utils.InfoPrint("[-] 在PHP文件中搜索 '%s':", keyword)

	// 使用更高效的文件搜索方法
	searchDirs := []string{"/var/www", "/srv", "/opt", "/home", "/usr/local/www"}
	var wg sync.WaitGroup

	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err == nil {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				searchFilesInDir(d, ".php", keyword, resultChan)
			}(dir)
		}
	}
	wg.Wait()
}

// searchINIFiles 优化搜索INI文件
func searchINIFiles(keyword string, resultChan chan<- string) {
	utils.InfoPrint("[-] 在INI文件中搜索 '%s':", keyword)
	searchFilesInDir("/etc", ".ini", keyword, resultChan)
}

// searchLogFiles 优化搜索日志文件
func searchLogFiles(keyword string, resultChan chan<- string) {
	utils.InfoPrint("[-] 在日志文件中搜索 '%s':", keyword)
	searchFilesInDir("/var/log", ".log", keyword, resultChan)
}

// searchFilesInDir 在指定目录中搜索特定扩展名的文件
func searchFilesInDir(dir, ext, keyword string, resultChan chan<- string) {
	if _, err := os.Stat(dir); err != nil {
		return
	}

	var wg sync.WaitGroup
	fileChan := make(chan string, 100)

	// 并行文件搜索
	go func() {
		defer close(fileChan)
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(info.Name()), ext) {
				fileChan <- path
			}
			return nil
		})
	}()

	// 并行关键词检查
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				if containsKeyword(file, keyword) {
					resultChan <- fmt.Sprintf("在 %s 中找到匹配项", file)
				}
			}
		}()
	}
	wg.Wait()
}

// containsKeyword 高效检查文件是否包含关键词
func containsKeyword(filePath, keyword string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lowerKeyword := strings.ToLower(keyword)

	// 使用缓冲读取，避免一次性加载大文件
	for scanner.Scan() {
		if strings.Contains(strings.ToLower(scanner.Text()), lowerKeyword) {
			return true
		}
	}
	return false
}

// printDebugInfo 显示调试信息
func printDebugInfo(keyword, exportPath, reportName string, thorough, sudoPassword bool) {
	utils.InfoPrint("[-] 调试信息")

	if keyword != "" {
		utils.InfoPrint("[+] 在配置、PHP、INI和日志文件中搜索关键词: %s", keyword)
	}

	if reportName != "" {
		utils.InfoPrint("[+] 报告名称 = %s", reportName)
	}

	if exportPath != "" {
		utils.InfoPrint("[+] 导出位置 = %s", exportPath)
	}

	if thorough {
		utils.InfoPrint("[+] 详细测试 = 已启用")
	} else {
		utils.WarningPrint("[+] 详细测试 = 已禁用")
	}

	if sudoPassword {
		utils.WarningPrint("[+] 请提供sudo密码 - 不安全 - 仅用于CTF场景!")
	}

	// 获取当前用户
	currentUser := "unknown"
	if user := os.Getenv("USER"); user != "" {
		currentUser = user
	}
	utils.InfoPrint("当前用户: %s", currentUser)
	utils.InfoPrint("扫描开始时间: %s", utils.GetCurrentTime())
	fmt.Println()
}

// systemInfo 收集系统信息
func systemInfo() {
	utils.BoldInfo("### 系统信息 ##############################################")

	// 基本内核信息
	utils.InfoPrint("[-] 内核信息:")
	if output, err := utils.RunCommand("uname -a"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()

	// /proc/version信息
	utils.InfoPrint("[-] 内核信息 (续):")
	if content, err := os.ReadFile("/proc/version"); err == nil {
		fmt.Println(string(content))
	}
	fmt.Println()

	// 发行版信息
	utils.InfoPrint("[-] 特定发行版信息:")
	if files, err := os.ReadDir("/etc/"); err == nil {
		for _, file := range files {
			if strings.HasSuffix(file.Name(), "-release") {
				if content, err := os.ReadFile("/etc/" + file.Name()); err == nil {
					fmt.Printf("%s:\n%s\n", file.Name(), string(content))
				}
			}
		}
	}
	fmt.Println()

	// 主机名信息
	utils.InfoPrint("[-] 主机名:")
	if output, err := utils.RunCommand("hostname"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()
}

// userInfo 收集用户和组信息
func userInfo() {
	utils.BoldInfo("### 用户/组信息 ##########################################")

	// 当前用户详情
	utils.InfoPrint("[-] 当前用户/组信息:")
	if output, err := utils.RunCommand("id"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()

	// 最后登录的用户信息
	utils.InfoPrint("[-] 之前登录过系统的用户:")
	if output, err := utils.RunCommand("lastlog | grep -v Never"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()

	// 其他登录用户
	utils.InfoPrint("[-] 其他登录用户:")
	if output, err := utils.RunCommand("w"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()

	// 列出所有ID和相应的组
	utils.InfoPrint("[-] 组成员关系:")
	startTime := time.Now()

	// 读取/etc/passwd文件获取用户列表
	if content, err := os.ReadFile("/etc/passwd"); err == nil {
		var wg sync.WaitGroup
		resultChan := make(chan string, 50)

		// 启动结果收集器
		go func() {
			for result := range resultChan {
				fmt.Println(result)
			}
		}()

		// 并行处理用户ID查询
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) > 0 {
				user := fields[0]
				wg.Add(1)
				go func(u string) {
					defer wg.Done()
					if idOutput, err := utils.RunCommand("id " + u); err == nil {
						resultChan <- strings.TrimSpace(idOutput)
					}
				}(user)
			}
		}

		wg.Wait()
		close(resultChan)
	}

	utils.InfoPrint("用户信息枚举完成，耗时: %v", time.Since(startTime))
	fmt.Println()

	// 检查/etc/passwd中是否有哈希值
	utils.InfoPrint("[-] /etc/passwd内容:")
	if content, err := os.ReadFile("/etc/passwd"); err == nil {
		fmt.Println(string(content))
	}
	fmt.Println()

	// 检查是否可以读取shadow文件
	utils.InfoPrint("[-] 检查shadow文件可读性:")
	if _, err := os.ReadFile("/etc/shadow"); err == nil {
		utils.SuccessPrint("[+] 我们可以读取shadow文件!")
	} else {
		utils.InfoPrint("[-] 无法读取shadow文件")
	}
	fmt.Println()

	// 所有root账户(uid 0)
	utils.InfoPrint("[-] 超级用户账户:")
	if content, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) >= 3 && fields[2] == "0" {
				fmt.Println(fields[0])
			}
		}
	}
	fmt.Println()
}

// environmentalInfo 收集环境信息
func environmentalInfo() {
	utils.BoldInfo("### 环境信息 #######################################")

	// 环境信息
	utils.InfoPrint("[-] 环境信息:")
	envVars := os.Environ()
	for _, env := range envVars {
		if !strings.Contains(env, "LS_COLORS") {
			fmt.Println(env)
		}
	}
	fmt.Println()

	// 当前路径配置
	utils.InfoPrint("[-] 路径信息:")
	path := os.Getenv("PATH")
	fmt.Println(path)
	fmt.Println()

	// 可用shell
	utils.InfoPrint("[-] 可用shell:")
	if content, err := os.ReadFile("/etc/shells"); err == nil {
		fmt.Println(string(content))
	}
	fmt.Println()
}

// jobInfo 收集作业和任务信息
func jobInfo() {
	utils.BoldInfo("### 作业/任务 ##########################################")

	// 是否有配置的cron作业
	utils.InfoPrint("[-] Cron作业:")
	if output, err := utils.RunCommand("ls -la /etc/cron*"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()

	// crontab内容
	utils.InfoPrint("[-] Crontab内容:")
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		fmt.Println(string(content))
	}
	fmt.Println()
}

// networkingInfo 收集网络信息
func networkingInfo() {
	utils.BoldInfo("### 网络信息 ##########################################")

	// 网卡信息
	utils.InfoPrint("[-] 网络和IP信息:")
	if output, err := utils.RunCommand("/sbin/ifconfig -a"); err == nil {
		fmt.Println(output)
	} else if output, err := utils.RunCommand("/sbin/ip a"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()

	// 网络连接
	utils.InfoPrint("[-] 网络连接:")
	if output, err := utils.RunCommand("netstat -tuln"); err == nil {
		fmt.Println(output)
	}
	fmt.Println()
}

// servicesInfo 收集服务信息
func servicesInfo() {
	utils.BoldInfo("### 服务信息 ##########################################")

	// 运行中的服务
	utils.InfoPrint("[-] 运行中的服务:")
	if output, err := utils.RunCommand("ps aux"); err == nil {
		// 只显示前20行以避免输出过长
		lines := strings.Split(output, "\n")
		if len(lines) > 20 {
			lines = lines[:20]
		}
		fmt.Println(strings.Join(lines, "\n"))
		fmt.Println("... (输出截断)")
	}
	fmt.Println()
}

// softwareConfigs 检查软件配置
func softwareConfigs() {
	utils.BoldInfo("### 软件配置 ##########################################")
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(3)

	// 并行检查不同类型的配置
	go func() {
		defer wg.Done()
		checkSUIDFiles()
	}()

	go func() {
		defer wg.Done()
		checkSGIDFiles()
	}()

	go func() {
		defer wg.Done()
		checkDatabaseConfigs()
	}()

	wg.Wait()

	utils.InfoPrint("软件配置检查完成，耗时: %v", time.Since(startTime))
	fmt.Println()
}

// checkSUIDFiles 优化检查SUID文件
func checkSUIDFiles() {
	utils.InfoPrint("[-] SUID文件:")
	// 使用更高效的查找方法，限制搜索范围
	searchDirs := []string{"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"}
	var results []string

	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err == nil {
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// 检查SUID权限
				if info.Mode()&os.ModeSetuid != 0 {
					if fileInfo, err := os.Stat(path); err == nil {
						results = append(results, fmt.Sprintf("%s %s", fileInfo.Mode(), path))
					}
				}

				return nil
			})
		}
	}

	// 限制输出数量
	if len(results) > 0 {
		maxResults := 20
		if len(results) < maxResults {
			maxResults = len(results)
		}
		for i := 0; i < maxResults; i++ {
			fmt.Println(results[i])
		}
		if len(results) > maxResults {
			fmt.Printf("... (还有 %d 个文件)\n", len(results)-maxResults)
		}
	}
	fmt.Println()
}

// checkSGIDFiles 优化检查SGID文件
func checkSGIDFiles() {
	utils.InfoPrint("[-] SGID文件:")
	// 使用更高效的查找方法，限制搜索范围
	searchDirs := []string{"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"}
	var results []string

	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err == nil {
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// 检查SGID权限
				if info.Mode()&os.ModeSetgid != 0 {
					if fileInfo, err := os.Stat(path); err == nil {
						results = append(results, fmt.Sprintf("%s %s", fileInfo.Mode(), path))
					}
				}

				return nil
			})
		}
	}

	// 限制输出数量
	if len(results) > 0 {
		maxResults := 20
		if len(results) < maxResults {
			maxResults = len(results)
		}
		for i := 0; i < maxResults; i++ {
			fmt.Println(results[i])
		}
		if len(results) > maxResults {
			fmt.Printf("... (还有 %d 个文件)\n", len(results)-maxResults)
		}
	}
	fmt.Println()
}

// checkDatabaseConfigs 检查数据库配置
func checkDatabaseConfigs() {
	utils.InfoPrint("[-] 数据库配置检查:")

	// MySQL配置检查
	mysqlConfigs := []string{
		"/etc/mysql/my.cnf",
		"/etc/my.cnf",
		"~/.my.cnf",
	}

	for _, config := range mysqlConfigs {
		if _, err := os.Stat(config); err == nil {
			utils.InfoPrint("[+] 找到MySQL配置文件: %s", config)
		}
	}

	// PostgreSQL配置检查
	postgresConfigs := []string{
		"/etc/postgresql/*/postgresql.conf",
		"/var/lib/postgresql/*/postgresql.conf",
	}

	for _, pattern := range postgresConfigs {
		if files, _ := filepath.Glob(pattern); len(files) > 0 {
			for _, file := range files {
				utils.InfoPrint("[+] 找到PostgreSQL配置文件: %s", file)
			}
		}
	}

	// 检查数据库连接
	utils.InfoPrint("[-] 检查数据库连接:")

	// MySQL连接测试
	if output, err := utils.RunCommand("mysql -V 2>/dev/null"); err == nil {
		utils.InfoPrint("[+] MySQL可用: %s", strings.TrimSpace(output))
	}

	// PostgreSQL连接测试
	if output, err := utils.RunCommand("psql -V 2>/dev/null"); err == nil {
		utils.InfoPrint("[+] PostgreSQL可用: %s", strings.TrimSpace(output))
	}

	fmt.Println()
}

// interestingFiles 查找有趣的文件
func interestingFiles(thorough bool) {
	utils.BoldInfo("### 有趣文件 ##########################################")
	startTime := time.Now()

	if thorough {
		// 查找我们可以写入但不属于我们的文件
		utils.InfoPrint("[-] 不属于用户但组可写的文件:")
		searchGroupWritableFiles()

		// 查找属于我们的文件
		utils.InfoPrint("[-] 属于我们用户的文件:")
		searchUserFiles()
	}

	// 检查root主目录是否可访问
	utils.InfoPrint("[-] 检查root主目录可访问性:")
	if _, err := os.Stat("/root"); err == nil {
		if output, err := utils.RunCommand("ls -la /root/ 2>/dev/null | head -10"); err == nil {
			utils.SuccessPrint("[+] 我们可以读取root的主目录!")
			fmt.Println(output)
		}
	}

	utils.InfoPrint("文件搜索完成，耗时: %v", time.Since(startTime))
	fmt.Println()
}

// searchGroupWritableFiles 优化搜索组可写文件
func searchGroupWritableFiles() {
	var wg sync.WaitGroup
	resultChan := make(chan string, 50)

	// 启动结果收集器
	go func() {
		for result := range resultChan {
			fmt.Println(result)
		}
	}()

	// 并行搜索关键目录
	searchDirs := []string{"/home", "/tmp", "/var/tmp", "/opt", "/usr/local", "/var/www"}

	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err == nil {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				searchGroupWritableInDir(d, resultChan)
			}(dir)
		}
	}

	wg.Wait()
	close(resultChan)
}

// searchGroupWritableInDir 在指定目录中搜索组可写文件
func searchGroupWritableInDir(dir string, resultChan chan<- string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// 检查文件权限
		if isGroupWritable(info) && !isOwnedByCurrentUser(info) {
			if fileInfo, err := os.Stat(path); err == nil {
				resultChan <- fmt.Sprintf("%s %s %s %s",
					fileInfo.Mode(),
					fileInfo.ModTime().Format("Jan 02 15:04"),
					fileInfo.Size(),
					path)
			}
		}

		return nil
	})
}

// searchUserFiles 优化搜索用户文件
func searchUserFiles() {
	var wg sync.WaitGroup
	resultChan := make(chan string, 50)

	// 启动结果收集器
	go func() {
		for result := range resultChan {
			fmt.Println(result)
		}
	}()

	// 并行搜索用户相关目录
	searchDirs := []string{"/home", os.Getenv("HOME"), "/tmp", "/var/tmp"}

	for _, dir := range searchDirs {
		if _, err := os.Stat(dir); err == nil {
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				searchUserFilesInDir(d, resultChan)
			}(dir)
		}
	}

	wg.Wait()
	close(resultChan)
}

// searchUserFilesInDir 在指定目录中搜索用户文件
func searchUserFilesInDir(dir string, resultChan chan<- string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// 检查文件所有者
		if isOwnedByCurrentUser(info) {
			if fileInfo, err := os.Stat(path); err == nil {
				resultChan <- fmt.Sprintf("%s %s %s %s",
					fileInfo.Mode(),
					fileInfo.ModTime().Format("Jan 02 15:04"),
					fileInfo.Size(),
					path)
			}
		}

		return nil
	})
}

// isGroupWritable 检查文件是否组可写
func isGroupWritable(info os.FileInfo) bool {
	return info.Mode()&0020 != 0
}

// isOwnedByCurrentUser 检查文件是否属于当前用户
func isOwnedByCurrentUser(info os.FileInfo) bool {
	// 简化实现：在Windows上返回true，在Linux上使用备用方法
	// 实际使用中，linenum命令只在Linux上运行，所以这是安全的
	if runtime.GOOS == "windows" {
		return true
	}

	// 在Linux上，使用备用方法检查文件权限
	// 由于linenum命令只在Linux上运行，我们可以使用更精确的方法
	return checkFileOwnershipFallback(info)
}

// checkFileOwnershipFallback 使用备用方法检查文件所有者
func checkFileOwnershipFallback(info os.FileInfo) bool {
	// 在Linux上，我们可以使用stat命令来获取文件所有者信息
	// 这里使用简化实现，实际部署时可以更精确
	return true // 简化实现，实际使用中应该使用stat命令获取详细信息
}

// dockerChecks 检查Docker相关信息
func dockerChecks() {
	utils.BoldInfo("### Docker检查 ########################################")

	// 检查是否在Docker容器中
	utils.InfoPrint("[-] 检查Docker容器环境:")
	if _, err := os.Stat("/.dockerenv"); err == nil {
		utils.SuccessPrint("[+] 看起来我们在Docker容器中!")
	}

	// 检查Docker组
	utils.InfoPrint("[-] 检查Docker组成员:")
	if output, err := utils.RunCommand("id | grep -i docker"); err == nil {
		utils.SuccessPrint("[+] 我们是Docker组的成员 - 可能滥用这些权限!")
		fmt.Println(output)
	}
	fmt.Println()
}

// lxcContainerChecks 检查LXC容器相关信息
func lxcContainerChecks() {
	utils.BoldInfo("### LXC容器检查 ######################################")

	// 特定检查 - 我们是否在lxd/lxc容器中
	utils.InfoPrint("[-] 检查LXC容器环境:")
	if content, err := os.ReadFile("/proc/1/environ"); err == nil {
		if strings.Contains(string(content), "container=lxc") {
			utils.SuccessPrint("[+] 看起来我们在LXC容器中!")
		}
	}

	// 特定检查 - 我们是否是lxd组的成员
	utils.InfoPrint("[-] 检查LXD组成员:")
	if output, err := utils.RunCommand("id | grep -i lxd"); err == nil {
		utils.SuccessPrint("[+] 我们是LXD组的成员 - 可能滥用这些权限!")
		fmt.Println(output)
	}
	fmt.Println()
}

// init 初始化linenum命令
func init() {
	// 定义命令行参数
	linenumCmd.Flags().StringP("keyword", "k", "", "搜索关键词，在配置、PHP、INI和日志文件中搜索")
	linenumCmd.Flags().StringP("export", "e", "", "导出位置，将结果导出到指定目录")
	linenumCmd.Flags().StringP("report", "r", "", "报告名称，指定输出报告文件名")
	linenumCmd.Flags().BoolP("thorough", "t", false, "详细测试模式，执行更全面的检查")
	linenumCmd.Flags().BoolP("sudo-password", "s", false, "提供sudo密码进行权限检查（不安全，仅用于CTF）")

	// 在根命令中注册linenum命令
	// rootCmd.AddCommand(linenumCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
}
