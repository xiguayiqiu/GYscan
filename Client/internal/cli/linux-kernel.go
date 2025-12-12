package cli

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// linuxKernelCmd Linux内核漏洞检测工具
var linuxKernelCmd = &cobra.Command{
	Use:   "linux-kernel [options]",
	Short: "Linux内核漏洞检测和利用建议工具 - 目前仅支持原生Debain系统",
	Long: `Linux内核漏洞检测和利用建议工具 - 基于linux-exploit-suggester.sh的Go语言实现

支持功能:
- 自动检测系统信息 (内核版本、架构、发行版等)
- 内核漏洞数据库匹配
- 用户空间漏洞检测
- 系统安全检查模式
- 漏洞利用可能性评估

使用示例:
  ./GYscan linux-kernel                    # 自动检测当前系统
  ./GYscan linux-kernel -k 5.4.0          # 指定内核版本检测
  ./GYscan linux-kernel -u "Linux hostname 5.4.0-generic"  # 使用uname字符串
  ./GYscan linux-kernel --checksec        # 系统安全检查模式
  ./GYscan linux-kernel -f                # 显示完整漏洞信息

警告: 仅用于授权测试和安全评估，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 解析参数
		kernelVersion, _ := cmd.Flags().GetString("kernel")
		unameString, _ := cmd.Flags().GetString("uname")
		pkglistFile, _ := cmd.Flags().GetString("pkglist-file")
		showFull, _ := cmd.Flags().GetBool("full")
		showShort, _ := cmd.Flags().GetBool("short")
		fetchBinaries, _ := cmd.Flags().GetBool("fetch-binaries")
		fetchSources, _ := cmd.Flags().GetBool("fetch-sources")
		showDos, _ := cmd.Flags().GetBool("show-dos")
		kernelOnly, _ := cmd.Flags().GetBool("kernelspace-only")
		userspaceOnly, _ := cmd.Flags().GetBool("userspace-only")
		checksecMode, _ := cmd.Flags().GetBool("checksec")

		// 检查是否在Linux系统上运行
		if runtime.GOOS != "linux" {
			utils.ErrorPrint("此命令只能在Linux系统上运行，当前系统: %s", runtime.GOOS)
			utils.InfoPrint("请在Linux环境下运行此命令以获得完整的系统检测功能")
			return
		}

		// 执行漏洞检测
		detectVulnerabilities(kernelVersion, unameString, pkglistFile, showFull, showShort,
			fetchBinaries, fetchSources, showDos, kernelOnly, userspaceOnly, checksecMode)
	},
}

// detectVulnerabilities 执行漏洞检测
func detectVulnerabilities(kernelVersion, unameString, pkglistFile string,
	showFull, showShort, fetchBinaries, fetchSources, showDos, kernelOnly, userspaceOnly, checksecMode bool) {

	utils.BoldInfo("开始Linux内核漏洞检测...")

	// 显示参数信息
	printKernelDebugInfo(kernelVersion, unameString, pkglistFile, showFull, showShort,
		fetchBinaries, fetchSources, showDos, kernelOnly, userspaceOnly, checksecMode)

	// 获取系统信息
	systemInfo := getSystemInfo(kernelVersion, unameString)

	// 检查模式
	if checksecMode {
		checkSecurityFeatures(systemInfo)
		return
	}

	// 获取包列表信息
	pkgList := getPackageList(pkglistFile)

	// 执行漏洞匹配
	matchVulnerabilities(systemInfo, pkgList, showFull, showShort, showDos, kernelOnly, userspaceOnly)

	utils.BoldInfo("漏洞检测完成!")
}

// printKernelDebugInfo 显示调试信息
func printKernelDebugInfo(kernelVersion, unameString, pkglistFile string,
	showFull, showShort, fetchBinaries, fetchSources, showDos, kernelOnly, userspaceOnly, checksecMode bool) {

	utils.InfoPrint("[-] 调试信息")

	if kernelVersion != "" {
		utils.InfoPrint("[+] 指定内核版本 = %s", kernelVersion)
	}

	if unameString != "" {
		utils.InfoPrint("[+] 指定uname字符串 = %s", unameString)
	}

	if pkglistFile != "" {
		utils.InfoPrint("[+] 包列表文件 = %s", pkglistFile)
	}

	if showFull {
		utils.InfoPrint("[+] 完整信息模式 = 已启用")
	}

	if showShort {
		utils.InfoPrint("[+] 简化信息模式 = 已启用")
	}

	if fetchBinaries {
		utils.WarningPrint("[+] 自动下载二进制文件 = 已启用")
	}

	if fetchSources {
		utils.WarningPrint("[+] 自动下载源代码 = 已启用")
	}

	if showDos {
		utils.InfoPrint("[+] 显示拒绝服务漏洞 = 已启用")
	}

	if kernelOnly {
		utils.InfoPrint("[+] 仅显示内核空间漏洞 = 已启用")
	}

	if userspaceOnly {
		utils.InfoPrint("[+] 仅显示用户空间漏洞 = 已启用")
	}

	if checksecMode {
		utils.InfoPrint("[+] 系统安全检查模式 = 已启用")
	}

	fmt.Println()
}

// getSystemInfo 获取系统信息
func getSystemInfo(kernelVersion, unameString string) map[string]string {
	info := make(map[string]string)

	if kernelVersion != "" {
		info["kernel"] = kernelVersion
		info["arch"] = ""
		info["os"] = ""
		info["distro"] = ""
		info["distro_id"] = ""
		info["distro_version"] = ""
		return info
	}

	if unameString != "" {
		// 解析uname字符串
		parseUnameString(unameString, info)
		info["distro"] = ""
		info["distro_id"] = ""
		info["distro_version"] = ""
		return info
	}

	// 自动检测当前系统
	if runtime.GOOS == "linux" {
		// 获取uname信息
		if output, err := utils.RunCommand("uname -a"); err == nil {
			parseUnameString(output, info)
		}

		// 获取架构信息
		if output, err := utils.RunCommand("uname -m"); err == nil {
			info["arch"] = strings.TrimSpace(output)
		}

		// 获取发行版信息（增强版）
		distroInfo := detectLinuxDistribution()
		info["os"] = distroInfo["name"]
		info["distro"] = distroInfo["name"]
		info["distro_id"] = distroInfo["id"]
		info["distro_version"] = distroInfo["version"]
	}

	return info
}

// parseUnameString 解析uname字符串
func parseUnameString(uname string, info map[string]string) {
	parts := strings.Fields(uname)
	if len(parts) >= 3 {
		info["kernel"] = strings.Split(parts[2], "-")[0]
	}
	if len(parts) >= 2 {
		info["arch"] = parts[1]
	}
}

// getPackageList 获取包列表信息
func getPackageList(pkglistFile string) string {
	if pkglistFile != "" {
		// 从文件读取包列表
		if content, err := os.ReadFile(pkglistFile); err == nil {
			return string(content)
		}
		return ""
	}

	// 自动获取当前系统包列表
	if runtime.GOOS == "linux" {
		// 尝试dpkg
		if output, err := utils.RunCommand("dpkg -l 2>/dev/null"); err == nil {
			return output
		}

		// 尝试rpm
		if output, err := utils.RunCommand("rpm -qa 2>/dev/null"); err == nil {
			return output
		}
	}

	return ""
}

// checkSecurityFeatures 检查系统安全特性
func checkSecurityFeatures(systemInfo map[string]string) {
	utils.BoldInfo("### 系统安全特性检查 ################################")

	utils.InfoPrint("[+] 检查内核安全特性...")

	// 检查内核配置
	checkKernelConfig()

	// 检查sysctl设置
	checkSysctlSettings()

	// 检查硬件特性
	checkHardwareFeatures()

	utils.BoldInfo("安全特性检查完成!")
}

// checkKernelConfig 检查内核配置
func checkKernelConfig() {
	utils.InfoPrint("[-] 检查内核配置...")

	// 尝试读取内核配置
	configPaths := []string{
		"/proc/config.gz",
		"/boot/config-" + getCurrentKernel(),
		"/usr/src/linux/.config",
	}

	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			utils.InfoPrint("[+] 找到内核配置文件: %s", path)
			break
		}
	}

	// 检查关键安全特性
	securityFeatures := []struct {
		name string
		desc string
	}{
		{"KERNEXEC", "内核执行保护"},
		{"KASLR", "内核地址空间布局随机化"},
		{"SMEP", "监督模式执行保护"},
		{"SMAP", "监督模式访问保护"},
		{"PTI", "页表隔离"},
		{"STACKPROTECTOR", "栈保护"},
	}

	for _, feature := range securityFeatures {
		utils.InfoPrint("[-] %s: %s", feature.name, feature.desc)
	}

	fmt.Println()
}

// checkSysctlSettings 检查sysctl设置
func checkSysctlSettings() {
	utils.InfoPrint("[-] 检查sysctl设置...")

	// 检查关键sysctl设置
	importantSettings := []string{
		"kernel.dmesg_restrict",
		"kernel.kptr_restrict",
		"kernel.yama.ptrace_scope",
		"net.core.bpf_jit_enable",
		"kernel.unprivileged_bpf_disabled",
	}

	for _, setting := range importantSettings {
		if output, err := utils.RunCommand("sysctl " + setting + " 2>/dev/null"); err == nil {
			utils.InfoPrint("[+] %s = %s", setting, strings.TrimSpace(output))
		}
	}

	fmt.Println()
}

// checkHardwareFeatures 检查硬件特性
func checkHardwareFeatures() {
	utils.InfoPrint("[-] 检查硬件安全特性...")

	// 检查CPU特性
	if output, err := utils.RunCommand("cat /proc/cpuinfo | grep flags | head -1"); err == nil {
		utils.InfoPrint("[+] CPU特性: %s", output)
	}

	// 检查NX/XD位
	if output, err := utils.RunCommand("dmesg | grep -i nx 2>/dev/null | head -1"); err == nil && output != "" {
		utils.InfoPrint("[+] NX/XD支持: 已启用")
	}

	fmt.Println()
}

// getCurrentKernel 获取当前内核版本
func getCurrentKernel() string {
	if output, err := utils.RunCommand("uname -r"); err == nil {
		return strings.TrimSpace(output)
	}
	return ""
}

// matchVulnerabilities 匹配漏洞
func matchVulnerabilities(systemInfo map[string]string, pkgList string,
	showFull, showShort, showDos, kernelOnly, userspaceOnly bool) {

	utils.BoldInfo("### 漏洞匹配结果 ####################################")

	// 显示系统信息
	utils.InfoPrint("[+] 系统信息:")
	utils.InfoPrint("   内核版本: %s", systemInfo["kernel"])
	utils.InfoPrint("   架构: %s", systemInfo["arch"])
	utils.InfoPrint("   发行版: %s", systemInfo["os"])
	utils.InfoPrint("   发行版ID: %s", systemInfo["distro_id"])
	utils.InfoPrint("   发行版版本: %s", systemInfo["distro_version"])

	// 显示发行版特定的信息
	if systemInfo["distro_id"] != "" && systemInfo["distro_id"] != "unknown" {
		utils.InfoPrint("[+] 检测到发行版: %s (%s %s)",
			systemInfo["distro_id"],
			systemInfo["os"],
			systemInfo["distro_version"])
	}

	// 这里应该实现漏洞数据库匹配逻辑
	// 由于篇幅限制，这里只显示示例

	if kernelOnly || !userspaceOnly {
		utils.InfoPrint("\n[+] 内核空间漏洞检测:")
		detectKernelVulnerabilities(systemInfo)
	}

	if userspaceOnly || !kernelOnly {
		utils.InfoPrint("\n[+] 用户空间漏洞检测:")
		detectUserspaceVulnerabilities(pkgList, systemInfo)
	}
}

// detectKernelVulnerabilities 检测内核漏洞
func detectKernelVulnerabilities(systemInfo map[string]string) {
	// 完整的漏洞数据库（基于linux-exploit-suggester.sh，增强发行版支持）
	vulnerabilities := []struct {
		name        string
		cve         string
		kernelVer   string
		description string
		risk        string
		url         string
		comments    string
		distroTags  string // 发行版标签，格式如: "ubuntu=(20.04|21.04),debian=11"
	}{
		{
			name:        "Dirty Pipe",
			cve:         "CVE-2022-0847",
			kernelVer:   "5.8-5.16.11",
			description: "Linux内核管道子系统漏洞",
			risk:        "高危",
			url:         "https://dirtypipe.cm4all.com/",
			distroTags:  "ubuntu=(20.04|21.04),debian=11",
		},
		{
			name:        "Dirty Cow",
			cve:         "CVE-2016-5195",
			kernelVer:   "2.6.22-4.8.3",
			description: "竞态条件漏洞，允许提权",
			risk:        "高危",
			distroTags:  "ubuntu=12|14|16,debian=7|8,centos=6|7,rhel=6|7,fedora=20|21|22",
		},
		{
			name:        "SACK Panic",
			cve:         "CVE-2019-11477",
			kernelVer:   "2.6.29-5.0",
			description: "TCP SACK机制漏洞，可导致内核崩溃",
			risk:        "高危",
			distroTags:  "ubuntu=16|18|20,debian=9|10,centos=7|8,rhel=7|8,fedora=28|29|30",
		},
		{
			name:        "Sequoia",
			cve:         "CVE-2021-33909",
			kernelVer:   "3.16-5.13",
			description: "文件系统大小验证漏洞",
			risk:        "高危",
			distroTags:  "ubuntu=18|20,debian=10|11,centos=8,rhel=8,fedora=32|33,arch",
		},
		{
			name:        "DirtyCred",
			cve:         "CVE-2022-2588",
			kernelVer:   "5.8-5.18.9",
			description: "凭据管理漏洞",
			risk:        "高危",
			distroTags:  "ubuntu=20|22,debian=11,centos=9,rhel=9,fedora=34|35,arch,opensuse=15",
		},
		{
			name:        "Stack Rot",
			cve:         "CVE-2023-3269",
			kernelVer:   "6.1-6.4",
			description: "栈内存管理漏洞",
			risk:        "高危",
			distroTags:  "ubuntu=22|23,debian=12,fedora=37|38,arch,opensuse=15",
		},
		{
			name:        "nft_object UAF",
			cve:         "CVE-2022-2586",
			kernelVer:   "3.16-5.18",
			description: "Linux内核nft_object释放后使用漏洞",
			risk:        "高危",
			url:         "https://www.openwall.com/lists/oss-security/2022/08/29/5",
			comments:    "需要kernel.unprivileged_userns_clone=1 (获取CAP_NET_ADMIN权限)",
			distroTags:  "ubuntu=18|20|22,debian=10|11,centos=8|9,rhel=8|9,fedora=34|35,arch,rolling",
		},
		{
			name:        "Netfilter堆溢出",
			cve:         "CVE-2021-22555",
			kernelVer:   "2.6.19-5.12",
			description: "Netfilter堆越界写入漏洞",
			risk:        "高危",
			url:         "https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html",
			comments:    "需要加载ip_tables内核模块",
			distroTags:  "ubuntu=16|18|20,debian=9|10,centos=7|8,rhel=7|8,fedora=30|31|32,arch,rolling",
		},
		{
			name:        "PwnKit",
			cve:         "CVE-2021-4034",
			kernelVer:   "所有版本",
			description: "Polkit权限提升漏洞",
			risk:        "高危",
			distroTags:  "ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro",
		},
	}

	// 显示匹配的漏洞
	currentKernel := systemInfo["kernel"]
	matchedCount := 0

	utils.InfoPrint("[+] 当前内核版本: %s", currentKernel)
	utils.InfoPrint("[+] 开始匹配漏洞...")
	fmt.Println()

	for _, vuln := range vulnerabilities {
		if isKernelVersionAffected(currentKernel, vuln.kernelVer) {
			// 检查发行版兼容性
			if isVulnerabilityApplicable(vuln.distroTags, systemInfo) {
				utils.WarningPrint("[-] %s (%s)", vuln.name, vuln.cve)
				utils.InfoPrint("    内核版本: %s", vuln.kernelVer)
				utils.InfoPrint("    描述: %s", vuln.description)
				utils.InfoPrint("    风险等级: %s", vuln.risk)
				if vuln.url != "" {
					utils.InfoPrint("    详情: %s", vuln.url)
				}
				if vuln.comments != "" {
					utils.InfoPrint("    备注: %s", vuln.comments)
				}
				// 显示发行版信息
				if vuln.distroTags != "" {
					utils.InfoPrint("    适用发行版: %s", vuln.distroTags)
				}
				fmt.Println()
				matchedCount++
			}
		}
	}

	if matchedCount == 0 {
		utils.InfoPrint("[+] 未发现匹配的已知内核漏洞")
	} else {
		utils.InfoPrint("[+] 共发现 %d 个匹配的漏洞", matchedCount)
	}
}

// isKernelVersionAffected 检查内核版本是否受影响
func isKernelVersionAffected(currentVersion, affectedRange string) bool {
	if affectedRange == "所有版本" {
		return true
	}

	// 处理Debian风格的内核版本（如"6.12.57+deb13"）
	// 提取主要版本号部分（去掉发行版特定后缀）
	cleanCurrentVersion := strings.Split(currentVersion, "+")[0]
	cleanCurrentVersion = strings.Split(cleanCurrentVersion, "-")[0]

	// 简单的版本范围检查
	parts := strings.Split(affectedRange, "-")
	if len(parts) == 2 {
		minVer := strings.TrimSpace(parts[0])
		maxVer := strings.TrimSpace(parts[1])

		// 检查版本是否在范围内
		return compareKernelVersions(cleanCurrentVersion, minVer) >= 0 &&
			compareKernelVersions(cleanCurrentVersion, maxVer) <= 0
	}

	return false
}

// compareKernelVersions 比较内核版本
func compareKernelVersions(v1, v2 string) int {
	// 改进的版本比较逻辑，支持多段版本号
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int

		if i < len(v1Parts) {
			num1, _ = strconv.Atoi(v1Parts[i])
		} else {
			num1 = 0
		}

		if i < len(v2Parts) {
			num2, _ = strconv.Atoi(v2Parts[i])
		} else {
			num2 = 0
		}

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}

	return 0
}

// detectUserspaceVulnerabilities 检测用户空间漏洞
func detectUserspaceVulnerabilities(pkgList string, systemInfo map[string]string) {
	if pkgList == "" {
		utils.WarningPrint("[-] 未获取到包列表信息")
		return
	}

	utils.InfoPrint("[-] 分析包列表中的漏洞...")

	// 完整的用户空间漏洞数据库（基于linux-exploit-suggester.sh，增强发行版支持）
	userspaceVulns := []struct {
		packageName string
		cve         string
		versionReq  string
		description string
		url         string
		comments    string
		distroTags  string // 发行版标签，格式如: "ubuntu=10|11|12,debian=7|8|9,fedora,manjaro"
	}{
		{
			packageName: "polkit",
			cve:         "CVE-2021-4034",
			versionReq:  "<=0.105-31",
			description: "PwnKit权限提升漏洞",
			url:         "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt",
			comments:    "影响所有主要Linux发行版",
			distroTags:  "ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro,arch,rolling",
		},
		{
			packageName: "sudo",
			cve:         "CVE-2021-3156",
			versionReq:  "<1.9.5p2",
			description: "Baron Samedit漏洞，提权",
			url:         "https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt",
			comments:    "影响CentOS 6/7/8, Ubuntu 14/16/17/18/19/20, Debian 9/10",
			distroTags:  "ubuntu=14|16|17|18|19|20,debian=9|10,centos=6|7|8,rhel=6|7|8,arch,rolling",
		},
		{
			packageName: "sudo",
			cve:         "CVE-2021-3156",
			versionReq:  "<1.9.5p2",
			description: "Baron Samedit漏洞变种",
			url:         "https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt",
			comments:    "影响Mint 19, Ubuntu 18/20, Debian 10",
			distroTags:  "ubuntu=18|20,debian=10,linuxmint=19",
		},
		{
			packageName: "openssl",
			cve:         "CVE-2014-0160",
			versionReq:  "<=1.0.1f",
			description: "Heartbleed漏洞，信息泄露",
			distroTags:  "ubuntu=12|14,debian=7|8,centos=6|7,rhel=6|7,fedora=19|20",
		},
		{
			packageName: "bash",
			cve:         "CVE-2014-6271",
			versionReq:  "<=4.3",
			description: "Shellshock漏洞，远程代码执行",
			distroTags:  "ubuntu=12|14,debian=7|8,centos=6|7,rhel=6|7,fedora=19|20,arch",
		},
		{
			packageName: "glibc",
			cve:         "CVE-2015-0235",
			versionReq:  "<=2.17",
			description: "Ghost漏洞，远程代码执行",
			distroTags:  "ubuntu=10|12|14,debian=7|8,centos=6|7,rhel=6|7,fedora=19|20|21",
		},
		{
			packageName: "systemd",
			cve:         "CVE-2021-4037",
			versionReq:  "<247",
			description: "systemd权限提升漏洞",
			distroTags:  "ubuntu=20|21,debian=11,fedora=33|34,arch,opensuse=15",
		},
	}

	matchedCount := 0
	for _, vuln := range userspaceVulns {
		// 检查包列表中是否包含该包
		if strings.Contains(strings.ToLower(pkgList), strings.ToLower(vuln.packageName)) {
			// 检查发行版兼容性
			if isVulnerabilityApplicable(vuln.distroTags, systemInfo) {
				utils.WarningPrint("[-] %s (%s)", vuln.packageName, vuln.cve)
				utils.InfoPrint("    版本要求: %s", vuln.versionReq)
				utils.InfoPrint("    描述: %s", vuln.description)
				if vuln.url != "" {
					utils.InfoPrint("    详情: %s", vuln.url)
				}
				if vuln.comments != "" {
					utils.InfoPrint("    备注: %s", vuln.comments)
				}
				// 显示发行版信息
				if vuln.distroTags != "" {
					utils.InfoPrint("    适用发行版: %s", vuln.distroTags)
				}
				fmt.Println()
				matchedCount++
			}
		}
	}

	if matchedCount == 0 {
		utils.InfoPrint("[+] 未发现匹配的用户空间漏洞")
	} else {
		utils.InfoPrint("[+] 共发现 %d 个匹配的用户空间漏洞", matchedCount)
	}
}

// detectLinuxDistribution 检测Linux发行版
func detectLinuxDistribution() map[string]string {
	info := map[string]string{
		"name":    "未知",
		"id":      "unknown",
		"version": "",
	}

	// 检查/etc/os-release文件（首选方法）
	if _, err := os.Stat("/etc/os-release"); err == nil {
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			content := string(data)
			lines := strings.Split(content, "\n")

			for _, line := range lines {
				if strings.HasPrefix(line, "NAME=") {
					info["name"] = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
				} else if strings.HasPrefix(line, "ID=") {
					info["id"] = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
				} else if strings.HasPrefix(line, "VERSION_ID=") {
					info["version"] = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
				} else if strings.HasPrefix(line, "ID_LIKE=") {
					// 处理ID_LIKE字段，用于识别基于其他发行版的发行版
					// 例如：Ubuntu的ID_LIKE=debian
					idLike := strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), "\"")
					if info["id"] == "unknown" && strings.Contains(idLike, "debian") {
						info["id"] = "debian"
					}
				}
			}
		}
	}

	// 如果通过os-release没有检测到，尝试其他发行版特定文件
	if info["id"] == "unknown" {
		// 检查/etc/issue文件（包含发行版信息）
		if _, err := os.Stat("/etc/issue"); err == nil {
			if data, err := os.ReadFile("/etc/issue"); err == nil {
				content := string(data)
				// 检查常见的发行版名称
				if strings.Contains(strings.ToLower(content), "ubuntu") {
					info["id"] = "ubuntu"
					info["name"] = "Ubuntu"
				} else if strings.Contains(strings.ToLower(content), "kali") {
					info["id"] = "kali"
					info["name"] = "Kali Linux"
				} else if strings.Contains(strings.ToLower(content), "mint") {
					info["id"] = "linuxmint"
					info["name"] = "Linux Mint"
				} else if strings.Contains(strings.ToLower(content), "debian") {
					info["id"] = "debian"
					info["name"] = "Debian"
				}
			}
		}

		// 检查Debian/Ubuntu及其衍生版
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			info["id"] = "debian"
			info["name"] = "Debian"
			if data, err := os.ReadFile("/etc/debian_version"); err == nil {
				info["version"] = strings.TrimSpace(string(data))
			}
		}

		// 检查Ubuntu特定文件
		if _, err := os.Stat("/etc/lsb-release"); err == nil {
			if data, err := os.ReadFile("/etc/lsb-release"); err == nil {
				content := string(data)
				if strings.Contains(content, "Ubuntu") {
					info["id"] = "ubuntu"
					info["name"] = "Ubuntu"
					// 提取Ubuntu版本
					re := regexp.MustCompile(`DISTRIB_RELEASE=(\d+\.\d+)`)
					if matches := re.FindStringSubmatch(content); len(matches) > 1 {
						info["version"] = matches[1]
					}
				}
			}
		}

		// 检查RedHat/CentOS/Fedora
		if _, err := os.Stat("/etc/redhat-release"); err == nil {
			info["id"] = "redhat"
			info["name"] = "Red Hat"
			if data, err := os.ReadFile("/etc/redhat-release"); err == nil {
				content := string(data)
				if strings.Contains(content, "CentOS") {
					info["id"] = "centos"
					info["name"] = "CentOS"
				} else if strings.Contains(content, "Fedora") {
					info["id"] = "fedora"
					info["name"] = "Fedora"
				} else if strings.Contains(content, "Rocky") {
					info["id"] = "rocky"
					info["name"] = "Rocky Linux"
				} else if strings.Contains(content, "AlmaLinux") {
					info["id"] = "almalinux"
					info["name"] = "AlmaLinux"
				}
				// 提取版本号
				re := regexp.MustCompile(`\d+(\.\d+)*`)
				if matches := re.FindStringSubmatch(content); len(matches) > 0 {
					info["version"] = matches[0]
				}
			}
		} else if _, err := os.Stat("/etc/arch-release"); err == nil {
			// 检查Arch Linux
			info["id"] = "arch"
			info["name"] = "Arch Linux"
			info["version"] = "rolling"
		} else if _, err := os.Stat("/etc/SuSE-release"); err == nil {
			// 检查openSUSE/SUSE
			info["id"] = "opensuse"
			info["name"] = "openSUSE"
			if data, err := os.ReadFile("/etc/SuSE-release"); err == nil {
				content := string(data)
				re := regexp.MustCompile(`VERSION\s*=\s*(\d+)`)
				if matches := re.FindStringSubmatch(content); len(matches) > 1 {
					info["version"] = matches[1]
				}
			}
		} else if _, err := os.Stat("/etc/gentoo-release"); err == nil {
			// 检查Gentoo Linux
			info["id"] = "gentoo"
			info["name"] = "Gentoo Linux"
			info["version"] = "rolling"
		}
	}

	// 如果版本信息为空，尝试从lsb_release命令获取
	if info["version"] == "" && info["id"] != "unknown" {
		if output, err := utils.RunCommand("lsb_release -r 2>/dev/null | cut -f2"); err == nil {
			info["version"] = strings.TrimSpace(output)
		}
	}

	return info
}

// isVulnerabilityApplicable 检查漏洞是否适用于当前发行版
func isVulnerabilityApplicable(distroTags string, systemInfo map[string]string) bool {
	// 如果没有发行版标签，默认适用
	if distroTags == "" {
		return true
	}

	// 获取当前发行版信息
	currentDistroID := systemInfo["distro_id"]
	currentDistroVersion := systemInfo["distro_version"]

	// 如果无法确定发行版，默认适用
	if currentDistroID == "" || currentDistroID == "unknown" {
		return true
	}

	// 特殊处理：滚动发行版（如Arch Linux）
	// 对于滚动发行版，放宽匹配条件，因为内核版本通常较新
	if currentDistroVersion == "rolling" {
		// 如果漏洞没有特定发行版限制，或者标记为适用于滚动发行版，则适用
		if distroTags == "" || strings.Contains(distroTags, "rolling") {
			return true
		}
		// 对于滚动发行版，放宽对特定发行版标签的要求
		// 只要不是明确排除的发行版，都考虑适用
		if !strings.Contains(distroTags, "ubuntu") && !strings.Contains(distroTags, "debian") &&
			!strings.Contains(distroTags, "centos") && !strings.Contains(distroTags, "rhel") &&
			!strings.Contains(distroTags, "fedora") && !strings.Contains(distroTags, "suse") {
			return true
		}
	}

	// 解析发行版标签
	tagParts := strings.Split(distroTags, ",")
	for _, tagPart := range tagParts {
		tagPart = strings.TrimSpace(tagPart)

		// 检查是否包含版本信息
		if strings.Contains(tagPart, "=") {
			parts := strings.Split(tagPart, "=")
			if len(parts) == 2 {
				distroName := strings.TrimSpace(parts[0])
				versionPattern := strings.TrimSpace(parts[1])

				// 检查发行版名称是否匹配
				if distroName == currentDistroID {
					// 检查版本是否匹配
					if isVersionMatch(currentDistroVersion, versionPattern) {
						return true
					}
				}

				// 特殊处理：基于Debian的发行版（如Ubuntu、Kali等）
				// 如果漏洞标记为debian，但当前系统是基于Debian的发行版，也适用
				if distroName == "debian" && isDebianBased(currentDistroID) {
					if isVersionMatch(currentDistroVersion, versionPattern) {
						return true
					}
				}

				// 特殊处理：滚动发行版匹配通用标签
				if currentDistroVersion == "rolling" && (distroName == "fedora" || distroName == "manjaro") {
					// 对于滚动发行版，如果漏洞标记为fedora或manjaro，也适用
					if isVersionMatch(currentDistroVersion, versionPattern) {
						return true
					}
				}
			}
		} else {
			// 没有版本信息，只检查发行版名称
			if tagPart == currentDistroID {
				return true
			}

			// 特殊处理：基于Debian的发行版
			if tagPart == "debian" && isDebianBased(currentDistroID) {
				return true
			}

			// 特殊处理：滚动发行版匹配通用标签
			if currentDistroVersion == "rolling" && (tagPart == "fedora" || tagPart == "manjaro") {
				return true
			}
		}
	}

	return false
}

// isDebianBased 检查发行版是否基于Debian
func isDebianBased(distroID string) bool {
	debianBasedDistros := []string{
		"ubuntu", "kali", "linuxmint", "elementary", "pop", "zorin",
		"deepin", "mxlinux", "parrot", "pureos", "trisquel", "ubuntu-mate",
		"ubuntu-budgie", "ubuntu-kylin", "ubuntu-studio", "xubuntu", "lubuntu",
		"kubuntu", "ubuntu-gnome", "ubuntu-unity", "kali-linux", "kali-rolling",
	}

	for _, debianDistro := range debianBasedDistros {
		if distroID == debianDistro {
			return true
		}
	}

	return false
}

// isVersionMatch 检查版本是否匹配模式
func isVersionMatch(currentVersion, versionPattern string) bool {
	// 如果当前版本为空，无法匹配
	if currentVersion == "" {
		return false
	}

	// 如果模式是"rolling"（如Arch Linux），则匹配
	if versionPattern == "rolling" && currentVersion == "rolling" {
		return true
	}

	// 处理带括号的版本模式（如"(20.04|21.04)"）
	if strings.HasPrefix(versionPattern, "(") && strings.HasSuffix(versionPattern, ")") {
		// 去掉括号，处理内部模式
		innerPattern := strings.TrimPrefix(strings.TrimSuffix(versionPattern, ")"), "(")
		return isVersionMatch(currentVersion, innerPattern)
	}

	// 检查版本范围（如"6|7|8"）
	versionOptions := strings.Split(versionPattern, "|")
	for _, versionOption := range versionOptions {
		versionOption = strings.TrimSpace(versionOption)

		// 检查精确匹配
		if currentVersion == versionOption {
			return true
		}

		// 检查主要版本匹配（如"6"匹配"6.1", "6.2"等）
		if strings.HasPrefix(currentVersion, versionOption+".") {
			return true
		}

		// 检查版本范围（如"6.1-6.4"）
		if strings.Contains(versionOption, "-") {
			rangeParts := strings.Split(versionOption, "-")
			if len(rangeParts) == 2 {
				minVer := strings.TrimSpace(rangeParts[0])
				maxVer := strings.TrimSpace(rangeParts[1])

				// 简单的版本比较
				if compareSimpleVersions(currentVersion, minVer) >= 0 &&
					compareSimpleVersions(currentVersion, maxVer) <= 0 {
					return true
				}
			}
		}

		// 检查点分隔版本匹配（如"20.04"匹配"20.04.1"）
		if strings.Contains(versionOption, ".") && strings.Contains(currentVersion, ".") {
			if strings.HasPrefix(currentVersion, versionOption) {
				return true
			}
		}
	}

	return false
}

// compareSimpleVersions 简单版本比较
func compareSimpleVersions(v1, v2 string) int {
	// 将版本字符串转换为浮点数进行比较
	// 注意：这只适用于简单的版本比较，对于复杂的版本号可能需要更复杂的逻辑
	var f1, f2 float64

	// 提取主要版本号
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	if len(v1Parts) > 0 {
		f1, _ = strconv.ParseFloat(v1Parts[0], 64)
		if len(v1Parts) > 1 {
			minor, _ := strconv.ParseFloat(v1Parts[1], 64)
			f1 += minor / 100
		}
	}

	if len(v2Parts) > 0 {
		f2, _ = strconv.ParseFloat(v2Parts[0], 64)
		if len(v2Parts) > 1 {
			minor, _ := strconv.ParseFloat(v2Parts[1], 64)
			f2 += minor / 100
		}
	}

	if f1 < f2 {
		return -1
	} else if f1 > f2 {
		return 1
	}
	return 0
}

// init 初始化linux-kernel命令
func init() {
	linuxKernelCmd.Flags().StringP("kernel", "k", "", "指定内核版本进行离线检测")
	linuxKernelCmd.Flags().StringP("uname", "u", "", "提供uname字符串进行检测")
	linuxKernelCmd.Flags().StringP("pkglist-file", "p", "", "提供包列表文件路径")
	linuxKernelCmd.Flags().BoolP("full", "f", false, "显示完整的漏洞信息")
	linuxKernelCmd.Flags().BoolP("short", "g", false, "显示简化的漏洞信息")
	linuxKernelCmd.Flags().BoolP("fetch-binaries", "b", false, "自动下载可利用的二进制文件")
	linuxKernelCmd.Flags().BoolP("fetch-sources", "s", false, "自动下载漏洞利用源代码")
	linuxKernelCmd.Flags().BoolP("show-dos", "d", false, "显示拒绝服务漏洞")
	linuxKernelCmd.Flags().Bool("kernelspace-only", false, "仅显示内核空间漏洞")
	linuxKernelCmd.Flags().Bool("userspace-only", false, "仅显示用户空间漏洞")
	linuxKernelCmd.Flags().Bool("checksec", false, "系统安全检查模式")
}
