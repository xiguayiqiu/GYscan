package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SystemInfo 系统信息结构体
type SystemInfo struct {
	OS             string   `json:"os"`              // 操作系统类型
	Distro         string   `json:"distro"`          // 发行版名称
	Version        string   `json:"version"`         // 版本号
	Architecture   string   `json:"architecture"`    // 架构
	InstalledTools []string `json:"installed_tools"` // 已安装的工具
}

// DetectSystem 检测系统信息
func DetectSystem() (*SystemInfo, error) {
	info := &SystemInfo{}

	// 检测操作系统
	osType := strings.ToLower(os.Getenv("GOOS"))
	if osType == "" {
		osType = getOSType()
	}
	info.OS = osType

	// 检测发行版（仅Linux）
	if info.OS == "linux" {
		distro, version, err := detectLinuxDistro()
		if err != nil {
			return nil, err
		}
		info.Distro = distro
		info.Version = version
	}

	// 检测架构
	arch := strings.ToLower(os.Getenv("GOARCH"))
	if arch == "" {
		arch = getArchitecture()
	}
	info.Architecture = arch

	// 检测已安装的工具
	tools, err := DetectInstalledTools()
	if err != nil {
		return nil, err
	}
	info.InstalledTools = tools

	return info, nil
}

// getOSType 获取操作系统类型
func getOSType() string {
	// 尝试从/proc/version获取（Linux）
	if _, err := os.Stat("/proc/version"); err == nil {
		return "linux"
	}
	// 尝试从/System/Library获取（macOS）
	if _, err := os.Stat("/System/Library"); err == nil {
		return "darwin"
	}
	// 其他情况（Windows）
	return "windows"
}

// detectLinuxDistro 检测Linux发行版
func detectLinuxDistro() (string, string, error) {
	// 尝试从/etc/os-release文件获取
	if _, err := os.Stat("/etc/os-release"); err == nil {
		content, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return "", "", err
		}
		return parseOSRelease(string(content))
	}

	// 尝试从/etc/issue获取
	if _, err := os.Stat("/etc/issue"); err == nil {
		content, err := os.ReadFile("/etc/issue")
		if err != nil {
			return "", "", err
		}
		return parseIssueFile(string(content))
	}

	return "unknown", "unknown", nil
}

// parseOSRelease 解析/etc/os-release文件
func parseOSRelease(content string) (string, string, error) {
	lines := strings.Split(content, "\n")
	var distro, version string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "NAME=") {
			distro = strings.Trim(line[5:], `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(line[11:], `"`)
		}
	}

	return distro, version, nil
}

// parseIssueFile 解析/etc/issue文件
func parseIssueFile(content string) (string, string, error) {
	// 简单解析，提取发行版名称和版本
	content = strings.TrimSpace(content)
	content = strings.ReplaceAll(content, "\\n", "")
	content = strings.ReplaceAll(content, "\\l", "")

	// 尝试匹配常见格式：Distro Version
	parts := strings.Fields(content)
	if len(parts) >= 2 {
		distro := parts[0]
		version := parts[1]
		return distro, version, nil
	}

	return content, "unknown", nil
}

// getArchitecture 获取系统架构
func getArchitecture() string {
	cmd := exec.Command("uname", "-m")
	output, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	// 尝试其他命令
	cmd = exec.Command("arch")
	output, err = cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	return "unknown"
}

// IsKaliOrParrot 检查是否为Kali或Parrot OS
func IsKaliOrParrot(info *SystemInfo) bool {
	distro := strings.ToLower(info.Distro)
	return strings.Contains(distro, "kali") || strings.Contains(distro, "parrot")
}

// DetectInstalledTools 检测已安装的工具
func DetectInstalledTools() ([]string, error) {
	// 常见安全工具列表
	commonTools := []string{
		"nmap", "nikto", "sqlmap", "metasploit-framework", "msfconsole",
		"dirb", "dirsearch", "gobuster", "wfuzz", "burpsuite",
		"hydra", "john", "hashcat", "aircrack-ng", "wireshark",
		"tcpdump", "tshark", "openssl", "curl", "wget",
		"git", "python3", "python", "ruby", "perl",
		"gcc", "g++", "make", "cmake", "go",
	}

	var installed []string

	for _, tool := range commonTools {
		if isToolInstalled(tool) {
			installed = append(installed, tool)
		}
	}

	return installed, nil
}

// isToolInstalled 检查工具是否已安装
func isToolInstalled(tool string) bool {
	cmd := exec.Command("which", tool)
	_, err := cmd.Output()
	return err == nil
}

// GetPackageManager 获取系统包管理器
func GetPackageManager(info *SystemInfo) string {
	if info.OS != "linux" {
		return ""
	}

	// 检查常见包管理器
	packageManagers := []string{
		"apt",     // Debian, Ubuntu, Kali, Parrot
		"apt-get", // Debian, Ubuntu, Kali, Parrot
		"yum",     // CentOS, RHEL
		"dnf",     // Fedora, RHEL 8+
		"pacman",  // Arch Linux
		"yay",     // Arch Linux AUR helper
		"paru",    // Arch Linux AUR helper
		"zypper",  // SUSE
		"emerge",  // Gentoo
	}

	for _, pm := range packageManagers {
		if isToolInstalled(pm) {
			return pm
		}
	}

	return ""
}

// InstallTool 安装工具
func InstallTool(tool, packageManager string) error {
	if packageManager == "" {
		return fmt.Errorf("未检测到包管理器")
	}

	var cmd *exec.Cmd

	switch packageManager {
	case "apt", "apt-get":
		cmd = exec.Command(packageManager, "install", "-y", tool)
	case "yum":
		cmd = exec.Command(packageManager, "install", "-y", tool)
	case "dnf":
		cmd = exec.Command(packageManager, "install", "-y", tool)
	case "pacman":
		cmd = exec.Command(packageManager, "-S", "--noconfirm", tool)
	case "yay":
		// Arch Linux AUR helper
		cmd = exec.Command(packageManager, "-S", "--noconfirm", tool)
	case "paur":
		// Arch Linux AUR helper
		cmd = exec.Command(packageManager, "-S", "--noconfirm", tool)
	case "zypper":
		cmd = exec.Command(packageManager, "install", "-y", tool)
	case "emerge":
		cmd = exec.Command(packageManager, "--ask", "n", tool)
	default:
		return fmt.Errorf("不支持的包管理器: %s", packageManager)
	}

	// 执行命令
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("安装工具失败 %s: %v\n输出: %s", tool, err, string(output))
	}

	return nil
}
