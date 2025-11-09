package main

import (
	"os/exec"
	"strings"
)

// scanLinuxPrograms 扫描Linux程序
func scanLinuxPrograms() ([]ProgramInfo, []Vulnerability) {
	var programs []ProgramInfo
	var vulnerabilities []Vulnerability

	// 检测常见Linux程序
	commonPrograms := detectCommonPrograms()
	programs = append(programs, commonPrograms...)

	// 检测程序漏洞
	for i := range programs {
		programVulns := detectProgramVulnerabilities(programs[i].Name, programs[i].Version)
		programs[i].Vulnerabilities = programVulns
		vulnerabilities = append(vulnerabilities, programVulns...)
	}

	return programs, vulnerabilities
}

// detectCommonPrograms 检测常见Linux程序
func detectCommonPrograms() []ProgramInfo {
	var programs []ProgramInfo

	// 常见Linux程序列表
	programList := []string{
		"bash", "zsh", "fish",          // Shell
		"vim", "nano", "emacs",          // 编辑器
		"curl", "wget",                  // 网络工具
		"git", "svn",                    // 版本控制
		"python", "python3", "perl", "ruby", "php", "node", // 编程语言
		"gcc", "g++", "clang",           // 编译器
		"docker", "podman", "kubernetes", // 容器
		"mysql", "postgresql", "sqlite",  // 数据库
		"apache2", "nginx", "lighttpd",  // Web服务器
		"openssh", "openssl",            // 安全工具
		"samba", "nfs",                   // 文件共享
		"iptables", "ufw",               // 防火墙
		"systemd", "init",                // 系统服务
		"cron", "at",                     // 定时任务
		"rsync", "scp", "sftp",           // 文件传输
		"tar", "gzip", "bzip2", "zip",    // 压缩工具
		"find", "grep", "awk", "sed",      // 文本处理
		"top", "htop", "ps", "free",      // 系统监控
		"ifconfig", "ip", "netstat",      // 网络工具
	}

	for _, program := range programList {
		if isProgramInstalled(program) {
			version := getProgramVersion(program)
			path := getProgramPath(program)
			
			programInfo := ProgramInfo{
				Name:    program,
				Version: version,
				Path:    path,
			}
			programs = append(programs, programInfo)
		}
	}

	return programs
}

// isProgramInstalled 检查程序是否安装
func isProgramInstalled(program string) bool {
	cmd := exec.Command("which", program)
	err := cmd.Run()
	return err == nil
}

// getProgramVersion 获取程序版本
func getProgramVersion(program string) string {
	var cmd *exec.Cmd

	// 根据程序名称使用不同的版本查询命令
	switch program {
	case "bash", "zsh", "fish":
		cmd = exec.Command(program, "--version")
	case "vim", "nano", "emacs":
		cmd = exec.Command(program, "--version")
	case "curl", "wget":
		cmd = exec.Command(program, "--version")
	case "git":
		cmd = exec.Command("git", "--version")
	case "python", "python3":
		cmd = exec.Command(program, "--version")
	case "gcc", "g++", "clang":
		cmd = exec.Command(program, "--version")
	case "docker", "podman":
		cmd = exec.Command(program, "--version")
	case "mysql":
		cmd = exec.Command("mysql", "--version")
	case "postgresql":
		cmd = exec.Command("psql", "--version")
	case "apache2":
		cmd = exec.Command("apache2", "-v")
	case "nginx":
		cmd = exec.Command("nginx", "-v")
	case "openssh":
		cmd = exec.Command("ssh", "-V")
	case "openssl":
		cmd = exec.Command("openssl", "version")
	case "systemd":
		cmd = exec.Command("systemctl", "--version")
	default:
		// 默认使用 --version 参数
		cmd = exec.Command(program, "--version")
	}

	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	return strings.TrimSpace(string(output))
}

// getProgramPath 获取程序路径
func getProgramPath(program string) string {
	cmd := exec.Command("which", program)
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

// detectProgramVulnerabilities 检测程序漏洞
func detectProgramVulnerabilities(programName, version string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Bash漏洞检测
	if strings.Contains(programName, "bash") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "BASH-001",
			Name:        "Shellshock漏洞",
			Severity:    "Critical",
			Description: "Bash存在远程代码执行漏洞",
			Solution:    "更新Bash到4.3及以上版本",
			CVE:         "CVE-2014-6271",
			Affected:    "Bash 1.14-4.3",
		})
	}

	// OpenSSL漏洞检测
	if strings.Contains(programName, "openssl") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "OPENSSL-001",
			Name:        "Heartbleed漏洞",
			Severity:    "Critical",
			Description: "OpenSSL存在内存信息泄露漏洞",
			Solution:    "更新OpenSSL到1.0.1g及以上版本",
			CVE:         "CVE-2014-0160",
			Affected:    "OpenSSL 1.0.1-1.0.1f",
		})
	}

	// SSH漏洞检测
	if strings.Contains(programName, "ssh") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "SSH-002",
			Name:        "SSH版本漏洞",
			Severity:    "High",
			Description: "OpenSSH存在安全漏洞",
			Solution:    "更新OpenSSH到最新版本",
			CVE:         "CVE-2020-15778",
			Affected:    "OpenSSH 8.3p1及以下",
		})
	}

	// Samba漏洞检测
	if strings.Contains(programName, "samba") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "SAMBA-001",
			Name:        "EternalBlue漏洞",
			Severity:    "Critical",
			Description: "Samba存在远程代码执行漏洞",
			Solution:    "更新Samba到4.6.4及以上版本",
			CVE:         "CVE-2017-0144",
			Affected:    "Samba 3.5.0-4.6.3",
		})
	}

	// Apache漏洞检测
	if strings.Contains(programName, "apache") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "APACHE-001",
			Name:        "Apache Struts2漏洞",
			Severity:    "Critical",
			Description: "Apache Struts2存在远程代码执行漏洞",
			Solution:    "更新Struts2到2.3.32或2.5.10.1及以上版本",
			CVE:         "CVE-2017-5638",
			Affected:    "Struts 2.3.5-2.3.31, 2.5-2.5.10",
		})
	}

	// Nginx漏洞检测
	if strings.Contains(programName, "nginx") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "NGINX-001",
			Name:        "Nginx范围处理漏洞",
			Severity:    "High",
			Description: "Nginx存在整数溢出漏洞",
			Solution:    "更新Nginx到1.17.7、1.16.1或1.15.8及以上版本",
			CVE:         "CVE-2019-20372",
			Affected:    "Nginx 1.17.5-1.17.6",
		})
	}

	// MySQL漏洞检测
	if strings.Contains(programName, "mysql") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "MYSQL-001",
			Name:        "MySQL认证绕过漏洞",
			Severity:    "Critical",
			Description: "MySQL存在认证绕过漏洞",
			Solution:    "更新MySQL到5.7.28或8.0.18及以上版本",
			CVE:         "CVE-2019-2631",
			Affected:    "MySQL 5.7.27及以下，8.0.17及以下",
		})
	}

	// PostgreSQL漏洞检测
	if strings.Contains(programName, "postgres") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "POSTGRES-001",
			Name:        "PostgreSQL权限提升漏洞",
			Severity:    "High",
			Description: "PostgreSQL存在权限提升漏洞",
			Solution:    "更新PostgreSQL到13.3、12.7、11.12、10.17或9.6.22及以上版本",
			CVE:         "CVE-2021-3677",
			Affected:    "PostgreSQL 9.6-13.2",
		})
	}

	// Docker漏洞检测
	if strings.Contains(programName, "docker") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "DOCKER-001",
			Name:        "Docker逃逸漏洞",
			Severity:    "Critical",
			Description: "Docker存在容器逃逸漏洞",
			Solution:    "更新Docker到20.10.7及以上版本",
			CVE:         "CVE-2021-21284",
			Affected:    "Docker 20.10.5及以下",
		})
	}

	return vulnerabilities
}