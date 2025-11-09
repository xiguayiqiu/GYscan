package main

import (
	"os/exec"
	"strings"
)

// scanWindowsPrograms 扫描Windows程序
func scanWindowsPrograms() ([]ProgramInfo, []Vulnerability) {
	var programs []ProgramInfo
	var vulnerabilities []Vulnerability

	// 检测常见Windows程序
	commonPrograms := []string{
		"notepad.exe", "calc.exe", "mspaint.exe", "winword.exe", "excel.exe",
		"powerpnt.exe", "acrord32.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
		"java.exe", "python.exe", "node.exe", "git.exe", "putty.exe",
		"vncserver.exe", "teamviewer.exe", "anydesk.exe", "winscp.exe", "filezilla.exe",
		"mysql.exe", "postgres.exe", "mongod.exe", "redis-server.exe", "apache.exe",
		"nginx.exe", "iisexpress.exe", "tomcat.exe", "jenkins.exe", "docker.exe",
	}

	for _, prog := range commonPrograms {
		cmd := exec.Command("where", prog)
		output, err := cmd.Output()
		if err == nil {
			path := strings.TrimSpace(string(output))
			if path != "" {
				program := ProgramInfo{
					Name:    prog,
					Path:    path,
					Version: getProgramVersion(path),
				}
				programs = append(programs, program)
			}
		}
	}

	// 检测Windows程序漏洞
	vulnerabilities = append(vulnerabilities, detectWindowsProgramVulnerabilities(programs)...)

	return programs, vulnerabilities
}

// getProgramVersion 获取程序版本
func getProgramVersion(path string) string {
	// 这里可以实现获取程序版本信息的逻辑
	// 例如通过文件属性或执行命令获取版本
	return "Unknown Version"
}

// detectWindowsProgramVulnerabilities 检测Windows程序漏洞
func detectWindowsProgramVulnerabilities(programs []ProgramInfo) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, program := range programs {
		switch {
		case strings.Contains(strings.ToLower(program.Name), "chrome"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "CHROME-001",
				Name:        "Chrome V8引擎漏洞",
				Severity:    "High",
				Description: "Chrome V8 JavaScript引擎存在远程代码执行漏洞",
				Solution:    "更新到最新版本的Chrome浏览器",
				CVE:         "CVE-2021-30551",
				Affected:    "Google Chrome",
			})
		case strings.Contains(strings.ToLower(program.Name), "firefox"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "FIREFOX-001",
				Name:        "Firefox内存损坏漏洞",
				Severity:    "High",
				Description: "Firefox浏览器存在内存损坏漏洞",
				Solution:    "更新到最新版本的Firefox浏览器",
				CVE:         "CVE-2021-29964",
				Affected:    "Mozilla Firefox",
			})
		case strings.Contains(strings.ToLower(program.Name), "java"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "JAVA-001",
				Name:        "Java反序列化漏洞",
				Severity:    "Critical",
				Description: "Java存在反序列化远程代码执行漏洞",
				Solution:    "更新到最新版本的Java",
				CVE:         "CVE-2021-44228",
				Affected:    "Oracle Java",
			})
		case strings.Contains(strings.ToLower(program.Name), "python"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "PYTHON-001",
				Name:        "Python代码注入漏洞",
				Severity:    "Medium",
				Description: "Python存在代码注入漏洞",
				Solution:    "更新到最新版本的Python",
				CVE:         "CVE-2021-3177",
				Affected:    "Python",
			})
		case strings.Contains(strings.ToLower(program.Name), "node"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "NODE-001",
				Name:        "Node.js代码执行漏洞",
				Severity:    "High",
				Description: "Node.js存在远程代码执行漏洞",
				Solution:    "更新到最新版本的Node.js",
				CVE:         "CVE-2021-22931",
				Affected:    "Node.js",
			})
		case strings.Contains(strings.ToLower(program.Name), "mysql"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "MYSQL-001",
				Name:        "MySQL权限提升漏洞",
				Severity:    "High",
				Description: "MySQL存在权限提升漏洞",
				Solution:    "更新到最新版本的MySQL",
				CVE:         "CVE-2021-22946",
				Affected:    "MySQL",
			})
		case strings.Contains(strings.ToLower(program.Name), "docker"):
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:          "DOCKER-001",
				Name:        "Docker容器逃逸漏洞",
				Severity:    "Critical",
				Description: "Docker存在容器逃逸漏洞",
				Solution:    "更新到最新版本的Docker",
				CVE:         "CVE-2021-21285",
				Affected:    "Docker",
			})
		}
	}

	return vulnerabilities
}