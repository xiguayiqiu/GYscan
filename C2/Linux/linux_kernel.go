package main

import (
	"os/exec"
	"strings"
)

// detectLinuxKernelVulnerabilities 检测Linux内核漏洞
func detectLinuxKernelVulnerabilities() []Vulnerability {
	var vulnerabilities []Vulnerability

	// 获取内核版本信息
	kernelVersion := getKernelVersion()

	// 检测常见Linux内核漏洞
	vulnerabilities = append(vulnerabilities, detectCommonKernelVulnerabilities(kernelVersion)...)

	return vulnerabilities
}

// getKernelVersion 获取内核版本
func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown Kernel Version"
	}
	return strings.TrimSpace(string(output))
}

// detectCommonKernelVulnerabilities 检测常见内核漏洞
func detectCommonKernelVulnerabilities(kernelVersion string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Dirty Pipe漏洞 (CVE-2022-0847)
	if isVulnerableToDirtyPipe(kernelVersion) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "KERNEL-001",
			Name:        "Dirty Pipe漏洞",
			Severity:    "Critical",
			Description: "Linux内核存在Dirty Pipe漏洞，允许任意文件写入",
			Solution:    "升级到Linux内核5.16.11、5.15.25或5.10.102及以上版本",
			CVE:         "CVE-2022-0847",
			Affected:    "Linux内核5.8-5.16.10",
		})
	}

	// Dirty Cow漏洞 (CVE-2016-5195)
	if isVulnerableToDirtyCow(kernelVersion) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "KERNEL-002",
			Name:        "Dirty Cow漏洞",
			Severity:    "Critical",
			Description: "Linux内核存在Dirty Cow漏洞，允许权限提升",
			Solution:    "升级到Linux内核4.8.3、4.7.9或4.4.26及以上版本",
			CVE:         "CVE-2016-5195",
			Affected:    "Linux内核2.6.22-4.8.3",
		})
	}

	// SACK Panic漏洞 (CVE-2019-11477)
	if isVulnerableToSACKPanic(kernelVersion) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          "KERNEL-003",
			Name:        "SACK Panic漏洞",
			Severity:    "Critical",
			Description: "Linux内核TCP SACK处理存在拒绝服务漏洞",
			Solution:    "升级到Linux内核4.15、4.14.154、4.9.191、4.4.191或应用补丁",
			CVE:         "CVE-2019-11477",
			Affected:    "Linux内核2.6.29及以上",
		})
	}

	// BlueKeep漏洞 (CVE-2019-0708) - 虽然主要是Windows，但相关组件也可能受影响
	vulnerabilities = append(vulnerabilities, Vulnerability{
		ID:          "KERNEL-004",
		Name:        "内核内存泄露漏洞",
		Severity:    "High",
		Description: "Linux内核存在内存信息泄露漏洞",
		Solution:    "升级到最新内核版本",
		CVE:         "CVE-2021-33909",
		Affected:    "Linux内核3.16-5.13",
	})

	// PwnKit漏洞 (CVE-2021-4034)
	vulnerabilities = append(vulnerabilities, Vulnerability{
		ID:          "KERNEL-005",
		Name:        "PwnKit权限提升漏洞",
		Severity:    "Critical",
		Description: "Polkit存在本地权限提升漏洞",
		Solution:    "更新polkit包到0.120及以上版本",
		CVE:         "CVE-2021-4034",
		Affected:    "所有使用polkit的Linux系统",
	})

	return vulnerabilities
}

// isVulnerableToDirtyPipe 检查是否受Dirty Pipe漏洞影响
func isVulnerableToDirtyPipe(kernelVersion string) bool {
	// 简化的版本检查逻辑
	// 实际实现需要更精确的版本比较
	return strings.Contains(kernelVersion, "5.8") || 
		   strings.Contains(kernelVersion, "5.9") ||
		   strings.Contains(kernelVersion, "5.10") ||
		   strings.Contains(kernelVersion, "5.11") ||
		   strings.Contains(kernelVersion, "5.12") ||
		   strings.Contains(kernelVersion, "5.13") ||
		   strings.Contains(kernelVersion, "5.14") ||
		   strings.Contains(kernelVersion, "5.15") ||
		   strings.Contains(kernelVersion, "5.16")
}

// isVulnerableToDirtyCow 检查是否受Dirty Cow漏洞影响
func isVulnerableToDirtyCow(kernelVersion string) bool {
	// 简化的版本检查逻辑
	return strings.Contains(kernelVersion, "2.6") || 
		   strings.Contains(kernelVersion, "3.") ||
		   strings.Contains(kernelVersion, "4.0") ||
		   strings.Contains(kernelVersion, "4.1") ||
		   strings.Contains(kernelVersion, "4.2") ||
		   strings.Contains(kernelVersion, "4.3") ||
		   strings.Contains(kernelVersion, "4.4") ||
		   strings.Contains(kernelVersion, "4.5") ||
		   strings.Contains(kernelVersion, "4.6") ||
		   strings.Contains(kernelVersion, "4.7") ||
		   strings.Contains(kernelVersion, "4.8")
}

// isVulnerableToSACKPanic 检查是否受SACK Panic漏洞影响
func isVulnerableToSACKPanic(kernelVersion string) bool {
	// 简化的版本检查逻辑
	return strings.Contains(kernelVersion, "2.6") || 
		   strings.Contains(kernelVersion, "3.") ||
		   strings.Contains(kernelVersion, "4.")
}