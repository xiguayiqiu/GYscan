package scanners

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"GYscan-Win-C2/internal/vulnscan"
	"GYscan-Win-C2/pkg/types"
	"GYscan-Win-C2/pkg/utils"
	"GYscan-Win-C2/tools/nuclei"
)

// VulnScanner 漏洞扫描器
type VulnScanner struct {
	Verbose        bool
	nucleiEngine   *nuclei.Engine
	nucleiExecutor *nuclei.Executor
}

// ScanResult 扫描结果
type ScanResult struct {
	Target          string
	OSInfo          string
	Timestamp       time.Time
	ScanDuration    time.Duration
	Vulnerabilities []Vulnerability
	Services        []ServiceInfo
	Programs        []ProgramInfo
	EvidenceChains  []utils.EvidenceChain
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Solution    string
	CVE         string
	Affected    string
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name            string
	Port            int
	Protocol        string
	Status          string
	Version         string
	Vulnerabilities []Vulnerability
}

// ProgramInfo 程序信息
type ProgramInfo struct {
	Name            string
	Version         string
	Path            string
	InstallPath     string
	Publisher       string
	InstallDate     string
	Vulnerabilities []Vulnerability
}

// NewVulnScanner 创建新的漏洞扫描器
func NewVulnScanner(verbose bool) *VulnScanner {
	scanner := &VulnScanner{
		Verbose: verbose,
	}

	// 初始化nuclei引擎
	scanner.initNucleiEngine()

	return scanner
}

// Scan 执行漏洞扫描
func (vs *VulnScanner) Scan(target, scanType string) (*ScanResult, error) {
	result := &ScanResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	// 获取系统信息
	result.OSInfo = vs.getOSInfo()

	// 根据扫描类型执行相应的扫描
	scanTypes := strings.Split(scanType, ",")
	for _, t := range scanTypes {
		switch strings.ToLower(t) {
		case "all":
			vs.scanSystemVulnerabilities(result)
			vs.scanServices(result)
			vs.scanPrograms(result)
			vs.scanMiddleware(result)
			vs.scanCommandExec(result)
			vs.scanPrivilegeEscalation(result)
			vs.scanSQLInjection(result)
		case "system":
			vs.scanSystemVulnerabilities(result)
		case "services":
			vs.scanServices(result)
		case "programs":
			vs.scanPrograms(result)
		case "middleware":
			vs.scanMiddleware(result)
		case "command_exec":
			vs.scanCommandExec(result)
		case "privilege_escalation":
			vs.scanPrivilegeEscalation(result)
		case "sql_injection":
			vs.scanSQLInjection(result)
		}
	}

	result.ScanDuration = time.Since(result.Timestamp)
	return result, nil
}

// initNucleiEngine 初始化nuclei引擎
func (vs *VulnScanner) initNucleiEngine() {
	if vs.Verbose {
		fmt.Println("正在初始化nuclei引擎...")
	}

	// 创建nuclei引擎
	vs.nucleiEngine = nuclei.NewEngine(vs.Verbose)

	// 加载nuclei模板
	// 首先尝试当前目录下的templates文件夹
	backupDir := filepath.Join(".", "templates")
	if err := vs.nucleiEngine.LoadTemplates(backupDir); err != nil {
		if vs.Verbose {
			fmt.Printf("警告: 无法加载备用模板: %v\n", err)
		}
		// 尝试绝对路径模板目录
		templateDir := filepath.Join("i:\\GYscan\\nuclei_poc\\poc")
		if err := vs.nucleiEngine.LoadTemplates(templateDir); err != nil {
			if vs.Verbose {
				fmt.Printf("警告: 无法加载nuclei模板: %v\n", err)
			}
		}
	}

	// 创建执行器
	vs.nucleiExecutor = nuclei.NewExecutor(vs.nucleiEngine, vs.Verbose)

	if vs.Verbose {
		fmt.Printf("nuclei引擎初始化完成，加载了 %d 个模板\n", vs.nucleiEngine.TemplateCount())
	}
}

// scanWithNuclei 使用nuclei引擎进行漏洞扫描
func (vs *VulnScanner) scanWithNuclei(result *ScanResult) {
	if vs.nucleiEngine == nil || vs.nucleiExecutor == nil {
		if vs.Verbose {
			fmt.Println("警告: nuclei引擎未初始化，跳过nuclei扫描")
		}
		return
	}

	if vs.nucleiEngine.TemplateCount() == 0 {
		if vs.Verbose {
			fmt.Println("警告: 没有加载nuclei模板，跳过nuclei扫描")
		}
		return
	}

	if vs.Verbose {
		fmt.Println("开始使用nuclei引擎进行漏洞扫描...")
	}

	// 执行nuclei扫描
	nucleiResults, err := vs.nucleiExecutor.ExecuteAllTemplates(result.Target)
	if err != nil {
		if vs.Verbose {
			fmt.Printf("nuclei扫描错误: %v\n", err)
		}
		return
	}

	// 转换nuclei结果到Vulnerability格式
	for _, nr := range nucleiResults {
		if nr.Matched {
			vuln := Vulnerability{
				ID:          nr.TemplateID,
				Name:        nr.TemplateName,
				Severity:    nr.Severity,
				Description: fmt.Sprintf("nuclei检测到漏洞: %s", nr.TemplateName),
				Solution:    "请参考相关CVE信息进行修复",
				CVE:         extractCVEFromTemplateID(nr.TemplateID),
				Affected:    result.Target,
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	if vs.Verbose {
		fmt.Printf("nuclei扫描完成，发现 %d 个漏洞\n", len(nucleiResults))
	}
}

// extractCVEFromTemplateID 从模板ID中提取CVE编号
func extractCVEFromTemplateID(templateID string) string {
	if strings.HasPrefix(strings.ToUpper(templateID), "CVE-") {
		return templateID
	}

	// 尝试从ID中提取CVE编号
	if strings.Contains(strings.ToUpper(templateID), "CVE") {
		parts := strings.Split(templateID, "-")
		for i, part := range parts {
			if strings.ToUpper(part) == "CVE" && i+2 < len(parts) {
				return fmt.Sprintf("CVE-%s-%s", parts[i+1], parts[i+2])
			}
		}
	}

	return ""
}

// getOSInfo 获取操作系统信息
func (vs *VulnScanner) getOSInfo() string {
	// 实际获取Windows系统版本信息
	osInfo := getActualWindowsVersion()
	if osInfo == "" {
		return "Windows System Information"
	}
	return osInfo
}

// getActualWindowsVersion 获取实际的Windows版本信息
func getActualWindowsVersion() string {
	// 使用PowerShell命令获取详细的Windows版本信息
	cmd := exec.Command("powershell", "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json")
	output, err := cmd.Output()
	if err != nil {
		// 备用方法：使用systeminfo命令
		cmd = exec.Command("systeminfo", "|", "findstr", "/B", "/C:\"OS Name\"", "/C:\"OS Version\"")
		output, err = cmd.Output()
		if err != nil {
			return ""
		}
		return string(output)
	}
	return string(output)
}

// scanSystemVulnerabilities 扫描系统漏洞
func (vs *VulnScanner) scanSystemVulnerabilities(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描Windows系统漏洞...")
	}

	// 获取实际系统版本信息
	osInfo := vs.getOSInfo()

	// 基于实际系统版本检测漏洞
	vulnerabilities := detectWindowsSystemVulnerabilities()

	// 过滤掉不适用于当前系统的漏洞
	filteredVulnerabilities := vs.filterVulnerabilitiesBySystem(vulnerabilities, osInfo)

	// 过滤重复漏洞
	filteredVulnerabilities = vs.filterDuplicateVulnerabilities(filteredVulnerabilities)

	result.Vulnerabilities = append(result.Vulnerabilities, filteredVulnerabilities...)

	// 扫描补丁和更新状态
	patchVulns := scanPatchVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, patchVulns...)

	// 扫描文件系统和注册表
	fileSystemVulns := vs.scanFileSystemAndRegistry()
	result.Vulnerabilities = append(result.Vulnerabilities, fileSystemVulns...)

	// 扫描安全配置
	configVulns := vs.scanSecurityConfigurations()
	result.Vulnerabilities = append(result.Vulnerabilities, configVulns...)

	// 执行证据链分析
	if vs.Verbose {
		fmt.Println("开始证据链分析...")
	}
	evidenceChains := vs.performEvidenceChainAnalysis(result.Vulnerabilities)
	result.EvidenceChains = evidenceChains

	// 使用nuclei引擎进行真实漏洞扫描
	vs.scanWithNuclei(result)

	if vs.Verbose {
		fmt.Printf("发现系统漏洞: %d个 (过滤后: %d个)\n", len(vulnerabilities), len(filteredVulnerabilities))
		fmt.Printf("发现补丁漏洞: %d个\n", len(patchVulns))
		fmt.Printf("发现文件系统漏洞: %d个\n", len(fileSystemVulns))
		fmt.Printf("发现配置漏洞: %d个\n", len(configVulns))
		fmt.Printf("生成证据链: %d个\n", len(evidenceChains))
		fmt.Printf("nuclei扫描发现漏洞: %d个\n", len(result.Vulnerabilities)-len(filteredVulnerabilities)-len(patchVulns)-len(fileSystemVulns)-len(configVulns))
	}
}

// scanPatchVulnerabilities 扫描补丁和更新相关的漏洞
func scanPatchVulnerabilities() []Vulnerability {
	var vulnerabilities []Vulnerability

	// 创建补丁检查器
	patchChecker := utils.NewPatchChecker(false)

	// 检查系统补丁
	_, patchVulns := patchChecker.CheckSystemPatches()
	for _, vuln := range patchVulns {
		vulnerabilities = append(vulnerabilities, convertTypesVulnerability(vuln))
	}

	// 检查文件版本
	fileVulns := patchChecker.CheckFileVersions()
	for _, vuln := range fileVulns {
		vulnerabilities = append(vulnerabilities, convertTypesVulnerability(vuln))
	}

	// 检查安全更新状态
	updateVulns := patchChecker.CheckSecurityUpdates()
	for _, vuln := range updateVulns {
		vulnerabilities = append(vulnerabilities, convertTypesVulnerability(vuln))
	}

	return vulnerabilities
}

// convertTypesVulnerability 将types.Vulnerability转换为Vulnerability
func convertTypesVulnerability(tv types.Vulnerability) Vulnerability {
	// 由于types.Vulnerability和Vulnerability结构体相同，可以直接类型转换
	return Vulnerability(tv)
}

// filterVulnerabilitiesBySystem 根据实际系统版本过滤漏洞
func (vs *VulnScanner) filterVulnerabilitiesBySystem(vulnerabilities []Vulnerability, osInfo string) []Vulnerability {
	var filtered []Vulnerability

	// 解析系统版本信息
	versionInfo := parseWindowsVersion(osInfo)

	for _, vuln := range vulnerabilities {
		// 检查漏洞是否适用于当前系统
		if vs.isVulnerabilityApplicable(vuln, versionInfo) {
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}

// parseWindowsVersion 解析Windows版本信息
func parseWindowsVersion(osInfo string) map[string]string {
	info := make(map[string]string)

	// 简单的版本解析逻辑
	if strings.Contains(osInfo, "Windows 11") {
		info["major"] = "11"
	} else if strings.Contains(osInfo, "Windows 10") {
		info["major"] = "10"
	} else if strings.Contains(osInfo, "Windows 8") {
		info["major"] = "8"
	} else if strings.Contains(osInfo, "Windows 7") {
		info["major"] = "7"
	} else if strings.Contains(osInfo, "Windows Vista") {
		info["major"] = "Vista"
	}

	return info
}

// isVulnerabilityApplicable 检查漏洞是否适用于当前系统
func (vs *VulnScanner) isVulnerabilityApplicable(vuln Vulnerability, versionInfo map[string]string) bool {
	// 如果漏洞没有指定受影响系统，则默认适用
	if vuln.Affected == "" || vuln.Affected == "所有Windows系统" {
		return true
	}

	// 检查漏洞是否适用于当前系统版本
	if strings.Contains(vuln.Affected, versionInfo["major"]) {
		return true
	}

	// 检查通用漏洞
	if strings.Contains(vuln.Affected, "Windows") && !strings.Contains(vuln.Affected, "特定") {
		return true
	}

	return false
}

// filterDuplicateVulnerabilities 过滤重复的漏洞
func (vs *VulnScanner) filterDuplicateVulnerabilities(vulnerabilities []Vulnerability) []Vulnerability {
	var filtered []Vulnerability
	seen := make(map[string]bool)

	for _, vuln := range vulnerabilities {
		key := vuln.ID + "_" + vuln.Name
		if !seen[key] {
			seen[key] = true
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}

// scanServices 扫描服务漏洞
func (vs *VulnScanner) scanServices(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描服务漏洞...")
	}

	// 检测运行的服务
	services, serviceVulns := scanWindowsServices()
	result.Services = services
	result.Vulnerabilities = append(result.Vulnerabilities, serviceVulns...)

	if vs.Verbose {
		fmt.Printf("发现服务: %d个\n", len(services))
		fmt.Printf("发现服务漏洞: %d个\n", len(serviceVulns))
	}
}

// scanPrograms 扫描程序漏洞
func (vs *VulnScanner) scanPrograms(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描程序漏洞...")
	}

	// 检测安装的程序
	programs, programVulns := scanWindowsPrograms()
	result.Programs = programs
	result.Vulnerabilities = append(result.Vulnerabilities, programVulns...)

	if vs.Verbose {
		fmt.Printf("发现程序: %d个\n", len(programs))
		fmt.Printf("发现程序漏洞: %d个\n", len(programVulns))
	}
}

// scanMiddleware 扫描中间件漏洞
func (vs *VulnScanner) scanMiddleware(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描中间件漏洞...")
	}

	// 检测中间件漏洞
	middlewareVulns := utils.DetectMiddlewareVulnerabilities()
	
	// 转换types.Vulnerability到Vulnerability
	for _, vuln := range middlewareVulns {
		result.Vulnerabilities = append(result.Vulnerabilities, convertTypesVulnerability(vuln))
	}

	if vs.Verbose {
		fmt.Printf("发现中间件漏洞: %d个\n", len(middlewareVulns))
	}
}

// scanCommandExec 扫描命令执行漏洞
func (vs *VulnScanner) scanCommandExec(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描命令执行漏洞...")
	}

	// 检测命令执行漏洞
	commandExecVulns := detectCommandExecVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, commandExecVulns...)

	if vs.Verbose {
		fmt.Printf("发现命令执行漏洞: %d个\n", len(commandExecVulns))
	}
}

// scanPrivilegeEscalation 扫描权限提升漏洞
func (vs *VulnScanner) scanPrivilegeEscalation(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描权限提升漏洞...")
	}

	// 检测权限提升漏洞
	privilegeEscalationVulns := detectPrivilegeEscalationVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, privilegeEscalationVulns...)

	if vs.Verbose {
		fmt.Printf("发现权限提升漏洞: %d个\n", len(privilegeEscalationVulns))
	}
}

// scanSQLInjection 扫描SQL注入漏洞
func (vs *VulnScanner) scanSQLInjection(result *ScanResult) {
	if vs.Verbose {
		fmt.Println("开始扫描SQL注入漏洞...")
	}

	// 检测SQL注入漏洞
	sqlInjectionVulns := detectSQLInjectionVulnerabilities()
	result.Vulnerabilities = append(result.Vulnerabilities, sqlInjectionVulns...)

	if vs.Verbose {
		fmt.Printf("发现SQL注入漏洞: %d个\n", len(sqlInjectionVulns))
	}
}

// detectCommandExecVulnerabilities 检测命令执行漏洞
func detectCommandExecVulnerabilities() []Vulnerability {
	_ = vulnscan.NewCommandExecScanner(false)
	// 由于命令执行检测需要服务信息，这里暂时返回空结果
	// 在实际应用中应该先进行服务发现
	return []Vulnerability{}
}

// detectPrivilegeEscalationVulnerabilities 检测权限提升漏洞
func detectPrivilegeEscalationVulnerabilities() []Vulnerability {
	scanner := vulnscan.NewPrivilegeEscalationScanner(false)
	results := scanner.Scan()

	var vulnerabilities []Vulnerability
	for _, result := range results {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			ID:          result.ID,
			Name:        result.Name,
			Severity:    result.Severity,
			Description: result.Description,
			Solution:    result.Solution,
			CVE:         result.CVE,
			Affected:    result.Affected,
		})
	}
	return vulnerabilities
}

// detectSQLInjectionVulnerabilities 检测SQL注入漏洞
func detectSQLInjectionVulnerabilities() []Vulnerability {
	_ = vulnscan.NewSQLInjectionScanner(false)
	// 由于SQL注入检测需要服务信息，这里暂时返回空结果
	// 在实际应用中应该先进行服务发现
	return []Vulnerability{}
}

// performEvidenceChainAnalysis 执行证据链分析
func (vs *VulnScanner) performEvidenceChainAnalysis(vulnerabilities []Vulnerability) []utils.EvidenceChain {
	var evidenceChains []utils.EvidenceChain

	// 创建证据链分析器
	analyzer := utils.NewEvidenceChainAnalyzer(vs.Verbose)

	// 对每个漏洞进行证据链分析
	for _, vuln := range vulnerabilities {
		chain := analyzer.AnalyzeVulnerability(vuln.ID)
		if chain.Conclusion != "" {
			evidenceChains = append(evidenceChains, *chain)
		}
	}

	return evidenceChains
}

// scanFileSystemAndRegistry 扫描文件系统和注册表
func (vs *VulnScanner) scanFileSystemAndRegistry() []Vulnerability {
	if vs.Verbose {
		fmt.Println("开始扫描文件系统和注册表...")
	}

	// 创建文件系统检查器
	fileSystemChecker := utils.NewFileSystemChecker(vs.Verbose)

	// 检查系统文件
	_, fileVulns := fileSystemChecker.CheckSystemFiles()

	// 检查注册表
	_, registryVulns := fileSystemChecker.CheckRegistryKeys()

	// 合并漏洞结果
	var vulnerabilities []Vulnerability
	
	// 转换types.Vulnerability到Vulnerability
	for _, vuln := range fileVulns {
		vulnerabilities = append(vulnerabilities, convertTypesVulnerability(vuln))
	}
	for _, vuln := range registryVulns {
		vulnerabilities = append(vulnerabilities, convertTypesVulnerability(vuln))
	}

	return vulnerabilities
}

// scanSecurityConfigurations 扫描安全配置
func (vs *VulnScanner) scanSecurityConfigurations() []Vulnerability {
	if vs.Verbose {
		fmt.Println("开始扫描安全配置...")
	}

	// 创建配置检查器
	configChecker := utils.NewConfigChecker(vs.Verbose)

	// 检查安全配置
	_, configVulns := configChecker.CheckSecurityConfigurations()

	// 转换types.Vulnerability到Vulnerability
	var vulnerabilities []Vulnerability
	for _, vuln := range configVulns {
		vulnerabilities = append(vulnerabilities, convertTypesVulnerability(vuln))
	}

	return vulnerabilities
}
