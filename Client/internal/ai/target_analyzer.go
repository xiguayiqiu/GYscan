package ai

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"GYscan/internal/ai/config"
	"GYscan/internal/ai/types"
	"GYscan/internal/utils"
)

// TargetAnalyzer 目标识别与智能分析器
type TargetAnalyzer struct {
	AIClient    *AIClient
	ToolManager *ToolManager
	Config      config.AIConfig
}

// TargetAnalysisResult 目标分析结果
type TargetAnalysisResult struct {
	Target          string                `json:"target"`
	Type            types.TargetType      `json:"type"`
	Environment     string                `json:"environment"`
	RiskLevel       types.RiskLevel       `json:"risk_level"`
	OpenPorts       []int                 `json:"open_ports"`
	Services        map[int]string        `json:"services"`
	Technologies    []string              `json:"technologies"`
	Vulnerabilities []types.Vulnerability `json:"vulnerabilities"`
	Findings        []types.Finding       `json:"findings"`
	Recommendations []string              `json:"recommendations"`
	Confidence      float64               `json:"confidence"`
	AnalysisTime    time.Time             `json:"analysis_time"`
}

// NewTargetAnalyzer 创建新的目标分析器
func NewTargetAnalyzer(aiClient *AIClient, toolManager *ToolManager, cfg config.AIConfig) *TargetAnalyzer {
	return &TargetAnalyzer{
		AIClient:    aiClient,
		ToolManager: toolManager,
		Config:      cfg,
	}
}

// Analyze 执行目标智能分析
func (ta *TargetAnalyzer) Analyze(target string) (*TargetAnalysisResult, error) {
	utils.InfoPrint("开始智能分析目标: %s", target)

	result := &TargetAnalysisResult{
		Target:       target,
		AnalysisTime: time.Now(),
	}

	// 1. 基础目标验证
	if err := ta.validateTarget(target); err != nil {
		return nil, fmt.Errorf("目标验证失败: %v", err)
	}

	// 2. 目标类型识别
	targetType, err := ta.identifyTargetType(target)
	if err != nil {
		return nil, fmt.Errorf("目标类型识别失败: %v", err)
	}
	result.Type = targetType

	// 3. 环境分析
	environment, err := ta.analyzeEnvironment(target, targetType)
	if err != nil {
		utils.WarningPrint("环境分析失败: %v", err)
	} else {
		result.Environment = environment
	}

	// 4. 端口和服务扫描
	openPorts, services, err := ta.scanPortsAndServices(target)
	if err != nil {
		utils.WarningPrint("端口扫描失败: %v", err)
	} else {
		result.OpenPorts = openPorts
		result.Services = services
	}

	// 5. 技术栈识别
	technologies, err := ta.identifyTechnologies(target, services)
	if err != nil {
		utils.WarningPrint("技术栈识别失败: %v", err)
	} else {
		result.Technologies = technologies
	}

	// 6. 风险评估
	riskLevel, confidence, err := ta.assessRisk(target, targetType, services, technologies)
	if err != nil {
		utils.WarningPrint("风险评估失败: %v", err)
	} else {
		result.RiskLevel = riskLevel
		result.Confidence = confidence
	}

	// 7. 漏洞预测
	vulnerabilities, findings, err := ta.predictVulnerabilities(target, targetType, services, technologies)
	if err != nil {
		utils.WarningPrint("漏洞预测失败: %v", err)
	} else {
		result.Vulnerabilities = vulnerabilities
		result.Findings = findings
	}

	// 8. 生成建议
	recommendations := ta.generateRecommendations(targetType, riskLevel, vulnerabilities)
	result.Recommendations = recommendations

	utils.SuccessPrint("目标分析完成 - 类型: %s, 风险级别: %s, 置信度: %.2f",
		result.Type, result.RiskLevel, result.Confidence)

	return result, nil
}

// validateTarget 验证目标格式
func (ta *TargetAnalyzer) validateTarget(target string) error {
	// 检查是否为IP地址
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}

	// 检查是否为域名
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, target); matched {
		return nil
	}

	// 检查是否为URL
	if matched, _ := regexp.MatchString(`^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?$`, target); matched {
		return nil
	}

	return fmt.Errorf("无效的目标格式: %s", target)
}

// identifyTargetType 识别目标类型
func (ta *TargetAnalyzer) identifyTargetType(target string) (types.TargetType, error) {
	// 使用AI进行目标类型识别
	messages := []Message{
		{
			Role: "system",
			Content: `你是一个专业的网络安全专家，请分析给定的目标并确定其类型。

目标类型包括：
- web_application: Web应用
- network: 网络服务
- api: API服务
- mobile: 移动应用后端
- iot: IoT设备
- cloud: 云服务

请根据目标特征进行判断。`,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("分析目标: %s，请确定其类型", target),
		},
	}

	response, err := ta.AIClient.Chat(messages)
	if err != nil {
		return types.TargetTypeWebApp, fmt.Errorf("AI分析失败: %v", err)
	}

	// 解析AI响应
	if strings.Contains(strings.ToLower(response), "web") ||
		strings.Contains(strings.ToLower(response), "http") ||
		strings.Contains(strings.ToLower(response), "网站") {
		return types.TargetTypeWebApp, nil
	} else if strings.Contains(strings.ToLower(response), "api") {
		return types.TargetTypeAPI, nil
	} else if strings.Contains(strings.ToLower(response), "network") ||
		strings.Contains(strings.ToLower(response), "网络") {
		return types.TargetTypeNetwork, nil
	} else if strings.Contains(strings.ToLower(response), "mobile") ||
		strings.Contains(strings.ToLower(response), "移动") {
		return types.TargetTypeMobile, nil
	} else if strings.Contains(strings.ToLower(response), "iot") ||
		strings.Contains(strings.ToLower(response), "物联网") {
		return types.TargetTypeIoT, nil
	} else if strings.Contains(strings.ToLower(response), "cloud") ||
		strings.Contains(strings.ToLower(response), "云") {
		return types.TargetTypeCloud, nil
	}

	// 默认返回Web应用类型
	return types.TargetTypeWebApp, nil
}

// analyzeEnvironment 分析目标环境
func (ta *TargetAnalyzer) analyzeEnvironment(target string, targetType types.TargetType) (string, error) {
	messages := []Message{
		{
			Role: "system",
			Content: `你是一个专业的网络安全专家，请分析目标的环境特征。

环境类型包括：
- production: 生产环境
- staging: 预发布环境
- development: 开发环境
- testing: 测试环境

请根据目标特征进行判断。`,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("分析目标: %s (类型: %s) 的环境特征", target, targetType),
		},
	}

	response, err := ta.AIClient.Chat(messages)
	if err != nil {
		return "production", fmt.Errorf("AI分析失败: %v", err)
	}

	// 解析环境类型
	if strings.Contains(strings.ToLower(response), "production") ||
		strings.Contains(strings.ToLower(response), "prod") ||
		strings.Contains(strings.ToLower(response), "生产") {
		return "production", nil
	} else if strings.Contains(strings.ToLower(response), "staging") ||
		strings.Contains(strings.ToLower(response), "预发布") {
		return "staging", nil
	} else if strings.Contains(strings.ToLower(response), "development") ||
		strings.Contains(strings.ToLower(response), "dev") ||
		strings.Contains(strings.ToLower(response), "开发") {
		return "development", nil
	} else if strings.Contains(strings.ToLower(response), "testing") ||
		strings.Contains(strings.ToLower(response), "test") ||
		strings.Contains(strings.ToLower(response), "测试") {
		return "testing", nil
	}

	// 默认返回生产环境
	return "production", nil
}

// scanPortsAndServices 扫描端口和服务
func (ta *TargetAnalyzer) scanPortsAndServices(target string) ([]int, map[int]string, error) {
	utils.InfoPrint("正在扫描目标端口和服务...")

	openPorts := []int{}
	services := make(map[int]string)

	// 检查nmap工具是否可用
	if nmapTool, exists := ta.ToolManager.GetTool("nmap"); exists && nmapTool.IsAvailable() {
		// 使用nmap进行快速端口扫描
		result, err := nmapTool.Run("-sS", "-T4", "-F", target)
		if err != nil {
			utils.WarningPrint("nmap扫描失败: %v", err)
		} else {
			// 解析nmap输出
			openPorts, services = ta.parseNmapOutput(result)
		}
	} else {
		// 如果没有nmap，使用简单的TCP连接测试
		utils.InfoPrint("nmap不可用，使用基础端口扫描")
		commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080}

		for _, port := range commonPorts {
			if ta.isPortOpen(target, port) {
				openPorts = append(openPorts, port)
				services[port] = ta.guessService(port)
			}
		}
	}

	utils.InfoPrint("发现 %d 个开放端口", len(openPorts))
	return openPorts, services, nil
}

// parseNmapOutput 解析nmap输出
func (ta *TargetAnalyzer) parseNmapOutput(output string) ([]int, map[int]string) {
	openPorts := []int{}
	services := make(map[int]string)

	// 简单的nmap输出解析逻辑
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "open") && strings.Contains(line, "/tcp") {
			// 提取端口号和服务信息
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				portStr := strings.Split(fields[0], "/")[0]
				var port int
				fmt.Sscanf(portStr, "%d", &port)

				openPorts = append(openPorts, port)
				if len(fields) >= 4 {
					services[port] = fields[2]
				} else {
					services[port] = "unknown"
				}
			}
		}
	}

	return openPorts, services
}

// isPortOpen 检查端口是否开放
func (ta *TargetAnalyzer) isPortOpen(target string, port int) bool {
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// guessService 根据端口猜测服务
func (ta *TargetAnalyzer) guessService(port int) string {
	serviceMap := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		445:  "microsoft-ds",
		993:  "imaps",
		995:  "pop3s",
		1723: "pptp",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-proxy",
	}

	if service, exists := serviceMap[port]; exists {
		return service
	}
	return "unknown"
}

// identifyTechnologies 识别技术栈
func (ta *TargetAnalyzer) identifyTechnologies(target string, services map[int]string) ([]string, error) {
	technologies := []string{}

	// 基于开放服务识别技术栈
	for port, service := range services {
		switch service {
		case "http", "https":
			techs, err := ta.identifyWebTechnologies(target, port)
			if err == nil {
				technologies = append(technologies, techs...)
			}
		case "ssh":
			technologies = append(technologies, "openssh")
		case "mysql":
			technologies = append(technologies, "mysql")
		case "postgresql":
			technologies = append(technologies, "postgresql")
		case "rdp":
			technologies = append(technologies, "windows-remote-desktop")
		}
	}

	return technologies, nil
}

// identifyWebTechnologies 识别Web技术栈
func (ta *TargetAnalyzer) identifyWebTechnologies(target string, port int) ([]string, error) {
	technologies := []string{}

	// 这里可以集成whatweb或其他Web指纹识别工具
	// 暂时返回基础信息
	technologies = append(technologies, "web-server")

	return technologies, nil
}

// assessRisk 风险评估
func (ta *TargetAnalyzer) assessRisk(target string, targetType types.TargetType, services map[int]string, technologies []string) (types.RiskLevel, float64, error) {
	riskScore := 0.0

	// 基于目标类型评估基础风险
	switch targetType {
	case types.TargetTypeWebApp:
		riskScore += 6.0
	case types.TargetTypeAPI:
		riskScore += 7.0
	case types.TargetTypeNetwork:
		riskScore += 5.0
	case types.TargetTypeMobile:
		riskScore += 4.0
	case types.TargetTypeIoT:
		riskScore += 8.0
	case types.TargetTypeCloud:
		riskScore += 7.0
	}

	// 基于开放服务评估风险
	for _, service := range services {
		switch service {
		case "ssh", "rdp", "telnet":
			riskScore += 2.0
		case "ftp", "smtp", "pop3":
			riskScore += 1.5
		case "http", "https":
			riskScore += 1.0
		}
	}

	// 基于技术栈评估风险
	for _, tech := range technologies {
		if strings.Contains(tech, "outdated") || strings.Contains(tech, "vulnerable") {
			riskScore += 1.0
		}
	}

	// 计算风险级别
	var riskLevel types.RiskLevel
	if riskScore >= 8.0 {
		riskLevel = types.RiskLevelHigh
	} else if riskScore >= 5.0 {
		riskLevel = types.RiskLevelMedium
	} else {
		riskLevel = types.RiskLevelLow
	}

	// 计算置信度（基于分析数据的完整性）
	confidence := 0.7 // 基础置信度
	if len(services) > 0 {
		confidence += 0.2
	}
	if len(technologies) > 0 {
		confidence += 0.1
	}

	return riskLevel, confidence, nil
}

// predictVulnerabilities 预测漏洞
func (ta *TargetAnalyzer) predictVulnerabilities(target string, targetType types.TargetType, services map[int]string, technologies []string) ([]types.Vulnerability, []types.Finding, error) {
	vulnerabilities := []types.Vulnerability{}
	findings := []types.Finding{}

	// 基于目标类型和服务预测常见漏洞
	for port, service := range services {
		switch service {
		case "http", "https":
			vulns, finds := ta.predictWebVulnerabilities(target, port)
			vulnerabilities = append(vulnerabilities, vulns...)
			findings = append(findings, finds...)
		case "ssh":
			vulns, finds := ta.predictSSHVulnerabilities(target, port)
			vulnerabilities = append(vulnerabilities, vulns...)
			findings = append(findings, finds...)
		case "ftp":
			vulns, finds := ta.predictFTPVulnerabilities(target, port)
			vulnerabilities = append(vulnerabilities, vulns...)
			findings = append(findings, finds...)
		}
	}

	return vulnerabilities, findings, nil
}

// predictWebVulnerabilities 预测Web漏洞
func (ta *TargetAnalyzer) predictWebVulnerabilities(target string, port int) ([]types.Vulnerability, []types.Finding) {
	vulnerabilities := []types.Vulnerability{}
	findings := []types.Finding{}

	// 预测常见的Web漏洞
	commonVulns := []struct {
		name        string
		severity    string
		description string
	}{
		{"SQL注入", "high", "可能存在SQL注入漏洞"},
		{"XSS", "medium", "可能存在跨站脚本漏洞"},
		{"CSRF", "medium", "可能存在跨站请求伪造漏洞"},
		{"信息泄露", "low", "可能存在敏感信息泄露"},
	}

	for _, vuln := range commonVulns {
		vulnerabilities = append(vulnerabilities, types.Vulnerability{
			ID:          fmt.Sprintf("web-%s-%d", strings.ToLower(vuln.name), port),
			Name:        vuln.name,
			Description: vuln.description,
			Severity:    vuln.severity,
			Location:    fmt.Sprintf("%s:%d", target, port),
			Confidence:  0.5, // 预测性漏洞，置信度较低
			CreatedAt:   time.Now(),
		})
	}

	return vulnerabilities, findings
}

// predictSSHVulnerabilities 预测SSH漏洞
func (ta *TargetAnalyzer) predictSSHVulnerabilities(target string, port int) ([]types.Vulnerability, []types.Finding) {
	vulnerabilities := []types.Vulnerability{}
	findings := []types.Finding{}

	vulnerabilities = append(vulnerabilities, types.Vulnerability{
		ID:          fmt.Sprintf("ssh-weak-auth-%d", port),
		Name:        "SSH弱认证",
		Description: "SSH服务可能存在弱密码或默认凭据",
		Severity:    "high",
		Location:    fmt.Sprintf("%s:%d", target, port),
		Confidence:  0.6,
		CreatedAt:   time.Now(),
	})

	return vulnerabilities, findings
}

// predictFTPVulnerabilities 预测FTP漏洞
func (ta *TargetAnalyzer) predictFTPVulnerabilities(target string, port int) ([]types.Vulnerability, []types.Finding) {
	vulnerabilities := []types.Vulnerability{}
	findings := []types.Finding{}

	vulnerabilities = append(vulnerabilities, types.Vulnerability{
		ID:          fmt.Sprintf("ftp-anonymous-%d", port),
		Name:        "FTP匿名访问",
		Description: "FTP服务可能允许匿名访问",
		Severity:    "medium",
		Location:    fmt.Sprintf("%s:%d", target, port),
		Confidence:  0.7,
		CreatedAt:   time.Now(),
	})

	return vulnerabilities, findings
}

// generateRecommendations 生成建议
func (ta *TargetAnalyzer) generateRecommendations(targetType types.TargetType, riskLevel types.RiskLevel, vulnerabilities []types.Vulnerability) []string {
	recommendations := []string{}

	// 基于目标类型生成建议
	switch targetType {
	case types.TargetTypeWebApp:
		recommendations = append(recommendations,
			"执行Web应用安全扫描",
			"检查输入验证和输出编码",
			"验证会话管理安全性",
		)
	case types.TargetTypeAPI:
		recommendations = append(recommendations,
			"执行API安全测试",
			"验证认证和授权机制",
			"检查API速率限制",
		)
	case types.TargetTypeNetwork:
		recommendations = append(recommendations,
			"执行网络端口扫描",
			"检查防火墙配置",
			"验证网络分段",
		)
	}

	// 基于风险级别生成建议
	switch riskLevel {
	case types.RiskLevelHigh:
		recommendations = append(recommendations,
			"优先进行深度安全测试",
			"考虑立即修复高危问题",
			"加强监控和日志记录",
		)
	case types.RiskLevelMedium:
		recommendations = append(recommendations,
			"执行全面安全评估",
			"制定修复计划",
			"定期进行安全扫描",
		)
	}

	// 基于预测漏洞生成建议
	if len(vulnerabilities) > 0 {
		recommendations = append(recommendations,
			"验证预测漏洞的存在性",
			"实施相应的安全控制措施",
			"更新系统和应用程序",
		)
	}

	return recommendations
}
