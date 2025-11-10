package scanners

import (
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"
)

// ReportGenerator 报告生成器
type ReportGenerator struct{}

// NewReportGenerator 创建新的报告生成器
func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{}
}

// GenerateReport 生成报告
func (rg *ReportGenerator) GenerateReport(result *ScanResult, outputPath string) error {
	// 根据文件扩展名选择报告格式
	if strings.HasSuffix(outputPath, ".html") {
		return rg.generateHTMLReport(result, outputPath)
	} else if strings.HasSuffix(outputPath, ".json") {
		return rg.generateJSONReport(result, outputPath)
	} else {
		return rg.generateTextReport(result, outputPath)
	}
}

// generateTextReport 生成文本报告
func (rg *ReportGenerator) generateTextReport(result *ScanResult, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 报告头部
	fmt.Fprintf(file, "Windows漏洞扫描报告\n")
	fmt.Fprintf(file, "====================\n\n")
	fmt.Fprintf(file, "扫描目标: %s\n", result.Target)
	fmt.Fprintf(file, "操作系统: %s\n", result.OSInfo)
	fmt.Fprintf(file, "扫描时间: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "扫描耗时: %v\n\n", result.ScanDuration)
	
	// 添加提示信息
	fmt.Fprintf(file, "重要提示:\n")
	fmt.Fprintf(file, "==========\n")
	fmt.Fprintf(file, "本报告只是在基于你的服务、系统等信息进行的推测，可以留意并手动验证是否真实存在！\n\n")

	// 漏洞统计
	highCount := countSeverity(result.Vulnerabilities, "Critical") + countSeverity(result.Vulnerabilities, "High")
	mediumCount := countSeverity(result.Vulnerabilities, "Medium")
	lowCount := countSeverity(result.Vulnerabilities, "Low")

	fmt.Fprintf(file, "漏洞统计:\n")
	fmt.Fprintf(file, "- 高危漏洞: %d个\n", highCount)
	fmt.Fprintf(file, "- 中危漏洞: %d个\n", mediumCount)
	fmt.Fprintf(file, "- 低危漏洞: %d个\n", lowCount)
	fmt.Fprintf(file, "- 总计: %d个\n\n", len(result.Vulnerabilities))

	// 漏洞详情
	if len(result.Vulnerabilities) > 0 {
		fmt.Fprintf(file, "漏洞详情:\n")
		fmt.Fprintf(file, "==========\n\n")

		// 按严重程度排序
		sortedVulns := sortVulnerabilitiesBySeverity(result.Vulnerabilities)

		for i, vuln := range sortedVulns {
			fmt.Fprintf(file, "%d. [%s] %s\n", i+1, vuln.Severity, vuln.Name)
			fmt.Fprintf(file, "   漏洞ID: %s\n", vuln.ID)
			fmt.Fprintf(file, "   CVE编号: %s\n", vuln.CVE)
			fmt.Fprintf(file, "   描述: %s\n", vuln.Description)
			fmt.Fprintf(file, "   解决方案: %s\n", vuln.Solution)
			fmt.Fprintf(file, "   影响范围: %s\n\n", vuln.Affected)
		}
	} else {
		fmt.Fprintf(file, "未发现漏洞。\n\n")
	}

	// 服务信息
	if len(result.Services) > 0 {
		fmt.Fprintf(file, "发现的服务:\n")
		fmt.Fprintf(file, "============\n\n")
		for _, service := range result.Services {
			fmt.Fprintf(file, "- %s (端口: %d/%s, 状态: %s)\n", 
				service.Name, service.Port, service.Protocol, service.Status)
		}
		fmt.Fprintf(file, "\n")
	}

	// 程序信息
	if len(result.Programs) > 0 {
		fmt.Fprintf(file, "发现的程序:\n")
		fmt.Fprintf(file, "============\n\n")
		for _, program := range result.Programs {
			fmt.Fprintf(file, "- %s (版本: %s, 路径: %s)\n", 
				program.Name, program.Version, program.Path)
		}
	}

	return nil
}

// generateHTMLReport 生成HTML报告
func (rg *ReportGenerator) generateHTMLReport(result *ScanResult, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	tmpl := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows漏洞扫描报告 - {{.Target}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        .report-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            margin-bottom: 30px;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { 
            font-size: 2.5em; 
            margin-bottom: 10px; 
            font-weight: 300;
        }
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .info-item {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        .section { 
            padding: 30px; 
            border-bottom: 1px solid #eee; 
        }
        .section:last-child { border-bottom: none; }
        .section h2 { 
            color: #2c3e50; 
            margin-bottom: 20px; 
            font-size: 1.8em;
            font-weight: 600;
        }
        .warning-banner {
            background: linear-gradient(135deg, #ffeaa7 0%, #fab1a0 100%);
            border-left: 5px solid #e17055;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .stat-card.critical { border-left-color: #e74c3c; }
        .stat-card.high { border-left-color: #e67e22; }
        .stat-card.medium { border-left-color: #f39c12; }
        .stat-card.low { border-left-color: #27ae60; }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }
        .vulnerability { 
            background: #f8f9fa;
            border: 1px solid #e9ecef; 
            padding: 25px; 
            margin: 15px 0; 
            border-radius: 10px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .vulnerability:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        .vulnerability.critical { 
            border-left: 6px solid #e74c3c;
            background: linear-gradient(135deg, #fd746c 0%, #ff9068 100%);
            color: white;
        }
        .vulnerability.high { 
            border-left: 6px solid #e67e22;
            background: linear-gradient(135deg, #f46b45 0%, #eea849 100%);
        }
        .vulnerability.medium { 
            border-left: 6px solid #f39c12;
            background: linear-gradient(135deg, #feca57 0%, #d35400 100%);
        }
        .vulnerability.low { 
            border-left: 6px solid #27ae60;
            background: linear-gradient(135deg, #a8e6cf 0%, #3d9970 100%);
        }
        .vuln-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 15px;
        }
        .vuln-title {
            font-size: 1.3em;
            font-weight: 600;
            flex: 1;
        }
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .critical .severity-badge { background: rgba(255,255,255,0.2); }
        .vuln-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .detail-item {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 5px;
        }
        .detail-label {
            font-weight: 600;
            margin-bottom: 5px;
            opacity: 0.9;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        th, td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #eee;
        }
        th { 
            background: #3498db; 
            color: white; 
            font-weight: 600;
        }
        tr:hover { background: #f8f9fa; }
        @media (max-width: 768px) {
            .header-info { grid-template-columns: 1fr; }
            .vuln-details { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr; }
            .section { padding: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-card">
            <div class="header">
                <h1>🔒 Windows漏洞扫描报告</h1>
                <p>专业安全评估报告</p>
                <div class="header-info">
                    <div class="info-item">
                        <strong>扫描目标:</strong><br>{{.Target}}
                    </div>
                    <div class="info-item">
                        <strong>操作系统:</strong><br>{{.OSInfo}}
                    </div>
                    <div class="info-item">
                        <strong>扫描时间:</strong><br>{{.Timestamp.Format "2006-01-02 15:04:05"}}
                    </div>
                    <div class="info-item">
                        <strong>扫描耗时:</strong><br>{{.ScanDuration}}
                    </div>
                </div>
            </div>
            
            <!-- 重要提示 -->
            <div class="section">
                <div class="warning-banner">
                    <h2>⚠️ 重要提示</h2>
                    <p>本报告基于系统服务、配置等信息进行自动化分析，结果仅供参考。建议对发现的潜在漏洞进行手动验证，确保安全评估的准确性。</p>
                </div>
            </div>

            <div class="section">
                <h2>📊 漏洞统计概览</h2>
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <span class="stat-number">{{.CriticalCount}}</span>
                        <div>严重漏洞</div>
                    </div>
                    <div class="stat-card high">
                        <span class="stat-number">{{.HighCount}}</span>
                        <div>高危漏洞</div>
                    </div>
                    <div class="stat-card medium">
                        <span class="stat-number">{{.MediumCount}}</span>
                        <div>中危漏洞</div>
                    </div>
                    <div class="stat-card low">
                        <span class="stat-number">{{.LowCount}}</span>
                        <div>低危漏洞</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <h3>总计发现 <span style="color: #e74c3c; font-size: 1.5em;">{{.TotalCount}}</span> 个潜在漏洞</h3>
                </div>
            </div>

            {{if .Vulnerabilities}}
            <div class="section">
                <h2>🔍 漏洞详情分析</h2>
                {{range .Vulnerabilities}}
                <div class="vulnerability {{.Severity | lower}}">
                    <div class="vuln-header">
                        <div class="vuln-title">{{.Name}}</div>
                        <div class="severity-badge">{{.Severity}}</div>
                    </div>
                    <div class="vuln-details">
                        <div class="detail-item">
                            <div class="detail-label">漏洞ID</div>
                            <div>{{.ID}}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">CVE编号</div>
                            <div>{{.CVE}}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">影响范围</div>
                            <div>{{.Affected}}</div>
                        </div>
                    </div>
                    <div style="margin-top: 15px;">
                        <div class="detail-label">漏洞描述</div>
                        <div>{{.Description}}</div>
                    </div>
                    <div style="margin-top: 15px;">
                        <div class="detail-label">解决方案</div>
                        <div style="background: rgba(255,255,255,0.2); padding: 10px; border-radius: 5px;">{{.Solution}}</div>
                    </div>
                </div>
                {{end}}
            </div>
            {{else}}
            <div class="section">
                <h2>🔍 漏洞详情分析</h2>
                <div style="text-align: center; padding: 40px; background: #f8f9fa; border-radius: 10px;">
                    <h3 style="color: #27ae60;">✅ 未发现漏洞</h3>
                    <p>当前系统相对安全，未检测到已知漏洞。</p>
                </div>
            </div>
            {{end}}

            {{if .Services}}
            <div class="section">
                <h2>📋 系统信息概览</h2>
                <h3>🖥️ 发现的服务</h3>
                <table>
                    <thead>
                        <tr>
                            <th>服务名称</th>
                            <th>端口</th>
                            <th>协议</th>
                            <th>状态</th>
                        </tr>
                    </thead>
                    <tbody>
                    {{range .Services}}
                        <tr>
                            <td>{{.Name}}</td>
                            <td>{{.Port}}</td>
                            <td>{{.Protocol}}</td>
                            <td>{{.Status}}</td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}

            {{if .Programs}}
            <div class="section">
                <h3 style="margin-top: 30px;">📦 发现的程序</h3>
                <table>
                    <thead>
                        <tr>
                            <th>程序名称</th>
                            <th>版本</th>
                            <th>安装路径</th>
                        </tr>
                    </thead>
                    <tbody>
                    {{range .Programs}}
                        <tr>
                            <td>{{.Name}}</td>
                            <td>{{.Version}}</td>
                            <td>{{.Path}}</td>
                        </tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}

            <div class="section" style="text-align: center; background: #f8f9fa;">
                <p>🔒 报告生成时间: {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
                <p>⏱️ 扫描耗时: {{.ScanDuration}}</p>
            </div>
        </div>
    </div>
</body>
</html>`

	templateData := struct {
		*ScanResult
		CriticalCount int
		HighCount     int
		MediumCount   int
		LowCount      int
		TotalCount    int
	}{
		ScanResult:    result,
		CriticalCount: countSeverity(result.Vulnerabilities, "Critical"),
		HighCount:     countSeverity(result.Vulnerabilities, "High"),
		MediumCount:   countSeverity(result.Vulnerabilities, "Medium"),
		LowCount:      countSeverity(result.Vulnerabilities, "Low"),
		TotalCount:    len(result.Vulnerabilities),
	}

	t, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(tmpl)
	if err != nil {
		return err
	}

	return t.Execute(file, templateData)
}

// generateJSONReport 生成JSON报告
func (rg *ReportGenerator) generateJSONReport(result *ScanResult, outputPath string) error {
	// 简化版JSON报告实现
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 基本的JSON格式报告
	fmt.Fprintf(file, `{
    "scan_report": {
        "target": "%s",
        "os_info": "%s",
        "timestamp": "%s",
        "scan_duration": "%v",
        "vulnerabilities": %d,
        "services": %d,
        "programs": %d
    }
}`, result.Target, result.OSInfo, result.Timestamp.Format(time.RFC3339), 
		result.ScanDuration, len(result.Vulnerabilities), len(result.Services), len(result.Programs))

	return nil
}

// countSeverity 统计指定严重程度的漏洞数量
func countSeverity(vulnerabilities []Vulnerability, severity string) int {
	count := 0
	for _, vuln := range vulnerabilities {
		if vuln.Severity == severity {
			count++
		}
	}
	return count
}

// sortVulnerabilitiesBySeverity 按严重程度排序漏洞
func sortVulnerabilitiesBySeverity(vulnerabilities []Vulnerability) []Vulnerability {
	// 严重程度权重
	severityWeight := map[string]int{
		"Critical": 4,
		"High":     3,
		"Medium":   2,
		"Low":      1,
	}

	// 简单的冒泡排序
	for i := 0; i < len(vulnerabilities)-1; i++ {
		for j := 0; j < len(vulnerabilities)-i-1; j++ {
			if severityWeight[vulnerabilities[j].Severity] < severityWeight[vulnerabilities[j+1].Severity] {
				vulnerabilities[j], vulnerabilities[j+1] = vulnerabilities[j+1], vulnerabilities[j]
			}
		}
	}

	return vulnerabilities
}

// PrintSummary 打印扫描摘要到控制台
func PrintSummary(result *ScanResult, duration time.Duration) {
	highCount := countSeverity(result.Vulnerabilities, "Critical") + countSeverity(result.Vulnerabilities, "High")
	
	fmt.Println("\n=== 扫描摘要 ===")
	fmt.Printf("目标: %s\n", result.Target)
	fmt.Printf("耗时: %v\n", duration)
	fmt.Printf("发现漏洞: %d个 (高危: %d个)\n", len(result.Vulnerabilities), highCount)
	fmt.Printf("发现服务: %d个\n", len(result.Services))
	fmt.Printf("发现程序: %d个\n", len(result.Programs))
	
	if highCount > 0 {
		fmt.Println("⚠️  发现高危漏洞，请及时处理！")
	} else if len(result.Vulnerabilities) > 0 {
		fmt.Println("ℹ️  发现中低危漏洞，建议处理。")
	} else {
		fmt.Println("✅ 未发现漏洞，系统相对安全。")
	}
}