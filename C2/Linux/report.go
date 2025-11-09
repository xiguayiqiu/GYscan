package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ReportGenerator 报告生成器
type ReportGenerator struct {
	Result *ScanResult
}

// NewReportGenerator 创建新的报告生成器
func NewReportGenerator(result *ScanResult) *ReportGenerator {
	return &ReportGenerator{
		Result: result,
	}
}

// GenerateReport 生成报告
func (rg *ReportGenerator) GenerateReport(outputType, outputPath string) error {
	switch strings.ToLower(outputType) {
	case "text":
		return rg.generateTextReport(outputPath)
	case "html":
		return rg.generateHTMLReport(outputPath)
	case "json":
		return rg.generateJSONReport(outputPath)
	default:
		return fmt.Errorf("不支持的输出格式: %s", outputType)
	}
}

// generateTextReport 生成文本报告
func (rg *ReportGenerator) generateTextReport(outputPath string) error {
	var content strings.Builder

	// 报告头部
	content.WriteString("=== Linux漏洞扫描报告 ===\n")
	content.WriteString(fmt.Sprintf("扫描目标: %s\n", rg.Result.Target))
	content.WriteString(fmt.Sprintf("操作系统: %s\n", rg.Result.OSInfo))
	content.WriteString(fmt.Sprintf("发行版: %s\n", rg.Result.Distribution))
	content.WriteString(fmt.Sprintf("扫描时间: %s\n", rg.Result.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("扫描耗时: %s\n", rg.Result.ScanDuration))
	content.WriteString("\n")
	
	// 添加提示信息
	content.WriteString("=== 重要提示 ===\n")
	content.WriteString("本报告只是在基于你的服务、系统等信息进行的推测，可以留意并手动验证是否真实存在！\n")
	content.WriteString("\n")

	// 漏洞统计
	severityCount := rg.countSeverity()
	content.WriteString("=== 漏洞统计 ===\n")
	content.WriteString(fmt.Sprintf("总计: %d个漏洞\n", len(rg.Result.Vulnerabilities)))
	content.WriteString(fmt.Sprintf("严重: %d个\n", severityCount["Critical"]))
	content.WriteString(fmt.Sprintf("高危: %d个\n", severityCount["High"]))
	content.WriteString(fmt.Sprintf("中危: %d个\n", severityCount["Medium"]))
	content.WriteString(fmt.Sprintf("低危: %d个\n", severityCount["Low"]))
	content.WriteString("\n")

	// 漏洞详情
	if len(rg.Result.Vulnerabilities) > 0 {
		content.WriteString("=== 漏洞详情 ===\n")
		// 按严重程度排序
		sortedVulns := rg.sortVulnerabilitiesBySeverity()
		for i, vuln := range sortedVulns {
			content.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.Name))
			content.WriteString(fmt.Sprintf("    ID: %s\n", vuln.ID))
			content.WriteString(fmt.Sprintf("    描述: %s\n", vuln.Description))
			content.WriteString(fmt.Sprintf("    解决方案: %s\n", vuln.Solution))
			content.WriteString(fmt.Sprintf("    CVE: %s\n", vuln.CVE))
			content.WriteString(fmt.Sprintf("    影响范围: %s\n", vuln.Affected))
			content.WriteString("\n")
		}
	}

	// 服务信息
	if len(rg.Result.Services) > 0 {
		content.WriteString("=== 服务信息 ===\n")
		for i, service := range rg.Result.Services {
			content.WriteString(fmt.Sprintf("%d. %s (端口: %d, 协议: %s, 状态: %s)\n", 
				i+1, service.Name, service.Port, service.Protocol, service.Status))
			if len(service.Vulnerabilities) > 0 {
				content.WriteString("    相关漏洞:\n")
				for _, vuln := range service.Vulnerabilities {
					content.WriteString(fmt.Sprintf("    - [%s] %s\n", vuln.Severity, vuln.Name))
				}
			}
			content.WriteString("\n")
		}
	}

	// 程序信息
	if len(rg.Result.Programs) > 0 {
		content.WriteString("=== 程序信息 ===\n")
		for i, program := range rg.Result.Programs {
			content.WriteString(fmt.Sprintf("%d. %s (版本: %s, 路径: %s)\n", 
				i+1, program.Name, program.Version, program.Path))
			if len(program.Vulnerabilities) > 0 {
				content.WriteString("    相关漏洞:\n")
				for _, vuln := range program.Vulnerabilities {
					content.WriteString(fmt.Sprintf("    - [%s] %s\n", vuln.Severity, vuln.Name))
				}
			}
			content.WriteString("\n")
		}
	}

	// 写入文件
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		_, err = file.WriteString(content.String())
		if err != nil {
			return err
		}
		fmt.Printf("文本报告已生成: %s\n", outputPath)
	} else {
		fmt.Print(content.String())
	}

	return nil
}

// generateHTMLReport 生成HTML报告
func (rg *ReportGenerator) generateHTMLReport(outputPath string) error {
	var content strings.Builder

	content.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux漏洞扫描报告 - ` + rg.Result.Target + `</title>
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
                <h1>🔒 Linux漏洞扫描报告</h1>
                <p>专业安全评估报告</p>
                <div class="header-info">
                    <div class="info-item">
                        <strong>扫描目标:</strong><br>` + rg.Result.Target + `
                    </div>
                    <div class="info-item">
                        <strong>操作系统:</strong><br>` + rg.Result.OSInfo + `
                    </div>
                    <div class="info-item">
                        <strong>发行版:</strong><br>` + rg.Result.Distribution + `
                    </div>
                    <div class="info-item">
                        <strong>扫描时间:</strong><br>` + rg.Result.Timestamp.Format("2006-01-02 15:04:05") + `
                    </div>
                </div>
            </div>
            
            <!-- 重要提示 -->
            <div class="section">
                <div class="warning-banner">
                    <h2>⚠️ 重要提示</h2>
                    <p>本报告基于系统服务、配置等信息进行自动化分析，结果仅供参考。建议对发现的潜在漏洞进行手动验证，确保安全评估的准确性。</p>
                </div>
            </div>`)

	// 漏洞统计
	severityCount := rg.countSeverity()
	totalVulns := len(rg.Result.Vulnerabilities)
	
	content.WriteString(`
            <div class="section">
                <h2>📊 漏洞统计概览</h2>
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <span class="stat-number">` + fmt.Sprintf("%d", severityCount["Critical"]) + `</span>
                        <div>严重漏洞</div>
                    </div>
                    <div class="stat-card high">
                        <span class="stat-number">` + fmt.Sprintf("%d", severityCount["High"]) + `</span>
                        <div>高危漏洞</div>
                    </div>
                    <div class="stat-card medium">
                        <span class="stat-number">` + fmt.Sprintf("%d", severityCount["Medium"]) + `</span>
                        <div>中危漏洞</div>
                    </div>
                    <div class="stat-card low">
                        <span class="stat-number">` + fmt.Sprintf("%d", severityCount["Low"]) + `</span>
                        <div>低危漏洞</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <h3>总计发现 <span style="color: #e74c3c; font-size: 1.5em;">` + fmt.Sprintf("%d", totalVulns) + `</span> 个潜在漏洞</h3>
                </div>
            </div>`)

	// 漏洞详情
	if len(rg.Result.Vulnerabilities) > 0 {
		content.WriteString(`
            <div class="section">
                <h2>🔍 漏洞详情分析</h2>`)
		sortedVulns := rg.sortVulnerabilitiesBySeverity()
		for _, vuln := range sortedVulns {
			severityClass := strings.ToLower(vuln.Severity)
			content.WriteString(`
                <div class="vulnerability ` + severityClass + `">
                    <div class="vuln-header">
                        <div class="vuln-title">` + vuln.Name + `</div>
                        <div class="severity-badge">` + vuln.Severity + `</div>
                    </div>
                    <div class="vuln-details">
                        <div class="detail-item">
                            <div class="detail-label">漏洞ID</div>
                            <div>` + vuln.ID + `</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">CVE编号</div>
                            <div>` + vuln.CVE + `</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">影响范围</div>
                            <div>` + vuln.Affected + `</div>
                        </div>
                    </div>
                    <div style="margin-top: 15px;">
                        <div class="detail-label">漏洞描述</div>
                        <div>` + vuln.Description + `</div>
                    </div>
                    <div style="margin-top: 15px;">
                        <div class="detail-label">解决方案</div>
                        <div style="background: rgba(255,255,255,0.2); padding: 10px; border-radius: 5px;">` + vuln.Solution + `</div>
                    </div>
                </div>`)
		}
		content.WriteString(`
            </div>`)
	} else {
		content.WriteString(`
            <div class="section">
                <h2>🔍 漏洞详情分析</h2>
                <div style="text-align: center; padding: 40px; background: #f8f9fa; border-radius: 10px;">
                    <h3 style="color: #27ae60;">✅ 未发现漏洞</h3>
                    <p>当前系统相对安全，未检测到已知漏洞。</p>
                </div>
            </div>`)
	}

	// 服务和程序信息
	if len(rg.Result.Services) > 0 || len(rg.Result.Programs) > 0 {
		content.WriteString(`
            <div class="section">
                <h2>📋 系统信息概览</h2>`)
		
		if len(rg.Result.Services) > 0 {
			content.WriteString(`
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
                    <tbody>`)
			for _, service := range rg.Result.Services {
				content.WriteString(`
                        <tr>
                            <td>` + service.Name + `</td>
                            <td>` + fmt.Sprintf("%d", service.Port) + `</td>
                            <td>` + service.Protocol + `</td>
                            <td>` + service.Status + `</td>
                        </tr>`)
			}
			content.WriteString(`
                    </tbody>
                </table>`)
		}
		
		if len(rg.Result.Programs) > 0 {
			content.WriteString(`
                <h3 style="margin-top: 30px;">📦 发现的程序</h3>
                <table>
                    <thead>
                        <tr>
                            <th>程序名称</th>
                            <th>版本</th>
                            <th>安装路径</th>
                        </tr>
                    </thead>
                    <tbody>`)
			for _, program := range rg.Result.Programs {
				content.WriteString(`
                        <tr>
                            <td>` + program.Name + `</td>
                            <td>` + program.Version + `</td>
                            <td>` + program.Path + `</td>
                        </tr>`)
			}
			content.WriteString(`
                    </tbody>
                </table>`)
		}
		content.WriteString(`
            </div>`)
	}

	content.WriteString(`
            <div class="section" style="text-align: center; background: #f8f9fa;">
                <p>🔒 报告生成时间: ` + rg.Result.Timestamp.Format("2006-01-02 15:04:05") + `</p>
                <p>⏱️ 扫描耗时: ` + rg.Result.ScanDuration.String() + `</p>
            </div>
        </div>
    </div>
</body>
</html>`)

	// 写入文件
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		_, err = file.WriteString(content.String())
		if err != nil {
			return err
		}
		fmt.Printf("📄 HTML报告已生成: %s\n", outputPath)
	} else {
		fmt.Print(content.String())
	}

	return nil
}

// generateJSONReport 生成JSON报告
func (rg *ReportGenerator) generateJSONReport(outputPath string) error {
	jsonData, err := json.MarshalIndent(rg.Result, "", "  ")
	if err != nil {
		return err
	}

	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		_, err = file.Write(jsonData)
		if err != nil {
			return err
		}
		fmt.Printf("JSON报告已生成: %s\n", outputPath)
	} else {
		fmt.Println(string(jsonData))
	}

	return nil
}

// countSeverity 统计漏洞严重程度
func (rg *ReportGenerator) countSeverity() map[string]int {
	count := make(map[string]int)
	for _, vuln := range rg.Result.Vulnerabilities {
		count[vuln.Severity]++
	}
	return count
}

// sortVulnerabilitiesBySeverity 按严重程度排序漏洞
func (rg *ReportGenerator) sortVulnerabilitiesBySeverity() []Vulnerability {
	sorted := make([]Vulnerability, len(rg.Result.Vulnerabilities))
	copy(sorted, rg.Result.Vulnerabilities)
	
	sort.Slice(sorted, func(i, j int) bool {
		severityOrder := map[string]int{
			"Critical": 1,
			"High":     2,
			"Medium":   3,
			"Low":      4,
		}
		return severityOrder[sorted[i].Severity] < severityOrder[sorted[j].Severity]
	})
	
	return sorted
}

// PrintSummary 打印扫描摘要
func (rg *ReportGenerator) PrintSummary() {
	severityCount := rg.countSeverity()
	
	fmt.Println("=== 扫描摘要 ===")
	fmt.Printf("目标系统: %s\n", rg.Result.Target)
	fmt.Printf("发行版: %s\n", rg.Result.Distribution)
	fmt.Printf("扫描时间: %s\n", rg.Result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("扫描耗时: %s\n", rg.Result.ScanDuration)
	fmt.Printf("发现漏洞总数: %d\n", len(rg.Result.Vulnerabilities))
	fmt.Printf("严重: %d, 高危: %d, 中危: %d, 低危: %d\n", 
		severityCount["Critical"], severityCount["High"], 
		severityCount["Medium"], severityCount["Low"])
	fmt.Printf("发现服务: %d个\n", len(rg.Result.Services))
	fmt.Printf("发现程序: %d个\n", len(rg.Result.Programs))
}