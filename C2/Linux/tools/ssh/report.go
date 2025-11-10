package ssh

import (
	"fmt"
	"html/template"
	"os"
	"time"
)

// generateHTMLReport 生成HTML格式的SSH扫描报告
func (s *Scanner) generateHTMLReport(result *ScanResult) error {
	tmpl := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH配置安全扫描报告</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007acc;
            margin: 0;
        }
        .summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .score {
            font-size: 2.5em;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
        }
        .high-risk { color: #dc3545; }
        .medium-risk { color: #ffc107; }
        .low-risk { color: #28a745; }
        .safe { color: #17a2b8; }
        .vulnerability {
            border-left: 4px solid;
            padding: 15px;
            margin: 10px 0;
            background: #fff;
        }
        .high { border-color: #dc3545; background: #f8d7da; }
        .medium { border-color: #ffc107; background: #fff3cd; }
        .low { border-color: #28a745; background: #d4edda; }
        .recommendations {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }
        .timestamp {
            color: #6c757d;
            font-size: 0.9em;
            text-align: right;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007acc;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SSH配置安全扫描报告</h1>
            <p class="timestamp">生成时间: {{.ScanTime}}</p>
        </div>
        
        <div class="summary">
            <h2>扫描摘要</h2>
            <table>
                <tr><th>扫描目标</th><td>{{.Target}}</td></tr>
                <tr><th>总体评分</th><td>
                    <div class="score {{.RiskClass}}">{{.OverallScore}}/100</div>
                </td></tr>
                <tr><th>风险等级</th><td><span class="{{.RiskClass}}">{{.RiskLevel}}</span></td></tr>
                <tr><th>发现问题</th><td>{{.VulnerabilityCount}} 个</td></tr>
            </table>
        </div>
        
        {{if .Vulnerabilities}}
        <div class="vulnerabilities">
            <h2>发现的安全问题</h2>
            {{range .Vulnerabilities}}
            <div class="vulnerability {{.Severity}}">
                <h3>[{{.Severity}}] {{.Title}}</h3>
                <p><strong>描述:</strong> {{.Description}}</p>
                <p><strong>风险:</strong> {{.Risk}}</p>
                <p><strong>修复建议:</strong> {{.Remediation}}</p>
            </div>
            {{end}}
        </div>
        {{else}}
        <div style="text-align: center; padding: 40px; background: #d4edda; border-radius: 8px;">
            <h3 style="color: #155724;">✓ 未发现安全问题</h3>
            <p>SSH配置符合安全要求</p>
        </div>
        {{end}}
        
        {{if .Recommendations}}
        <div class="recommendations">
            <h2>安全建议</h2>
            <ol>
                {{range .Recommendations}}
                <li>{{.}}</li>
                {{end}}
            </ol>
        </div>
        {{end}}
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
            <p><strong>报告说明:</strong> 本报告基于ssh-audit工具生成，提供了SSH服务配置的安全评估结果。</p>
            <p><strong>注意:</strong> 安全配置需要根据实际业务需求进行调整，建议定期进行安全审计。</p>
        </div>
    </div>
</body>
</html>`

	// 准备模板数据
	type TemplateData struct {
		Target             string
		ScanTime           string
		OverallScore       int
		RiskLevel          string
		RiskClass          string
		VulnerabilityCount int
		Vulnerabilities    []Vulnerability
		Recommendations    []string
	}

	data := TemplateData{
		Target:             result.Target,
		ScanTime:           result.ScanTime.Format("2006-01-02 15:04:05"),
		OverallScore:       result.OverallScore,
		RiskLevel:          result.RiskLevel,
		VulnerabilityCount: len(result.Vulnerabilities),
		Vulnerabilities:    result.Vulnerabilities,
		Recommendations:    result.Recommendations,
	}

	// 设置风险等级对应的CSS类
	switch result.RiskLevel {
	case "高危":
		data.RiskClass = "high-risk"
	case "中危":
		data.RiskClass = "medium-risk"
	case "低危":
		data.RiskClass = "low-risk"
	default:
		data.RiskClass = "safe"
	}

	// 解析并执行模板
	t, err := template.New("ssh_report").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %v", err)
	}

	// 创建输出文件
	file, err := os.Create(s.config.OutputFile)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	// 写入HTML内容
	err = t.Execute(file, data)
	if err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	s.logger.Infof("HTML报告已生成: %s", s.config.OutputFile)
	return nil
}

// GetRiskColor 获取风险等级对应的颜色
func GetRiskColor(riskLevel string) string {
	switch riskLevel {
	case "高危":
		return "#dc3545"
	case "中危":
		return "#ffc107"
	case "低危":
		return "#28a745"
	default:
		return "#17a2b8"
	}
}

// FormatDuration 格式化时间间隔
func FormatDuration(start, end time.Time) string {
	duration := end.Sub(start)
	if duration < time.Second {
		return fmt.Sprintf("%dms", duration.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", duration.Seconds())
}