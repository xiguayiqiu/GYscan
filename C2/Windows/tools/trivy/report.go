package trivy

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

// HTMLReportData HTML报告数据结构
type HTMLReportData struct {
	Title           string
	ScanTime        string
	ScanDuration    string
	Target          string
	TotalVulns      int
	Vulnerabilities []HTMLVulnerability
	SeverityStats   map[string]int
}

// HTMLVulnerability HTML格式的漏洞信息
type HTMLVulnerability struct {
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
	Description      string
	References       []string
	SeverityClass    string // CSS类名
}

// GenerateHTMLReport 生成HTML格式报告
func (s *Scanner) GenerateHTMLReport(outputPath string) error {
	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 准备HTML报告数据
	reportData := s.prepareHTMLReportData()

	// 创建HTML模板
	tmpl := template.Must(template.New("report").Parse(htmlTemplate))

	// 创建输出文件
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	// 执行模板
	err = tmpl.Execute(file, reportData)
	if err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	return nil
}

// prepareHTMLReportData 准备HTML报告数据
func (s *Scanner) prepareHTMLReportData() HTMLReportData {
	data := HTMLReportData{
		Title:        "Trivy漏洞扫描报告",
		ScanTime:     s.results.ScanTime.Format("2006-01-02 15:04:05"),
		ScanDuration: s.results.ScanDuration,
		Target:       s.results.Target,
		TotalVulns:   s.results.TotalVulns,
		SeverityStats: map[string]int{
			"CRITICAL": 0,
			"HIGH":     0,
			"MEDIUM":   0,
			"LOW":      0,
			"UNKNOWN":  0,
		},
	}

	// 转换漏洞数据并统计严重性
	for _, vuln := range s.results.Vulnerabilities {
		htmlVuln := HTMLVulnerability{
			VulnerabilityID:  vuln.VulnerabilityID,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Severity:         vuln.Severity,
			Title:            vuln.Title,
			Description:      vuln.Description,
			References:       vuln.References,
			SeverityClass:    getSeverityClass(vuln.Severity),
		}

		data.Vulnerabilities = append(data.Vulnerabilities, htmlVuln)

		// 统计严重性
		if count, exists := data.SeverityStats[vuln.Severity]; exists {
			data.SeverityStats[vuln.Severity] = count + 1
		} else {
			data.SeverityStats["UNKNOWN"] = data.SeverityStats["UNKNOWN"] + 1
		}
	}

	return data
}

// getSeverityClass 根据严重性获取CSS类名
func getSeverityClass(severity string) string {
	switch severity {
	case "CRITICAL":
		return "severity-critical"
	case "HIGH":
		return "severity-high"
	case "MEDIUM":
		return "severity-medium"
	case "LOW":
		return "severity-low"
	default:
		return "severity-unknown"
	}
}

// HTML模板
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
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
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 20px;
        }
        .summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            margin-bottom: 30px;
        }
        .severity-stats {
            display: flex;
            gap: 15px;
            margin-top: 15px;
        }
        .severity-item {
            flex: 1;
            text-align: center;
            padding: 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #000; }
        .severity-low { background: #28a745; }
        .severity-unknown { background: #6c757d; }
        .vulnerability {
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
        }
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-id {
            font-weight: bold;
            font-size: 1.1em;
        }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 0.9em;
        }
        .vuln-details {
            margin-top: 10px;
        }
        .vuln-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .vuln-description {
            margin-bottom: 10px;
            color: #666;
        }
        .vuln-references {
            font-size: 0.9em;
            color: #007bff;
        }
        .no-vulns {
            text-align: center;
            color: #28a745;
            font-size: 1.2em;
            padding: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p>扫描目标: {{.Target}}</p>
            <p>扫描时间: {{.ScanTime}} | 耗时: {{.ScanDuration}}</p>
        </div>

        <div class="summary">
            <h3>扫描摘要</h3>
            <p>总共发现 <strong>{{.TotalVulns}}</strong> 个漏洞</p>
            {{if gt .TotalVulns 0}}
            <div class="severity-stats">
                {{range $severity, $count := .SeverityStats}}
                {{if gt $count 0}}
                <div class="severity-item severity-{{lower $severity}}">
                    {{$severity}}: {{$count}}
                </div>
                {{end}}
                {{end}}
            </div>
            {{end}}
        </div>

        {{if gt .TotalVulns 0}}
        <div class="vulnerabilities">
            <h3>漏洞详情</h3>
            {{range .Vulnerabilities}}
            <div class="vulnerability">
                <div class="vulnerability-header">
                    <span class="vuln-id">{{.VulnerabilityID}}</span>
                    <span class="severity-badge {{.SeverityClass}}">{{.Severity}}</span>
                </div>
                <div class="vuln-details">
                    <div class="vuln-title">{{.Title}}</div>
                    <div class="package-info">
                        包名: {{.PkgName}} {{.InstalledVersion}}
                        {{if .FixedVersion}} | 修复版本: {{.FixedVersion}}{{end}}
                    </div>
                    {{if .Description}}
                    <div class="vuln-description">{{.Description}}</div>
                    {{end}}
                    {{if .References}}
                    <div class="vuln-references">
                        参考链接:
                        {{range .References}}
                        <br><a href="{{.}}" target="_blank">{{.}}</a>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        {{else}}
        <div class="no-vulns">
            🎉 未发现漏洞！
        </div>
        {{end}}
    </div>
</body>
</html>`