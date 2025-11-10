package trivy

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

// HTMLReportData HTML报告数据结构
type HTMLReportData struct {
	Title          string
	Timestamp      string
	Target         string
	ScanDuration   string
	Vulnerabilities []HTMLVulnerability
	TotalVulns     int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	UnknownCount   int
}

// HTMLVulnerability HTML格式的漏洞信息
type HTMLVulnerability struct {
	ID              string
	Title           string
	Severity        string
	SeverityClass   string
	Package         string
	InstalledVersion string
	FixedVersion    string
	Description     string
	CVSSScore       float64
	References      []string
	PublishedDate   string
}

// GenerateHTMLReport 生成HTML格式的报告
func (s *Scanner) GenerateHTMLReport(outputPath string) error {
	result, err := s.Scan()
	if err != nil {
		return err
	}

	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if mkdirErr := os.MkdirAll(dir, 0755); mkdirErr != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 准备HTML报告数据
	reportData := s.prepareHTMLReportData(result)

	// 创建HTML模板
	tmpl := template.Must(template.New("report").Parse(htmlTemplate))

	// 创建输出文件
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	// 执行模板
	if err := tmpl.Execute(file, reportData); err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	if s.verbose {
		fmt.Printf("HTML报告已生成: %s\n", outputPath)
	}

	return nil
}

// prepareHTMLReportData 准备HTML报告数据
func (s *Scanner) prepareHTMLReportData(result *ScanResult) *HTMLReportData {
	// 统计漏洞数量
	criticalCount, highCount, mediumCount, lowCount, unknownCount := s.countVulnerabilitiesBySeverity(result.Vulnerabilities)

	// 转换漏洞数据到HTML格式
	htmlVulns := make([]HTMLVulnerability, 0, len(result.Vulnerabilities))
	for _, vuln := range result.Vulnerabilities {
		// 获取CVSS分数
		cvssScore := 0.0
		if scores, ok := vuln.CVSS["nvd"]; ok {
			cvssScore = scores
		} else if scores, ok := vuln.CVSS["redhat"]; ok {
			cvssScore = scores
		}

		htmlVulns = append(htmlVulns, HTMLVulnerability{
			ID:              vuln.VulnerabilityID,
			Title:           vuln.Title,
			Severity:        vuln.Severity,
			SeverityClass:   s.getSeverityClass(vuln.Severity),
			Package:         vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:    vuln.FixedVersion,
			Description:     vuln.Description,
			CVSSScore:       cvssScore,
			References:      vuln.References,
			PublishedDate:   vuln.PublishedDate,
		})
	}

	return &HTMLReportData{
		Title:          "Trivy漏洞扫描报告",
		Timestamp:      result.Timestamp.Format("2006-01-02 15:04:05"),
		Target:         result.Target,
		ScanDuration:   result.ScanDuration.String(),
		Vulnerabilities: htmlVulns,
		TotalVulns:     len(result.Vulnerabilities),
		CriticalCount:  criticalCount,
		HighCount:      highCount,
		MediumCount:    mediumCount,
		LowCount:       lowCount,
		UnknownCount:   unknownCount,
	}
}

// countVulnerabilitiesBySeverity 按严重性统计漏洞数量
func (s *Scanner) countVulnerabilitiesBySeverity(vulns []Vulnerability) (critical, high, medium, low, unknown int) {
	for _, vuln := range vulns {
		switch vuln.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		default:
			unknown++
		}
	}
	return
}

// getSeverityClass 获取严重性对应的CSS类
func (s *Scanner) getSeverityClass(severity string) string {
	switch severity {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "unknown"
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
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-item {
            text-align: center;
            padding: 15px;
            border-radius: 6px;
            color: white;
            font-weight: bold;
        }
        .summary-total { background-color: #2196F3; }
        .critical { background-color: #f44336; }
        .high { background-color: #ff9800; }
        .medium { background-color: #ffeb3b; color: #333; }
        .low { background-color: #4caf50; }
        .unknown { background-color: #9e9e9e; }
        .vulnerability {
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #fafafa;
        }
        .vulnerability.critical { border-left: 4px solid #f44336; }
        .vulnerability.high { border-left: 4px solid #ff9800; }
        .vulnerability.medium { border-left: 4px solid #ffeb3b; }
        .vulnerability.low { border-left: 4px solid #4caf50; }
        .vulnerability.unknown { border-left: 4px solid #9e9e9e; }
        .vuln-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-id {
            font-weight: bold;
            font-size: 1.1em;
        }
        .vuln-severity {
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 0.9em;
        }
        .vuln-details {
            margin-top: 10px;
        }
        .vuln-package {
            font-weight: bold;
            color: #333;
        }
        .vuln-description {
            margin: 10px 0;
            line-height: 1.5;
        }
        .vuln-references {
            margin-top: 10px;
        }
        .reference {
            display: block;
            margin: 2px 0;
            color: #2196F3;
            text-decoration: none;
        }
        .reference:hover {
            text-decoration: underline;
        }
        .info-section {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
        }
        .info-item {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
        </div>
        
        <div class="info-section">
            <div class="info-item"><strong>扫描目标:</strong> {{.Target}}</div>
            <div class="info-item"><strong>扫描时间:</strong> {{.Timestamp}}</div>
            <div class="info-item"><strong>扫描耗时:</strong> {{.ScanDuration}}</div>
        </div>
        
        <div class="summary">
            <div class="summary-item summary-total">
                <div>总漏洞数</div>
                <div style="font-size: 2em;">{{.TotalVulns}}</div>
            </div>
            <div class="summary-item critical">
                <div>严重</div>
                <div style="font-size: 2em;">{{.CriticalCount}}</div>
            </div>
            <div class="summary-item high">
                <div>高危</div>
                <div style="font-size: 2em;">{{.HighCount}}</div>
            </div>
            <div class="summary-item medium">
                <div>中危</div>
                <div style="font-size: 2em;">{{.MediumCount}}</div>
            </div>
            <div class="summary-item low">
                <div>低危</div>
                <div style="font-size: 2em;">{{.LowCount}}</div>
            </div>
            <div class="summary-item unknown">
                <div>未知</div>
                <div style="font-size: 2em;">{{.UnknownCount}}</div>
            </div>
        </div>
        
        <h2>漏洞详情</h2>
        {{range .Vulnerabilities}}
        <div class="vulnerability {{.SeverityClass}}">
            <div class="vuln-header">
                <span class="vuln-id">{{.ID}}</span>
                <span class="vuln-severity {{.SeverityClass}}">{{.Severity}}</span>
            </div>
            <div class="vuln-details">
                <div class="vuln-package">{{.Package}} {{.InstalledVersion}}</div>
                {{if .FixedVersion}}
                <div>修复版本: {{.FixedVersion}}</div>
                {{end}}
                {{if .CVSSScore}}
                <div>CVSS评分: {{.CVSSScore}}</div>
                {{end}}
                <div class="vuln-description">{{.Description}}</div>
                {{if .References}}
                <div class="vuln-references">
                    <strong>参考链接:</strong>
                    {{range .References}}
                    <a href="{{.}}" class="reference" target="_blank">{{.}}</a>
                    {{end}}
                </div>
                {{end}}
                {{if .PublishedDate}}
                <div style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    发布日期: {{.PublishedDate}}
                </div>
                {{end}}
            </div>
        </div>
        {{else}}
        <div style="text-align: center; padding: 40px; color: #666;">
            <h3>未发现漏洞</h3>
            <p>扫描目标未发现已知的安全漏洞。</p>
        </div>
        {{end}}
    </div>
</body>
</html>`