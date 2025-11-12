package goss

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

// HTMLReportData HTML报告数据结构
type HTMLReportData struct {
	Title           string
	Timestamp       string
	Target          string
	ScanDuration    string
	Summary         HTMLSummary
	Results         []HTMLTestResult
	TotalTests      int
	FailedTests     int
	SkippedTests    int
	PassedTests     int
}

// HTMLSummary HTML格式的摘要信息
type HTMLSummary struct {
	TestCount    int `json:"test_count"`
	FailedCount  int `json:"failed_count"`
	SkippedCount int `json:"skipped_count"`
	TotalCount   int `json:"total_count"`
}

// HTMLTestResult HTML格式的测试结果
type HTMLTestResult struct {
	ID           string
	Title        string
	Property     string
	Pattern      string
	Duration     string
	Status       string
	StatusClass  string
	Successful   bool
	Skipped      bool
}

// GenerateReport 生成报告，根据文件扩展名自动选择格式
func (s *Scanner) GenerateReport(outputPath string) error {
	result, err := s.Scan()
	if err != nil {
		return err
	}

	ext := filepath.Ext(outputPath)
	
	switch ext {
	case ".html", ".htm":
		return s.GenerateHTMLReport(result, outputPath)
	case ".txt", "":
		return s.GenerateTextReport(result, outputPath)
	case ".json":
		return s.GenerateJSONReport(result, outputPath)
	default:
		return fmt.Errorf("不支持的文件格式: %s，支持格式: .html, .htm, .txt, .json", ext)
	}
}

// GenerateHTMLReport 生成HTML格式的报告
func (s *Scanner) GenerateHTMLReport(result *ScanResult, outputPath string) error {
	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 准备HTML报告数据
	reportData := s.prepareHTMLReportData(result)

	// 创建HTML模板
	tmpl := template.Must(template.New("report").Parse(htmlTemplate))

	// 创建输出文件，使用UTF-8编码
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	// 写入UTF-8 BOM头以确保正确编码
	_, err = file.Write([]byte{0xEF, 0xBB, 0xBF})
	if err != nil {
		return fmt.Errorf("写入UTF-8 BOM失败: %v", err)
	}

	// 执行模板
	if err := tmpl.Execute(file, reportData); err != nil {
		return fmt.Errorf("生成HTML报告失败: %v", err)
	}

	if s.verbose {
		fmt.Printf("HTML报告已生成: %s\n", outputPath)
	}

	return nil
}

// GenerateTextReport 生成文本格式的报告
func (s *Scanner) GenerateTextReport(result *ScanResult, outputPath string) error {
	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 创建输出文件
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建文本文件失败: %v", err)
	}
	defer file.Close()

	// 写入报告头部
	fmt.Fprintf(file, "Goss Windows配置审计报告\n")
	fmt.Fprintf(file, "==========================\n\n")
	fmt.Fprintf(file, "目标系统: %s\n", result.Target)
	fmt.Fprintf(file, "扫描时间: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "扫描耗时: %s\n\n", result.ScanDuration.String())

	// 写入摘要信息
	fmt.Fprintf(file, "摘要信息:\n")
	fmt.Fprintf(file, "- 总测试数: %d\n", result.Summary.TotalCount)
	fmt.Fprintf(file, "- 通过测试: %d\n", result.Summary.TotalCount-result.Summary.FailedCount-result.Summary.SkippedCount)
	fmt.Fprintf(file, "- 失败测试: %d\n", result.Summary.FailedCount)
	fmt.Fprintf(file, "- 跳过测试: %d\n\n", result.Summary.SkippedCount)

	// 写入测试结果详情
	if len(result.Results) > 0 {
		fmt.Fprintf(file, "测试结果详情 (%d):\n", len(result.Results))
		fmt.Fprintf(file, "============\n\n")
		
		for i, test := range result.Results {
			status := "通过"
			if !test.Successful {
				status = "失败"
			}
			if test.Skipped {
				status = "跳过"
			}
			
			fmt.Fprintf(file, "%d. [%s] %s\n", i+1, status, test.Title)
			fmt.Fprintf(file, "   属性: %s\n", test.Meta.Property)
			fmt.Fprintf(file, "   模式: %s\n", test.Meta.Pattern)
			fmt.Fprintf(file, "   耗时: %dms\n", test.Duration)
			fmt.Fprintf(file, "   ID: %s\n\n", test.ID)
		}
	}

	// 写入报告尾部
	fmt.Fprintf(file, "报告生成时间: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	if s.verbose {
		fmt.Printf("文本报告已生成: %s\n", outputPath)
	}

	return nil
}

// GenerateJSONReport 生成JSON格式的报告
func (s *Scanner) GenerateJSONReport(result *ScanResult, outputPath string) error {
	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 创建输出文件
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建JSON文件失败: %v", err)
	}
	defer file.Close()

	// 将结果转换为JSON格式
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	// 写入JSON数据
	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	if s.verbose {
		fmt.Printf("JSON报告已生成: %s\n", outputPath)
	}

	return nil
}

// prepareHTMLReportData 准备HTML报告数据
func (s *Scanner) prepareHTMLReportData(result *ScanResult) *HTMLReportData {
	// 转换测试结果到HTML格式
	htmlResults := make([]HTMLTestResult, 0, len(result.Results))
	for _, test := range result.Results {
		status := "通过"
		statusClass := "success"
		
		if !test.Successful {
			status = "失败"
			statusClass = "danger"
		}
		if test.Skipped {
			status = "跳过"
			statusClass = "warning"
		}
		
		htmlResults = append(htmlResults, HTMLTestResult{
			ID:          test.ID,
			Title:       test.Title,
			Property:    test.Meta.Property,
			Pattern:     test.Meta.Pattern,
			Duration:    fmt.Sprintf("%dms", test.Duration),
			Status:      status,
			StatusClass: statusClass,
			Successful:  test.Successful,
			Skipped:     test.Skipped,
		})
	}

	// 计算通过测试数
	passedTests := result.Summary.TotalCount - result.Summary.FailedCount - result.Summary.SkippedCount

	return &HTMLReportData{
		Title:        "Goss Windows配置审计报告",
		Timestamp:    result.Timestamp.Format("2006-01-02 15:04:05"),
		Target:       result.Target,
		ScanDuration: result.ScanDuration.String(),
		Summary: HTMLSummary{
			TestCount:    result.Summary.TotalCount,
			FailedCount:  result.Summary.FailedCount,
			SkippedCount: result.Summary.SkippedCount,
			TotalCount:   result.Summary.TotalCount,
		},
		Results:      htmlResults,
		TotalTests:   result.Summary.TotalCount,
		FailedTests:  result.Summary.FailedCount,
		SkippedTests: result.Summary.SkippedCount,
		PassedTests:  passedTests,
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
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .test-result { border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
        .success { background: #d4edda; border-color: #c3e6cb; }
        .danger { background: #f8d7da; border-color: #f5c6cb; }
        .warning { background: #fff3cd; border-color: #ffeaa7; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-item { text-align: center; padding: 10px; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.Title}}</h1>
        <p><strong>目标系统:</strong> {{.Target}}</p>
        <p><strong>扫描时间:</strong> {{.Timestamp}}</p>
        <p><strong>扫描耗时:</strong> {{.ScanDuration}}</p>
    </div>

    <div class="stats">
        <div class="stat-item">
            <div class="stat-value" style="color: #28a745;">{{.PassedTests}}</div>
            <div class="stat-label">通过测试</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" style="color: #dc3545;">{{.FailedTests}}</div>
            <div class="stat-label">失败测试</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" style="color: #ffc107;">{{.SkippedTests}}</div>
            <div class="stat-label">跳过测试</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" style="color: #007bff;">{{.TotalTests}}</div>
            <div class="stat-label">总测试数</div>
        </div>
    </div>

    <div class="summary">
        <h3>摘要信息</h3>
        <p>总测试数: {{.Summary.TotalCount}} | 通过: {{.PassedTests}} | 失败: {{.FailedTests}} | 跳过: {{.SkippedTests}}</p>
    </div>

    <h3>测试结果详情</h3>
    {{range .Results}}
    <div class="test-result {{.StatusClass}}">
        <h4>{{.Title}}</h4>
        <p><strong>状态:</strong> <span class="{{.StatusClass}}">{{.Status}}</span></p>
        <p><strong>属性:</strong> {{.Property}}</p>
        <p><strong>模式:</strong> {{.Pattern}}</p>
        <p><strong>耗时:</strong> {{.Duration}}</p>
        <p><strong>ID:</strong> {{.ID}}</p>
    </div>
    {{end}}

    <div style="margin-top: 30px; text-align: center; color: #666;">
        <p>报告生成时间: {{.Timestamp}}</p>
    </div>
</body>
</html>`