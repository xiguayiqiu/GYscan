package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PenetrationPhase 渗透测试阶段
type PenetrationPhase string

const (
	PhaseStart                     PenetrationPhase = "开始"
	PhaseInfoGathering             PenetrationPhase = "信息收集"
	PhaseScanning                  PenetrationPhase = "扫描探测"
	PhaseVulnerabilityAnalysis     PenetrationPhase = "漏洞分析"
	PhaseVulnerabilityExploitation PenetrationPhase = "漏洞利用"
	PhasePrivilegeEscalation       PenetrationPhase = "权限提升"
	PhaseLateralMove               PenetrationPhase = "横向移动"
	PhasePersistence               PenetrationPhase = "持久化"
	PhaseCleanup                   PenetrationPhase = "清理痕迹"
	PhaseReport                    PenetrationPhase = "报告生成"
	PhaseComplete                  PenetrationPhase = "完成"
)

// LogEntry 日志条目
type LogEntry struct {
	Timestamp   time.Time        `json:"timestamp"`
	Phase       PenetrationPhase `json:"phase"`
	Tool        string           `json:"tool,omitempty"`
	Command     string           `json:"command,omitempty"`
	Output      string           `json:"output,omitempty"`
	Error       string           `json:"error,omitempty"`
	Duration    time.Duration    `json:"duration,omitempty"`
	Severity    string           `json:"severity,omitempty"` // info, warning, error, success
	Description string           `json:"description"`
}

// PenetrationLogger 渗透测试日志记录器
type PenetrationLogger struct {
	target      string
	logDir      string
	logFile     string
	entries     []LogEntry
	mu          sync.Mutex
	currentFile *os.File
}

// NewPenetrationLogger 创建新的渗透测试日志记录器
func NewPenetrationLogger(target, resourceDir string) (*PenetrationLogger, error) {
	timestamp := time.Now().Format("20060102-150405")
	safeTarget := sanitizeFilename(target)

	logDir := filepath.Join(resourceDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}

	logFile := filepath.Join(logDir, fmt.Sprintf("penetration_%s_%s.log", safeTarget, timestamp))

	logger := &PenetrationLogger{
		target:  target,
		logDir:  logDir,
		logFile: logFile,
		entries: make([]LogEntry, 0),
	}

	// 创建日志文件
	file, err := os.Create(logFile)
	if err != nil {
		return nil, fmt.Errorf("创建日志文件失败: %v", err)
	}
	logger.currentFile = file

	// 写入日志头
	logger.writeHeader()

	return logger, nil
}

// sanitizeFilename 清理文件名中的特殊字符
func sanitizeFilename(filename string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\"", "_",
	)
	return replacer.Replace(filename)
}

// writeHeader 写入日志文件头
func (l *PenetrationLogger) writeHeader() {
	header := fmt.Sprintf(`# 渗透测试日志
# 目标: %s
# 开始时间: %s
# 日志文件: %s

`, l.target, time.Now().Format("2006-01-02 15:04:05"), l.logFile)

	l.currentFile.WriteString(header)
}

// Log 记录日志条目
func (l *PenetrationLogger) Log(phase PenetrationPhase, tool, command, output, errorMsg, description string, duration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp:   time.Now(),
		Phase:       phase,
		Tool:        tool,
		Command:     command,
		Output:      output,
		Error:       errorMsg,
		Duration:    duration,
		Description: description,
	}

	// 设置严重程度
	if errorMsg != "" {
		entry.Severity = "error"
	} else if output != "" {
		entry.Severity = "success"
	} else {
		entry.Severity = "info"
	}

	l.entries = append(l.entries, entry)

	// 写入文件
	l.writeEntryToFile(entry)
}

// LogPhaseStart 记录阶段开始
func (l *PenetrationLogger) LogPhaseStart(phase PenetrationPhase, description string) {
	l.Log(phase, "", "", "", "", description, 0)
}

// LogToolExecution 记录工具执行
func (l *PenetrationLogger) LogToolExecution(phase PenetrationPhase, tool, command, output, errorMsg string, duration time.Duration) {
	description := fmt.Sprintf("执行工具: %s", tool)
	l.Log(phase, tool, command, output, errorMsg, description, duration)
}

// LogPhaseComplete 记录阶段完成
func (l *PenetrationLogger) LogPhaseComplete(phase PenetrationPhase, description string, duration time.Duration) {
	l.Log(phase, "", "", "", "", description, duration)
}

// writeEntryToFile 将日志条目写入文件
func (l *PenetrationLogger) writeEntryToFile(entry LogEntry) {
	logLine := fmt.Sprintf("[%s] [%s] %s",
		entry.Timestamp.Format("15:04:05"),
		strings.ToUpper(string(entry.Phase)),
		entry.Description)

	if entry.Tool != "" {
		logLine += fmt.Sprintf(" - 工具: %s", entry.Tool)
	}

	if entry.Command != "" {
		logLine += fmt.Sprintf(" - 命令: %s", entry.Command)
	}

	if entry.Duration > 0 {
		logLine += fmt.Sprintf(" - 耗时: %v", entry.Duration)
	}

	if entry.Error != "" {
		logLine += fmt.Sprintf(" - 错误: %s", entry.Error)
	}

	logLine += "\n"

	if entry.Output != "" {
		logLine += fmt.Sprintf("输出:\n%s\n", entry.Output)
	}

	l.currentFile.WriteString(logLine)
}

// GetLogEntries 获取所有日志条目
func (l *PenetrationLogger) GetLogEntries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries
}

// GetLogFile 获取日志文件路径
func (l *PenetrationLogger) GetLogFile() string {
	return l.logFile
}

// GetLogSummary 获取日志摘要
func (l *PenetrationLogger) GetLogSummary() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	var summary strings.Builder
	summary.WriteString("渗透测试日志摘要\n")
	summary.WriteString(fmt.Sprintf("目标: %s\n", l.target))
	summary.WriteString(fmt.Sprintf("总条目数: %d\n", len(l.entries)))

	// 统计各阶段条目
	phaseCount := make(map[PenetrationPhase]int)
	toolCount := make(map[string]int)
	errorCount := 0
	successCount := 0

	for _, entry := range l.entries {
		phaseCount[entry.Phase]++
		if entry.Tool != "" {
			toolCount[entry.Tool]++
		}
		if entry.Error != "" {
			errorCount++
		} else if entry.Output != "" {
			successCount++
		}
	}

	summary.WriteString("\n阶段统计:\n")
	for phase, count := range phaseCount {
		summary.WriteString(fmt.Sprintf("  %s: %d 条\n", phase, count))
	}

	summary.WriteString("\n工具统计:\n")
	for tool, count := range toolCount {
		summary.WriteString(fmt.Sprintf("  %s: %d 次\n", tool, count))
	}

	summary.WriteString(fmt.Sprintf("\n成功执行: %d 次\n", successCount))
	summary.WriteString(fmt.Sprintf("执行失败: %d 次\n", errorCount))

	return summary.String()
}

// GetLogContent 获取完整的日志内容
func (l *PenetrationLogger) GetLogContent() (string, error) {
	content, err := os.ReadFile(l.logFile)
	if err != nil {
		return "", fmt.Errorf("读取日志文件失败: %v", err)
	}
	return string(content), nil
}

// GetLogContentForAI 获取适合AI处理的日志内容（智能截断和摘要）
func (l *PenetrationLogger) GetLogContentForAI(maxTokens int) string {
	content, err := l.GetLogContent()
	if err != nil {
		return l.GetLogSummary()
	}

	// 如果内容长度在限制内，直接返回
	if len(content) <= maxTokens {
		return content
	}

	// 智能截断：保留重要部分
	return l.getSmartTruncatedContent(content, maxTokens)
}

// getSmartTruncatedContent 智能截断日志内容
func (l *PenetrationLogger) getSmartTruncatedContent(content string, maxTokens int) string {
	lines := strings.Split(content, "\n")

	// 保留重要部分：开头、结尾、错误信息、关键工具输出
	var importantLines []string

	// 保留开头部分（前50行）
	startLines := min(50, len(lines))
	importantLines = append(importantLines, lines[:startLines]...)

	// 保留结尾部分（后50行）
	endLines := min(50, len(lines))
	if len(lines) > 100 {
		importantLines = append(importantLines, "\n... [中间内容已省略] ...\n")
		importantLines = append(importantLines, lines[len(lines)-endLines:]...)
	}

	// 添加错误和关键信息
	for _, line := range lines {
		if strings.Contains(line, "错误:") || strings.Contains(line, "ERROR") ||
			strings.Contains(line, "漏洞") || strings.Contains(line, "VULNERABILITY") ||
			strings.Contains(line, "成功:") || strings.Contains(line, "SUCCESS") {
			if !contains(importantLines, line) {
				importantLines = append(importantLines, line)
			}
		}
	}

	result := strings.Join(importantLines, "\n")

	// 如果仍然太长，进一步截断
	if len(result) > maxTokens {
		result = result[:maxTokens] + "\n... [内容已截断]"
	}

	return result
}

// Close 关闭日志记录器
func (l *PenetrationLogger) Close() error {
	if l.currentFile != nil {
		return l.currentFile.Close()
	}
	return nil
}

// SaveJSONLog 保存JSON格式的日志
func (l *PenetrationLogger) SaveJSONLog() (string, error) {
	jsonFile := strings.TrimSuffix(l.logFile, ".log") + ".json"

	logData := map[string]interface{}{
		"target":    l.target,
		"startTime": time.Now().Format("2006-01-02 15:04:05"),
		"entries":   l.entries,
		"summary":   l.GetLogSummary(),
	}

	data, err := json.MarshalIndent(logData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化日志数据失败: %v", err)
	}

	if err := os.WriteFile(jsonFile, data, 0644); err != nil {
		return "", fmt.Errorf("写入JSON日志文件失败: %v", err)
	}

	return jsonFile, nil
}

// 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
