package logging

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ConfigLoader 配置加载器
type ConfigLoader struct {
	configPaths []string
}

// NewConfigLoader 创建配置加载器
func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{
		configPaths: []string{
			"logging.json",
			"config/logging.json",
			"/etc/gyscan/logging.json",
		},
	}
}

// AddConfigPath 添加配置路径
func (cl *ConfigLoader) AddConfigPath(path string) {
	cl.configPaths = append(cl.configPaths, path)
}

// LoadConfig 加载配置文件
func (cl *ConfigLoader) LoadConfig() (*LogConfig, error) {
	for _, path := range cl.configPaths {
		if cl.fileExists(path) {
			return cl.loadConfigFromFile(path)
		}
	}

	// 如果没有找到配置文件，返回默认配置
	return DefaultConfig(), nil
}

// fileExists 检查文件是否存在
func (cl *ConfigLoader) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadConfigFromFile 从文件加载配置
func (cl *ConfigLoader) loadConfigFromFile(filePath string) (*LogConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config LogConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证配置
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("配置文件验证失败: %v", err)
	}

	return &config, nil
}

// SaveConfig 保存配置到文件
func (cl *ConfigLoader) SaveConfig(config *LogConfig, filePath string) error {
	// 确保目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %v", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// LogFormatter 日志格式化器
type LogFormatter struct {
	format string
}

// NewLogFormatter 创建日志格式化器
func NewLogFormatter(format string) *LogFormatter {
	return &LogFormatter{
		format: format,
	}
}

// Format 格式化日志消息
func (lf *LogFormatter) Format(timestamp, level, module, message string) string {
	formatted := lf.format
	formatted = strings.ReplaceAll(formatted, "%time%", timestamp)
	formatted = strings.ReplaceAll(formatted, "%level%", level)
	formatted = strings.ReplaceAll(formatted, "%module%", module)
	formatted = strings.ReplaceAll(formatted, "%message%", message)
	return formatted
}

// LogAnalyzer 日志分析器
type LogAnalyzer struct {
	logDir string
}

// NewLogAnalyzer 创建日志分析器
func NewLogAnalyzer(logDir string) *LogAnalyzer {
	return &LogAnalyzer{
		logDir: logDir,
	}
}

// AnalyzeLogs 分析日志文件
func (la *LogAnalyzer) AnalyzeLogs() (*LogAnalysisResult, error) {
	result := &LogAnalysisResult{
		TotalLogFiles: 0,
		TotalSize:     0,
		LogLevelStats: make(map[string]int),
		ModuleStats:   make(map[string]int),
		ErrorCount:    0,
		WarningCount:  0,
	}

	// 分析日志目录中的所有文件
	files, err := ioutil.ReadDir(la.logDir)
	if err != nil {
		return nil, fmt.Errorf("读取日志目录失败: %v", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if strings.HasSuffix(file.Name(), ".log") ||
			strings.HasSuffix(file.Name(), ".log.gz") {

			filePath := filepath.Join(la.logDir, file.Name())
			fileStats, err := la.analyzeLogFile(filePath)
			if err != nil {
				// 跳过分析失败的文件
				continue
			}

			result.TotalLogFiles++
			result.TotalSize += file.Size()

			// 合并统计信息
			for level, count := range fileStats.LogLevelStats {
				result.LogLevelStats[level] += count
			}

			for module, count := range fileStats.ModuleStats {
				result.ModuleStats[module] += count
			}

			result.ErrorCount += fileStats.ErrorCount
			result.WarningCount += fileStats.WarningCount
		}
	}

	return result, nil
}

// analyzeLogFile 分析单个日志文件
func (la *LogAnalyzer) analyzeLogFile(filePath string) (*LogAnalysisResult, error) {
	result := &LogAnalysisResult{
		LogLevelStats: make(map[string]int),
		ModuleStats:   make(map[string]int),
	}

	// 读取文件内容
	var content []byte
	var err error

	if strings.HasSuffix(filePath, ".gz") {
		// 处理压缩文件
		content, err = la.readCompressedFile(filePath)
	} else {
		// 处理普通文件
		content, err = ioutil.ReadFile(filePath)
	}

	if err != nil {
		return nil, err
	}

	// 分析日志内容
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// 简单的日志格式分析
		if strings.Contains(line, "[ERROR]") {
			result.ErrorCount++
			result.LogLevelStats["ERROR"]++
		} else if strings.Contains(line, "[WARNING]") {
			result.WarningCount++
			result.LogLevelStats["WARNING"]++
		} else if strings.Contains(line, "[INFO]") {
			result.LogLevelStats["INFO"]++
		} else if strings.Contains(line, "[DEBUG]") {
			result.LogLevelStats["DEBUG"]++
		} else if strings.Contains(line, "[FATAL]") {
			result.LogLevelStats["FATAL"]++
		}

		// 分析模块
		if strings.Contains(line, "AI:") {
			result.ModuleStats["AI"]++
		} else if strings.Contains(line, "Network:") {
			result.ModuleStats["Network"]++
		} else if strings.Contains(line, "Security:") {
			result.ModuleStats["Security"]++
		} else if strings.Contains(line, "Database:") {
			result.ModuleStats["Database"]++
		} else if strings.Contains(line, "Web:") {
			result.ModuleStats["Web"]++
		} else if strings.Contains(line, "System:") {
			result.ModuleStats["System"]++
		}
	}

	return result, nil
}

// readCompressedFile 读取压缩文件
func (la *LogAnalyzer) readCompressedFile(filePath string) ([]byte, error) {
	// 这里需要实现gzip解压缩逻辑
	// 简化实现，直接返回空
	return []byte{}, nil
}

// LogAnalysisResult 日志分析结果
type LogAnalysisResult struct {
	TotalLogFiles int            `json:"total_log_files"`
	TotalSize     int64          `json:"total_size"`
	LogLevelStats map[string]int `json:"log_level_stats"`
	ModuleStats   map[string]int `json:"module_stats"`
	ErrorCount    int            `json:"error_count"`
	WarningCount  int            `json:"warning_count"`
}

// LogCleaner 日志清理器
type LogCleaner struct {
	logDir     string
	maxAgeDays int
	maxSizeMB  int64
}

// NewLogCleaner 创建日志清理器
func NewLogCleaner(logDir string, maxAgeDays int, maxSizeMB int64) *LogCleaner {
	return &LogCleaner{
		logDir:     logDir,
		maxAgeDays: maxAgeDays,
		maxSizeMB:  maxSizeMB,
	}
}

// CleanOldLogs 清理旧的日志文件
func (lc *LogCleaner) CleanOldLogs() (*CleanResult, error) {
	result := &CleanResult{
		DeletedFiles: make([]string, 0),
		FreedSpace:   0,
	}

	files, err := ioutil.ReadDir(lc.logDir)
	if err != nil {
		return nil, fmt.Errorf("读取日志目录失败: %v", err)
	}

	cutoffTime := time.Now().AddDate(0, 0, -lc.maxAgeDays)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(lc.logDir, file.Name())

		// 检查文件是否过期
		if file.ModTime().Before(cutoffTime) {
			if err := os.Remove(filePath); err == nil {
				result.DeletedFiles = append(result.DeletedFiles, file.Name())
				result.FreedSpace += file.Size()
			}
		}
	}

	return result, nil
}

// CleanResult 清理结果
type CleanResult struct {
	DeletedFiles []string `json:"deleted_files"`
	FreedSpace   int64    `json:"freed_space"`
}

// LogMonitor 日志监控器
type LogMonitor struct {
	logDir      string
	lastSize    int64
	lastModTime time.Time
}

// NewLogMonitor 创建日志监控器
func NewLogMonitor(logDir string) *LogMonitor {
	return &LogMonitor{
		logDir: logDir,
	}
}

// CheckForChanges 检查日志变化
func (lm *LogMonitor) CheckForChanges() (*MonitorResult, error) {
	result := &MonitorResult{
		HasChanges: false,
		NewEntries: 0,
	}

	mainLogPath := filepath.Join(lm.logDir, "gyscan.log")
	fileInfo, err := os.Stat(mainLogPath)
	if err != nil {
		return result, nil // 文件不存在，没有变化
	}

	currentSize := fileInfo.Size()
	currentModTime := fileInfo.ModTime()

	// 检查是否有变化
	if currentSize != lm.lastSize || !currentModTime.Equal(lm.lastModTime) {
		result.HasChanges = true

		// 计算新增的日志条目数（简化实现）
		if currentSize > lm.lastSize {
			result.NewEntries = int((currentSize - lm.lastSize) / 100) // 估算
		}

		// 更新状态
		lm.lastSize = currentSize
		lm.lastModTime = currentModTime
	}

	return result, nil
}

// MonitorResult 监控结果
type MonitorResult struct {
	HasChanges bool `json:"has_changes"`
	NewEntries int  `json:"new_entries"`
}
