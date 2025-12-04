package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogManager 日志管理器
type LogManager struct {
	config     *LogConfig
	file       *os.File
	fileMutex  sync.Mutex
	fileSize   int64
	lastRotate time.Time
}

// NewLogManager 创建新的日志管理器
func NewLogManager(config *LogConfig) (*LogManager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("日志配置验证失败: %v", err)
	}
	
	manager := &LogManager{
		config:     config,
		lastRotate: time.Now(),
	}
	
	// 确保日志目录存在
	if err := config.EnsureLogDir(); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}
	
	// 如果启用文件日志，初始化日志文件
	if config.LogToFile {
		if err := manager.initializeLogFile(); err != nil {
			return nil, fmt.Errorf("初始化日志文件失败: %v", err)
		}
	}
	
	return manager, nil
}

// initializeLogFile 初始化日志文件
func (m *LogManager) initializeLogFile() error {
	m.fileMutex.Lock()
	defer m.fileMutex.Unlock()
	
	logFilePath := m.config.GetLogFilePath()
	
	// 检查是否需要日志轮转
	if m.shouldRotate() {
		if err := m.rotateLogFile(); err != nil {
			return fmt.Errorf("日志轮转失败: %v", err)
		}
	}
	
	// 打开或创建日志文件
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}
	
	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("获取文件信息失败: %v", err)
	}
	
	m.file = file
	m.fileSize = fileInfo.Size()
	
	return nil
}

// shouldRotate 检查是否需要日志轮转
func (m *LogManager) shouldRotate() bool {
	logFilePath := m.config.GetLogFilePath()
	
	// 检查文件是否存在
	fileInfo, err := os.Stat(logFilePath)
	if err != nil {
		return false // 文件不存在，不需要轮转
	}
	
	// 检查文件大小
	if m.config.MaxSizeMB > 0 {
		maxSize := int64(m.config.MaxSizeMB) * 1024 * 1024
		if fileInfo.Size() >= maxSize {
			return true
		}
	}
	
	// 检查时间间隔
	if m.config.MaxAgeDays > 0 {
		maxAge := time.Duration(m.config.MaxAgeDays) * 24 * time.Hour
		if time.Since(fileInfo.ModTime()) >= maxAge {
			return true
		}
	}
	
	return false
}

// rotateLogFile 执行日志轮转
func (m *LogManager) rotateLogFile() error {
	logFilePath := m.config.GetLogFilePath()
	
	// 检查文件是否存在
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		return nil // 文件不存在，无需轮转
	}
	
	// 备份现有的日志文件
	if err := m.backupLogFile(); err != nil {
		return fmt.Errorf("备份日志文件失败: %v", err)
	}
	
	// 删除旧的备份文件
	if err := m.cleanupOldBackups(); err != nil {
		return fmt.Errorf("清理旧备份文件失败: %v", err)
	}
	
	return nil
}

// backupLogFile 备份日志文件
func (m *LogManager) backupLogFile() error {
	logFilePath := m.config.GetLogFilePath()
	
	// 查找下一个可用的备份索引
	backupIndex := m.findNextBackupIndex()
	
	// 确定备份文件名
	var backupFilePath string
	if m.config.Compress {
		backupFilePath = m.config.GetCompressedBackupLogFilePath(backupIndex)
	} else {
		backupFilePath = m.config.GetBackupLogFilePath(backupIndex)
	}
	
	// 备份文件
	if m.config.Compress {
		return m.compressAndBackup(logFilePath, backupFilePath)
	} else {
		return os.Rename(logFilePath, backupFilePath)
	}
}

// compressAndBackup 压缩并备份日志文件
func (m *LogManager) compressAndBackup(sourcePath, destPath string) error {
	// 打开源文件
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	
	// 创建目标文件
	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()
	
	// 创建gzip写入器
	gzipWriter := gzip.NewWriter(destFile)
	defer gzipWriter.Close()
	
	// 复制文件内容
	_, err = io.Copy(gzipWriter, sourceFile)
	if err != nil {
		return err
	}
	
	// 删除原文件
	return os.Remove(sourcePath)
}

// findNextBackupIndex 查找下一个可用的备份索引
func (m *LogManager) findNextBackupIndex() int {
	logDir := m.config.LogDir
	baseName := m.config.LogFileName
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)
	
	// 查找现有的备份文件
	pattern := fmt.Sprintf("%s.*%s", nameWithoutExt, ext)
	if m.config.Compress {
		pattern = fmt.Sprintf("%s.*%s.gz", nameWithoutExt, ext)
	}
	
	files, err := filepath.Glob(filepath.Join(logDir, pattern))
	if err != nil {
		return 1
	}
	
	// 提取备份索引
	indices := make([]int, 0)
	for _, file := range files {
		fileName := filepath.Base(file)
		parts := strings.Split(fileName, ".")
		if len(parts) >= 3 {
			var index int
			fmt.Sscanf(parts[len(parts)-2], "%d", &index)
			if index > 0 {
				indices = append(indices, index)
			}
		}
	}
	
	// 如果没有备份文件，从1开始
	if len(indices) == 0 {
		return 1
	}
	
	// 排序并返回下一个索引
	sort.Ints(indices)
	return indices[len(indices)-1] + 1
}

// cleanupOldBackups 清理旧的备份文件
func (m *LogManager) cleanupOldBackups() error {
	if m.config.MaxBackups <= 0 {
		return nil // 不限制备份数量
	}
	
	logDir := m.config.LogDir
	baseName := m.config.LogFileName
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)
	
	// 查找所有的备份文件
	pattern := fmt.Sprintf("%s.*%s", nameWithoutExt, ext)
	if m.config.Compress {
		pattern = fmt.Sprintf("%s.*%s.gz", nameWithoutExt, ext)
	}
	
	files, err := filepath.Glob(filepath.Join(logDir, pattern))
	if err != nil {
		return err
	}
	
	// 按修改时间排序
	sort.Slice(files, func(i, j int) bool {
		fileInfoI, _ := os.Stat(files[i])
		fileInfoJ, _ := os.Stat(files[j])
		return fileInfoI.ModTime().Before(fileInfoJ.ModTime())
	})
	
	// 删除超出数量限制的文件
	if len(files) > m.config.MaxBackups {
		filesToDelete := files[:len(files)-m.config.MaxBackups]
		for _, file := range filesToDelete {
			os.Remove(file)
		}
	}
	
	return nil
}

// WriteLog 写入日志
func (m *LogManager) WriteLog(message string) error {
	if !m.config.LogToFile || m.file == nil {
		return nil
	}
	
	m.fileMutex.Lock()
	defer m.fileMutex.Unlock()
	
	// 检查是否需要轮转
	if m.shouldRotate() {
		if err := m.rotateLogFile(); err != nil {
			return fmt.Errorf("日志轮转失败: %v", err)
		}
		
		// 重新初始化日志文件
		if err := m.initializeLogFile(); err != nil {
			return fmt.Errorf("重新初始化日志文件失败: %v", err)
		}
	}
	
	// 写入日志
	_, err := m.file.WriteString(message + "\n")
	if err != nil {
		return fmt.Errorf("写入日志失败: %v", err)
	}
	
	// 更新文件大小
	m.fileSize += int64(len(message) + 1)
	
	return nil
}

// Close 关闭日志管理器
func (m *LogManager) Close() error {
	m.fileMutex.Lock()
	defer m.fileMutex.Unlock()
	
	if m.file != nil {
		return m.file.Close()
	}
	
	return nil
}

// GetLogStats 获取日志统计信息
func (m *LogManager) GetLogStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	logFilePath := m.config.GetLogFilePath()
	
	// 获取主日志文件信息
	fileInfo, err := os.Stat(logFilePath)
	if err == nil {
		stats["main_log_size"] = fileInfo.Size()
		stats["main_log_modified"] = fileInfo.ModTime()
	}
	
	// 获取备份文件信息
	backupFiles := m.getBackupFiles()
	stats["backup_count"] = len(backupFiles)
	stats["backup_files"] = backupFiles
	
	// 获取目录信息
	dirInfo, err := os.Stat(m.config.LogDir)
	if err == nil {
		stats["log_dir_size"] = m.calculateDirSize(m.config.LogDir)
		stats["log_dir_modified"] = dirInfo.ModTime()
	}
	
	return stats, nil
}

// getBackupFiles 获取备份文件列表
func (m *LogManager) getBackupFiles() []map[string]interface{} {
	logDir := m.config.LogDir
	baseName := m.config.LogFileName
	ext := filepath.Ext(baseName)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)
	
	pattern := fmt.Sprintf("%s.*%s", nameWithoutExt, ext)
	if m.config.Compress {
		pattern = fmt.Sprintf("%s.*%s.gz", nameWithoutExt, ext)
	}
	
	files, err := filepath.Glob(filepath.Join(logDir, pattern))
	if err != nil {
		return nil
	}
	
	backupFiles := make([]map[string]interface{}, 0)
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			continue
		}
		
		backupFile := map[string]interface{}{
			"name":     filepath.Base(file),
			"size":     fileInfo.Size(),
			"modified": fileInfo.ModTime(),
		}
		backupFiles = append(backupFiles, backupFile)
	}
	
	return backupFiles
}

// calculateDirSize 计算目录大小
func (m *LogManager) calculateDirSize(dirPath string) int64 {
	var totalSize int64
	
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	
	return totalSize
}