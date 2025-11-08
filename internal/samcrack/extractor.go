//go:build windows

package samcrack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Extractor SAM/SYSTEM文件提取器
type Extractor struct {
	samPath     string
	systemPath  string
	tempDir     string
}

// NewExtractor 创建新的文件提取器
func NewExtractor() *Extractor {
	tempDir := filepath.Join(os.TempDir(), "samcrack")
	return &Extractor{
		tempDir: tempDir,
	}
}

// CheckAdminPrivileges 检查管理员权限
func (e *Extractor) CheckAdminPrivileges() bool {
	var token windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// 检查管理员权限
	var isAdmin bool
	
	// 使用TOKEN_ELEVATION类型检查权限
	tokenElevation := struct {
		TokenIsElevated uint32
	}{}
	elevationSize := uint32(unsafe.Sizeof(tokenElevation))
	
	err = windows.GetTokenInformation(token, windows.TokenElevation, 
		(*byte)(unsafe.Pointer(&tokenElevation)), elevationSize, &elevationSize)
	
	if err == nil && tokenElevation.TokenIsElevated != 0 {
		isAdmin = true
	}
	
	return isAdmin
}

// ExtractSAMFiles 提取SAM和SYSTEM文件
func (e *Extractor) ExtractSAMFiles(samPath, systemPath string) error {
	// 如果提供了文件路径，直接使用而不需要提取
	if samPath != "" && systemPath != "" {
		// 检查文件是否存在
		if _, err := os.Stat(samPath); os.IsNotExist(err) {
			return fmt.Errorf("SAM文件不存在: %s", samPath)
		}
		if _, err := os.Stat(systemPath); os.IsNotExist(err) {
			return fmt.Errorf("SYSTEM文件不存在: %s", systemPath)
		}
		
		e.samPath = samPath
		e.systemPath = systemPath
		return nil
	}

	// 检查管理员权限
	if !e.CheckAdminPrivileges() {
		return fmt.Errorf("需要管理员权限才能提取SAM/SYSTEM文件")
	}

	// 创建临时目录
	if err := os.MkdirAll(e.tempDir, 0755); err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}

	// 提取SAM文件
	if err := e.extractRegistryHive("SAM"); err != nil {
		return fmt.Errorf("提取SAM文件失败: %v", err)
	}

	// 提取SYSTEM文件
	if err := e.extractRegistryHive("SYSTEM"); err != nil {
		return fmt.Errorf("提取SYSTEM文件失败: %v", err)
	}

	e.samPath = filepath.Join(e.tempDir, "sam.hive")
	e.systemPath = filepath.Join(e.tempDir, "system.hive")

	return nil
}

// extractRegistryHive 提取注册表hive文件
func (e *Extractor) extractRegistryHive(hiveName string) error {
	// 简化实现：直接从系统目录复制SAM/SYSTEM文件
	// 在实际环境中，需要管理员权限和更复杂的注册表操作
	
	sourcePath := filepath.Join("C:\\Windows\\System32\\config", hiveName)
	destPath := filepath.Join(e.tempDir, fmt.Sprintf("%s.hive", strings.ToLower(hiveName)))
	
	// 复制文件
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("读取%s文件失败: %v", hiveName, err)
	}
	
	err = os.WriteFile(destPath, sourceData, 0644)
	if err != nil {
		return fmt.Errorf("写入%s文件失败: %v", hiveName, err)
	}

	return nil
}

// GetSAMPath 获取SAM文件路径
func (e *Extractor) GetSAMPath() string {
	return e.samPath
}

// GetSystemPath 获取SYSTEM文件路径
func (e *Extractor) GetSystemPath() string {
	return e.systemPath
}

// Cleanup 清理临时文件
func (e *Extractor) Cleanup() error {
	if e.tempDir != "" {
		return os.RemoveAll(e.tempDir)
	}
	return nil
}