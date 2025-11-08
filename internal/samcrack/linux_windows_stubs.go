//go:build !windows

package samcrack

import "fmt"

// Extractor Windows SAM文件提取器（Linux空实现）
type Extractor struct{}

// NewExtractor 创建新的Extractor（Linux空实现）
func NewExtractor() *Extractor {
	return &Extractor{}
}

// CheckAdminPrivileges 检查管理员权限（Linux空实现）
func (e *Extractor) CheckAdminPrivileges() bool {
	return false // Linux系统不支持此功能
}

// ExtractSAMFiles 提取SAM文件（Linux空实现）
func (e *Extractor) ExtractSAMFiles(samPath, systemPath string) error {
	return fmt.Errorf("SAM文件提取功能仅在Windows系统上可用")
}

// GetSAMPath 获取SAM文件路径（Linux空实现）
func (e *Extractor) GetSAMPath() string {
	return "" // Linux系统不支持此功能
}

// GetSystemPath 获取SYSTEM文件路径（Linux空实现）
func (e *Extractor) GetSystemPath() string {
	return "" // Linux系统不支持此功能
}