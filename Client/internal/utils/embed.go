package utils

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed embed_resources/waf_rules.json
var wafRulesFS embed.FS

//go:embed embed_resources/dicc.txt
//go:embed embed_resources/medium.txt
var dirscanDictFS embed.FS

// LoadEmbeddedWAFRules 加载嵌入的WAF规则文件
func LoadEmbeddedWAFRules() ([]byte, error) {
	return wafRulesFS.ReadFile("embed_resources/waf_rules.json")
}

// LoadEmbeddedDirscanDict 加载嵌入的目录扫描字典文件
func LoadEmbeddedDirscanDict(filename string) ([]byte, error) {
	return dirscanDictFS.ReadFile("embed_resources/" + filename)
}

// ExtractEmbeddedFiles 将嵌入的文件提取到临时目录
func ExtractEmbeddedFiles() (string, error) {
	tempDir, err := os.MkdirTemp("", "gyscan_embedded")
	if err != nil {
		return "", err
	}

	// 提取WAF规则文件
	wafRulesData, err := LoadEmbeddedWAFRules()
	if err == nil {
		wafRulesPath := filepath.Join(tempDir, "waf_rules.json")
		os.WriteFile(wafRulesPath, wafRulesData, 0644)
	}

	// 提取目录扫描字典文件
	dictFiles := []string{"dicc.txt", "medium.txt"}
	for _, filename := range dictFiles {
		dictData, err := LoadEmbeddedDirscanDict(filename)
		if err == nil {
			dictPath := filepath.Join(tempDir, filename)
			os.WriteFile(dictPath, dictData, 0644)
		}
	}

	return tempDir, nil
}

// GetEmbeddedDictPath 获取嵌入字典文件的路径
func GetEmbeddedDictPath(choice string) (string, error) {
	tempDir, err := ExtractEmbeddedFiles()
	if err != nil {
		return "", err
	}

	switch choice {
	case "1":
		return filepath.Join(tempDir, "dicc.txt"), nil
	case "2":
		return filepath.Join(tempDir, "medium.txt"), nil
	default:
		return "", nil
	}
}