package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

// ToJSON 将任意对象转换为JSON字符串
func ToJSON(v interface{}) (string, error) {
	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}
	return string(jsonBytes), nil
}

// FromJSON 将JSON字符串解析为指定类型的对象
func FromJSON(jsonStr string, v interface{}) error {
	err := json.Unmarshal([]byte(jsonStr), v)
	if err != nil {
		return fmt.Errorf("JSON反序列化失败: %v", err)
	}
	return nil
}

// PrettyJSON 美化JSON字符串
func PrettyJSON(jsonStr string) (string, error) {
	var v interface{}
	err := json.Unmarshal([]byte(jsonStr), &v)
	if err != nil {
		return "", fmt.Errorf("JSON解析失败: %v", err)
	}
	
	prettyJSON, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON美化失败: %v", err)
	}
	
	return string(prettyJSON), nil
}

// SaveJSON 将对象保存为JSON文件
func SaveJSON(filename string, v interface{}) error {
	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		return fmt.Errorf("文件写入失败: %v", err)
	}

	return nil
}