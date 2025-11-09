package samcrack

import (
	"time"
)

// CrackResult 破解结果
type CrackResult struct {
	Username    string
	Password    string
	NTLMHash    string
	Found       bool
	ElapsedTime time.Duration
	Attempts    int64
	Method      string
	TotalUsers  int
	CrackedUsers []*CrackResult
	SuccessRate float64
	Error       string
}

// UserHash 用户哈希信息
type UserHash struct {
	Username string
	NTLMHash string
	RID      uint32
}



// PredefinedCharsets 预定义字符集
var PredefinedCharsets = map[string]string{
	"numeric":      "0123456789",
	"lowercase":    "abcdefghijklmnopqrstuvwxyz",
	"uppercase":    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alphanumeric": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"common":       "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?",
}