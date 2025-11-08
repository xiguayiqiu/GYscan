package samcrack

import (
	"encoding/hex"
	"unicode/utf16"
	
	"golang.org/x/crypto/md4"
)

// NTLMHasher NTLM哈希计算器
type NTLMHasher struct{}

// NewNTLMHasher 创建新的NTLM哈希计算器
func NewNTLMHasher() *NTLMHasher {
	return &NTLMHasher{}
}

// ComputeNTLMHash 计算密码的NTLM哈希
func (h *NTLMHasher) ComputeNTLMHash(password string) string {
	// 空密码的特殊哈希
	if password == "" {
		return "31d6cfe0d16ae931b73c59d7e0c089c0"
	}

	// 将密码转换为UTF-16LE编码
	utf16Password := h.stringToUTF16LE(password)

	// 计算MD4哈希
	hash := md4.New()
	hash.Write(utf16Password)
	hashBytes := hash.Sum(nil)

	// 转换为十六进制字符串
	return hex.EncodeToString(hashBytes)
}

// stringToUTF16LE 将字符串转换为UTF-16LE编码
func (h *NTLMHasher) stringToUTF16LE(s string) []byte {
	// 将字符串转换为UTF-16编码
	utf16Chars := utf16.Encode([]rune(s))
	
	// 转换为小端字节序
	result := make([]byte, len(utf16Chars)*2)
	for i, char := range utf16Chars {
		result[i*2] = byte(char)
		result[i*2+1] = byte(char >> 8)
	}
	
	return result
}

// VerifyPassword 验证密码是否匹配NTLM哈希
func (h *NTLMHasher) VerifyPassword(password, targetHash string) bool {
	computedHash := h.ComputeNTLMHash(password)
	return computedHash == targetHash
}

// HashInfo NTLM哈希信息
type HashInfo struct {
	Password    string
	NTLMHash    string
	IsWeak      bool
	Strength    string // weak, medium, strong
}

// AnalyzePassword 分析密码强度
func (h *NTLMHasher) AnalyzePassword(password string) *HashInfo {
	hash := h.ComputeNTLMHash(password)
	
	info := &HashInfo{
		Password: password,
		NTLMHash: hash,
	}
	
	// 分析密码强度
	info.IsWeak = h.isWeakPassword(password)
	info.Strength = h.getPasswordStrength(password)
	
	return info
}

// isWeakPassword 判断是否为弱密码
func (h *NTLMHasher) isWeakPassword(password string) bool {
	if len(password) < 6 {
		return true
	}
	
	// 常见弱密码列表
	weakPasswords := []string{
		"123456", "password", "12345678", "qwerty", "123456789",
		"12345", "1234", "111111", "1234567", "dragon",
		"123123", "baseball", "abc123", "football", "monkey",
		"letmein", "696969", "shadow", "master", "666666",
		"qwertyuiop", "123321", "mustang", "1234567890",
		"michael", "654321", "superman", "1qaz2wsx", "7777777",
		"fuckyou", "121212", "000000", "qazwsx", "123qwe",
		"killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
		"asdfgh", "hunter", "buster", "soccer", "harley",
		"batman", "andrew", "tigger", "sunshine", "iloveyou",
		"fuckme", "2000", "charlie", "robert", "thomas",
		"hockey", "ranger", "daniel", "starwars", "klaster",
		"112233", "george", "asshole", "computer", "michelle",
		"jessica", "pepper", "1111", "zxcvbn", "555555",
		"11111111", "131313", "freedom", "777777", "pass",
		"fuck", "maggie", "159753", "aaaaaa", "ginger",
		"princess", "joshua", "cheese", "amanda", "summer",
		"love", "ashley", "6969", "nicole", "chelsea",
		"biteme", "matthew", "access", "yankees", "987654321",
		"dallas", "austin", "thunder", "taylor", "matrix",
	}
	
	for _, weak := range weakPasswords {
		if password == weak {
			return true
		}
	}
	
	return false
}

// getPasswordStrength 获取密码强度
func (h *NTLMHasher) getPasswordStrength(password string) string {
	length := len(password)
	
	if length < 6 {
		return "weak"
	}
	
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	
	score := 0
	if length >= 8 {
		score++
	}
	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}
	
	switch {
	case score >= 4:
		return "strong"
	case score >= 2:
		return "medium"
	default:
		return "weak"
	}
}