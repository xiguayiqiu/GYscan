package utils

import (
	"math/rand"
	"time"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// GenerateRandomString 生成指定长度的随机字符串
func GenerateRandomString(n int) string {
	if n <= 0 {
		return ""
	}

	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// GenerateRandomStringWithCharset 使用指定字符集生成随机字符串
func GenerateRandomStringWithCharset(n int, charset string) string {
	if n <= 0 || charset == "" {
		return ""
	}

	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// GenerateRandomNumberString 生成数字随机字符串
func GenerateRandomNumberString(n int) string {
	return GenerateRandomStringWithCharset(n, "0123456789")
}

// GenerateRandomHexString 生成十六进制随机字符串
func GenerateRandomHexString(n int) string {
	return GenerateRandomStringWithCharset(n, "0123456789abcdef")
}