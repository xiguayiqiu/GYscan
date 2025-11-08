package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// EDREvasion EDR规避技术
type EDREvasion struct {
	// 基础规避
	SleepJitter      bool          `json:"sleep_jitter"`
	ProcessSpoofing  bool          `json:"process_spoofing"`
	MemoryObfuscation bool         `json:"memory_obfuscation"`
	
	// 网络规避
	TrafficEncryption bool         `json:"traffic_encryption"`
	ProtocolMimicry   bool         `json:"protocol_mimicry"`
	DomainFronting    bool         `json:"domain_fronting"`
	
	// 行为规避
	SlowExecution    bool          `json:"slow_execution"`
	APIUnhooking     bool          `json:"api_unhooking"`
	SandboxDetection bool          `json:"sandbox_detection"`
	
	// 配置参数
	MinSleep         time.Duration `json:"min_sleep"`
	MaxSleep         time.Duration `json:"max_sleep"`
	JitterFactor     float64       `json:"jitter_factor"`
}

// NewEDREvasion 创建EDR规避实例
func NewEDREvasion() *EDREvasion {
	return &EDREvasion{
		SleepJitter:       true,
		ProcessSpoofing:   true,
		MemoryObfuscation: true,
		TrafficEncryption: true,
		ProtocolMimicry:   true,
		DomainFronting:    false,
		SlowExecution:     true,
		APIUnhooking:      true,
		SandboxDetection:  true,
		MinSleep:          100 * time.Millisecond,
		MaxSleep:          500 * time.Millisecond,
		JitterFactor:      0.2,
	}
}

// ApplySleepJitter 应用睡眠抖动规避
func (e *EDREvasion) ApplySleepJitter() {
	if !e.SleepJitter {
		return
	}
	
	// 使用crypto/rand生成随机数
	var buf [8]byte
	rand.Read(buf[:])
	randomNum := int64(binary.BigEndian.Uint64(buf[:]))
	if randomNum < 0 {
		randomNum = -randomNum
	}
	
	baseSleep := e.MinSleep + time.Duration(randomNum%int64(e.MaxSleep-e.MinSleep))
	
	// 生成抖动因子
	rand.Read(buf[:])
	jitterFactor := float64(binary.BigEndian.Uint64(buf[:])%1000)/1000.0 - 0.5
	jitter := time.Duration(float64(baseSleep) * e.JitterFactor * jitterFactor * 2)
	actualSleep := baseSleep + jitter
	
	if actualSleep < 0 {
		actualSleep = e.MinSleep
	}
	
	logrus.Debugf("[GYscan-EDR] 应用睡眠抖动: 基础=%v, 抖动=%v, 实际=%v", 
		baseSleep, jitter, actualSleep)
	
	time.Sleep(actualSleep)
}

// DetectSandbox 沙箱检测
func (e *EDREvasion) DetectSandbox() bool {
	if !e.SandboxDetection {
		return false
	}
	
	// 检测运行时间
	if e.isShortRuntime() {
		logrus.Warn("[GYscan-EDR] 检测到沙箱环境: 运行时间过短")
		return true
	}
	
	// 检测内存大小
	if e.isLowMemory() {
		logrus.Warn("[GYscan-EDR] 检测到沙箱环境: 内存过小")
		return true
	}
	
	// 检测CPU核心数
	if e.isLowCPUCores() {
		logrus.Warn("[GYscan-EDR] 检测到沙箱环境: CPU核心数过少")
		return true
	}
	
	// 检测网络适配器
	if e.hasSuspiciousNetwork() {
		logrus.Warn("[GYscan-EDR] 检测到沙箱环境: 可疑网络配置")
		return true
	}
	
	return false
}

// isShortRuntime 检测运行时间是否过短
func (e *EDREvasion) isShortRuntime() bool {
	// 模拟一些计算工作
	start := time.Now()
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i
	}
	duration := time.Since(start)
	
	// 如果计算时间异常短，可能是沙箱
	return duration < 10*time.Millisecond
}

// isLowMemory 检测内存是否过小
func (e *EDREvasion) isLowMemory() bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// 如果总内存小于2GB，可能是沙箱
	totalMemory := m.Sys / 1024 / 1024 // MB
	return totalMemory < 2048
}

// isLowCPUCores 检测CPU核心数是否过少
func (e *EDREvasion) isLowCPUCores() bool {
	cores := runtime.NumCPU()
	return cores < 2
}

// hasSuspiciousNetwork 检测可疑网络配置
func (e *EDREvasion) hasSuspiciousNetwork() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	
	// 检查是否有VMware、VirtualBox等虚拟网卡
	for _, iface := range interfaces {
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "vmware") || 
		   strings.Contains(name, "virtual") ||
		   strings.Contains(name, "vbox") ||
		   strings.Contains(name, "hyper-v") {
			return true
		}
	}
	
	return false
}

// ObfuscateMemory 内存混淆
func (e *EDREvasion) ObfuscateMemory(data []byte) []byte {
	if !e.MemoryObfuscation {
		return data
	}
	
	// XOR混淆
	key := make([]byte, len(data))
	rand.Read(key)
	
	obfuscated := make([]byte, len(data))
	for i := range data {
		obfuscated[i] = data[i] ^ key[i]
	}
	
	logrus.Debugf("[GYscan-EDR] 内存混淆完成: 原始大小=%d, 混淆后大小=%d", 
		len(data), len(obfuscated))
	
	return obfuscated
}

// DeobfuscateMemory 内存反混淆
func (e *EDREvasion) DeobfuscateMemory(data []byte, key []byte) []byte {
	if !e.MemoryObfuscation {
		return data
	}
	
	deobfuscated := make([]byte, len(data))
	for i := range data {
		deobfuscated[i] = data[i] ^ key[i]
	}
	
	return deobfuscated
}

// GenerateTrafficSignature 生成流量签名
func (e *EDREvasion) GenerateTrafficSignature() string {
	if !e.TrafficEncryption {
		return ""
	}
	
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	
	signature := fmt.Sprintf("%d-%x", timestamp, randomBytes)
	return signature
}

// MimicLegitimateProtocol 模拟合法协议
func (e *EDREvasion) MimicLegitimateProtocol(data []byte) []byte {
	if !e.ProtocolMimicry {
		return data
	}
	
	// 模拟HTTP流量
	httpHeader := "POST /api/data HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: %d\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
		"\r\n"
	
	encodedData := e.base64Encode(data)
	httpData := fmt.Sprintf(httpHeader, len(encodedData)) + encodedData
	
	return []byte(httpData)
}

// base64Encode Base64编码
func (e *EDREvasion) base64Encode(data []byte) string {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	return string(encoded)
}

// ApplySlowExecution 应用慢速执行规避
func (e *EDREvasion) ApplySlowExecution() {
	if !e.SlowExecution {
		return
	}
	
	// 随机插入小延迟
	delays := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
	}
	
	// 使用crypto/rand选择延迟
	var buf [8]byte
	rand.Read(buf[:])
	index := int(binary.BigEndian.Uint64(buf[:]) % uint64(len(delays)))
	delay := delays[index]
	time.Sleep(delay)
}

// CheckEDRPresence 检测EDR存在
func (e *EDREvasion) CheckEDRPresence() bool {
	// 检测常见EDR进程
	_ = []string{
		"crowdstrike", "carbonblack", "sentinelone",
		"cylance", "mcafee", "symantec", "trendmicro",
		"kaspersky", "bitdefender", "sophos",
		"windowsdefender", "msmpeng", "defender",
	}
	
	// 这里需要实现进程检测逻辑
	// 由于平台限制，这里返回false表示未检测到EDR
	return false
}

// GenerateEvasionReport 生成规避报告
func (e *EDREvasion) GenerateEvasionReport() map[string]interface{} {
	report := make(map[string]interface{})
	
	report["sleep_jitter"] = e.SleepJitter
	report["process_spoofing"] = e.ProcessSpoofing
	report["memory_obfuscation"] = e.MemoryObfuscation
	report["traffic_encryption"] = e.TrafficEncryption
	report["protocol_mimicry"] = e.ProtocolMimicry
	report["slow_execution"] = e.SlowExecution
	report["api_unhooking"] = e.APIUnhooking
	report["sandbox_detection"] = e.SandboxDetection
	report["sandbox_detected"] = e.DetectSandbox()
	report["edr_present"] = e.CheckEDRPresence()
	
	return report
}