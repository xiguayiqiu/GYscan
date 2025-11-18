package xss

// XssConfig 定义XSS检测的配置
type XssConfig struct {
	URL          string // 目标URL
	Type         string // XSS类型 (reflected/stored/dom/all)
	LoginURL     string // 登录页面URL
	Username     string // 登录用户名
	Password     string // 登录密码
	Threads      int    // 并发线程数
	WafBypass    bool   // 是否启用WAF绕过
	PayloadLevel string // Payload级别 (low/medium/high)
	Verbose      bool   // 是否显示详细信息
	TestMode     bool   // 是否启用测试模式
}

// XssResult 定义XSS检测结果
 type XssResult struct {
	URL          string // 检测的URL
	Param        string // 存在漏洞的参数
	Type         string // XSS类型
	Payload      string // 有效Payload
	StatusCode   int    // HTTP响应状态码
	Evidence     string // 漏洞证据
	Location     string // 漏洞位置类型 (HTML/JSON/JS/CSS/URL等)
	IsVulnerable bool   // 是否存在漏洞
}

// XssResults 定义XSS检测结果列表
 type XssResults struct {
	Results []XssResult
	Summary Summary
}

// Summary 定义检测总结
 type Summary struct {
	TotalURLs    int // 检测的URL总数
	TotalParams  int // 检测的参数总数
	Vulnerable   int // 发现的漏洞数
	Reflected    int // 反射型XSS数量
	Stored       int // 存储型XSS数量
	DOM          int // DOM型XSS数量
	DetectionTime float64 // 检测耗时(秒)
}

// PayloadType 定义Payload类型
 type PayloadType string

const (
	ReflectedXSS PayloadType = "reflected"
	StoredXSS    PayloadType = "stored"
	DOMXSS       PayloadType = "dom"
)

// PayloadLevel 定义Payload级别
 const (
	LowPayload    = "low"
	MediumPayload = "medium"
	HighPayload   = "high"
)

// 默认配置
 const (
	DefaultThreads      = 10
	DefaultPayloadLevel = "medium"
	DefaultXssType      = "reflected"
)