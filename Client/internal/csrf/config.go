package csrf

// Config 定义CSRF漏洞检测的配置
type Config struct {
	URL          string // 目标URL
	Method       string // HTTP请求方法 (GET/POST)
	Params       string // 自定义参数 (key=value格式，多个参数用&分隔)
	Headers      string // 自定义HTTP头 (key:value格式，多个头用&分隔)
	Data         string // POST数据 (key=value格式)
	Threads      int    // 并发线程数
	Verbose      bool   // 是否显示详细信息
	TestMode     bool   // 是否启用测试模式
	Timeout      int    // 请求超时时间(秒)
	Proxy        string // 代理服务器
	Cookies      string // Cookie信息
	Referer      string // Referer头
	UserAgent    string // User-Agent头
	LoginURL     string // 登录URL
	LoginUsername string // 登录用户名
	LoginPassword string // 登录密码
	LoginMethod   string // 登录方法
	LoginData     string // 登录数据
	LoginSuccess  string // 登录成功标识
}

// Result 定义CSRF漏洞检测结果
type Result struct {
	URL          string // 检测的URL
	Method       string // 请求方法
	VulnerabilityType string // 漏洞类型
	Payload      string // 使用的Payload
	StatusCode   int    // HTTP响应状态码
	ResponseTime float64 // 响应时间(秒)
	Evidence     string // 漏洞证据
	IsVulnerable bool   // 是否存在漏洞
}

// Summary 定义检测总结
type Summary struct {
	TotalURLs      int // 总检测URL数
	TotalTests     int // 总测试数
	VulnerableTests int // 发现漏洞的测试数
	TotalVulnerabilities int // 总漏洞数
}

// Results 定义检测结果集合
type Results struct {
	Summary Summary // 检测总结
	Items   []Result // 详细结果列表
}