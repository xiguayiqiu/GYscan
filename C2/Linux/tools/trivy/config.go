package trivy

// Config 配置结构体
type Config struct {
	Target      string   // 扫描目标
	Output      string   // 输出文件路径
	Severity    string   // 严重性级别
	Timeout     int      // 超时时间（秒）
	Format      string   // 输出格式
	SkipUpdate  bool     // 是否跳过数据库更新
	Quiet       bool     // 静默模式
	Debug       bool     // 调试模式
	VulnType    string   // 漏洞类型
	Scanners    []string // 扫描器列表
	IgnoreFile  string   // 忽略文件路径
	CacheDir    string   // 缓存目录
	DBRepository string  // 数据库仓库
}

// NewConfig 创建默认配置
func NewConfig() *Config {
	return &Config{
		Target:      "",
		Output:      "",
		Severity:    "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		Timeout:     300,
		Format:      "json",
		SkipUpdate:  false,
		Quiet:       false,
		Debug:       false,
		VulnType:    "os,library",
		Scanners:    []string{"vuln"},
		IgnoreFile:  "",
		CacheDir:    "/tmp/trivy",
		DBRepository: "ghcr.io/aquasecurity/trivy-db:2",
	}
}

// SetTarget 设置扫描目标
func (c *Config) SetTarget(target string) {
	c.Target = target
}

// SetOutput 设置输出文件
func (c *Config) SetOutput(output string) {
	c.Output = output
}

// SetSeverity 设置严重性级别
func (c *Config) SetSeverity(severity string) {
	c.Severity = severity
}

// SetFormat 设置输出格式
func (c *Config) SetFormat(format string) {
	c.Format = format
}

// SetQuiet 设置静默模式
func (c *Config) SetQuiet(quiet bool) {
	c.Quiet = quiet
}

// SetDebug 设置调试模式
func (c *Config) SetDebug(debug bool) {
	c.Debug = debug
}