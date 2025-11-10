package goss

// Config 配置结构体
type Config struct {
	Target      string   // 扫描目标
	Output      string   // 输出文件路径
	Verbose     bool     // 详细模式
	Quiet       bool     // 静默模式
	Debug       bool     // 调试模式
	GossFile    string   // Goss配置文件路径
	Format      string   // 输出格式 (json, yaml, documentation, tap, junit, nagios, rspecish)
	RetryTimeout int     // 重试超时时间(秒)
	Sleep       int      // 检查间隔时间(毫秒)
}

// NewConfig 创建默认配置
func NewConfig() *Config {
	return &Config{
		Target:      "localhost",
		Output:      "",
		Verbose:     false,
		Quiet:       false,
		Debug:       false,
		GossFile:    "goss.yaml",
		Format:      "json",
		RetryTimeout: 0,
		Sleep:       0,
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

// SetVerbose 设置详细模式
func (c *Config) SetVerbose(verbose bool) {
	c.Verbose = verbose
}

// SetQuiet 设置静默模式
func (c *Config) SetQuiet(quiet bool) {
	c.Quiet = quiet
}

// SetDebug 设置调试模式
func (c *Config) SetDebug(debug bool) {
	c.Debug = debug
}

// SetGossFile 设置Goss配置文件
func (c *Config) SetGossFile(gossFile string) {
	c.GossFile = gossFile
}

// SetFormat 设置输出格式
func (c *Config) SetFormat(format string) {
	c.Format = format
}

// SetRetryTimeout 设置重试超时
func (c *Config) SetRetryTimeout(timeout int) {
	c.RetryTimeout = timeout
}

// SetSleep 设置检查间隔
func (c *Config) SetSleep(sleep int) {
	c.Sleep = sleep
}