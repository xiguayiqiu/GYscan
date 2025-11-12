package lynis

// Config 安全审计配置结构
type Config struct {
	Target       string // 审计目标（本地系统）
	OutputFile   string // 输出文件路径
	Verbose      bool   // 详细输出模式
	QuickScan    bool   // 快速扫描模式
	FullScan     bool   // 完整扫描模式
	ReportFormat string // 报告格式：text/html/json
}

// NewConfig 创建新的安全审计配置
func NewConfig() *Config {
	return &Config{
		Target:       "localhost",
		OutputFile:   "lynis_security_audit_report.html",
		Verbose:      false,
		QuickScan:    false,
		FullScan:     true,
		ReportFormat: "html",
	}
}

// SetTarget 设置审计目标
func (c *Config) SetTarget(target string) {
	c.Target = target
}

// SetOutput 设置输出文件
func (c *Config) SetOutput(output string) {
	c.OutputFile = output
}

// SetVerbose 设置详细输出模式
func (c *Config) SetVerbose(verbose bool) {
	c.Verbose = verbose
}

// SetQuickScan 设置快速扫描模式
func (c *Config) SetQuickScan(quick bool) {
	c.QuickScan = quick
	if quick {
		c.FullScan = false
	}
}

// SetFullScan 设置完整扫描模式
func (c *Config) SetFullScan(full bool) {
	c.FullScan = full
	if full {
		c.QuickScan = false
	}
}

// SetReportType 设置报告格式
func (c *Config) SetReportType(reportFormat string) {
	c.ReportFormat = reportFormat
}