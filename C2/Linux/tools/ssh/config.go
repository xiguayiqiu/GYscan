package ssh

// Config 包含SSH扫描的配置参数
type Config struct {
	Target      string `json:"target"`      // SSH服务地址，格式为host:port
	ConfigFile  string `json:"config_file"` // SSH配置文件路径（可选）
	Verbose     bool   `json:"verbose"`     // 详细输出模式
	OutputFile  string `json:"output_file"` // 输出文件路径
}

// NewConfig 创建默认配置
func NewConfig() *Config {
	return &Config{
		Target:     "localhost:22",
		Verbose:    false,
		OutputFile: "ssh_audit_report.html",
	}
}