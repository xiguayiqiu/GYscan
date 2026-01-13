package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Global    GlobalConfig    `json:"global"`
	Scan      ScanConfig      `json:"scan"`
	Output    OutputConfig    `json:"output"`
	Proxy     ProxyConfig     `json:"proxy"`
	RateLimit RateLimitConfig `json:"rate_limit"`
}

type GlobalConfig struct {
	Version   string `json:"version"`
	Timeout   int    `json:"timeout"`
	Retries   int    `json:"retries"`
	Workers   int    `json:"workers"`
	UserAgent string `json:"user_agent"`
	NoBanner  bool   `json:"no_banner"`
	NoColor   bool   `json:"no_color"`
	Silent    bool   `json:"silent"`
	Verbose   bool   `json:"verbose"`
}

type ScanConfig struct {
	PortRange   string `json:"port_range"`
	CommonPorts []int  `json:"common_ports"`
	Timeout     int    `json:"timeout"`
	Concurrent  int    `json:"concurrent"`
	RateLimit   int    `json:"rate_limit"`
}

type OutputConfig struct {
	Format     string `json:"format"`
	OutputFile string `json:"output_file"`
	JSONIndent int    `json:"json_indent"`
}

type ProxyConfig struct {
	HTTP       string `json:"http"`
	HTTPS      string `json:"https"`
	SOCKS5     string `json:"socks5"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	SkipVerify bool   `json:"skip_verify"`
}

type RateLimitConfig struct {
	RequestsPerSecond int `json:"requests_per_second"`
	Burst             int `json:"burst"`
	ConnectionTimeout int `json:"connection_timeout"`
	ReadTimeout       int `json:"read_timeout"`
}

var AppConfig *Config

func GetConfigPath() string {
	var configDir string

	// 优先使用用户主目录下的配置文件夹，避免权限问题
	homeDir, err := os.UserHomeDir()
	if err == nil {
		configDir = filepath.Join(homeDir, ".GYscan", "config")
	} else {
		// 回退到当前目录
		configDir = "./GYscan/config"
	}

	os.MkdirAll(configDir, 0755)
	return filepath.Join(configDir, "config.json")
}

func LoadConfig() (*Config, error) {
	configPath := GetConfigPath()

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := DefaultConfig()
		if err := SaveConfig(defaultConfig); err != nil {
			return defaultConfig, fmt.Errorf("保存默认配置失败: %v", err)
		}
		return defaultConfig, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	loadFromEnv(&config)
	return &config, nil
}

func loadFromEnv(cfg *Config) {
	if v := os.Getenv("GYSCAN_TIMEOUT"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.Global.Timeout = val
		}
	}
	if v := os.Getenv("GYSCAN_RETRIES"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.Global.Retries = val
		}
	}
	if v := os.Getenv("GYSCAN_WORKERS"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.Global.Workers = val
		}
	}
	if v := os.Getenv("GYSCAN_PROXY"); v != "" {
		cfg.Proxy.HTTP = v
	}
	if v := os.Getenv("GYSCAN_USER_AGENT"); v != "" {
		cfg.Global.UserAgent = v
	}
	if v := os.Getenv("GYSCAN_RATE_LIMIT"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.RequestsPerSecond = val
		}
	}
	if v := os.Getenv("GYSCAN_SILENT"); v != "" {
		cfg.Global.Silent = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("GYSCAN_VERBOSE"); v != "" {
		cfg.Global.Verbose = strings.ToLower(v) == "true"
	}
}

func SaveConfig(config *Config) error {
	configPath := GetConfigPath()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}
	// 使用 0600 权限，仅文件所有者可读写，保护敏感配置信息
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}
	return nil
}

func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			Version:   "v2.7",
			Timeout:   30,
			Retries:   3,
			Workers:   10,
			UserAgent: "GYscan/v2.7",
			NoBanner:  false,
			NoColor:   false,
			Silent:    false,
			Verbose:   false,
		},
		Scan: ScanConfig{
			PortRange:   "1-65535",
			CommonPorts: []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443},
			Timeout:     3,
			Concurrent:  100,
			RateLimit:   1000,
		},
		Output: OutputConfig{
			Format:     "text",
			OutputFile: "",
			JSONIndent: 2,
		},
		Proxy: ProxyConfig{
			HTTP:       "",
			HTTPS:      "",
			SOCKS5:     "",
			Username:   "",
			Password:   "",
			SkipVerify: false,
		},
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 500,
			Burst:             20,
			ConnectionTimeout: 10,
			ReadTimeout:       30,
		},
	}
}

func InitConfig() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %v", err)
	}

	AppConfig = cfg
	return nil
}

// Validate 验证配置的有效性
func (c *Config) Validate() error {
	if c.Global.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %d", c.Global.Timeout)
	}
	if c.Global.Retries < 0 {
		return fmt.Errorf("retries must be non-negative, got %d", c.Global.Retries)
	}
	if c.Global.Workers <= 0 {
		return fmt.Errorf("workers must be positive, got %d", c.Global.Workers)
	}
	if c.Scan.Timeout <= 0 {
		return fmt.Errorf("scan timeout must be positive, got %d", c.Scan.Timeout)
	}
	if c.Scan.Concurrent <= 0 {
		return fmt.Errorf("scan concurrent must be positive, got %d", c.Scan.Concurrent)
	}
	if c.Scan.RateLimit <= 0 {
		return fmt.Errorf("scan rate limit must be positive, got %d", c.Scan.RateLimit)
	}
	if c.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate limit requests per second must be positive, got %d", c.RateLimit.RequestsPerSecond)
	}
	if c.RateLimit.Burst <= 0 {
		return fmt.Errorf("rate limit burst must be positive, got %d", c.RateLimit.Burst)
	}
	if c.RateLimit.ConnectionTimeout <= 0 {
		return fmt.Errorf("connection timeout must be positive, got %d", c.RateLimit.ConnectionTimeout)
	}
	if c.RateLimit.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive, got %d", c.RateLimit.ReadTimeout)
	}

	for _, port := range c.Scan.CommonPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
		}
	}

	return nil
}

func GetGlobalConfig() *GlobalConfig {
	if AppConfig == nil {
		return &DefaultConfig().Global
	}
	return &AppConfig.Global
}

func GetScanConfig() *ScanConfig {
	if AppConfig == nil {
		return &DefaultConfig().Scan
	}
	return &AppConfig.Scan
}

func GetProxyConfig() *ProxyConfig {
	if AppConfig == nil {
		return &DefaultConfig().Proxy
	}
	return &AppConfig.Proxy
}

func GetRateLimitConfig() *RateLimitConfig {
	if AppConfig == nil {
		return &DefaultConfig().RateLimit
	}
	return &AppConfig.RateLimit
}
