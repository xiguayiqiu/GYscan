package database

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DatabaseType 定义支持的数据库类型
type DatabaseType string

const (
	MySQL      DatabaseType = "mysql"
	PostgreSQL DatabaseType = "postgres"
	MSSQL      DatabaseType = "mssql"
	Oracle     DatabaseType = "oracle"
	MariaDB    DatabaseType = "mariadb"
)

// DatabaseConfig 数据库连接配置
type DatabaseConfig struct {
	Type     DatabaseType
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSL      bool
	Timeout  int
	Threads  int
}

// NewDatabaseConfig 创建数据库配置
func NewDatabaseConfig(dbType DatabaseType, host string, port int) *DatabaseConfig {
	return &DatabaseConfig{
		Type:    dbType,
		Host:    host,
		Port:    port,
		SSL:     false,
		Timeout: 10,
		Threads: 5,
	}
}

// Validate 验证配置参数
func (c *DatabaseConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Port)
	}

	if c.Threads <= 0 {
		return fmt.Errorf("threads must be greater than 0")
	}

	return nil
}

// GetConnectionString 获取数据库连接字符串
func (c *DatabaseConfig) GetConnectionString() string {
	switch c.Type {
	case MySQL:
		return c.getMySQLConnectionString()
	case PostgreSQL:
		return c.getPostgreSQLConnectionString()
	case MSSQL:
		return c.getMSSQLConnectionString()
	case Oracle:
		return c.getOracleConnectionString()
	case MariaDB:
		return c.getMariaDBConnectionString()
	default:
		return ""
	}
}

func (c *DatabaseConfig) getMySQLConnectionString() string {
	params := []string{}

	if c.SSL {
		params = append(params, "tls=true")
	}

	if c.Timeout > 0 {
		params = append(params, fmt.Sprintf("timeout=%ds", c.Timeout))
	}

	paramStr := ""
	if len(params) > 0 {
		paramStr = "?" + strings.Join(params, "&")
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s%s",
		c.Username, c.Password, c.Host, c.Port, c.Database, paramStr)
}

func (c *DatabaseConfig) getPostgreSQLConnectionString() string {
	params := []string{}

	if c.SSL {
		params = append(params, "sslmode=require")
	} else {
		params = append(params, "sslmode=disable")
	}

	if c.Timeout > 0 {
		params = append(params, fmt.Sprintf("connect_timeout=%d", c.Timeout))
	}

	paramStr := ""
	if len(params) > 0 {
		paramStr = "?" + strings.Join(params, "&")
	}

	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s%s",
		c.Host, c.Port, c.Username, c.Password, c.Database, paramStr)
}

func (c *DatabaseConfig) getMSSQLConnectionString() string {
	params := []string{}

	if c.Timeout > 0 {
		params = append(params, fmt.Sprintf("connection timeout=%d", c.Timeout))
	}

	paramStr := ""
	if len(params) > 0 {
		paramStr = "?" + strings.Join(params, "&")
	}

	return fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;database=%s%s",
		c.Host, c.Port, c.Username, c.Password, c.Database, paramStr)
}

func (c *DatabaseConfig) getOracleConnectionString() string {
	return fmt.Sprintf("%s/%s@%s:%d/%s",
		c.Username, c.Password, c.Host, c.Port, c.Database)
}

func (c *DatabaseConfig) getMariaDBConnectionString() string {
	// MariaDB使用与MySQL相同的连接格式
	params := []string{}

	if c.SSL {
		params = append(params, "tls=true")
	}

	if c.Timeout > 0 {
		params = append(params, fmt.Sprintf("timeout=%ds", c.Timeout))
	}

	// 添加MariaDB特定参数
	params = append(params, "charset=utf8mb4")
	params = append(params, "parseTime=true")

	paramStr := ""
	if len(params) > 0 {
		paramStr = "?" + strings.Join(params, "&")
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s%s",
		c.Username, c.Password, c.Host, c.Port, c.Database, paramStr)
}

// ParseTarget 解析目标地址
func ParseTarget(target string) (string, int, error) {
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return "", 0, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}

		return host, port, nil
	}

	// 默认端口
	return target, getDefaultPort(""), nil
}

// getDefaultPort 获取数据库默认端口
func getDefaultPort(dbType string) int {
	switch strings.ToLower(dbType) {
	case "mysql":
		return 3306
	case "postgres", "postgresql":
		return 5432
	case "mssql", "sqlserver":
		return 1433
	case "oracle":
		return 1521
	case "mariadb":
		return 3306
	default:
		return 0
	}
}
