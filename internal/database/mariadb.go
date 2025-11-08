package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql" // MariaDB使用MySQL驱动
)

// MariaDBCracker MariaDB数据库破解器
type MariaDBCracker struct {
	*BaseCracker
}

// NewMariaDBCracker 创建MariaDB破解器
func NewMariaDBCracker() *MariaDBCracker {
	return &MariaDBCracker{
		BaseCracker: NewBaseCracker("MariaDB"),
	}
}

// TestConnection 测试MariaDB连接
func (m *MariaDBCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 构建MariaDB连接字符串
	dsn := m.getMariaDBConnectionString(config)
	
	// 尝试连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open MariaDB connection: %v", err)
	}
	defer db.Close()
	
	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(config.Timeout) * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	
	// 测试连接
	err = db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("MariaDB authentication failed: %v", err)
	}
	
	return nil
}

// Crack 执行MariaDB破解
func (m *MariaDBCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, m, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// getMariaDBConnectionString 构建MariaDB连接字符串
func (m *MariaDBCracker) getMariaDBConnectionString(config *DatabaseConfig) string {
	// MariaDB使用与MySQL相同的连接格式
	// 格式: username:password@tcp(host:port)/database
	
	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Database)
	
	// 添加连接参数
	params := ""
	
	// 设置字符集
	params += "charset=utf8mb4&"
	
	// 设置时区
	params += "loc=Local&"
	
	// 设置解析时间
	params += "parseTime=true&"
	
	// 设置超时
	params += fmt.Sprintf("timeout=%ds&", config.Timeout)
	
	// 设置读写超时
	params += fmt.Sprintf("readTimeout=%ds&writeTimeout=%ds", 
		config.Timeout, config.Timeout)
	
	if params != "" {
		connectionString += "?" + params
	}
	
	return connectionString
}

// MariaDBProtocolCracker MariaDB协议级破解器（直接TCP连接）
type MariaDBProtocolCracker struct {
	*BaseCracker
}

// NewMariaDBProtocolCracker 创建MariaDB协议级破解器
func NewMariaDBProtocolCracker() *MariaDBProtocolCracker {
	return &MariaDBProtocolCracker{
		BaseCracker: NewBaseCracker("MariaDB Protocol"),
	}
}

// TestConnection 测试MariaDB协议连接
func (m *MariaDBProtocolCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 使用TCP连接进行协议级认证
	err := m.mariadbProtocolAuth(ctx, config)
	if err != nil {
		return fmt.Errorf("MariaDB protocol authentication failed: %v", err)
	}
	
	return nil
}

// mariadbProtocolAuth MariaDB协议级认证
func (m *MariaDBProtocolCracker) mariadbProtocolAuth(ctx context.Context, config *DatabaseConfig) error {
	// MariaDB协议与MySQL协议高度兼容
	// 这里实现MariaDB协议握手和认证
	// 由于复杂度较高，这里先使用数据库驱动的方式
	// 实际实现需要解析MySQL/MariaDB协议包
	
	// 临时使用数据库驱动方式
	dsn := m.getMariaDBConnectionString(config)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	
	err = db.PingContext(ctx)
	if err != nil {
		return err
	}
	
	return nil
}

// Crack 执行MariaDB协议破解
func (m *MariaDBProtocolCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, m, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// getMariaDBConnectionString 构建MariaDB连接字符串（协议级版本）
func (m *MariaDBProtocolCracker) getMariaDBConnectionString(config *DatabaseConfig) string {
	// 与标准版本相同
	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
		config.Database)
	
	// 添加连接参数
	params := ""
	
	// 设置字符集
	params += "charset=utf8mb4&"
	
	// 设置时区
	params += "loc=Local&"
	
	// 设置解析时间
	params += "parseTime=true&"
	
	// 设置超时
	params += fmt.Sprintf("timeout=%ds&", config.Timeout)
	
	// 设置读写超时
	params += fmt.Sprintf("readTimeout=%ds&writeTimeout=%ds", 
		config.Timeout, config.Timeout)
	
	if params != "" {
		connectionString += "?" + params
	}
	
	return connectionString
}

// MariaDBCrackerFactory MariaDB破解器工厂
func MariaDBCrackerFactory(useProtocol bool) DatabaseCracker {
	if useProtocol {
		return NewMariaDBProtocolCracker()
	}
	return NewMariaDBCracker()
}