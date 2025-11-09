package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLCracker MySQL数据库破解器
type MySQLCracker struct {
	*BaseCracker
}

// NewMySQLCracker 创建MySQL破解器
func NewMySQLCracker() *MySQLCracker {
	return &MySQLCracker{
		BaseCracker: NewBaseCracker("MySQL"),
	}
}

// TestConnection 测试MySQL连接
func (m *MySQLCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 构建连接字符串
	dsn := config.GetConnectionString()
	
	// 尝试连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open MySQL connection: %v", err)
	}
	defer db.Close()
	
	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(config.Timeout) * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	
	// 测试连接
	err = db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("MySQL authentication failed: %v", err)
	}
	
	return nil
}

// Crack 执行MySQL破解
func (m *MySQLCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, m, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// MySQLProtocolCracker MySQL协议级破解器（直接TCP连接）
type MySQLProtocolCracker struct {
	*BaseCracker
}

// NewMySQLProtocolCracker 创建MySQL协议级破解器
func NewMySQLProtocolCracker() *MySQLProtocolCracker {
	return &MySQLProtocolCracker{
		BaseCracker: NewBaseCracker("MySQL Protocol"),
	}
}

// TestConnection 测试MySQL协议连接
func (m *MySQLProtocolCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 使用TCP连接进行协议级认证
	err := m.mysqlProtocolAuth(ctx, config)
	if err != nil {
		return fmt.Errorf("MySQL protocol authentication failed: %v", err)
	}
	
	return nil
}

// mysqlProtocolAuth MySQL协议级认证
func (m *MySQLProtocolCracker) mysqlProtocolAuth(ctx context.Context, config *DatabaseConfig) error {
	// 这里实现MySQL协议握手和认证
	// 由于复杂度较高，这里先使用数据库驱动的方式
	// 实际实现需要解析MySQL协议包
	
	// 临时使用数据库驱动方式
	dsn := config.GetConnectionString()
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

// Crack 执行MySQL协议破解
func (m *MySQLProtocolCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, m, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// MySQLCrackerFactory MySQL破解器工厂
func MySQLCrackerFactory(useProtocol bool) DatabaseCracker {
	if useProtocol {
		return NewMySQLProtocolCracker()
	}
	return NewMySQLCracker()
}