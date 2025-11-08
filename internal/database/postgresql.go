package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PostgreSQLCracker PostgreSQL数据库破解器
type PostgreSQLCracker struct {
	*BaseCracker
}

// NewPostgreSQLCracker 创建PostgreSQL破解器
func NewPostgreSQLCracker() *PostgreSQLCracker {
	return &PostgreSQLCracker{
		BaseCracker: NewBaseCracker("PostgreSQL"),
	}
}

// TestConnection 测试PostgreSQL连接
func (p *PostgreSQLCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 构建连接字符串
	dsn := config.GetConnectionString()
	
	// 尝试连接
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to open PostgreSQL connection: %v", err)
	}
	defer db.Close()
	
	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(config.Timeout) * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	
	// 测试连接
	err = db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("PostgreSQL authentication failed: %v", err)
	}
	
	return nil
}

// Crack 执行PostgreSQL破解
func (p *PostgreSQLCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, p, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// PostgreSQLProtocolCracker PostgreSQL协议级破解器
type PostgreSQLProtocolCracker struct {
	*BaseCracker
}

// NewPostgreSQLProtocolCracker 创建PostgreSQL协议级破解器
func NewPostgreSQLProtocolCracker() *PostgreSQLProtocolCracker {
	return &PostgreSQLProtocolCracker{
		BaseCracker: NewBaseCracker("PostgreSQL Protocol"),
	}
}

// TestConnection 测试PostgreSQL协议连接
func (p *PostgreSQLProtocolCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 使用TCP连接进行协议级认证
	err := p.postgresProtocolAuth(ctx, config)
	if err != nil {
		return fmt.Errorf("PostgreSQL protocol authentication failed: %v", err)
	}
	
	return nil
}

// postgresProtocolAuth PostgreSQL协议级认证
func (p *PostgreSQLProtocolCracker) postgresProtocolAuth(ctx context.Context, config *DatabaseConfig) error {
	// 这里实现PostgreSQL协议握手和认证
	// 由于复杂度较高，这里先使用数据库驱动的方式
	// 实际实现需要解析PostgreSQL协议包
	
	// 临时使用数据库驱动方式
	dsn := config.GetConnectionString()
	db, err := sql.Open("postgres", dsn)
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

// Crack 执行PostgreSQL协议破解
func (p *PostgreSQLProtocolCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, p, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// PostgreSQLCrackerFactory PostgreSQL破解器工厂
func PostgreSQLCrackerFactory(useProtocol bool) DatabaseCracker {
	if useProtocol {
		return NewPostgreSQLProtocolCracker()
	}
	return NewPostgreSQLCracker()
}