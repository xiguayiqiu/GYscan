package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

// MSSQLCracker MSSQL数据库破解器
type MSSQLCracker struct {
	*BaseCracker
}

// NewMSSQLCracker 创建MSSQL破解器
func NewMSSQLCracker() *MSSQLCracker {
	return &MSSQLCracker{
		BaseCracker: NewBaseCracker("MSSQL"),
	}
}

// TestConnection 测试MSSQL连接
func (m *MSSQLCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()

	// 构建连接字符串
	dsn := config.GetConnectionString()

	// 尝试连接
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return fmt.Errorf("failed to open MSSQL connection: %v", err)
	}
	defer db.Close()

	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(config.Timeout) * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// 测试连接
	err = db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("MSSQL authentication failed: %v", err)
	}

	return nil
}

// Crack 执行MSSQL破解
func (m *MSSQLCracker) Crack(ctx context.Context, config *DatabaseConfig,
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {

	// 创建破解工作器
	worker := NewCrackWorker(config, m, usernames, passwords, progress)

	// 运行破解
	results := worker.Run(ctx, config.Threads)

	return results, nil
}

// MSSQLProtocolCracker MSSQL协议级破解器
type MSSQLProtocolCracker struct {
	*BaseCracker
}

// NewMSSQLProtocolCracker 创建MSSQL协议级破解器
func NewMSSQLProtocolCracker() *MSSQLProtocolCracker {
	return &MSSQLProtocolCracker{
		BaseCracker: NewBaseCracker("MSSQL Protocol"),
	}
}

// TestConnection 测试MSSQL协议连接
func (m *MSSQLProtocolCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()

	// 使用TCP连接进行协议级认证
	err := m.mssqlProtocolAuth(ctx, config)
	if err != nil {
		return fmt.Errorf("MSSQL protocol authentication failed: %v", err)
	}

	return nil
}

// mssqlProtocolAuth MSSQL协议级认证
func (m *MSSQLProtocolCracker) mssqlProtocolAuth(ctx context.Context, config *DatabaseConfig) error {
	// 这里实现MSSQL TDS协议握手和认证
	// 由于复杂度较高，这里先使用数据库驱动的方式
	// 实际实现需要解析MSSQL TDS协议包

	// 临时使用数据库驱动方式
	dsn := config.GetConnectionString()
	db, err := sql.Open("sqlserver", dsn)
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

// Crack 执行MSSQL协议破解
func (m *MSSQLProtocolCracker) Crack(ctx context.Context, config *DatabaseConfig,
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {

	// 创建破解工作器
	worker := NewCrackWorker(config, m, usernames, passwords, progress)

	// 运行破解
	results := worker.Run(ctx, config.Threads)

	return results, nil
}

// MSSQLCrackerFactory MSSQL破解器工厂
func MSSQLCrackerFactory(useProtocol bool) DatabaseCracker {
	if useProtocol {
		return NewMSSQLProtocolCracker()
	}
	return NewMSSQLCracker()
}
