package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/godror/godror"
)

// OracleCracker Oracle数据库破解器
type OracleCracker struct {
	*BaseCracker
}

// NewOracleCracker 创建Oracle破解器
func NewOracleCracker() *OracleCracker {
	return &OracleCracker{
		BaseCracker: NewBaseCracker("Oracle"),
	}
}

// TestConnection 测试Oracle连接
func (o *OracleCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 构建连接字符串
	dsn := GetOracleConnectionString(config)
	
	// 尝试连接
	db, err := sql.Open("godror", dsn)
	if err != nil {
		return fmt.Errorf("failed to open Oracle connection: %v", err)
	}
	defer db.Close()
	
	// 设置连接参数
	db.SetConnMaxLifetime(time.Duration(config.Timeout) * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	
	// 测试连接
	err = db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("Oracle authentication failed: %v", err)
	}
	
	return nil
}

// Crack 执行Oracle破解
func (o *OracleCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, o, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// OracleProtocolCracker Oracle协议级破解器（直接TCP连接）
type OracleProtocolCracker struct {
	*BaseCracker
}

// NewOracleProtocolCracker 创建Oracle协议级破解器
func NewOracleProtocolCracker() *OracleProtocolCracker {
	return &OracleProtocolCracker{
		BaseCracker: NewBaseCracker("Oracle Protocol"),
	}
}

// TestConnection 测试Oracle协议连接
func (o *OracleProtocolCracker) TestConnection(ctx context.Context, config *DatabaseConfig) error {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()
	
	// 使用TCP连接进行协议级认证
	err := o.oracleProtocolAuth(ctx, config)
	if err != nil {
		return fmt.Errorf("Oracle protocol authentication failed: %v", err)
	}
	
	return nil
}

// oracleProtocolAuth Oracle协议级认证
func (o *OracleProtocolCracker) oracleProtocolAuth(ctx context.Context, config *DatabaseConfig) error {
	// 这里实现Oracle协议握手和认证
	// 由于复杂度较高，这里先使用数据库驱动的方式
	// 实际实现需要解析Oracle协议包
	
	// 临时使用数据库驱动方式
	dsn := GetOracleConnectionString(config)
	db, err := sql.Open("godror", dsn)
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

// Crack 执行Oracle协议破解
func (o *OracleProtocolCracker) Crack(ctx context.Context, config *DatabaseConfig, 
	usernames, passwords []string, progress ProgressCallback) ([]CrackResult, error) {
	
	// 创建破解工作器
	worker := NewCrackWorker(config, o, usernames, passwords, progress)
	
	// 运行破解
	results := worker.Run(ctx, config.Threads)
	
	return results, nil
}

// OracleCrackerFactory Oracle破解器工厂
func OracleCrackerFactory(useProtocol bool) DatabaseCracker {
	if useProtocol {
		return NewOracleProtocolCracker()
	}
	return NewOracleCracker()
}

// GetOracleConnectionString 获取Oracle连接字符串
func GetOracleConnectionString(config *DatabaseConfig) string {
	// Oracle连接字符串格式: user/password@host:port/service_name
	var dsn strings.Builder
	
	if config.Username != "" {
		dsn.WriteString(config.Username)
		if config.Password != "" {
			dsn.WriteString("/")
			dsn.WriteString(config.Password)
		}
		dsn.WriteString("@")
	}
	
	dsn.WriteString(config.Host)
	if config.Port > 0 {
		dsn.WriteString(fmt.Sprintf(":%d", config.Port))
	}
	
	if config.Database != "" {
		dsn.WriteString("/")
		dsn.WriteString(config.Database)
	}
	
	return dsn.String()
}