package database

// 数据库破解模块初始化

import (
	"log"
)

// Init 初始化数据库破解模块
func Init() {
	log.Println("数据库破解模块已初始化")
}

// GetSupportedDatabases 获取支持的数据库类型
func GetSupportedDatabases() []DatabaseType {
	return []DatabaseType{
		MySQL,
		PostgreSQL,
		MSSQL,
		Oracle,
	}
}

// GetDefaultPort 获取数据库默认端口
func GetDefaultPort(dbType DatabaseType) int {
	switch dbType {
	case MySQL:
		return 3306
	case PostgreSQL:
		return 5432
	case MSSQL:
		return 1433
	case Oracle:
		return 1521
	default:
		return 0
	}
}

// ValidateDatabaseType 验证数据库类型
func ValidateDatabaseType(dbType string) bool {
	switch DatabaseType(dbType) {
	case MySQL, PostgreSQL, MSSQL, Oracle:
		return true
	default:
		return false
	}
}