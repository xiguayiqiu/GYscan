package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"GYscan/internal/database"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// databaseCmd 数据库破解命令
var databaseCmd = &cobra.Command{
	Use:   "database [target] [options]",
	Short: "数据库密码破解工具",
	Long: `数据库密码破解工具 - 支持MySQL、PostgreSQL、MSSQL、Oracle、MariaDB等数据库

支持功能:
- 多线程并发破解
- 用户名/密码字典攻击
- 协议级认证测试
- 实时进度显示

使用示例:
  ./GYscan database mysql://192.168.1.100:3306 -u user.txt -p pass.txt
  ./GYscan database postgres://192.168.1.101:5432 -u admin -p top100.txt
  ./GYscan database mssql://192.168.1.102:1433 -u user.txt -p pass.txt -t 10
  ./GYscan database oracle://192.168.1.103:1521 -u scott -p tiger -d orcl
  ./GYscan database mariadb://192.168.1.104:3306 -u root -p password.txt -d test

警告: 仅用于授权测试，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 解析参数
		target, _ := cmd.Flags().GetString("target")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		dbName, _ := cmd.Flags().GetString("database")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		ssl, _ := cmd.Flags().GetBool("ssl")
		protocol, _ := cmd.Flags().GetBool("protocol")

		// 如果提供了位置参数，优先使用位置参数
		if len(args) > 0 && target == "" {
			target = args[0]
		}

		// 验证参数
		if target == "" {
			utils.ErrorPrint("目标地址不能为空")
			cmd.Help()
			return
		}

		if username == "" {
			utils.ErrorPrint("用户名或用户字典文件不能为空")
			cmd.Help()
			return
		}

		if password == "" {
			utils.ErrorPrint("密码或密码字典文件不能为空")
			cmd.Help()
			return
		}

		// 执行数据库破解
		err := runDatabaseCrack(target, username, password, dbName, threads, timeout, ssl, protocol)
		if err != nil {
			utils.ErrorPrint("数据库破解失败: %v", err)
			os.Exit(1)
		}
	},
}

// runDatabaseCrack 执行数据库破解
func runDatabaseCrack(target, username, password, dbName string, threads, timeout int, ssl, protocol bool) error {
	// 解析目标地址
	dbType, host, port, err := parseDatabaseTarget(target)
	if err != nil {
		return fmt.Errorf("解析目标地址失败: %v", err)
	}

	// 加载用户名列表
	usernames, err := loadCredentials(username)
	if err != nil {
		return fmt.Errorf("加载用户名列表失败: %v", err)
	}

	// 加载密码列表
	passwords, err := loadCredentials(password)
	if err != nil {
		return fmt.Errorf("加载密码列表失败: %v", err)
	}

	// 创建数据库配置
	config := database.NewDatabaseConfig(dbType, host, port)
	config.Username = "" // 将在破解过程中设置
	config.Password = "" // 将在破解过程中设置
	config.Database = dbName
	config.SSL = ssl
	config.Timeout = timeout
	config.Threads = threads

	// 创建破解管理器
	manager := database.NewCrackManager()
	
	// 注册破解器
	manager.RegisterCracker(database.MySQL, database.MySQLCrackerFactory(protocol))
	manager.RegisterCracker(database.PostgreSQL, database.PostgreSQLCrackerFactory(protocol))
	manager.RegisterCracker(database.MSSQL, database.MSSQLCrackerFactory(protocol))
	manager.RegisterCracker(database.Oracle, database.OracleCrackerFactory(protocol))
	manager.RegisterCracker(database.MariaDB, database.MariaDBCrackerFactory(protocol))

	utils.InfoPrint("开始数据库破解...")
	utils.InfoPrint("目标: %s://%s:%d", dbType, host, port)
	utils.InfoPrint("用户名数量: %d", len(usernames))
	utils.InfoPrint("密码数量: %d", len(passwords))
	utils.InfoPrint("线程数: %d", threads)
	utils.InfoPrint("超时时间: %d秒", timeout)
	utils.InfoPrint("")

	// 创建上下文
	ctx := context.Background()

	// 进度回调函数
	progress := func(current, total, found int) {
		if current%100 == 0 || current == total {
			percent := float64(current) / float64(total) * 100
			utils.InfoPrint("进度: %d/%d (%.1f%%) - 成功: %d", current, total, percent, found)
		}
	}

	// 执行破解
	startTime := time.Now()
	results, err := manager.Crack(ctx, config, usernames, passwords, progress)
	if err != nil {
		return err
	}

	// 显示结果
	duration := time.Since(startTime)
	utils.InfoPrint("")
	utils.InfoPrint("破解完成! 耗时: %v", duration)
	
	database.PrintResults(results)

	return nil
}

// parseDatabaseTarget 解析数据库目标地址
func parseDatabaseTarget(target string) (database.DatabaseType, string, int, error) {
	// 支持格式: mysql://host:port, postgres://host:port, mssql://host:port, oracle://host:port, mariadb://host:port
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) != 2 {
			return "", "", 0, fmt.Errorf("无效的目标格式: %s", target)
		}

		dbType := database.DatabaseType(parts[0])
		hostPort := parts[1]

		// 解析主机和端口
		host, port, err := database.ParseTarget(hostPort)
		if err != nil {
			return "", "", 0, err
		}

		// 如果没有指定端口，使用默认端口
		if port == 0 {
			port = getDefaultPort(string(dbType))
		}

		return dbType, host, port, nil
	}

	// 简单格式: host:port (默认MySQL)
	host, port, err := database.ParseTarget(target)
	if err != nil {
		return "", "", 0, err
	}

	if port == 0 {
		port = 3306 // MySQL默认端口
	}

	return database.MySQL, host, port, nil
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
		return 3306 // MariaDB默认使用3306端口
	default:
		return 0
	}
}

// loadCredentials 加载凭据列表（支持文件和直接值）
func loadCredentials(input string) ([]string, error) {
	// 如果是文件路径
	if _, err := os.Stat(input); err == nil {
		return loadFromFile(input)
	}

	// 如果是逗号分隔的值
	if strings.Contains(input, ",") {
		values := strings.Split(input, ",")
		result := make([]string, 0, len(values))
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v != "" {
				result = append(result, v)
			}
		}
		return result, nil
	}

	// 单个值
	return []string{input}, nil
}

// loadFromFile 从文件加载凭据
func loadFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// init 初始化数据库命令
func init() {
	// 添加命令参数
	databaseCmd.Flags().StringP("target", "t", "", "目标数据库地址 (格式: mysql://host:port)")
	databaseCmd.Flags().StringP("username", "u", "", "用户名或用户字典文件")
	databaseCmd.Flags().StringP("password", "p", "", "密码或密码字典文件")
	databaseCmd.Flags().StringP("database", "d", "", "数据库名 (可选)")
	databaseCmd.Flags().IntP("threads", "T", 5, "并发线程数")
	databaseCmd.Flags().Int("timeout", 10, "连接超时时间(秒)")
	databaseCmd.Flags().Bool("ssl", false, "启用SSL连接")
	databaseCmd.Flags().Bool("protocol", false, "使用协议级破解 (高级功能)")
}