package cli

import (
	"fmt"
	"GYscan/internal/persistence"

	"github.com/spf13/cobra"
)

var (
	persistenceConfig = &persistence.PersistenceConfig{}

	// persistenceCmd 持久化技术主命令
	persistenceCmd = &cobra.Command{
		Use:   "persistence",
		Short: "持久化技术模块 [测试阶段]",
		Long:  `提供多种Windows持久化技术的实现，包括启动项、注册表、WMI事件订阅、计划任务和服务等。[测试阶段]`,
	}

	// createPersistenceCmd 创建持久化命令
	createPersistenceCmd = &cobra.Command{
		Use:   "create",
		Short: "创建持久化",
		Long:  `使用指定的技术在目标系统上创建持久化机制。`,
		Run:   executeCreatePersistence,
	}

	// removePersistenceCmd 移除持久化命令
	removePersistenceCmd = &cobra.Command{
		Use:   "remove",
		Short: "移除持久化",
		Long:  `移除之前创建的持久化机制。`,
		Run:   executeRemovePersistence,
	}

	// listPersistenceCmd 列出支持的持久化技术命令
	listPersistenceCmd = &cobra.Command{
		Use:   "list",
		Short: "列出支持的持久化技术",
		Long:  `显示所有支持的持久化技术。`,
		Run:   executeListPersistenceTechniques,
	}
)

func init() {
	// 将持久化命令添加到根命令
	// rootCmd.AddCommand(persistenceCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理

	// 添加子命令
	persistenceCmd.AddCommand(createPersistenceCmd)
	persistenceCmd.AddCommand(removePersistenceCmd)
	persistenceCmd.AddCommand(listPersistenceCmd)

	// 通用参数
	persistenceCmd.PersistentFlags().StringVarP(&persistenceConfig.Target, "target", "t", "localhost", "目标主机地址")
	persistenceCmd.PersistentFlags().StringVarP(&persistenceConfig.Username, "username", "u", "", "用户名（用于远程连接）")
	persistenceCmd.PersistentFlags().StringVarP(&persistenceConfig.Password, "password", "p", "", "密码（用于远程连接）")
	persistenceCmd.PersistentFlags().StringVarP(&persistenceConfig.Technique, "technique", "m", "", "持久化技术类型")

	// 创建持久化特定参数
	createPersistenceCmd.Flags().StringVarP(&persistenceConfig.PayloadPath, "payload", "f", "", "payload文件路径（必需）")
	createPersistenceCmd.Flags().StringVarP(&persistenceConfig.ServiceName, "service-name", "s", "SysUpdateService", "服务名称（适用于service技术）")
	createPersistenceCmd.Flags().StringVarP(&persistenceConfig.TaskName, "task-name", "n", "SystemMaintenance", "计划任务名称（适用于scheduledtask技术）")
	createPersistenceCmd.Flags().StringVarP(&persistenceConfig.Description, "description", "d", "", "描述信息")
	createPersistenceCmd.Flags().StringVarP(&persistenceConfig.Interval, "interval", "i", "", "执行间隔（适用于scheduledtask和wmi技术）")

	// 移除持久化特定参数
	removePersistenceCmd.Flags().StringVarP(&persistenceConfig.ServiceName, "service-name", "s", "SysUpdateService", "服务名称（适用于service技术）")
	removePersistenceCmd.Flags().StringVarP(&persistenceConfig.TaskName, "task-name", "n", "SystemMaintenance", "计划任务名称（适用于scheduledtask技术）")

	// 移除自动参数验证，改用手动验证（在执行函数中实现）
}

// executeCreatePersistence 执行创建持久化操作
func executeCreatePersistence(cmd *cobra.Command, args []string) {
	// 参数验证
	if persistenceConfig.Technique == "" {
		fmt.Println("[错误] 必须指定持久化技术类型 (--technique)")
		return
	}
	if persistenceConfig.PayloadPath == "" {
		fmt.Println("[错误] 必须指定payload文件路径 (--payload)")
		return
	}

	// 验证技术类型
	supportedTechniques := persistence.ListPersistenceTechniques()
	supported := false
	for _, tech := range supportedTechniques {
		if persistenceConfig.Technique == tech {
			supported = true
			break
		}
	}

	if !supported {
		fmt.Printf("不支持的持久化技术: %s\n", persistenceConfig.Technique)
		fmt.Println("支持的技术: startup, registry, wmi, scheduledtask, service")
		return
	}

	// 创建客户端并执行
	client := persistence.NewPersistenceClient(persistenceConfig)
	result, err := client.CreatePersistence()
	if err != nil {
		fmt.Printf("创建持久化失败: %v\n", err)
		return
	}

	// 输出结果
	if result.Success {
		fmt.Printf("持久化创建成功!\n技术类型: %s\n详情: %s\n", result.Technique, result.Message)
	} else {
		fmt.Printf("持久化创建失败!\n技术类型: %s\n错误信息: %s\n", result.Technique, result.Message)
	}
}

// executeRemovePersistence 执行移除持久化操作
func executeRemovePersistence(cmd *cobra.Command, args []string) {
	// 参数验证
	if persistenceConfig.Technique == "" {
		fmt.Println("[错误] 必须指定持久化技术类型 (--technique)")
		return
	}

	// 验证技术类型
	supportedTechniques := persistence.ListPersistenceTechniques()
	supported := false
	for _, tech := range supportedTechniques {
		if persistenceConfig.Technique == tech {
			supported = true
			break
		}
	}

	if !supported {
		fmt.Printf("不支持的持久化技术: %s\n", persistenceConfig.Technique)
		fmt.Println("支持的技术: startup, registry, wmi, scheduledtask, service")
		return
	}

	// 创建客户端并执行
	client := persistence.NewPersistenceClient(persistenceConfig)
	result, err := client.RemovePersistence()
	if err != nil {
		fmt.Printf("移除持久化失败: %v\n", err)
		return
	}

	// 输出结果
	if result.Success {
		fmt.Printf("持久化移除成功!\n技术类型: %s\n详情: %s\n", result.Technique, result.Message)
	} else {
		fmt.Printf("持久化移除失败!\n技术类型: %s\n错误信息: %s\n", result.Technique, result.Message)
	}
}

// executeListPersistenceTechniques 执行列出支持的持久化技术操作
func executeListPersistenceTechniques(cmd *cobra.Command, args []string) {
	fmt.Println("支持的持久化技术:")
	fmt.Println()

	// 技术列表和描述
	techniques := map[string]string{
		"startup":        "启动文件夹 - 将程序添加到用户启动文件夹",
		"registry":       "注册表自启动项 - 添加注册表Run键值",
		"wmi":           "WMI事件订阅 - 创建WMI事件过滤器和消费者",
		"scheduledtask": "计划任务 - 创建定期执行的计划任务",
		"service":       "Windows服务 - 创建并配置自动启动服务",
	}

	// 遍历并显示每个技术
	for tech, desc := range techniques {
		fmt.Printf("  %-15s %s\n", tech, desc)
	}

	fmt.Println()
	fmt.Println("使用示例:")
	fmt.Println("  gyscan persistence create --technique registry --payload C:\\path\\to\\payload.exe")
	fmt.Println("  gyscan persistence create --technique service --payload C:\\path\\to\\payload.exe --service-name MyService")
	fmt.Println("  gyscan persistence remove --technique registry")
}