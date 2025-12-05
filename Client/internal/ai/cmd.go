package ai

import (
	"fmt"

	"GYscan/internal/ai/config"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// 定义全局变量
var (
	configPath  string
	force       bool
	resourceDir string
	forceScan   bool // 强制全盘扫描标志
)

// AICmd 定义AI主命令
var AICmd = &cobra.Command{
	Use:   "ai",
	Short: "AI模型驱动的渗透测试与安全探测功能 [测试阶段]",
	Long:  `基于AI Agent的自动化网络安全操作，包括渗透测试、安全探测和报告生成。`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// ConfigCmd 定义AI配置命令
var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "AI功能配置管理",
	Long:  `管理AI功能的配置，包括生成默认配置、测试配置和显示配置。`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// ConfigDefaultCmd 定义生成默认配置命令
var ConfigDefaultCmd = &cobra.Command{
	Use:   "default",
	Short: "生成标准YAML格式的默认配置文件",
	Long:  `生成AI功能的默认配置文件，可指定配置文件路径。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果未指定配置路径，使用默认路径
		if configPath == "" {
			configPath = config.GetDefaultConfigPath()
		}

		// 获取默认配置
		defaultConfig := config.GetDefaultConfig()

		// 保存配置到文件
		if err := config.SaveConfig(defaultConfig, configPath, force); err != nil {
			utils.ErrorPrint("生成默认配置失败: %v", err)
			return
		}

		utils.SuccessPrint("默认配置文件已生成: %s", configPath)
	},
}

// ConfigTestCmd 定义测试配置命令
var ConfigTestCmd = &cobra.Command{
	Use:   "test",
	Short: "验证当前AI配置的有效性与连通性",
	Long:  `测试AI配置的有效性，包括API端点可达性、密钥有效性和模型可用性。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果未指定配置路径，使用默认路径
		if configPath == "" {
			configPath = config.GetDefaultConfigPath()
		}

		// 加载配置
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			utils.ErrorPrint("加载配置失败: %v", err)
			return
		}

		// 测试配置
		latency, err := config.TestConfig(*cfg)
		if err != nil {
			utils.ErrorPrint("配置测试失败: %v", err)
			return
		}

		if latency > 0 {
			utils.SuccessPrint("配置测试通过，网络延迟: %v", latency)
		} else {
			utils.SuccessPrint("配置测试通过")
		}
	},
}

// ConfigShowCmd 定义显示配置命令
var ConfigShowCmd = &cobra.Command{
	Use:   "show",
	Short: "展示当前配置信息",
	Long:  `显示AI功能的当前配置，敏感信息将进行脱敏处理。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 如果未指定配置路径，使用默认路径
		if configPath == "" {
			configPath = config.GetDefaultConfigPath()
		}

		// 加载配置
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			utils.ErrorPrint("加载配置失败: %v", err)
			return
		}

		// 脱敏配置
		maskedCfg := config.MaskConfig(*cfg)

		// 显示配置
		fmt.Println("当前AI配置:")
		fmt.Printf("  服务提供商: %s\n", maskedCfg.Provider)
		fmt.Printf("  模型名称: %s\n", maskedCfg.Model)
		fmt.Printf("  API密钥: %s\n", maskedCfg.APIKey)
		fmt.Printf("  请求超时: %d秒\n", maskedCfg.Timeout)
		fmt.Printf("  最大重试: %d次\n", maskedCfg.MaxRetries)
		fmt.Println("  工具映射:")
		for tool, available := range maskedCfg.ToolMapping {
			status := "不可用"
			if available {
				status = "可用"
			}
			fmt.Printf("    %s: %s\n", tool, status)
		}
	},
}

// ExpCmd 定义AI驱动渗透测试命令
var ExpCmd = &cobra.Command{
	Use:   "exp <目标>",
	Short: "AI驱动的渗透测试",
	Long:  `对指定目标执行智能化渗透测试流程，包括目标探测、漏洞利用和横向移动。`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		PenetrationTestWithResource(target, resourceDir)
	},
}

// AuxCmd 定义AI辅助探测命令
var AuxCmd = &cobra.Command{
	Use:   "aux <目标>",
	Short: "AI辅助的安全探测",
	Long:  `专注于信息收集与漏洞探测，不执行主动攻击，包括目标信息收集、可用漏洞检测和安全配置评估。`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		AuxiliaryScanWithResource(target, resourceDir)
	},
}

// RegisterCommands 注册AI相关命令
func RegisterCommands() {
	// 设置全局选项
	AICmd.PersistentFlags().StringVar(&configPath, "config", "", "配置文件路径")

	// 配置命令子选项
	ConfigDefaultCmd.Flags().BoolVarP(&force, "force", "f", false, "强制覆盖现有配置文件")

	// 为exp和aux命令添加资源目录选项
	ExpCmd.Flags().StringVarP(&resourceDir, "resource", "r", "", "指定资源目录路径，默认在用户目录创建GYscan\\Resources文件夹")
	AuxCmd.Flags().StringVarP(&resourceDir, "resource", "r", "", "指定资源目录路径，默认在用户目录创建GYscan\\Resources文件夹")

	// 为exp和aux命令添加强制全盘扫描选项
	ExpCmd.Flags().BoolVarP(&forceScan, "scan", "n", false, "强制全盘扫描更新工具，即使配置文件中已有工具记录")
	AuxCmd.Flags().BoolVarP(&forceScan, "scan", "n", false, "强制全盘扫描更新工具，即使配置文件中已有工具记录")

	// 注册命令
	AICmd.AddCommand(ConfigCmd)
	ConfigCmd.AddCommand(ConfigDefaultCmd)
	ConfigCmd.AddCommand(ConfigTestCmd)
	ConfigCmd.AddCommand(ConfigShowCmd)
	AICmd.AddCommand(ExpCmd)
	AICmd.AddCommand(AuxCmd)
}
