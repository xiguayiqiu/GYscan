package cli

import (
	"fmt"
	"os"
	"runtime"

	"GYscan/internal/process"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

// processCmd 进程与服务分析命令
var processCmd = &cobra.Command{
	Use:   "process [options]",
	Short: "进程与服务信息收集工具",
	Long: `进程与服务信息收集工具 - 分析运行中的进程和系统服务，识别高权限运行的软件

支持功能:
- 跨平台进程分析 (Windows/Linux)
- 系统服务信息收集
- 高权限进程和服务识别
- 详细的权限级别分类

权限级别说明:
- 系统权限: 操作系统核心组件，具有最高权限
- 高权限: 网络服务、数据库服务等关键应用
- 中权限: 普通系统服务和应用
- 低权限: 普通用户应用

使用示例:
  ./GYscan process                    # 显示所有进程和服务信息
  ./GYscan process -H                  # 仅显示高权限进程和服务
  ./GYscan process -p                  # 仅显示进程信息
  ./GYscan process -S                  # 仅显示服务信息
  ./GYscan process --output json       # 以JSON格式输出

警告: 仅用于授权测试和安全评估，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			return
		}

		// 解析参数
		highPrivilege, _ := cmd.Flags().GetBool("high")
		processesOnly, _ := cmd.Flags().GetBool("process")
		servicesOnly, _ := cmd.Flags().GetBool("service")
		outputFormat, _ := cmd.Flags().GetString("output")

		// 验证参数
		if processesOnly && servicesOnly {
			utils.ErrorPrint("不能同时指定 -p/--process 和 -s/--service")
			cmd.Help()
			return
		}

		// 执行进程与服务分析
		err := runProcessAnalysis(highPrivilege, processesOnly, servicesOnly, outputFormat)
		if err != nil {
			utils.ErrorPrint("进程与服务分析失败: %v", err)
			os.Exit(1)
		}
	},
}

// runProcessAnalysis 执行进程与服务分析
func runProcessAnalysis(highPrivilege, processesOnly, servicesOnly bool, outputFormat string) error {
	utils.InfoPrint("开始进程与服务分析...")
	utils.InfoPrint("操作系统: %s", getOSInfo())
	utils.InfoPrint("")

	var processes []process.ProcessInfo
	var services []process.ServiceInfo
	var err error

	// 分析进程
	if !servicesOnly {
		utils.InfoPrint("正在分析运行中的进程...")
		if highPrivilege {
			processes, err = process.GetHighPrivilegeProcesses()
		} else {
			processes, err = process.AnalyzeProcesses()
		}
		if err != nil {
			utils.WarningPrint("进程分析失败: %v", err)
		} else {
			utils.InfoPrint("发现 %d 个进程", len(processes))
		}
	}

	// 分析服务
	if !processesOnly {
		utils.InfoPrint("正在分析系统服务...")
		if highPrivilege {
			services, err = process.GetHighPrivilegeServices()
		} else {
			services, err = process.AnalyzeServices()
		}
		if err != nil {
			utils.WarningPrint("服务分析失败: %v", err)
		} else {
			utils.InfoPrint("发现 %d 个服务", len(services))
		}
	}

	utils.InfoPrint("")

	// 输出结果
	return outputResults(processes, services, highPrivilege, processesOnly, servicesOnly, outputFormat)
}

// outputResults 输出分析结果
func outputResults(processes []process.ProcessInfo, services []process.ServiceInfo, 
	highPrivilege, processesOnly, servicesOnly bool, outputFormat string) error {
	
	switch outputFormat {
	case "json":
		return outputJSON(processes, services)
	default:
		return outputText(processes, services, highPrivilege, processesOnly, servicesOnly)
	}
}

// outputText 以文本格式输出结果
func outputText(processes []process.ProcessInfo, services []process.ServiceInfo,
	highPrivilege, processesOnly, servicesOnly bool) error {
	
	if highPrivilege {
		// 高权限模式
		result := process.FormatHighPrivilegeInfo(processes, services)
		fmt.Println(result)
	} else {
		// 完整模式
		if !servicesOnly && len(processes) > 0 {
			result := process.FormatProcessInfo(processes)
			fmt.Println(result)
		}

		if !processesOnly && len(services) > 0 {
			if !servicesOnly {
				fmt.Println()
			}
			result := process.FormatServiceInfo(services)
			fmt.Println(result)
		}

		// 如果没有数据
		if len(processes) == 0 && len(services) == 0 {
			if processesOnly {
				utils.InfoPrint("未发现任何进程")
			} else if servicesOnly {
				utils.InfoPrint("未发现任何服务")
			} else {
				utils.InfoPrint("未发现任何进程或服务")
			}
		}
	}

	return nil
}

// outputJSON 以JSON格式输出结果
func outputJSON(processes []process.ProcessInfo, services []process.ServiceInfo) error {
	// 创建结果结构
	result := struct {
		Processes []process.ProcessInfo `json:"processes"`
		Services  []process.ServiceInfo `json:"services"`
	}{
		Processes: processes,
		Services:  services,
	}

	// 转换为JSON
	jsonData, err := utils.ToJSON(result)
	if err != nil {
		return fmt.Errorf("JSON转换失败: %v", err)
	}

	fmt.Println(jsonData)
	return nil
}

// getOSInfo 获取操作系统信息
func getOSInfo() string {
	return fmt.Sprintf("%s/%s", getOSName(), getArchitecture())
}

// getOSName 获取操作系统名称
func getOSName() string {
	// 使用runtime包获取实际的操作系统
	return runtime.GOOS
}

// getArchitecture 获取系统架构
func getArchitecture() string {
	// 使用runtime包获取实际的系统架构
	return runtime.GOARCH
}

// init 初始化命令参数
func init() {
	// 添加命令参数
	processCmd.Flags().BoolP("high", "H", false, "仅显示高权限进程和服务")
	processCmd.Flags().BoolP("process", "p", false, "仅显示进程信息")
	processCmd.Flags().BoolP("service", "S", false, "仅显示服务信息")
	processCmd.Flags().String("output", "text", "输出格式 (text|json)")
}