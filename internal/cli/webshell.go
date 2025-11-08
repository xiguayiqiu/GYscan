package cli

import (
	"os"
	"path/filepath"

	"GYscan/internal/webshell"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	webshellType   string
	outputPath     string
	passwordField  string
)

// webshellCmd 表示webshell命令
var webshellCmd = &cobra.Command{
	Use:   "webshell",
	Short: "WebShell生成工具",
	Long: `生成PHP大马和小马，强制使用无加密版本。

使用示例:
  ./GYscan webshell -t small -o ./webshell.php
  ./GYscan webshell -t large -o ./large.php`,
	RunE:             runWebShellGenerator,
	TraverseChildren: true,
}

func init() {
	// 添加webshell命令的参数
	webshellCmd.Flags().StringVarP(&webshellType, "type", "t", "small", "WebShell类型: small(小马) 或 large(大马)")
	webshellCmd.Flags().StringVarP(&outputPath, "output", "o", "./webshell.php", "输出文件路径")
	webshellCmd.Flags().StringVarP(&passwordField, "pw", "w", "attack", "密码字段名（仅小马有效）")
	// 删除不需要的参数：密码、编码、混淆、无密码模式
	// 强制使用默认值（在runWebShellGenerator函数中直接设置）
}

func runWebShellGenerator(cmd *cobra.Command, args []string) error {
	// 检查是否包含help参数
	for _, arg := range args {
		if arg == "help" {
			return cmd.Help()
		}
	}

	// 强制使用无加密设置，忽略用户输入的所有加密相关参数
	options := webshell.PHPOptions{
		Password:       passwordField, // 使用-pw参数指定的密码字段
		Type:           webshellType,  // 只保留类型参数
		EncodeType:     "none",       // 强制不使用编码
		ObfuscateLevel: 0,            // 强制不使用混淆
		NoPassword:     true,         // 强制使用无密码模式
	}

	// 生成webshell内容
	webshellContent, err := webshell.GeneratePHPWebShell(options)
	if err != nil {
		utils.ErrorPrint("生成WebShell失败: %v", err)
		return err
	}

	// 确保输出目录存在
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		utils.ErrorPrint("创建目录失败: %v", err)
		return err
	}

	// 写入文件
	if err := os.WriteFile(outputPath, []byte(webshellContent), 0644); err != nil {
		utils.ErrorPrint("写入文件失败: %v", err)
		return err
	}

	utils.SuccessPrint("WebShell生成成功！")
	utils.InfoPrint("类型: %s", webshellType)
	utils.InfoPrint("路径: %s", outputPath)
	if webshellType == "small" {
		utils.InfoPrint("密码字段: %s", passwordField)
	}
	utils.InfoPrint("编码: none (强制禁用)")
	utils.InfoPrint("混淆级别: 0 (强制禁用)")
	utils.InfoPrint("无密码模式: true (强制启用)")
	return nil
}
