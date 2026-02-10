package cli

import (
	"GYscan/internal/cupp"
	"GYscan/internal/utils"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cuppCmd = &cobra.Command{
	Use:   "cupp [目标名字] [flags]",
	Short: "根据社会工程学信息生成密码-社会工程学密码生成器",
	Long: `CUPP - Common User Passwords Profiler
根据目标用户信息生成密码字典，用于密码安全测试
警告：仅用于授权测试，严禁未授权使用！

用法示例:
  ./GYscan cupp john                    # 基于名字生成密码
  ./GYscan cupp john --leet             # 启用Leet模式
  ./GYscan cupp john -n -s              # 添加数字和特殊字符
  ./GYscan cupp -i                      # 交互式模式
  ./GYscan cupp -w wordlist.txt         # 改进现有字典
  ./GYscan cupp -w wordlist.txt --concat --leet  # 改进字典并添加选项`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		interactive, _ := cmd.Flags().GetBool("interactive")
		improve, _ := cmd.Flags().GetString("improve")

		// 无参数时显示帮助信息
		if len(args) == 0 && !interactive && improve == "" {
			cmd.Help()
			return
		}

		// 检查改进字典模式
		if improve != "" {
			runCuppImprove(cmd, improve)
			return
		}

		// 检查交互式模式
		if interactive {
			runCuppInteractive()
			return
		}

		// 快速模式需要目标名字
		if len(args) == 0 {
			cmd.Help()
			return
		}

		targetName := args[0]
		utils.LogInfo("开始执行CUPP密码分析，目标名字: %s", targetName)

		leet, _ := cmd.Flags().GetBool("leet")
		numbers, _ := cmd.Flags().GetBool("numbers")
		special, _ := cmd.Flags().GetBool("special")
		output, _ := cmd.Flags().GetString("output")

		runCuppQuick(targetName, leet, numbers, special, output)

		utils.LogInfo("CUPP密码分析完成")
	},
}

func init() {
	rootCmd.AddCommand(cuppCmd)
	cuppCmd.Flags().BoolP("interactive", "i", false, "交互式输入用户信息")
	cuppCmd.Flags().StringP("improve", "w", "", "改进现有字典文件")
	cuppCmd.Flags().BoolP("concat", "c", false, "改进字典时连接词汇")
	cuppCmd.Flags().BoolP("leet", "l", false, "启用Leet模式 (e=3, a=4, etc)")
	cuppCmd.Flags().BoolP("numbers", "n", false, "添加随机数字")
	cuppCmd.Flags().BoolP("special", "s", false, "添加特殊字符")
	cuppCmd.Flags().StringP("output", "o", "", "输出文件路径")
}

func runCuppInteractive() {
	cupp.InitConfig()

	profile := &cupp.Profile{}
	cuppInst := cupp.NewCUPP()
	cuppInst.Interactive(profile)

	outputFile := profile.Name + ".txt"
	cupp.GenerateWordlist(profile, outputFile)
}

func runCuppQuick(name string, leet, numbers, special bool, output string) {
	cupp.InitConfig()

	profile := &cupp.Profile{
		Name:      name,
		Surname:   "",
		Nick:      "",
		Birthdate: "",
		Wife:      "",
		Wifen:     "",
		Wifeb:     "",
		Kid:       "",
		Kidn:      "",
		Kidb:      "",
		Pet:       "",
		Company:   "",
		Words:     []string{},
	}

	if leet {
		profile.Leetmode = "y"
	} else {
		profile.Leetmode = "n"
	}

	if numbers {
		profile.Randnum = "y"
	} else {
		profile.Randnum = "n"
	}

	if special {
		profile.Spechars1 = "y"
	} else {
		profile.Spechars1 = "n"
	}

	if output == "" {
		output = name + ".txt"
	}

	cupp.GenerateWordlist(profile, output)
}

func runCuppImprove(cmd *cobra.Command, filename string) {
	cupp.InitConfig()

	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		fmt.Printf("Error: 文件 %s 不存在\n", filename)
		return
	}

	concat, _ := cmd.Flags().GetBool("concat")
	leet, _ := cmd.Flags().GetBool("leet")
	numbers, _ := cmd.Flags().GetBool("numbers")
	special, _ := cmd.Flags().GetBool("special")

	cupp.ImproveDictionary(filename, concat, leet, numbers, special)
}
