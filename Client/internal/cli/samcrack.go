package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"GYscan/internal/samcrack"
	"github.com/spf13/cobra"
)

// samCrackCmd represents the samcrack command
var samCrackCmd = &cobra.Command{
	Use:   "samcrack",
	Short: "SAM密码破解工具",
	Long: `SAM密码破解工具 - 从SAM/SYSTEM文件提取并破解Windows用户密码

该工具通过以下步骤破解Windows密码：
1. 提取SAM/SYSTEM注册表文件
2. 解析BootKey启动密钥
3. 解密SAM中的NTLM哈希
4. 使用字典或暴力破解匹配密码

注意：仅可用于自己拥有所有权的系统或获得授权的渗透测试。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查是否有help参数
		if len(args) > 0 && args[0] == "help" {
			cmd.Help()
			os.Exit(0)
		}
		
		// 获取命令行参数
		samPath, _ := cmd.Flags().GetString("sam")
		systemPath, _ := cmd.Flags().GetString("system")
		dictionaryPath, _ := cmd.Flags().GetString("dictionary")
		bruteForce, _ := cmd.Flags().GetBool("brute-force")
		charset, _ := cmd.Flags().GetString("charset")
		minLength, _ := cmd.Flags().GetInt("min-length")
		maxLength, _ := cmd.Flags().GetInt("max-length")
		workers, _ := cmd.Flags().GetInt("workers")
		verbose, _ := cmd.Flags().GetBool("verbose")
		
		// 验证参数
		if dictionaryPath == "" && !bruteForce {
			fmt.Println("错误: 必须指定字典文件(--dictionary)或启用暴力破解(--brute-force)")
			os.Exit(1)
		}
		
		if dictionaryPath != "" {
			if _, err := os.Stat(dictionaryPath); os.IsNotExist(err) {
				fmt.Printf("错误: 字典文件不存在: %s\n", dictionaryPath)
				os.Exit(1)
			}
		}
		
		if bruteForce {
			if minLength < 1 || maxLength < minLength {
				fmt.Printf("错误: 无效的长度参数: min=%d, max=%d\n", minLength, maxLength)
				os.Exit(1)
			}
			
			// 检查字符集
			predefinedCharsets := map[string]string{
				"numeric":      "0123456789",
				"lowercase":    "abcdefghijklmnopqrstuvwxyz",
				"uppercase":    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
				"alphanumeric": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
				"common":       "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?",
			}
			
			if predefined, exists := predefinedCharsets[charset]; exists {
				charset = predefined
			} else if charset == "" {
				charset = predefinedCharsets["alphanumeric"]
			}
		}
		
		// 创建破解选项
		options := &samcrack.CrackOptions{
			SAMPath:       samPath,
			SYSTEMPath:    systemPath,
			DictionaryPath: dictionaryPath,
			BruteForce:    bruteForce,
			Charset:       charset,
			MinLength:     minLength,
			MaxLength:     maxLength,
			Workers:       workers,
			Verbose:       verbose,
		}
		
		// 创建破解器
		cracker := samcrack.NewSAMCracker(options)
		
		// 执行破解
		result, err := cracker.Crack()
		if err != nil {
			fmt.Printf("破解失败: %v\n", err)
			os.Exit(1)
		}
		
		// 打印结果
		cracker.PrintResults(result)
		
		// 清理临时文件
		if err := cracker.Cleanup(); err != nil {
			fmt.Printf("清理临时文件失败: %v\n", err)
		}
	},
}

func init() {
	// 由于samCmd已被移除，直接将samCrackCmd添加到rootCmd
	rootCmd.AddCommand(samCrackCmd)
	
	// 文件路径参数
	samCrackCmd.Flags().String("sam", "", "SAM文件路径（如未提供，将从注册表提取）")
	samCrackCmd.Flags().String("system", "", "SYSTEM文件路径（如未提供，将从注册表提取）")
	
	// 破解方法参数
	samCrackCmd.Flags().String("dictionary", "", "字典文件路径")
	samCrackCmd.Flags().Bool("brute-force", false, "启用暴力破解")
	
	// 暴力破解参数
	samCrackCmd.Flags().String("charset", "alphanumeric", "暴力破解字符集（numeric/lowercase/uppercase/alphanumeric/common）")
	samCrackCmd.Flags().Int("min-length", 4, "暴力破解最小密码长度")
	samCrackCmd.Flags().Int("max-length", 8, "暴力破解最大密码长度")
	
	// 性能参数
	samCrackCmd.Flags().Int("workers", 4, "并发工作线程数")
	
	// 其他参数
	samCrackCmd.Flags().Bool("verbose", true, "显示详细输出")
}

// createExampleDictionary 创建示例字典文件
func createExampleDictionary() error {
	content := `# 常用密码字典示例
# 请根据实际情况扩展此字典

123456
password
admin
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
123123
baseball
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
superman
1qaz2wsx
7777777
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveyou
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow`
	
	filename := "example_dictionary.txt"
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return err
	}
	
	absPath, _ := filepath.Abs(filename)
	fmt.Printf("示例字典文件已创建: %s\n", absPath)
	fmt.Println("请根据实际需要扩展此字典文件。")
	
	return nil
}

// showLegalWarning 显示法律警告
func showLegalWarning() {
	warning := `
===============================================
               法律警告
===============================================

本工具仅可用于以下合法场景：
1. 自己拥有所有权的系统
2. 获得书面授权的渗透测试
3. 授权的安全审计
4. 授权的取证分析

非法使用本工具可能触犯以下法律：
- 《中华人民共和国网络安全法》
- 《中华人民共和国刑法》
- 其他相关法律法规

使用前请确保您有合法的授权！
===============================================
`
	fmt.Println(warning)
}