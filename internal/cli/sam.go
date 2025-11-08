package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"GYscan/internal/sam"
	"GYscan/internal/utils"
	"github.com/spf13/cobra"
)

var (
	samFilePath string
	showDetails bool
	exportPath  string
)

// samCmd 表示SAM文件分析命令
var samCmd = &cobra.Command{
	Use:   "sam [SAM文件路径]",
	Short: "Windows SAM文件分析工具",
	Long: `分析Windows SAM文件，提取用户账户信息、密码哈希等安全数据。

SAM文件通常位于：
  C:\\Windows\\System32\\config\\SAM

使用示例:
  ./GYscan sam C:\\Windows\\System32\\config\\SAM
  ./GYscan sam C:\\Windows\\System32\\config\\SAM --details
  ./GYscan sam C:\\Windows\\System32\\config\\SAM --export users.txt

注意：需要管理员权限才能访问SAM文件。`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("需要指定SAM文件路径")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// 检查是否请求帮助
		if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
			return cmd.Help()
		}
		
		if len(args) < 1 {
			return fmt.Errorf("请提供SAM文件路径")
		}
		samFilePath = args[0]
		
		// 检查文件是否存在
		if _, err := os.Stat(samFilePath); os.IsNotExist(err) {
			return fmt.Errorf("SAM文件不存在: %s", samFilePath)
		}
		
		utils.InfoPrint("[+] 开始分析SAM文件: %s", samFilePath)
		
		// 分析SAM文件
		result, err := analyzeSamFile(samFilePath)
		if err != nil {
			return fmt.Errorf("分析SAM文件失败: %v", err)
		}
		
		// 显示分析结果
		printSamAnalysisResult(result)
		
		// 如果需要导出结果
		if exportPath != "" {
			err := exportSamResult(result, exportPath)
			if err != nil {
				return fmt.Errorf("导出结果失败: %v", err)
			}
			utils.SuccessPrint("[+] 结果已导出到: %s", exportPath)
		}
		
		return nil
	},
}

func init() {
	// 添加sam命令的参数
	samCmd.Flags().BoolVarP(&showDetails, "details", "d", false, "显示详细用户信息")
	samCmd.Flags().StringVarP(&exportPath, "export", "e", "", "导出结果到指定文件")
}

// runSamAnalysis 执行SAM文件分析
func runSamAnalysis(cmd *cobra.Command, args []string) error {
	samFilePath = args[0]

	// 检查文件是否存在
	if _, err := os.Stat(samFilePath); os.IsNotExist(err) {
		return fmt.Errorf("SAM文件不存在: %s", samFilePath)
	}

	fmt.Printf("[+] 开始分析SAM文件: %s\n", samFilePath)

	// 分析SAM文件
	result, err := analyzeSamFile(samFilePath)
	if err != nil {
		return fmt.Errorf("分析SAM文件失败: %v", err)
	}

	// 显示分析结果
	printSamAnalysisResult(result)

	// 如果需要导出结果
	if exportPath != "" {
		err := exportSamResult(result, exportPath)
		if err != nil {
			return fmt.Errorf("导出结果失败: %v", err)
		}
		fmt.Printf("[+] 结果已导出到: %s\n", exportPath)
	}

	return nil
}

// SamAnalysisResult SAM文件分析结果结构
type SamAnalysisResult struct {
	FilePath        string
	FileSize        int64
	UserCount       int
	Users           []SamUser
	IsEncrypted     bool
	Version         string
	Signature       string
	RegistryType    string
	SecurityPolicies SecurityPolicies
	RegistryKeys    []RegistryKey
	FileInfo        FileInfo
}

// SamUser SAM用户信息结构
type SamUser struct {
	Username          string `json:"username"`
	RID               string `json:"rid"`
	LMHash            string `json:"lm_hash"`
	NTLMHash          string `json:"ntlm_hash"`
	PlaintextPassword string `json:"plaintext_password"`
	LastLogin         string `json:"last_login"`
	LastLogoff        string `json:"last_logoff"`
	AccountType       string `json:"account_type"`
	IsDisabled        bool   `json:"is_disabled"`
	IsLocked          bool   `json:"is_locked"`
	FullName          string `json:"full_name"`
	Description       string `json:"description"`
	Groups            []string `json:"groups"`
	SID               string `json:"sid"`
	PasswordNeverExpires bool `json:"password_never_expires"`
	UserCannotChangePassword bool `json:"user_cannot_change_password"`
	PasswordStrength  string `json:"password_strength"`
	IsWeakPassword    bool   `json:"is_weak_password"`
}

// SecurityPolicies 安全策略信息
type SecurityPolicies struct {
	MinPasswordLength    int
	PasswordComplexity   bool
	AccountLockoutPolicy AccountLockoutPolicy
}

// AccountLockoutPolicy 账户锁定策略
type AccountLockoutPolicy struct {
	LockoutThreshold    int
	LockoutDuration     string
	ResetLockoutCounter string
}

// RegistryKey 注册表键值信息
type RegistryKey struct {
	KeyPath   string
	ValueName string
	ValueType string
	ValueData string
}

// FileInfo 文件信息
type FileInfo struct {
	CreatedTime     string
	ModifiedTime    string
	AccessedTime    string
	FileAttributes  string
}

// analyzeSamFile 分析SAM文件
func analyzeSamFile(filePath string) (*SamAnalysisResult, error) {
	// 使用SAM解析器
	parser, err := sam.NewParser(filePath)
	if err != nil {
		return nil, err
	}

	// 解析SAM文件
	analysisResult, err := parser.Parse()
	if err != nil {
		return nil, err
	}

	// 转换为CLI结果格式
	result := &SamAnalysisResult{
		FilePath:     filePath,
		FileSize:     analysisResult.FileSize,
		UserCount:    analysisResult.UserCount,
		IsEncrypted:  analysisResult.IsEncrypted,
		Version:      analysisResult.Version,
		Signature:    analysisResult.Signature,
		RegistryType: analysisResult.RegistryType,
	}

	// 转换安全策略信息
	result.SecurityPolicies = SecurityPolicies{
		MinPasswordLength:  analysisResult.SecurityPolicies.MinPasswordLength,
		PasswordComplexity: analysisResult.SecurityPolicies.PasswordComplexity,
		AccountLockoutPolicy: AccountLockoutPolicy{
			LockoutThreshold:    analysisResult.SecurityPolicies.AccountLockoutPolicy.LockoutThreshold,
			LockoutDuration:     analysisResult.SecurityPolicies.AccountLockoutPolicy.LockoutDuration.String(),
			ResetLockoutCounter: analysisResult.SecurityPolicies.AccountLockoutPolicy.ResetLockoutCounter.String(),
		},
	}

	// 转换文件信息
	result.FileInfo = FileInfo{
		CreatedTime:    analysisResult.FileInfo.CreatedTime.Format("2006-01-02 15:04:05"),
		ModifiedTime:   analysisResult.FileInfo.ModifiedTime.Format("2006-01-02 15:04:05"),
		AccessedTime:   analysisResult.FileInfo.AccessedTime.Format("2006-01-02 15:04:05"),
		FileAttributes: analysisResult.FileInfo.FileAttributes,
	}

	// 转换注册表键值
	for _, key := range analysisResult.RegistryKeys {
		result.RegistryKeys = append(result.RegistryKeys, RegistryKey{
			KeyPath:   key.KeyPath,
			ValueName: key.ValueName,
			ValueType: key.ValueType,
			ValueData: key.ValueData,
		})
	}

	// 转换用户信息
	for _, user := range analysisResult.Users {
		samUser := SamUser{
			Username:          user.Username,
			RID:               fmt.Sprintf("%d", user.RID),
			LMHash:            user.LMHash,
			NTLMHash:          user.NTLMHash,
			PlaintextPassword: user.PlaintextPassword,
			AccountType:       user.AccountType,
			IsDisabled:        user.IsDisabled,
			IsLocked:          user.IsLocked,
			FullName:          user.FullName,
			Description:       user.Description,
			Groups:            user.Groups,
			SID:               user.SID,
			PasswordNeverExpires: user.PasswordNeverExpires,
			UserCannotChangePassword: user.UserCannotChangePassword,
		}
		
		// 分析密码强度
		samUser.PasswordStrength = analyzePasswordStrength(samUser)
		samUser.IsWeakPassword = isWeakPassword(samUser)
		
		if !user.LastLogin.IsZero() {
			samUser.LastLogin = user.LastLogin.Format("2006-01-02 15:04:05")
		}
		
		if !user.LastLogoff.IsZero() {
			samUser.LastLogoff = user.LastLogoff.Format("2006-01-02 15:04:05")
		}
		
		result.Users = append(result.Users, samUser)
	}

	return result, nil
}

// printSamAnalysisResult 打印SAM分析结果
func printSamAnalysisResult(result *SamAnalysisResult) {
	utils.InfoPrint("\n[+] SAM文件分析结果:")
	fmt.Printf("   文件路径: %s\n", result.FilePath)
	fmt.Printf("   文件大小: %d 字节\n", result.FileSize)
	fmt.Printf("   文件签名: %s\n", result.Signature)
	fmt.Printf("   文件类型: %s\n", result.RegistryType)
	fmt.Printf("   用户数量: %d\n", result.UserCount)
	fmt.Printf("   加密状态: %v\n", result.IsEncrypted)
	fmt.Printf("   系统版本: %s\n", result.Version)

	// 文件信息
	utils.InfoPrint("\n[+] 文件信息:")
	fmt.Printf("   创建时间: %s\n", result.FileInfo.CreatedTime)
	fmt.Printf("   修改时间: %s\n", result.FileInfo.ModifiedTime)
	fmt.Printf("   访问时间: %s\n", result.FileInfo.AccessedTime)
	fmt.Printf("   文件属性: %s\n", result.FileInfo.FileAttributes)

	// 安全策略
	utils.InfoPrint("\n[+] 安全策略:")
	fmt.Printf("   最小密码长度: %d\n", result.SecurityPolicies.MinPasswordLength)
	fmt.Printf("   密码复杂度要求: %v\n", result.SecurityPolicies.PasswordComplexity)
	fmt.Printf("   账户锁定阈值: %d 次失败登录\n", result.SecurityPolicies.AccountLockoutPolicy.LockoutThreshold)
	fmt.Printf("   锁定持续时间: %s\n", result.SecurityPolicies.AccountLockoutPolicy.LockoutDuration)
	fmt.Printf("   重置锁定计数器: %s\n", result.SecurityPolicies.AccountLockoutPolicy.ResetLockoutCounter)

	utils.InfoPrint("\n[+] 用户账户信息:")
	for i, user := range result.Users {
		fmt.Printf("   %d. 用户名: %s\n", i+1, user.Username)
		fmt.Printf("      相对标识符(RID): %s\n", user.RID)
		fmt.Printf("      安全标识符(SID): %s\n", user.SID)
		fmt.Printf("      账户类型: %s\n", user.AccountType)
		
		// 显示明文密码信息
		if user.PlaintextPassword != "" && user.PlaintextPassword != "未破解" {
			fmt.Printf("      明文密码: %s\n", user.PlaintextPassword)
			fmt.Printf("      密码强度: %s\n", user.PasswordStrength)
			if user.IsWeakPassword {
				fmt.Printf("      ⚠️  弱密码警告: 检测到弱密码\n")
			}
		} else {
			// 如果没有找到明文密码，则显示哈希值
			if user.NTLMHash != "空密码" && user.NTLMHash != "" {
				fmt.Printf("      NTLM Hash: %s\n", user.NTLMHash)
			}
			if user.LMHash != "空密码或禁用LM哈希" && user.LMHash != "" {
				fmt.Printf("      LM Hash: %s\n", user.LMHash)
			}
			fmt.Printf("      明文密码: %s\n", user.PlaintextPassword)
		}
		
		if showDetails {
			fmt.Printf("      LM Hash: %s\n", user.LMHash)
			fmt.Printf("      NTLM Hash: %s\n", user.NTLMHash)
			fmt.Printf("      全名: %s\n", user.FullName)
			fmt.Printf("      描述: %s\n", user.Description)
			fmt.Printf("      所属组: %v\n", user.Groups)
			fmt.Printf("      是否禁用: %v\n", user.IsDisabled)
			fmt.Printf("      是否锁定: %v\n", user.IsLocked)
			fmt.Printf("      密码永不过期: %v\n", user.PasswordNeverExpires)
			fmt.Printf("      用户不能更改密码: %v\n", user.UserCannotChangePassword)
			if user.LastLogin != "" {
				fmt.Printf("      最后登录: %s\n", user.LastLogin)
			}
			if user.LastLogoff != "" {
				fmt.Printf("      最后注销: %s\n", user.LastLogoff)
			}
		}
		fmt.Println()
	}

	// 注册表键值信息
	if showDetails && len(result.RegistryKeys) > 0 {
		utils.InfoPrint("\n[+] 注册表键值信息:")
		for i, key := range result.RegistryKeys {
			fmt.Printf("   %d. 键路径: %s\n", i+1, key.KeyPath)
			fmt.Printf("      值名称: %s\n", key.ValueName)
			fmt.Printf("      值类型: %s\n", key.ValueType)
			fmt.Printf("      值数据: %s\n", key.ValueData)
			fmt.Println()
		}
	}

	// 安全建议
	utils.InfoPrint("[+] 安全建议:")
	fmt.Printf("   - 检查是否存在弱密码账户\n")
	fmt.Printf("   - 验证管理员账户状态\n")
	fmt.Printf("   - 检查是否有不必要的用户账户\n")
	fmt.Printf("   - 建议启用强密码策略\n")
	fmt.Printf("   - 配置账户锁定策略\n")
	fmt.Printf("   - 定期审计用户账户\n")
	fmt.Printf("   - 禁用不必要的用户账户\n")
}

// analyzePasswordStrength 分析密码强度
func analyzePasswordStrength(user SamUser) string {
	if user.PlaintextPassword == "" || user.PlaintextPassword == "未破解" {
		return "未知"
	}
	
	password := user.PlaintextPassword
	
	// 检查密码长度
	if len(password) < 6 {
		return "极弱"
	}
	
	// 检查密码复杂度
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= '!' && char <= '/':
			hasSpecial = true
		case char >= ':' && char <= '@':
			hasSpecial = true
		case char >= '[' && char <= '`':
			hasSpecial = true
		case char >= '{' && char <= '~':
			hasSpecial = true
		}
	}
	
	// 评估强度
	if len(password) >= 12 && hasUpper && hasLower && hasDigit && hasSpecial {
		return "极强"
	} else if len(password) >= 8 && hasUpper && hasLower && hasDigit {
		return "强"
	} else if len(password) >= 6 && (hasUpper || hasLower) && hasDigit {
		return "中等"
	} else {
		return "弱"
	}
}

// isWeakPassword 判断是否为弱密码
func isWeakPassword(user SamUser) bool {
	if user.PlaintextPassword == "" || user.PlaintextPassword == "未破解" {
		return false
	}
	
	password := user.PlaintextPassword
	
	// 常见弱密码列表
	weakPasswords := []string{
		"", "password", "123456", "12345678", "123456789", "1234567890",
		"admin", "administrator", "root", "guest", "test", "demo",
		"pass", "pass123", "password123", "qwerty", "abc123",
		"letmein", "welcome", "monkey", "dragon", "master",
		"hello", "freedom", "whatever", "qazwsx", "123qwe",
		"1q2w3e4r", "1qaz2wsx", "zaq12wsx", "!@#$%^&*",
		"P@ssw0rd", "P@ssw0rd123", "Admin123", "Root123",
	}
	
	for _, weak := range weakPasswords {
		if password == weak {
			return true
		}
	}
	
	// 检查是否为用户名相关的弱密码
	if password == user.Username || 
	   password == user.Username + "123" ||
	   password == user.Username + "!" {
		return true
	}
	
	return false
}

// exportSamResult 导出SAM分析结果到JSON文件
func exportSamResult(result *SamAnalysisResult, exportPath string) error {
	// 确保目录存在
	dir := filepath.Dir(exportPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建导出文件
	file, err := os.Create(exportPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("编码JSON失败: %v", err)
	}

	fmt.Printf("[+] 完整SAM分析结果已导出到: %s\n", exportPath)
	fmt.Printf("   包含: 文件信息、安全策略、用户账户详情、注册表键值、安全评估\n")
	return nil
}