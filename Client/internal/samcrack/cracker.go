package samcrack

import (
	"fmt"
	"os"
	"time"
)

// SAMCracker SAM密码破解器主类
type SAMCracker struct {
	extractor     *Extractor
	bootKeyParser *BootKeyParser
	samDecryptor  *SAMDecryptor
	options       *CrackOptions
}

// CrackOptions 破解选项
type CrackOptions struct {
	SAMPath        string
	SYSTEMPath     string
	DictionaryPath string
	BruteForce     bool
	Charset        string
	MinLength      int
	MaxLength      int
	Workers        int
	Verbose        bool
}

// NewSAMCracker 创建新的SAM密码破解器
func NewSAMCracker(options *CrackOptions) *SAMCracker {
	return &SAMCracker{
		extractor:     NewExtractor(),
		bootKeyParser: NewBootKeyParser(options.SYSTEMPath),
		samDecryptor:  NewSAMDecryptor(options.SAMPath),
		options:       options,
	}
}

// Crack 执行完整的SAM密码破解流程
func (s *SAMCracker) Crack() (*CrackResult, error) {
	startTime := time.Now()

	// 1. 检查管理员权限（仅在需要从注册表提取文件时）
	if s.options.SAMPath == "" || s.options.SYSTEMPath == "" {
		if !s.extractor.CheckAdminPrivileges() {
			return nil, fmt.Errorf("需要管理员权限运行此工具")
		}
	}

	// 2. 提取SAM/SYSTEM文件（如果未提供）
	samPath, systemPath, err := s.ensureFilesExist()
	if err != nil {
		return nil, err
	}

	if s.options.Verbose {
		fmt.Printf("使用SAM文件: %s\n", samPath)
		fmt.Printf("使用SYSTEM文件: %s\n", systemPath)
	}

	// 3. 提取BootKey
	if s.options.Verbose {
		fmt.Println("正在提取BootKey...")
	}

	bootKey, err := s.bootKeyParser.ExtractBootKey()
	if err != nil {
		return nil, fmt.Errorf("提取BootKey失败: %v", err)
	}

	if s.options.Verbose {
		fmt.Printf("成功提取BootKey: %x\n", bootKey.Key)
	}

	// 4. 解密SAM文件中的用户哈希
	if s.options.Verbose {
		fmt.Println("正在解密SAM文件中的用户哈希...")
	}

	userHashes, err := s.samDecryptor.DecryptUserHashes(bootKey.Key)
	if err != nil {
		return nil, fmt.Errorf("解密用户哈希失败: %v", err)
	}

	if s.options.Verbose {
		fmt.Printf("成功解密 %d 个用户的哈希\n", len(userHashes))
		for _, user := range userHashes {
			fmt.Printf("  - %s: %s\n", user.Username, user.NTLMHash)
		}
	}

	// 5. 执行破解
	var cracker PasswordCracker
	var crackMethod string

	if s.options.DictionaryPath != "" {
		// 使用字典破解
		cracker = NewDictionaryCracker(s.options.DictionaryPath)
		crackMethod = "字典破解"

		if s.options.Verbose {
			fmt.Printf("使用字典破解: %s\n", s.options.DictionaryPath)
		}
	} else if s.options.BruteForce {
		// 使用暴力破解
		cracker = NewBruteForceCracker(s.options.Charset, s.options.MinLength, s.options.MaxLength)
		crackMethod = "暴力破解"

		if s.options.Verbose {
			fmt.Printf("使用暴力破解: 字符集=%s, 长度范围=%d-%d\n",
				s.options.Charset, s.options.MinLength, s.options.MaxLength)
		}
	} else {
		return nil, fmt.Errorf("必须指定字典文件或启用暴力破解")
	}

	if s.options.Verbose {
		fmt.Printf("开始%s...\n", crackMethod)
	}

	// 破解所有用户哈希
	results, err := cracker.CrackMultiple(userHashes)
	if err != nil {
		return nil, fmt.Errorf("%s失败: %v", crackMethod, err)
	}

	// 6. 汇总结果
	finalResult := s.aggregateResults(results, startTime, crackMethod)

	return finalResult, nil
}

// ensureFilesExist 确保SAM/SYSTEM文件存在
func (s *SAMCracker) ensureFilesExist() (string, string, error) {
	samPath := s.options.SAMPath
	systemPath := s.options.SYSTEMPath

	// 如果提供了文件路径，直接使用
	if samPath != "" && systemPath != "" {
		if _, err := os.Stat(samPath); os.IsNotExist(err) {
			return "", "", fmt.Errorf("SAM文件不存在: %s", samPath)
		}
		if _, err := os.Stat(systemPath); os.IsNotExist(err) {
			return "", "", fmt.Errorf("SYSTEM文件不存在: %s", systemPath)
		}
		return samPath, systemPath, nil
	}

	// 否则从注册表提取
	if s.options.Verbose {
		fmt.Println("正在从注册表提取SAM/SYSTEM文件...")
	}

	err := s.extractor.ExtractSAMFiles("", "")
	if err != nil {
		return "", "", fmt.Errorf("提取SAM/SYSTEM文件失败: %v", err)
	}

	return s.extractor.GetSAMPath(), s.extractor.GetSystemPath(), nil
}

// aggregateResults 汇总破解结果
func (s *SAMCracker) aggregateResults(results []*CrackResult, startTime time.Time, method string) *CrackResult {
	finalResult := &CrackResult{
		Method:      method,
		ElapsedTime: time.Since(startTime),
	}

	var totalAttempts int64
	var crackedUsers []*CrackResult

	for _, result := range results {
		totalAttempts += result.Attempts

		if result.Found {
			crackedUsers = append(crackedUsers, result)
		}
	}

	finalResult.Attempts = totalAttempts
	finalResult.CrackedUsers = crackedUsers
	finalResult.TotalUsers = len(results)
	finalResult.SuccessRate = float64(len(crackedUsers)) / float64(len(results))

	return finalResult
}

// PasswordCracker 密码破解器接口
type PasswordCracker interface {
	CrackMultiple(userHashes []*UserHash) ([]*CrackResult, error)
	Stop()
}

// DefaultOptions 默认破解选项
func DefaultOptions() *CrackOptions {
	return &CrackOptions{
		SAMPath:        "",
		SYSTEMPath:     "",
		DictionaryPath: "",
		BruteForce:     false,
		Charset:        PredefinedCharsets["alphanumeric"],
		MinLength:      4,
		MaxLength:      8,
		Workers:        4,
		Verbose:        true,
	}
}

// Cleanup 清理临时文件
func (s *SAMCracker) Cleanup() error {
	// 清理临时文件
	if s.options.SAMPath == "" {
		if err := os.Remove("sam.hive"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	if s.options.SYSTEMPath == "" {
		if err := os.Remove("system.hive"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

// PrintResults 打印破解结果
func (s *SAMCracker) PrintResults(result *CrackResult) {
	fmt.Println("=== SAM密码破解结果 ===")
	fmt.Printf("破解方法: %s\n", result.Method)
	fmt.Printf("总耗时: %v\n", result.ElapsedTime)
	fmt.Printf("总尝试次数: %d\n", result.Attempts)
	fmt.Printf("破解成功率: %.2f%%\n", result.SuccessRate*100)
	fmt.Printf("破解用户数: %d/%d\n", len(result.CrackedUsers), result.TotalUsers)

	if len(result.CrackedUsers) > 0 {
		fmt.Println("\n破解成功的用户:")
		for _, user := range result.CrackedUsers {
			fmt.Printf("  - %s: %s\n", user.Username, user.Password)
		}
	}

	if result.Error != "" {
		fmt.Printf("错误信息: %s\n", result.Error)
	}

	fmt.Println("======================")
}
