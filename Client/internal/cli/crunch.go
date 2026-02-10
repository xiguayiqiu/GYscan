package cli

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"GYscan/internal/utils"
	"github.com/spf13/cobra"
)

var (
	crunchOutputPath string
	threadCount     int
)

// crunchCmd 表示crunch命令
var crunchCmd = &cobra.Command{
	Use:   "crunch min max chars [options]",
	Short: "计算机根据算法生成的密码字典生成工具",
	Long: `生成密码字典，模仿crunch工具的功能。

使用示例:
  ./GYscan crunch 4 6 abcdefg -o passwords.txt
  ./GYscan crunch 8 8 0123456789 -o numbers.txt

参数说明:
  min		密码最小长度
  max		密码最大长度
  chars		包含的字符集
  -o, --output	输出文件路径`,
	Args: func(cmd *cobra.Command, args []string) error {
		// 如果请求帮助，直接返回nil让RunE函数处理
		if len(args) > 0 && args[0] == "help" {
			return nil
		}
		if len(args) < 3 {
			return fmt.Errorf("需要至少3个参数：最小长度、最大长度、字符集")
		}
		// 验证最小长度
		min, err := strconv.Atoi(args[0])
		if err != nil || min < 1 {
			return fmt.Errorf("最小长度必须是大于0的整数")
		}
		// 验证最大长度
		max, err := strconv.Atoi(args[1])
		if err != nil || max < min {
			return fmt.Errorf("最大长度必须是大于等于最小长度的整数")
		}
		// 验证字符集
		if len(args[2]) == 0 {
			return fmt.Errorf("字符集不能为空")
		}
		return nil
	},
	RunE: runCrunch,
	TraverseChildren: true,
}

func init() {
	// 添加crunch命令的参数
	crunchCmd.Flags().StringVarP(&crunchOutputPath, "output", "o", "", "输出文件路径（必须指定）")
	// 不设置MarkFlagRequired，改为在Run函数内部验证必需参数
	crunchCmd.Flags().IntVarP(&threadCount, "threads", "t", 4, "使用的线程数量（默认4线程）")
}

// 计算预估的密码数量
func calculatePasswordCount(minLen, maxLen int, charsetLen int) uint64 {
	var total uint64 = 0
	for length := minLen; length <= maxLen; length++ {
		// 计算每个长度的密码数量：charsetLen^length
		count := math.Pow(float64(charsetLen), float64(length))
		if count > float64(math.MaxUint64) {
			return math.MaxUint64 // 溢出
		}
		total += uint64(count)
	}
	return total
}

// 计算预估的文件大小（基于平均密码长度）
func calculateFileSize(passwordCount uint64, minLen, maxLen int) uint64 {
	// 计算平均密码长度
	averageLength := (minLen + maxLen) / 2
	// 每个密码后面加一个换行符，假设UTF-8编码
	return passwordCount * (uint64(averageLength) + 1)
}

// 格式化文件大小显示
func formatFileSize(size uint64) string {
	if size < 1024 {
		return fmt.Sprintf("%d 字节", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(size)/1024)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	} else if size < 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(size)/(1024*1024*1024))
	} else if size < 1024*1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f TB", float64(size)/(1024*1024*1024*1024))
	} else {
		return fmt.Sprintf("%.2f PB", float64(size)/(1024*1024*1024*1024*1024))
	}
}

// 生成字典的主函数
func runCrunch(cmd *cobra.Command, args []string) error {
	// 检查是否请求帮助
	if len(args) > 0 && args[0] == "help" {
		return cmd.Help()
	}
	
	// 验证必需参数
	if crunchOutputPath == "" {
		fmt.Println("错误: 必须指定输出文件路径 (-o, --output)")
		fmt.Println("用法: GYscan crunch min max chars -o 输出文件路径 [选项]")
		return nil
	}
	
	// 解析参数
	minLen, _ := strconv.Atoi(args[0])
	maxLen, _ := strconv.Atoi(args[1])
	charset := args[2]
	charsetLen := len(charset)

	// 限制线程数最小值为1
	if threadCount < 1 {
		threadCount = 1
	}

	// 预估密码数量和文件大小
	passwordCount := calculatePasswordCount(minLen, maxLen, charsetLen)
	fileSize := calculateFileSize(passwordCount, minLen, maxLen)

	// 显示预估信息
	utils.InfoPrint("[+] 预估信息:")
	fmt.Printf("   - 密码最小长度: %d\n", minLen)
	fmt.Printf("   - 密码最大长度: %d\n", maxLen)
	fmt.Printf("   - 字符集大小: %d\n", charsetLen)
	fmt.Printf("   - 预估密码数量: %d\n", passwordCount)
	fmt.Printf("   - 预估文件大小: %s\n", formatFileSize(fileSize))
	fmt.Printf("   - 使用线程数: %d\n", threadCount)

	// 确认是否继续
	utils.InfoPrint("\n[*] 开始生成密码字典...")

	// 确保输出目录存在
	dir := filepath.Dir(crunchOutputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 打开输出文件
	file, err := os.Create(crunchOutputPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 生成密码字典（使用多线程）
	generatedCount, err := generatePasswordsWithThreads(file, charset, minLen, maxLen, threadCount)
	if err != nil {
		return fmt.Errorf("生成密码失败: %v", err)
	}

	utils.SuccessPrint("\n[+] 密码字典生成完成！")
	fmt.Printf("   - 实际生成密码数量: %d\n", generatedCount)
	fmt.Printf("   - 输出文件路径: %s\n", crunchOutputPath)

	return nil
}

// 使用多线程生成密码
func generatePasswordsWithThreads(file *os.File, charset string, minLen, maxLen, threads int) (uint64, error) {
	
	var totalCount uint64 = 0
	var wg sync.WaitGroup
	var mu sync.Mutex // 用于保护文件写入

	// 按长度分配任务
	for length := minLen; length <= maxLen; length++ {
		// 计算此长度下的总密码数
		countForLength := uint64(math.Pow(float64(len(charset)), float64(length)))
		
		// 确定每个线程处理的密码数量
		passwordsPerThread := countForLength / uint64(threads)
		remainder := countForLength % uint64(threads)

		// 为每个线程创建任务
		for threadID := 0; threadID < threads; threadID++ {
			wg.Add(1)
			
			// 计算此线程的起始和结束位置
			start := uint64(threadID) * passwordsPerThread
			end := start + passwordsPerThread
			
			// 处理余数
			if threadID < int(remainder) {
				end++
			}
			
			// 确保不会超出范围
			if start >= countForLength {
				wg.Done()
				continue
			}
			if end > countForLength {
				end = countForLength
			}
			
			// 启动goroutine
			go func(length, threadID int, start, end uint64) {
				defer wg.Done()
				
				// 为每个线程创建一个缓冲区
				var buffer []byte
				localCount := uint64(0)
				
				// 生成此范围内的密码
				for i := start; i < end; i++ {
					// 将数字转换为密码
					password := numberToPassword(i, charset, length)
					buffer = append(buffer, password...)
					buffer = append(buffer, '\n')
					localCount++
					
					// 当缓冲区达到一定大小时，写入文件
					if len(buffer) >= 1024*1024 { // 1MB
						mu.Lock()
						file.Write(buffer)
						mu.Unlock()
						buffer = buffer[:0] // 清空缓冲区
					}
				}
				
				// 写入剩余的缓冲区内容
				if len(buffer) > 0 {
					mu.Lock()
					file.Write(buffer)
					mu.Unlock()
				}
				
				// 更新总计数
				atomic.AddUint64(&totalCount, localCount)
			}(length, threadID, start, end)
		}
	}
	
	// 等待所有线程完成
	wg.Wait()
	
	return totalCount, nil
}

// 将数字转换为密码
func numberToPassword(num uint64, charset string, length int) []byte {
	password := make([]byte, length)
	charsetLen := uint64(len(charset))
	
	// 从右到左填充密码字符
	for i := length - 1; i >= 0; i-- {
		charIndex := num % charsetLen
		password[i] = charset[charIndex]
		num = num / charsetLen
	}
	
	return password
}
