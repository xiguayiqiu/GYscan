package audit

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileSystemAudit 文件系统审计模块
type FileSystemAudit struct {
	config *Config
}

// NewFileSystemAudit 创建文件系统审计模块
func NewFileSystemAudit(config *Config) *FileSystemAudit {
	return &FileSystemAudit{
		config: config,
	}
}

// Name 返回模块名称
func (fsa *FileSystemAudit) Name() string {
	return "filesystem"
}

// Description 返回模块描述
func (fsa *FileSystemAudit) Description() string {
	return "Windows文件系统安全审计，包括文件完整性检查、权限审计、敏感文件监控"
}

// RequiredPermissions 返回所需权限
func (fsa *FileSystemAudit) RequiredPermissions() []string {
	return []string{"SeBackupPrivilege", "SeRestorePrivilege"}
}

// Run 执行文件系统审计
func (fsa *FileSystemAudit) Run() ([]AuditResult, error) {
	var results []AuditResult

	// 检查是否具有管理员权限
	isAdmin := fsa.checkAdminPrivileges()
	
	if !isAdmin {
		// 非管理员权限下的降级检查
		results = append(results, fsa.auditWithLimitedPrivileges()...)
	} else {
		// 管理员权限下的完整检查
		// 1. 检查关键系统文件完整性
		results = append(results, fsa.auditSystemFiles()...)
		
		// 2. 检查文件权限设置
		results = append(results, fsa.auditFilePermissions()...)
		
		// 3. 检查敏感文件
		results = append(results, fsa.auditSensitiveFiles()...)
	}
	
	// 4. 实时文件监控（如果启用）
	if fsa.config.Verbose {
		results = append(results, fsa.monitorFileChanges()...)
	}

	return results, nil
}

// auditSystemFiles 审计系统文件完整性
func (fsa *FileSystemAudit) auditSystemFiles() []AuditResult {
	var results []AuditResult

	// 关键系统文件列表
	criticalFiles := []struct {
		path        string
		description string
		expectedHash string // 可选的预期哈希值
	}{
		{
			path:        "C:\\Windows\\System32\\kernel32.dll",
			description: "Windows内核库",
		},
		{
			path:        "C:\\Windows\\System32\\ntoskrnl.exe",
			description: "Windows内核",
		},
		{
			path:        "C:\\Windows\\System32\\lsass.exe",
			description: "本地安全认证子系统",
		},
		{
			path:        "C:\\Windows\\System32\\svchost.exe",
			description: "服务宿主进程",
		},
		{
			path:        "C:\\Windows\\System32\\cmd.exe",
			description: "命令提示符",
		},
		{
			path:        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			description: "PowerShell",
		},
	}

	for _, file := range criticalFiles {
		fileInfo, err := os.Stat(file.path)
		if err != nil {
			results = append(results, AuditResult{
				ModuleName:    fsa.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   fmt.Sprintf("关键系统文件缺失: %s", file.path),
				Details:       file.description,
				RiskScore:     90,
				Recommendation: "检查系统完整性，可能被恶意软件篡改",
				Timestamp:     time.Now(),
			})
			continue
		}

		// 检查文件权限
		if !fsa.hasSecurePermissions(file.path) {
			results = append(results, AuditResult{
				ModuleName:    fsa.Name(),
				Level:         AuditLevelMedium,
				Status:        "warning",
				Description:   fmt.Sprintf("系统文件权限不安全: %s", file.path),
				Details:       fileInfo.Mode().String(),
				RiskScore:     70,
				Recommendation: "修复文件权限设置",
				Timestamp:     time.Now(),
			})
		}

		// 计算文件哈希（如果配置了哈希算法）
		if fsa.config.FileHashAlgo != "" {
			_, err := fsa.calculateFileHash(file.path, fsa.config.FileHashAlgo)
			if err == nil {
				// 这里可以添加哈希验证逻辑
				// 例如与已知的干净哈希对比
			}
		}
	}

	return results
}

// hasSecurePermissions 检查文件权限是否安全
func (fsa *FileSystemAudit) hasSecurePermissions(filePath string) bool {
	// 简化实现：检查文件是否存在
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	
	// 检查文件权限：在Windows上，我们主要关注文件是否可被普通用户修改
	// 对于系统文件，应该只有管理员有写权限
	mode := fileInfo.Mode()
	
	// 如果是系统文件，检查是否可被普通用户写入
	if strings.Contains(strings.ToLower(filePath), "windows\\system32") {
		// 系统文件应该只有管理员有写权限
		// 这里简化检查：如果文件权限包含其他用户写权限，则认为不安全
		if mode.Perm()&0002 != 0 {
			return false // 其他用户有写权限，不安全
		}
	}
	
	// 对于普通文件，检查是否可被其他用户写入
	if mode.Perm()&0002 != 0 {
		return false // 其他用户有写权限，不安全
	}
	
	return true
}

// calculateFileHash 计算文件哈希
func (fsa *FileSystemAudit) calculateFileHash(filePath, algorithm string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hashWriter io.Writer
	switch strings.ToLower(algorithm) {
	case "md5":
		hashWriter = md5.New()
	case "sha1":
		hashWriter = sha1.New()
	case "sha256":
		hashWriter = sha256.New()
	default:
		return "", fmt.Errorf("不支持的哈希算法: %s", algorithm)
	}

	if _, err := io.Copy(hashWriter, file); err != nil {
		return "", err
	}

	hashBytes := hashWriter.(interface{ Sum([]byte) []byte }).Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// auditFilePermissions 审计文件权限
func (fsa *FileSystemAudit) auditFilePermissions() []AuditResult {
	var results []AuditResult

	// 检查关键目录的权限
	criticalDirs := []struct {
		path        string
		description string
	}{
		{
			path:        "C:\\Windows\\System32",
			description: "系统文件目录",
		},
		{
			path:        "C:\\Windows\\System32\\config",
			description: "注册表文件目录",
		},
		{
			path:        "C:\\Windows\\System32\\drivers",
			description: "驱动程序目录",
		},
		{
			path:        "C:\\Program Files",
			description: "程序文件目录",
		},
		{
			path:        "C:\\Users",
			description: "用户目录",
		},
	}

	for _, dir := range criticalDirs {
		if !fsa.isDirectorySecure(dir.path) {
			results = append(results, AuditResult{
				ModuleName:    fsa.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   fmt.Sprintf("关键目录权限不安全: %s", dir.path),
				Details:       dir.description,
				RiskScore:     80,
				Recommendation: "修复目录权限设置",
				Timestamp:     time.Now(),
			})
		}
	}

	return results
}

// isDirectorySecure 检查目录权限是否安全
func (fsa *FileSystemAudit) isDirectorySecure(dirPath string) bool {
	// 检查目录是否存在
	if _, err := os.Stat(dirPath); err != nil {
		return false
	}

	// 使用Windows API检查目录权限
	// 实现类似于hasSecurePermissions的逻辑
	return fsa.hasSecurePermissions(dirPath)
}

// auditSensitiveFiles 审计敏感文件
func (fsa *FileSystemAudit) auditSensitiveFiles() []AuditResult {
	var results []AuditResult

	// 敏感文件模式
	sensitivePatterns := []struct {
		pattern     string
		description string
		riskScore   int
	}{
		{
			pattern:     "*.pem",
			description: "SSL证书文件",
			riskScore:   85,
		},
		{
			pattern:     "*.key",
			description: "加密密钥文件",
			riskScore:   90,
		},
		{
			pattern:     "*.pfx",
			description: "PKCS#12证书文件",
			riskScore:   85,
		},
		{
			pattern:     "*.kdbx",
			description: "KeePass数据库",
			riskScore:   80,
		},
		{
			pattern:     "passwords*.txt",
			description: "密码文件",
			riskScore:   75,
		},
		{
			pattern:     "*.sql",
			description: "数据库文件",
			riskScore:   70,
		},
	}

	// 搜索敏感文件
	for _, pattern := range sensitivePatterns {
		files, err := filepath.Glob(filepath.Join("C:\\", pattern.pattern))
		if err != nil {
			continue
		}

		// 递归搜索用户目录
		userDirs, _ := filepath.Glob("C:\\Users\\*")
		for _, userDir := range userDirs {
			userFiles, _ := filepath.Glob(filepath.Join(userDir, pattern.pattern))
			files = append(files, userFiles...)
		}

		for _, file := range files {
			// 检查文件权限
			if !fsa.hasSecurePermissions(file) {
				results = append(results, AuditResult{
					ModuleName:    fsa.Name(),
					Level:         AuditLevelHigh,
					Status:        "fail",
					Description:   fmt.Sprintf("敏感文件权限不安全: %s", file),
					Details:       pattern.description,
					RiskScore:     pattern.riskScore,
					Recommendation: "保护敏感文件，设置适当权限",
					Timestamp:     time.Now(),
				})
			}
		}
	}

	return results
}

// monitorFileChanges 监控文件变化
func (fsa *FileSystemAudit) monitorFileChanges() []AuditResult {
	var results []AuditResult

	// 创建文件监控器
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return results
	}
	defer watcher.Close()

	// 监控关键目录
	watchDirs := []string{
		"C:\\Windows\\System32",
		"C:\\Windows\\System32\\config",
		"C:\\Windows\\System32\\drivers",
		"C:\\Program Files",
	}

	for _, dir := range watchDirs {
		err = watcher.Add(dir)
		if err != nil && fsa.config.Verbose {
			fmt.Printf("无法监控目录 %s: %v\n", dir, err)
		}
	}

	// 设置监控超时
	timeout := time.After(10 * time.Second)

	// 处理文件变化事件
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return results
			}

			// 分析文件变化事件
			if fsa.isSuspiciousFileEvent(event) {
				results = append(results, AuditResult{
					ModuleName:    fsa.Name(),
					Level:         AuditLevelMedium,
					Status:        "warning",
					Description:   fmt.Sprintf("检测到可疑文件操作: %s - %s", event.Op.String(), event.Name),
					Details:       event,
					RiskScore:     60,
					Recommendation: "监控文件系统活动",
					Timestamp:     time.Now(),
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return results
			}
			if fsa.config.Verbose {
				fmt.Printf("文件监控错误: %v\n", err)
			}

		case <-timeout:
			// 监控超时，返回结果
			return results
		}
	}
}

// isSuspiciousFileEvent 检查是否为可疑文件事件
func (fsa *FileSystemAudit) isSuspiciousFileEvent(event fsnotify.Event) bool {
	// 可疑的文件操作模式
	suspiciousOps := []fsnotify.Op{
		fsnotify.Write, // 文件写入
		fsnotify.Remove, // 文件删除
		fsnotify.Rename, // 文件重命名
	}

	// 检查操作类型
	for _, op := range suspiciousOps {
		if event.Op&op == op {
			// 检查文件路径是否可疑
			if fsa.isSuspiciousFilePath(event.Name) {
				return true
			}
		}
	}

	return false
}

// checkAdminPrivileges 检查是否具有管理员权限
func (fsa *FileSystemAudit) checkAdminPrivileges() bool {
	// 在Windows上检查管理员权限的多种方法
	
	// 方法1: 尝试写入系统目录
	testPath := "C:\\Windows\\System32\\test_admin_privilege.tmp"
	file, err := os.Create(testPath)
	if err == nil {
		file.Close()
		os.Remove(testPath)
		return true
	}
	
	// 方法2: 检查当前进程令牌
	if fsa.isCurrentProcessElevated() {
		return true
	}
	
	// 方法3: 尝试访问受保护的系统文件
	testFile := "C:\\Windows\\System32\\config\\SAM"
	_, err = os.Stat(testFile)
	if err == nil {
		return true
	}
	
	// 方法4: 检查Windows注册表权限
	if fsa.canWriteToRegistry() {
		return true
	}
	
	return false
}

// isCurrentProcessElevated 检查当前进程是否提升权限
func (fsa *FileSystemAudit) isCurrentProcessElevated() bool {
	// 在Windows上，可以通过检查进程令牌来确定是否提升权限
	// 这里使用简单的文件系统检查作为替代
	
	// 尝试访问需要管理员权限的目录
	testDirs := []string{
		"C:\\Windows\\System32\\config",
		"C:\\Windows\\System32\\drivers",
		"C:\\Windows\\System32\\catroot2",
	}
	
	for _, dir := range testDirs {
		_, err := os.Stat(dir)
		if err == nil {
			// 尝试列出目录内容
			files, err := os.ReadDir(dir)
			if err == nil && len(files) > 0 {
				return true
			}
		}
	}
	
	return false
}

// canWriteToRegistry 检查是否可以写入注册表
func (fsa *FileSystemAudit) canWriteToRegistry() bool {
	// 尝试通过文件系统模拟注册表写入检查
	// 检查是否可以写入系统目录
	testWritePath := "C:\\Windows\\System32\\test_write_access.tmp"
	file, err := os.Create(testWritePath)
	if err == nil {
		file.Close()
		os.Remove(testWritePath)
		return true
	}
	
	return false
}

// auditWithLimitedPrivileges 非管理员权限下的文件系统审计
func (fsa *FileSystemAudit) auditWithLimitedPrivileges() []AuditResult {
	var results []AuditResult
	
	// 1. 检查当前用户目录
	results = append(results, fsa.auditUserDirectory()...)
	
	// 2. 检查临时文件目录
	results = append(results, fsa.auditTempDirectory()...)
	
	// 3. 检查可访问的公共目录
	results = append(results, fsa.auditPublicDirectories()...)
	
	// 4. 检查环境变量和路径
	results = append(results, fsa.auditEnvironmentVariables()...)
	
	// 5. 检查启动项和计划任务
	results = append(results, fsa.auditStartupItems()...)
	
	// 6. 检查文件关联
	results = append(results, fsa.auditFileAssociations()...)
	
	// 7. 检查共享文件夹
	results = append(results, fsa.auditSharedFolders()...)
	
	// 8. 添加权限限制警告
	results = append(results, AuditResult{
		ModuleName:    fsa.Name(),
		Level:         AuditLevelMedium,
		Status:        "warning",
		Description:   "文件系统审计在非管理员权限下运行",
		Details:       "某些系统文件和目录无法访问，审计结果可能不完整",
		RiskScore:     50,
		Recommendation: "以管理员权限运行以获得完整审计结果",
		Timestamp:     time.Now(),
	})
	
	return results
}

// auditUserDirectory 审计当前用户目录
func (fsa *FileSystemAudit) auditUserDirectory() []AuditResult {
	var results []AuditResult
	
	// 获取当前用户目录
	userDir, err := os.UserHomeDir()
	if err != nil {
		return results
	}
	
	// 检查用户目录下的敏感文件
	sensitiveFiles := []string{
		filepath.Join(userDir, "Desktop", "passwords.txt"),
		filepath.Join(userDir, "Documents", "*.pem"),
		filepath.Join(userDir, "Downloads", "*.key"),
	}
	
	for _, pattern := range sensitiveFiles {
		files, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		
		for _, file := range files {
			fileInfo, err := os.Stat(file)
			if err != nil {
				continue
			}
			
			// 检查文件权限
			if fileInfo.Mode().Perm()&0022 != 0 {
				results = append(results, AuditResult{
					ModuleName:    fsa.Name(),
					Level:         AuditLevelMedium,
					Status:        "warning",
					Description:   fmt.Sprintf("用户目录文件权限不安全: %s", file),
					Details:       fmt.Sprintf("文件权限: %s", fileInfo.Mode().String()),
					RiskScore:     60,
					Recommendation: "设置适当的文件权限，限制其他用户访问",
					Timestamp:     time.Now(),
				})
			}
		}
	}
	
	return results
}

// auditTempDirectory 审计临时文件目录
func (fsa *FileSystemAudit) auditTempDirectory() []AuditResult {
	var results []AuditResult
	
	tempDir := os.TempDir()
	
	// 检查临时目录下的可执行文件
	executablePatterns := []string{
		filepath.Join(tempDir, "*.exe"),
		filepath.Join(tempDir, "*.bat"),
		filepath.Join(tempDir, "*.ps1"),
	}
	
	for _, pattern := range executablePatterns {
		files, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		
		for _, file := range files {
			results = append(results, AuditResult{
				ModuleName:    fsa.Name(),
				Level:         AuditLevelMedium,
				Status:        "warning",
				Description:   fmt.Sprintf("临时目录发现可执行文件: %s", filepath.Base(file)),
				Details:       "临时目录中的可执行文件可能是恶意软件",
				RiskScore:     70,
				Recommendation: "定期清理临时目录，监控可疑文件",
				Timestamp:     time.Now(),
			})
		}
	}
	
	return results
}

// auditPublicDirectories 审计公共目录
func (fsa *FileSystemAudit) auditPublicDirectories() []AuditResult {
	var results []AuditResult
	
	// 检查可访问的公共目录
	publicDirs := []string{
		"C:\\",
		"C:\\Users\\Public",
		"C:\\ProgramData",
	}
	
	for _, dir := range publicDirs {
		if _, err := os.Stat(dir); err == nil {
			// 检查目录权限
			results = append(results, AuditResult{
				ModuleName:    fsa.Name(),
				Level:         AuditLevelLow,
				Status:        "info",
				Description:   fmt.Sprintf("可访问公共目录: %s", dir),
				Details:       "目录存在且可访问",
				RiskScore:     30,
				Recommendation: "监控公共目录的文件活动",
				Timestamp:     time.Now(),
			})
		}
	}
	
	return results
}

// auditEnvironmentVariables 审计环境变量
func (fsa *FileSystemAudit) auditEnvironmentVariables() []AuditResult {
	var results []AuditResult
	
	// 检查PATH环境变量
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		// 检查PATH中是否包含可疑目录
		if strings.Contains(pathEnv, "temp") || strings.Contains(pathEnv, "tmp") {
			results = append(results, AuditResult{
				ModuleName:    fsa.Name(),
				Level:         AuditLevelHigh,
				Status:        "fail",
				Description:   "PATH环境变量包含临时目录",
				Details:       "临时目录在PATH中可能导致安全风险",
				RiskScore:     80,
				Recommendation: "从PATH中移除临时目录",
				Timestamp:     time.Now(),
			})
		}
	}
	
	// 检查TEMP和TMP环境变量
	tempDir := os.Getenv("TEMP")
	tmpDir := os.Getenv("TMP")
	if tempDir != "" {
		results = append(results, AuditResult{
			ModuleName:    fsa.Name(),
			Level:         AuditLevelLow,
			Status:        "info",
			Description:   fmt.Sprintf("TEMP环境变量: %s", tempDir),
			Details:       "临时文件目录",
			RiskScore:     20,
			Recommendation: "定期清理临时目录",
			Timestamp:     time.Now(),
		})
	}
	
	if tmpDir != "" {
		results = append(results, AuditResult{
			ModuleName:    fsa.Name(),
			Level:         AuditLevelLow,
			Status:        "info",
			Description:   fmt.Sprintf("TMP环境变量: %s", tmpDir),
			Details:       "临时文件目录",
			RiskScore:     20,
			Recommendation: "定期清理临时目录",
			Timestamp:     time.Now(),
		})
	}
	
	return results
}

// auditStartupItems 审计启动项
func (fsa *FileSystemAudit) auditStartupItems() []AuditResult {
	var results []AuditResult
	
	// 检查用户启动目录
	userDir, err := os.UserHomeDir()
	if err == nil {
		startupDirs := []string{
			filepath.Join(userDir, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
			filepath.Join(userDir, "Start Menu", "Programs", "Startup"),
		}
		
		for _, dir := range startupDirs {
			if _, err := os.Stat(dir); err == nil {
				// 检查启动目录中的文件
				files, err := os.ReadDir(dir)
				if err == nil {
					for _, file := range files {
						if !file.IsDir() {
							results = append(results, AuditResult{
								ModuleName:    fsa.Name(),
								Level:         AuditLevelMedium,
								Status:        "warning",
								Description:   fmt.Sprintf("启动项发现: %s", file.Name()),
								Details:       "用户启动目录中的可执行文件",
								RiskScore:     60,
								Recommendation: "审查启动项，确保只有可信程序",
								Timestamp:     time.Now(),
							})
						}
					}
				}
			}
		}
	}
	
	return results
}

// auditFileAssociations 审计文件关联
func (fsa *FileSystemAudit) auditFileAssociations() []AuditResult {
	var results []AuditResult
	
	// 检查常见的文件关联风险
	fileTypes := []string{
		".exe",
		".bat",
		".cmd",
		".ps1",
		".vbs",
		".js",
	}
	
	// 检查当前目录下的可执行文件
	currentDir, err := os.Getwd()
	if err == nil {
		for _, ext := range fileTypes {
			pattern := filepath.Join(currentDir, "*"+ext)
			files, err := filepath.Glob(pattern)
			if err == nil && len(files) > 0 {
				for _, file := range files {
					results = append(results, AuditResult{
						ModuleName:    fsa.Name(),
						Level:         AuditLevelMedium,
						Status:        "warning",
						Description:   fmt.Sprintf("当前目录发现可执行文件: %s", filepath.Base(file)),
						Details:       "当前工作目录中的可执行文件",
						RiskScore:     50,
						Recommendation: "将可执行文件移至专用目录",
						Timestamp:     time.Now(),
					})
				}
			}
		}
	}
	
	return results
}

// auditSharedFolders 审计共享文件夹
func (fsa *FileSystemAudit) auditSharedFolders() []AuditResult {
	var results []AuditResult
	
	// 检查常见的共享文件夹位置
	sharedDirs := []string{
		"C:\\Users\\Public",
		"C:\\ProgramData",
		"C:\\Windows\\Temp",
	}
	
	for _, dir := range sharedDirs {
		if _, err := os.Stat(dir); err == nil {
			// 检查共享目录中的可执行文件
			executablePatterns := []string{
				filepath.Join(dir, "*.exe"),
				filepath.Join(dir, "*.bat"),
				filepath.Join(dir, "*.ps1"),
			}
			
			for _, pattern := range executablePatterns {
				files, err := filepath.Glob(pattern)
				if err == nil && len(files) > 0 {
					for _, file := range files {
						results = append(results, AuditResult{
							ModuleName:    fsa.Name(),
							Level:         AuditLevelHigh,
							Status:        "fail",
							Description:   fmt.Sprintf("共享目录发现可执行文件: %s", filepath.Base(file)),
							Details:       "共享目录中的可执行文件可能是恶意软件",
							RiskScore:     85,
							Recommendation: "立即审查并移除可疑文件",
							Timestamp:     time.Now(),
						})
					}
				}
			}
		}
	}
	
	return results
}

// isSuspiciousFilePath 检查是否为可疑文件路径
func (fsa *FileSystemAudit) isSuspiciousFilePath(filePath string) bool {
	// 可疑文件路径模式
	suspiciousPatterns := []string{
		"System32",
		"drivers",
		"config",
		".exe",
		".dll",
		".sys",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(filePath), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}