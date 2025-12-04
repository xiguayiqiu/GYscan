package data

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"GYscan/internal/ai/types"
	"github.com/google/uuid"
)

// StorageInterface 数据存储接口
type StorageInterface interface {
	// 任务管理
	SaveTask(ctx context.Context, task *types.Task) error
	GetTask(ctx context.Context, taskID string) (*types.Task, error)
	UpdateTask(ctx context.Context, task *types.Task) error
	ListTasks(ctx context.Context, filters map[string]interface{}) ([]*types.Task, error)
	DeleteTask(ctx context.Context, taskID string) error

	// 凭证管理
	SaveCredential(ctx context.Context, credential *types.Credential) error
	GetCredential(ctx context.Context, credentialID string) (*types.Credential, error)
	ListCredentials(ctx context.Context, filters map[string]interface{}) ([]*types.Credential, error)
	DeleteCredential(ctx context.Context, credentialID string) error

	// 工具执行结果管理
	SaveToolResult(ctx context.Context, result *types.ToolResult) error
	GetToolResults(ctx context.Context, taskID string) ([]*types.ToolResult, error)

	// 初始化和关闭
	Init(ctx context.Context) error
	Close(ctx context.Context) error
}

// EncryptedStorage 加密存储实现
type EncryptedStorage struct {
	storagePath  string
	encryptionKey []byte
}

// NewEncryptedStorage 创建新的加密存储实例
func NewEncryptedStorage() *EncryptedStorage {
	return &EncryptedStorage{
		storagePath: getDefaultStoragePath(),
	}
}

// getDefaultStoragePath 获取默认存储路径
func getDefaultStoragePath() string {
	var basePath string

	switch runtime.GOOS {
	case "windows":
		basePath = filepath.Join(os.Getenv("APPDATA"), "GYscan")
	case "linux":
		basePath = filepath.Join(os.Getenv("HOME"), ".config", "GYscan")
	default:
		basePath = "./gyscan_data"
	}

	return filepath.Join(basePath, "ai_storage")
}

// Init 初始化存储
func (s *EncryptedStorage) Init(ctx context.Context) error {
	// 确保存储目录存在
	if err := os.MkdirAll(s.storagePath, 0700); err != nil {
		return fmt.Errorf("创建存储目录失败: %v", err)
	}

	// 初始化加密密钥
	if err := s.initEncryptionKey(); err != nil {
		return fmt.Errorf("初始化加密密钥失败: %v", err)
	}

	return nil
}

// initEncryptionKey 初始化加密密钥
func (s *EncryptedStorage) initEncryptionKey() error {
	// 从环境变量获取密钥
	key := os.Getenv("GYSCAN_AI_ENCRYPTION_KEY")

	// 如果没有密钥，生成一个新的
	if key == "" {
		newKey := make([]byte, 32) // AES-256
		if _, err := rand.Read(newKey); err != nil {
			return fmt.Errorf("生成加密密钥失败: %v", err)
		}
		// 注意：在实际生产环境中，应该将密钥安全存储，而不是打印出来
		fmt.Printf("生成新的加密密钥: %x\n", newKey)
		s.encryptionKey = newKey
	} else {
		// 解析十六进制密钥
		if len(key) != 64 {
			return fmt.Errorf("无效的加密密钥长度，必须为64个十六进制字符")
		}
		var err error
		s.encryptionKey, err = hex.DecodeString(key)
		if err != nil {
			return fmt.Errorf("解析加密密钥失败: %v", err)
		}
	}

	return nil
}

// Close 关闭存储
func (s *EncryptedStorage) Close(ctx context.Context) error {
	// 加密存储不需要特殊的关闭操作
	return nil
}

// encrypt 加密数据
func (s *EncryptedStorage) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt 解密数据
func (s *EncryptedStorage) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("无效的密文")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SaveTask 保存任务
func (s *EncryptedStorage) SaveTask(ctx context.Context, task *types.Task) error {
	if task.ID == "" {
		task.ID = uuid.New().String()
	}
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("序列化任务失败: %v", err)
	}

	encryptedData, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("加密任务失败: %v", err)
	}

	filePath := filepath.Join(s.storagePath, "tasks", fmt.Sprintf("%s.json", task.ID))
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("创建任务目录失败: %v", err)
	}

	if err := os.WriteFile(filePath, encryptedData, 0600); err != nil {
		return fmt.Errorf("写入任务文件失败: %v", err)
	}

	return nil
}

// GetTask 获取任务
func (s *EncryptedStorage) GetTask(ctx context.Context, taskID string) (*types.Task, error) {
	filePath := filepath.Join(s.storagePath, "tasks", fmt.Sprintf("%s.json", taskID))

	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取任务文件失败: %v", err)
	}

	data, err := s.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("解密任务失败: %v", err)
	}

	var task types.Task
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("反序列化任务失败: %v", err)
	}

	return &task, nil
}

// UpdateTask 更新任务
func (s *EncryptedStorage) UpdateTask(ctx context.Context, task *types.Task) error {
	task.UpdatedAt = time.Now()
	return s.SaveTask(ctx, task)
}

// ListTasks 列出任务
func (s *EncryptedStorage) ListTasks(ctx context.Context, filters map[string]interface{}) ([]*types.Task, error) {
	tasksDir := filepath.Join(s.storagePath, "tasks")
	files, err := os.ReadDir(tasksDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.Task{}, nil
		}
		return nil, fmt.Errorf("读取任务目录失败: %v", err)
	}

	var tasks []*types.Task
	for _, file := range files {
		if !file.Type().IsRegular() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		taskID := strings.TrimSuffix(file.Name(), ".json")
		task, err := s.GetTask(ctx, taskID)
		if err != nil {
			continue
		}

		// 应用过滤器
		if matchesFilters(task, filters) {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

// DeleteTask 删除任务
func (s *EncryptedStorage) DeleteTask(ctx context.Context, taskID string) error {
	filePath := filepath.Join(s.storagePath, "tasks", fmt.Sprintf("%s.json", taskID))
	return os.Remove(filePath)
}

// SaveCredential 保存凭证
func (s *EncryptedStorage) SaveCredential(ctx context.Context, credential *types.Credential) error {
	if credential.ID == "" {
		credential.ID = uuid.New().String()
	}
	credential.CreatedAt = time.Now()
	credential.UpdatedAt = time.Now()

	data, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("序列化凭证失败: %v", err)
	}

	encryptedData, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("加密凭证失败: %v", err)
	}

	filePath := filepath.Join(s.storagePath, "credentials", fmt.Sprintf("%s.json", credential.ID))
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("创建凭证目录失败: %v", err)
	}

	if err := os.WriteFile(filePath, encryptedData, 0600); err != nil {
		return fmt.Errorf("写入凭证文件失败: %v", err)
	}

	return nil
}

// GetCredential 获取凭证
func (s *EncryptedStorage) GetCredential(ctx context.Context, credentialID string) (*types.Credential, error) {
	filePath := filepath.Join(s.storagePath, "credentials", fmt.Sprintf("%s.json", credentialID))

	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取凭证文件失败: %v", err)
	}

	data, err := s.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("解密凭证失败: %v", err)
	}

	var credential types.Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return nil, fmt.Errorf("反序列化凭证失败: %v", err)
	}

	return &credential, nil
}

// ListCredentials 列出凭证
func (s *EncryptedStorage) ListCredentials(ctx context.Context, filters map[string]interface{}) ([]*types.Credential, error) {
	credentialsDir := filepath.Join(s.storagePath, "credentials")
	files, err := os.ReadDir(credentialsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.Credential{}, nil
		}
		return nil, fmt.Errorf("读取凭证目录失败: %v", err)
	}

	var credentials []*types.Credential
	for _, file := range files {
		if !file.Type().IsRegular() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		credentialID := strings.TrimSuffix(file.Name(), ".json")
		credential, err := s.GetCredential(ctx, credentialID)
		if err != nil {
			continue
		}

		// 应用过滤器
		if matchesCredentialFilters(credential, filters) {
			credentials = append(credentials, credential)
		}
	}

	return credentials, nil
}

// DeleteCredential 删除凭证
func (s *EncryptedStorage) DeleteCredential(ctx context.Context, credentialID string) error {
	filePath := filepath.Join(s.storagePath, "credentials", fmt.Sprintf("%s.json", credentialID))
	return os.Remove(filePath)
}

// SaveToolResult 保存工具执行结果
func (s *EncryptedStorage) SaveToolResult(ctx context.Context, result *types.ToolResult) error {
	if result.ID == "" {
		result.ID = uuid.New().String()
	}
	// 注意：types.ToolResult可能没有CreatedAt字段，暂时注释掉
	// result.CreatedAt = time.Now()

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("序列化工具结果失败: %v", err)
	}

	encryptedData, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("加密工具结果失败: %v", err)
	}

	filePath := filepath.Join(s.storagePath, "tool_results", result.TaskID, fmt.Sprintf("%s.json", result.ID))
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("创建工具结果目录失败: %v", err)
	}

	if err := os.WriteFile(filePath, encryptedData, 0600); err != nil {
		return fmt.Errorf("写入工具结果文件失败: %v", err)
	}

	return nil
}

// GetToolResults 获取工具执行结果
func (s *EncryptedStorage) GetToolResults(ctx context.Context, taskID string) ([]*types.ToolResult, error) {
	resultsDir := filepath.Join(s.storagePath, "tool_results", taskID)
	files, err := os.ReadDir(resultsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.ToolResult{}, nil
		}
		return nil, fmt.Errorf("读取工具结果目录失败: %v", err)
	}

	var results []*types.ToolResult
	for _, file := range files {
		if !file.Type().IsRegular() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		// 移除未使用的resultID变量
		// resultID := strings.TrimSuffix(file.Name(), ".json")
		filePath := filepath.Join(resultsDir, file.Name())

		encryptedData, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		data, err := s.decrypt(encryptedData)
		if err != nil {
			continue
		}

		var result types.ToolResult
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		results = append(results, &result)
	}

	return results, nil
}

// matchesFilters 检查任务是否匹配过滤器
func matchesFilters(task *types.Task, filters map[string]interface{}) bool {
	for key, value := range filters {
		switch key {
		case "target":
			if task.Target != value {
				return false
			}
		case "status":
			if task.Status != value {
				return false
			}
		case "start_time":
			if startTime, ok := value.(time.Time); ok {
				if task.CreatedAt.Before(startTime) {
					return false
				}
			}
		}
	}
	return true
}

// matchesCredentialFilters 检查凭证是否匹配过滤器
func matchesCredentialFilters(credential *types.Credential, filters map[string]interface{}) bool {
	for key, value := range filters {
		switch key {
		case "target":
			if credential.Target != value {
				return false
			}
		case "type":
			if credential.Type != value {
				return false
			}
		}
	}
	return true
}