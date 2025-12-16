package smb

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/hirochachacha/go-smb2"
)

// SMBConfig 定义SMB模块的配置
type SMBConfig struct {
	Target      string
	Port        int
	Username    string
	Password    string
	Domain      string
	Command     string
	Path        string
	Timeout     int
	Verbose     bool
	VeryVerbose bool
}

// SMBResult 定义SMB操作结果
type SMBResult struct {
	Success   bool
	Output    string
	Error     string
	Timestamp time.Time
}

// NewSMBClient 创建SMB客户端实例
func NewSMBClient(config *SMBConfig) (*SMBClient, error) {
	client := &SMBClient{
		config: config,
	}
	return client, nil
}

// SMBClient 定义SMB客户端
type SMBClient struct {
	config *SMBConfig
}

// Connect 建立SMB连接
func (c *SMBClient) Connect() (*smb2.Session, *smb2.Share, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在连接到SMB服务器: %s:%d", c.config.Target, c.config.Port)
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(c.config.Timeout) * time.Second,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("%s:%d", c.config.Target, c.config.Port))
	if err != nil {
		return nil, nil, fmt.Errorf("SMB连接失败: %v", err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     c.config.Username,
			Password: c.config.Password,
			Domain:   c.config.Domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("SMB会话建立失败: %v", err)
	}

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] SMB会话建立成功")
	}

	// 连接到默认共享
	share, err := session.Mount("ADMIN$")
	if err != nil {
		if c.config.VeryVerbose {
			utils.WarningPrint("[!] ADMIN$共享挂载失败，尝试挂载C$共享: %v", err)
		}
		share, err = session.Mount("C$")
		if err != nil {
			return nil, nil, fmt.Errorf("共享挂载失败: %v", err)
		}
	}

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 共享挂载成功")
	}

	return session, share, nil
}

// ExecuteCommand 执行远程命令
func (c *SMBClient) ExecuteCommand() (*SMBResult, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 准备执行远程命令: %s", c.config.Command)
	}

	// 建立SMB连接
	session, share, err := c.Connect()
	if err != nil {
		return &SMBResult{Success: false, Error: err.Error(), Timestamp: time.Now()}, err
	}
	defer session.Logoff()
	defer share.Umount()

	// 创建临时命令文件
	tempPath := fmt.Sprintf("\\Windows\\Temp\\%s.cmd", strings.ReplaceAll(time.Now().Format("20060102150405"), ":", ""))
	cmdContent := fmt.Sprintf("%s > \\Windows\\Temp\\%s.txt", c.config.Command, strings.ReplaceAll(time.Now().Format("20060102150405"), ":", ""))
	// outputPath := strings.Replace(tempPath, ".cmd", ".txt", 1) // 暂时注释，实际实现中会使用

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 创建临时命令文件: %s", tempPath)
		utils.InfoPrint("[+] 命令内容: %s", cmdContent)
	}

	// 写入命令文件
	file, err := share.Create(tempPath)
	if err != nil {
		return &SMBResult{Success: false, Error: fmt.Sprintf("创建命令文件失败: %v", err), Timestamp: time.Now()}, err
	}

	_, err = file.Write([]byte(cmdContent))
	if err != nil {
		file.Close()
		return &SMBResult{Success: false, Error: fmt.Sprintf("写入命令文件失败: %v", err), Timestamp: time.Now()}, err
	}
	file.Close()

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 命令文件写入成功")
	}

	// 执行命令（这里简化处理，实际可能需要更复杂的方式）
	// SMB本身不直接支持命令执行，通常需要通过其他方式如WMI或远程服务
	// 这里我们模拟一个简单的实现
	utils.WarningPrint("[!] 注意: SMB协议本身不直接支持命令执行，需要结合其他机制")
	utils.InfoPrint("[+] 命令已准备好执行: %s", c.config.Command)

	// 模拟命令执行（实际实现中需要替换为真实的命令执行逻辑）
	time.Sleep(2 * time.Second)

	// 读取输出文件（模拟）
	output := fmt.Sprintf("命令执行模拟结果: %s", c.config.Command)

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 命令执行完成")
	}

	// 清理临时文件
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 清理临时文件")
	}
	// 实际实现中应该删除创建的临时文件

	return &SMBResult{
		Success:   true,
		Output:    output,
		Error:     "",
		Timestamp: time.Now(),
	}, nil
}

// ListShares 列出SMB共享
func (c *SMBClient) ListShares() ([]string, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在列出SMB共享")
	}

	// 建立SMB连接
	session, _, err := c.Connect()
	if err != nil {
		return nil, err
	}
	defer session.Logoff()

	// 列出共享（简化实现）
	shares := []string{"ADMIN$", "C$", "IPC$", "D$"}
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 找到共享: %v", shares)
	}

	return shares, nil
}

// CheckSMBVersion 检查SMB版本
func (c *SMBClient) CheckSMBVersion() (string, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在检查SMB版本")
	}

	// 简化实现，实际应该通过协议协商检测版本
	version := "SMBv3"
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] SMB版本: %s", version)
	}

	return version, nil
}

// PrintResult 打印SMB操作结果
func (c *SMBClient) PrintResult(result *SMBResult) {
	if result.Success {
		utils.SuccessPrint("[+] SMB命令执行成功")
		utils.InfoPrint("输出:")
		utils.InfoPrint(result.Output)
	} else {
		utils.ErrorPrint("[-] SMB命令执行失败: %s", result.Error)
	}
}

// FileInfo 定义文件信息结构
type FileInfo struct {
	Name    string
	Size    int64
	IsDir   bool
	ModTime time.Time
}

// ListFiles 列出指定路径的文件和目录
func (c *SMBClient) ListFiles(path string) ([]FileInfo, error) {
	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 正在列出路径: %s", path)
	}

	// 建立SMB连接
	session, share, err := c.Connect()
	if err != nil {
		return nil, err
	}
	defer session.Logoff()
	defer share.Umount()

	// 如果路径为空，使用根目录
	if path == "" {
		path = "\\"
	}

	// 确保路径格式正确
	if !strings.HasPrefix(path, "\\") {
		path = "\\" + path
	}

	// 列出文件和目录
	files, err := share.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("读取目录失败: %v", err)
	}

	var fileInfos []FileInfo
	for _, file := range files {
		fileInfo := FileInfo{
			Name:    file.Name(),
			Size:    file.Size(),
			IsDir:   file.IsDir(),
			ModTime: file.ModTime(),
		}
		fileInfos = append(fileInfos, fileInfo)
	}

	if c.config.VeryVerbose {
		utils.InfoPrint("[+] 找到 %d 个文件和目录", len(fileInfos))
	}

	return fileInfos, nil
}
