package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DeployManager 部署管理结构体
type DeployManager struct {
	buildDir      string
	outputDir     string
	goVersion     string
	supportedOS   []string
	supportedArch []string
}

// BuildConfig 构建配置
type BuildConfig struct {
	OS              string   `json:"os"`              // 目标操作系统
	Arch            string   `json:"arch"`            // 目标架构
	OutputName      string   `json:"output_name"`     // 输出文件名
	BuildTags       []string `json:"build_tags"`      // 构建标签
	LDFlags         []string `json:"ld_flags"`        // 链接标志
	EnableCGO       bool     `json:"enable_cgo"`      // 是否启用CGO
	EmbedResources  bool     `json:"embed_resources"` // 是否嵌入资源
	CompressBinary  bool     `json:"compress_binary"` // 是否压缩二进制文件
}

// NewDeployManager 创建新的部署管理器实例
func NewDeployManager() *DeployManager {
	return &DeployManager{
		buildDir:      filepath.Join(".", "build"),
		outputDir:     filepath.Join(".", "dist"),
		goVersion:     runtime.Version(),
		supportedOS:   []string{"linux", "windows", "darwin"},
		supportedArch: []string{"amd64", "arm64"},
	}
}

// Init 初始化部署管理器
func (dm *DeployManager) Init(ctx context.Context) error {
	// 确保构建目录存在
	if err := os.MkdirAll(dm.buildDir, 0755); err != nil {
		return fmt.Errorf("创建构建目录失败: %v", err)
	}

	// 确保输出目录存在
	if err := os.MkdirAll(dm.outputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	return nil
}

// BuildBinary 构建二进制文件
func (dm *DeployManager) BuildBinary(ctx context.Context, config BuildConfig) (string, error) {
	fmt.Printf("开始构建 %s/%s 二进制文件...\n", config.OS, config.Arch)

	// 设置环境变量
	env := os.Environ()
	if !config.EnableCGO {
		env = append(env, "CGO_ENABLED=0")
	}

	// 设置构建命令
	cmd := dm.getBuildCommand(config)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 执行构建命令
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("构建失败: %v", err)
	}

	outputPath := dm.getOutputPath(config)
	fmt.Printf("构建成功: %s\n", outputPath)

	return outputPath, nil
}

// getBuildCommand 获取构建命令
func (dm *DeployManager) getBuildCommand(config BuildConfig) *exec.Cmd {
	args := []string{"build"}

	// 添加构建标签
	if len(config.BuildTags) > 0 {
		args = append(args, "-tags", strings.Join(config.BuildTags, ","))
	}

	// 添加链接标志
	if len(config.LDFlags) > 0 {
		args = append(args, "-ldflags", strings.Join(config.LDFlags, " "))
	}

	// 设置输出名称
	outputPath := dm.getOutputPath(config)
	args = append(args, "-o", outputPath)

	// 设置主入口文件
	args = append(args, ".")

	// 创建命令
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", config.OS))
	cmd.Env = append(cmd.Env, fmt.Sprintf("GOARCH=%s", config.Arch))
	if !config.EnableCGO {
		cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	}

	return cmd
}

// getOutputPath 获取输出路径
func (dm *DeployManager) getOutputPath(config BuildConfig) string {
	outputName := config.OutputName
	if outputName == "" {
		outputName = "gyscan"
	}

	// 添加操作系统和架构后缀
	outputName = fmt.Sprintf("%s_%s_%s", outputName, config.OS, config.Arch)

	// 添加文件扩展名
	if config.OS == "windows" {
		outputName += ".exe"
	}

	return filepath.Join(dm.outputDir, outputName)
}

// BuildAll 构建所有支持的操作系统和架构的二进制文件
func (dm *DeployManager) BuildAll(ctx context.Context, baseConfig BuildConfig) ([]string, error) {
	var results []string

	// 遍历所有支持的操作系统和架构
	for _, os := range dm.supportedOS {
		for _, arch := range dm.supportedArch {
			// 创建当前平台的构建配置
			config := baseConfig
			config.OS = os
			config.Arch = arch

			// 构建二进制文件
			outputPath, err := dm.BuildBinary(ctx, config)
			if err != nil {
				fmt.Printf("构建 %s/%s 失败: %v\n", os, arch, err)
				continue
			}

			results = append(results, outputPath)
		}
	}

	return results, nil
}

// BuildWithGox 使用Gox批量构建（简化实现）
func (dm *DeployManager) BuildWithGox(ctx context.Context, config BuildConfig) error {
	fmt.Println("使用Gox批量构建...")
	fmt.Println("注意: 此功能需要安装Gox库，当前使用简化实现")
	
	// 简化实现：使用BuildAll方法替代
	_, err := dm.BuildAll(ctx, config)
	if err != nil {
		return fmt.Errorf("批量构建失败: %v", err)
	}

	fmt.Println("批量构建完成")
	return nil
}

// PackageBinary 打包二进制文件
func (dm *DeployManager) PackageBinary(ctx context.Context, binaryPath string, includeResources bool) (string, error) {
	// 创建包文件名
	baseName := strings.TrimSuffix(filepath.Base(binaryPath), filepath.Ext(filepath.Base(binaryPath)))
	packageName := baseName + ".zip"
	packagePath := filepath.Join(dm.outputDir, packageName)

	fmt.Printf("打包二进制文件: %s -> %s\n", binaryPath, packagePath)

	// 这里应该添加打包逻辑，如使用zip库打包二进制文件和相关资源
	// 简化实现：直接复制文件到包目录
	if err := os.WriteFile(packagePath, []byte(fmt.Sprintf("Package for %s", baseName)), 0644); err != nil {
		return "", fmt.Errorf("创建包文件失败: %v", err)
	}

	return packagePath, nil
}

// GenerateBuildInfo 生成构建信息
func (dm *DeployManager) GenerateBuildInfo() map[string]interface{} {
	return map[string]interface{}{
		"go_version":   dm.goVersion,
		"build_time":   time.Now().Format(time.RFC3339),
		"git_commit":   dm.getGitCommit(),
		"git_branch":   dm.getGitBranch(),
		"supported_os": dm.supportedOS,
		"supported_arch": dm.supportedArch,
	}
}

// getGitCommit 获取当前Git提交哈希
func (dm *DeployManager) getGitCommit() string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// getGitBranch 获取当前Git分支
func (dm *DeployManager) getGitBranch() string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// CheckDependencies 检查构建依赖
func (dm *DeployManager) CheckDependencies() map[string]bool {
	deps := map[string]bool{
		"go":     false,
		"git":    false,
		"gox":    false,
		"zip":    false,
	}

	// 检查Go
	if _, err := exec.LookPath("go"); err == nil {
		deps["go"] = true
	}

	// 检查Git
	if _, err := exec.LookPath("git"); err == nil {
		deps["git"] = true
	}

	// 检查Gox
	if _, err := exec.LookPath("gox"); err == nil {
		deps["gox"] = true
	}

	// 检查Zip
	if _, err := exec.LookPath("zip"); err == nil {
		deps["zip"] = true
	}

	return deps
}

// EmbedResources 嵌入资源文件
func (dm *DeployManager) EmbedResources(ctx context.Context, resourceDir string) error {
	// 这里应该添加资源嵌入逻辑
	// 简化实现：创建资源嵌入配置文件
	configPath := filepath.Join(dm.buildDir, "resources.json")
	configContent := fmt.Sprintf(`{
	"resource_dir": "%s",
	"embed_time": "%s",
	"resources": [
		// 资源文件列表将在这里生成
	]
}`, resourceDir, time.Now().Format(time.RFC3339))

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("创建资源配置文件失败: %v", err)
	}

	fmt.Printf("资源嵌入配置已生成: %s\n", configPath)
	return nil
}
