# GYscan - 内网横向边界安全测试工具

## 项目简介

GYscan是一款专注于内网横向移动和边界安全测试的专业工具，基于Go语言开发。该工具集成了丰富的内网渗透测试功能，包括端口扫描、服务识别、漏洞检测、远程命令执行、弱口令爆破等核心功能，为安全研究人员和渗透测试人员提供高效、可靠的内网安全评估解决方案。

## 核心优势

- **专注内网安全**：专门针对内网横向移动和边界安全测试场景优化
- **功能丰富**：集成了端口扫描、服务识别、远程命令执行、弱口令爆破等多种功能
- **跨平台支持**：支持Windows、Linux、macOS三大主流操作系统
- **模块化设计**：采用插件化架构，支持功能扩展和自定义模块开发
- **易用性强**：提供简洁的命令行界面和详细的帮助文档
- **性能优异**：基于Go语言开发，具备出色的并发处理能力

### 📋 基本信息

| 项目 | 信息 |
|------|------|
| **项目名称** | GYscan |
| **开发语言** | Go 1.24+ |
| **支持平台** | Windows 7+/Linux/macOS |
| **许可证** | Apache2.0 |
| **最新版本** | v2.5.0 |

### ⚠️ 法律声明

**重要提示**: 本工具仅用于授权的安全测试目的。任何未授权的使用行为均属违法，使用者需承担相应的法律责任。

## 🚀 快速上手

### 环境准备

1. **安装Go环境** (版本1.18+)
   ```bash
   # 下载并安装Go
   https://golang.org/dl/
   
   # 验证安装
   go version
   ```

2. **获取项目代码**
   ```bash
   git clone https://github.com/xiguayiqiu/GYscan.git
   cd GYscan
   ```

### 编译安装

#### Windows平台编译
```bash
# 编译客户端
cd Client
go build -o GYscan.exe
```

#### Linux平台编译
```bash
# 编译客户端
cd Client
go build -o GYscan-linux-amd64
```

#### 交叉编译
```bash
# 编译Windows版本（在Linux上）
cd Client
GOOS=windows GOARCH=amd64 go build -o GYscan.exe

# 编译Linux版本（在Windows上）
cd Client
GOOS=linux GOARCH=amd64 go build -o GYscan-linux-amd64
```

### 一键构建脚本
```bash
# Windows平台
.build.ps1

# Linux平台
chmod +x build_linux.sh
./build_linux.sh
```

## 📋 功能列表

### 核心功能

| 命令 | 功能描述 | 状态 |
|------|----------|------|
| about | 查看工具信息 | ✅ 稳定 |
| crunch | 密码字典生成工具 | ✅ 稳定 |
| csrf | CSRF漏洞检测 | ⚠️ 测试阶段 |
| database | 数据库密码破解工具 | ✅ 稳定 |
| dirscan | 网站目录扫描工具 | ✅ 稳定 |
| ftp | FTP密码破解工具 | ✅ 稳定 |
| powershell | PowerShell远程执行工具 [WinRM服务利用] | ✅ 稳定 |
| process | 进程与服务信息收集工具 | ✅ 稳定 |
| rdp | RDP远程桌面工具 | ✅ 稳定 |
| route | 路由跳数检测 | ✅ 稳定 |
| sam | Windows SAM文件分析工具 | ⚠️ 测试阶段 |
| scan | 网络扫描工具，支持主机发现、端口扫描、服务识别等功能 | ✅ 稳定 |
| smb | SMB协议操作工具 | ✅ 稳定 |
| ssh | SSH密码爆破工具（Hydra风格） | ✅ 稳定 |
| userinfo | 本地用户和组分析 | ✅ 稳定 |
| webshell | WebShell生成工具 | ✅ 稳定 |
| wmi | WMI远程管理工具 | ✅ 稳定 |
| xss | XSS漏洞检测工具，支持反射型、存储型、DOM型XSS检测 | ✅ 稳定 |

## 💡 常用功能使用示例

### 1. 网络扫描

```bash
# 扫描单个IP地址
./GYscan.exe scan --target 192.168.1.100

# 扫描IP段
./GYscan.exe scan --target 192.168.1.0/24

# 扫描指定端口范围
./GYscan.exe scan --target 192.168.1.100 --ports 80,443,22,21
```

### 2. PowerShell远程执行

```bash
# 执行远程PowerShell命令
./GYscan.exe powershell exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"

# 测试WinRM端口
./GYscan.exe powershell test --target 192.168.1.100 --port 5985

# 使用HTTPS连接
./GYscan.exe powershell exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami" --https
```

### 3. WMI远程管理

```bash
# 获取操作系统信息
./GYscan.exe wmi osinfo --target 192.168.1.100 --user Administrator --password "Password123"

# 执行远程命令
./GYscan.exe wmi exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"

# 列出远程进程
./GYscan.exe wmi processes --target 192.168.1.100 --user Administrator --password "Password123"

# 查询WMI数据
./GYscan.exe wmi query --target 192.168.1.100 --user Administrator --password "Password123" --query "SELECT * FROM Win32_OperatingSystem"
```

### 4. RDP远程桌面

```bash
# 检查RDP服务可用性
./GYscan.exe rdp check --target 192.168.1.100

# 连接到RDP服务
./GYscan.exe rdp connect --target 192.168.1.100 --user Administrator --password "Password123"

# 列出RDP会话
./GYscan.exe rdp sessions --target 192.168.1.100 --user Administrator --password "Password123"

# 列出远程进程
./GYscan.exe rdp processes --target 192.168.1.100 --user Administrator --password "Password123"
```

### 5. SMB协议操作

```bash
# 检测SMB版本
./GYscan.exe smb version --target 192.168.1.100

# 列出SMB共享
./GYscan.exe smb shares --target 192.168.1.100 --user Administrator --password "Password123"

# 执行远程命令
./GYscan.exe smb exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"
```

### 6. 漏洞检测

```bash
# XSS漏洞检测
./GYscan.exe xss --target http://example.com --payload "<script>alert('xss')</script>"

# CSRF漏洞检测
./GYscan.exe csrf --target http://example.com/vul/csrf.php -X POST -d "action=delete&id=1"
```

### 7. 弱口令爆破

```bash
# SSH弱口令检测
./GYscan.exe ssh --target 192.168.1.100 --user admin --wordlist passwords.txt

# FTP弱口令检测
./GYscan.exe ftp --target 192.168.1.100 --user anonymous --wordlist passwords.txt
```

## ⚙️ 高级配置

### 性能调优

```bash
# 设置并发线程数
./GYscan.exe scan --target 192.168.1.0/24 --threads 50

# 设置超时时间
./GYscan.exe scan --target 192.168.1.100 --timeout 3
```

### 输出控制

```bash
# 静默模式（仅输出关键结果）
./GYscan.exe scan --target 192.168.1.100 --silent

# 详细输出模式
./GYscan.exe scan --target 192.168.1.100 --verbose

# 更详细的输出模式
./GYscan.exe scan --target 192.168.1.100 --very-verbose
```

## 🏗️ 技术架构

### 项目结构

```
GYscan/
├── C2/                    # C2服务器端
│   ├── Linux/             # Linux版本C2
│   └── Windows/           # Windows版本C2
├── Client/                # 客户端主程序
│   ├── main.go            # 程序主入口
│   ├── go.mod             # Go模块依赖
│   ├── go.sum             # Go模块校验
│   ├── internal/          # 内部包
│   │   ├── cli/           # 命令行界面
│   │   ├── csrf/          # CSRF漏洞检测模块
│   │   ├── database/      # 数据库相关功能
│   │   ├── dirscan/       # 目录扫描模块
│   │   ├── ftp/           # FTP相关功能
│   │   ├── network/       # 网络相关功能
│   │   ├── nmap/          # Nmap集成功能
│   │   ├── plugin/        # 插件系统
│   │   ├── powershell/    # PowerShell远程执行模块
│   │   ├── process/       # 进程相关功能
│   │   ├── rdp/           # RDP远程桌面模块
│   │   ├── sam/           # SAM文件分析
│   │   ├── samcrack/      # SAM密码破解
│   │   ├── security/      # 安全相关功能
│   │   ├── smb/           # SMB协议操作模块
│   │   ├── ssh/           # SSH相关功能
│   │   ├── userinfo/      # 用户信息收集
│   │   ├── utils/         # 工具函数
│   │   ├── webshell/      # WebShell相关功能
│   │   ├── wmi/           # WMI远程管理模块
│   │   └── xss/           # XSS漏洞检测模块
│   └── dirmap/            # 目录扫描字典
├── PSTools/               # 微软提供的Windows系统的测试工具
├── build.ps1              # Windows构建脚本
└── build_linux.sh         # Linux构建脚本
```

### 技术特性

#### 高性能并发
- **Go原生并发** - 基于goroutine的轻量级并发模型
- **智能线程管理** - 可配置的并发线程数
- **超时控制** - 可配置的超时机制，避免无限等待

#### 安全机制
- **错误隔离** - 模块化错误处理，避免单点故障
- **资源管理** - 智能资源释放，防止内存泄漏
- **输入验证** - 严格的参数验证，确保操作安全

#### 用户体验
- **实时进度** - 详细的扫描进度和统计信息
- **多种输出** - 支持控制台、文件输出格式
- **智能提示** - 友好的错误提示和使用建议

#### 扩展性设计
- **模块化架构** - 清晰的模块分离，易于功能扩展
- **配置驱动** - 灵活的配置系统，支持多种场景
- **标准接口** - 统一的接口规范，便于二次开发

## 📊 开发状态

### 当前稳定功能
- ✅ 基础端口扫描（TCP/UDP）
- ✅ 服务识别和指纹采集
- ✅ PowerShell远程执行工具 [WinRM服务利用]
- ✅ WMI远程管理工具
- ✅ RDP远程桌面工具
- ✅ SMB协议操作工具
- ✅ 弱口令爆破框架
- ✅ 基础漏洞检测（XSS、CSRF等）
- ✅ 命令行界面
- ✅ 配置文件管理

### 近期优化
- ✅ 完善PowerShell模块功能，支持HTTPS连接
- ✅ 优化WMI模块功能，增强远程管理能力
- ✅ 完善RDP模块功能，支持会话管理和进程查看
- ✅ 优化SMB模块功能，支持版本检测和共享枚举
- ✅ 改进各功能模块的性能和稳定性
- ✅ 更新帮助文档和示例

### 计划功能
- ⏳ 高级漏洞检测插件
- ⏳ 分布式扫描架构

## 📝 更新日志

### v2.5.0 (最新版本)
- **新功能**: 完善PowerShell模块，添加HTTPS支持
- **新功能**: 增强WMI模块功能，支持更多远程管理操作
- **新功能**: 完善RDP模块，支持会话管理和进程查看
- **新功能**: 优化SMB模块，支持版本检测和共享枚举
- **代码优化**: 优化各模块代码结构和性能

### v2.0.1
- **功能优化**: 移除Payload生成功能，专注安全测试
- **代码优化**: 优化代码结构和性能
- **文档完善**: 更新帮助文档和示例

### v2.0.0
- **新功能**: 新增CSRF漏洞检测模块
- **功能增强**: 完善XSS检测功能
- **模块优化**: 改进各功能模块的性能和稳定性

### v1.0.0
- **初始发布**: 基础端口扫描功能
- **功能实现**: 服务识别和指纹采集
- **框架搭建**: 弱口令爆破框架
- **基础检测**: 基础漏洞检测功能

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进项目。请确保：
1. 代码符合Go语言规范
2. 添加适当的测试用例
3. 更新相关文档
4. 遵循安全开发规范

## 📄 许可证

本项目采用MIT许可证。详情请查看LICENSE文件。

## ⚠️ 免责声明

**重要提示**: 本工具仅供安全研究和授权测试使用。任何未授权的使用行为均属违法，使用者需承担相应的法律责任。作者不承担任何因使用本工具而产生的直接或间接责任。

---

**GYscan - 专注内网安全，守护网络边界** 🛡️