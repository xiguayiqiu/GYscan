# GYscan - Go语言内网横向渗透测试工具

GYscan是一款基于Go语言开发的内网横向渗透测试工具，采用模块化架构设计，包含C2服务器端和客户端组件，支持Windows和Linux平台的系统安全分析和网络扫描功能。

## ✨ 核心优势

- **跨平台兼容** - 原生支持Windows和Linux系统，无需额外依赖
- **模块化架构** - 清晰的C2服务器端和客户端分离设计，便于功能扩展
- **高性能并发** - 基于Go语言的轻量级goroutine并发模型，支持多线程扫描
- **安全可靠** - 支持流量加密和代理转发，保障测试安全
- **易用性强** - 友好的命令行界面和详细的进度提示，支持多种输出格式

### 🎯 适用场景

- **内网横向渗透测试** - 企业内网安全评估和漏洞检测
- **红队演练** - 模拟攻击者行为，测试防御体系
- **安全研究** - 系统安全配置分析和用户信息收集
- **合规检查** - 满足等保、ISO27001等安全标准要求

### 📋 基本信息

| 项目 | 信息 |
|------|------|
| **项目名称** | GYscan |
| **开发语言** | Go 1.24.5+ |
| **支持平台** | Windows 7+/Linux (CentOS 7+, Ubuntu 16.04+) |
| **许可证** | Apache 2.0 |
| **最新版本** | v2.0.1 |

### ⚠️ 法律声明

**重要提示**: 本工具仅用于授权的安全测试目的。任何未授权的使用行为均属违法，使用者需承担相应的法律责任。

## 🚀 快速上手

### 环境准备

1. **安装Go环境** (版本1.24.5+)
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
# 编译C2服务器端
cd C2\Windows
go build -o GYscan_C2_Windows.exe

# 编译客户端
cd ..\..\Client
go build -o GYscan_Client.exe
```

#### Linux平台编译
```bash
# 编译C2服务器端
cd C2/Linux
go build -o GYscan_C2_Linux

# 编译客户端
cd ../../Client
go build -o GYscan_Client
```

### 基础使用

#### C2服务器端使用
```bash
# Windows平台
GYscan_C2_Windows.exe userinfo -o user_report.html
GYscan_C2_Windows.exe ssh -o ssh_report.html

# Linux平台  
./GYscan_C2_Linux userinfo -o user_report.txt
./GYscan_C2_Linux ssh -o ssh_report.txt
```

#### 客户端使用
```bash
# 网络扫描
GYscan_Client.exe scan 192.168.1.0/24

# 目录扫描
GYscan_Client.exe dirscan http://target.com

# 服务破解
GYscan_Client.exe ftp 192.168.1.100 -u admin -p password.txt
```

### 🎯 实战示例

#### 示例1：Windows用户信息分析
```bash
# 分析Windows系统用户信息并生成报告
.\GYscan-Win-C2.exe userinfo
```

#### 示例2：Linux用户信息分析
```bash
# 分析Linux系统用户信息并生成报告
.\GYscan-linux-C2.exe userinfo
```

#### 示例3：Windows容器安全扫描
```bash
# 扫描Windows容器安全配置
.\GYscan-Win-C2.exe trivy
```

#### 示例4：SSH安全配置分析
```bash
# Windows平台SSH安全配置分析
.\GYscan_C2_Windows.exe ssh -o ssh_report.html

# Linux平台SSH安全配置分析
./GYscan_C2_Linux ssh -o ssh_report.txt
```

### ⚙️ 高级配置

#### 性能调优
```bash
# 设置并发线程数
GYscan_Client.exe dirscan http://target.com -t 100

# 设置超时时间
GYscan_Client.exe scan 192.168.1.0/24 --timeout 10s
```

#### 输出控制
```bash
# 静默模式（仅输出结果）
GYscan_Client.exe --silent scan 192.168.1.1

# 输出到文件
GYscan_Client.exe scan 192.168.1.0/24 -o results.json
```

## 🛠️ 核心功能模块

GYscan采用模块化架构，包含C2服务器端和客户端组件，支持Windows和Linux平台的系统安全分析和网络扫描功能。

### 📊 功能模块概览

| 组件类型 | 平台 | 主要功能 | 技术特点 |
|---------|------|---------|---------|
| **C2服务器端** | Windows | 用户信息分析、SSH安全配置分析 | 基于系统API，支持HTML报告生成 |
| **C2服务器端** | Linux | 用户信息分析、SSH安全配置分析 | 基于系统命令，支持文本报告生成 |
| **客户端** | 跨平台 | 网络扫描、服务破解、负载测试 | 多线程并发，模块化设计 |

### 1. C2服务器端 - Windows平台
Windows C2服务器端提供系统安全分析和用户信息检测功能：

**主要功能：**
- **用户信息分析** - 分析本地用户和组信息
- **SSH安全配置分析** - 检测SSH服务安全配置
- **HTML报告生成** - 生成美观的HTML格式安全报告

**技术特点：**
- 基于Windows系统API实现
- 支持子命令模式（userinfo/ssh）
- 自动识别输出文件路径
- 详细的扫描摘要和统计信息

### 2. C2服务器端 - Linux平台
Linux C2服务器端提供系统安全分析和用户信息检测功能：

**主要功能：**
- **用户信息分析** - 分析本地用户和组信息
- **SSH安全配置分析** - 检测SSH服务安全配置
- **文本报告生成** - 生成文本格式的报告

**技术特点：**
- 基于Linux系统命令实现
- 支持子命令模式（userinfo/ssh）
- 跨发行版兼容性
- 详细的执行时间统计

### 3. 客户端组件
客户端组件提供网络扫描、服务破解和负载测试功能：

**主要功能：**
- **网络扫描** - 主机发现和端口扫描
- **服务破解** - FTP/SSH等服务密码破解
- **Web安全** - 目录扫描和WebShell生成
- **负载测试** - 支持多种协议的负载压力测试

**技术特点：**
- 多线程并发处理
- 模块化架构设计
- 支持多种输出格式
- 完善的错误处理机制

## 🔧 全局参数

```bash
./GYscan.exe [command] [flags]

全局参数:
  -h, --help           显示帮助信息
  -v, --version        显示版本信息
  -s, --silent         静默模式，仅输出关键结果
      --key string     流量加密密钥 (AES-256)
      --proxy string   代理服务器 (支持 HTTP/SOCKS5)
```

## 🏗️ 技术架构

### 项目结构
GYscan采用模块化架构设计，包含C2服务器端和客户端组件：

```
GYscan/
├── C2/                     # C2服务器端组件
│   ├── Windows/           # Windows C2服务器端
│   │   ├── internal/      # 内部模块
│   │   │   ├── userinfo/  # 用户信息分析模块
│   │   │   ├── trivy/     # 容器安全扫描模块
│   │   │   └── ssh/       # SSH安全配置分析模块
│   │   ├── main.go        # 主程序入口
│   │   ├── scanner.go     # 扫描器核心
│   │   ├── report.go      # 报告生成模块
│   │   └── middleware.go  # 中间件模块
│   └── Linux/             # Linux C2服务器端
│       ├── internal/      # 内部模块
│       │   ├── userinfo/  # 用户信息分析模块
│       │   ├── trivy/     # 容器安全扫描模块
│       │   └── ssh/       # SSH安全配置分析模块
│       ├── main.go        # 主程序入口
│       ├── scanner.go     # 扫描器核心
│       └── report.go      # 报告生成模块
├── Client/                 # 客户端组件
│   ├── internal/          # 内部功能模块
│   │   ├── cli/           # 命令行接口
│   │   ├── database/      # 数据库破解
│   │   ├── dirscan/       # 目录扫描
│   │   ├── ftp/           # FTP服务破解
│   │   ├── nmap/          # 网络扫描
│   │   ├── process/       # 进程分析
│   │   ├── sam/           # SAM文件分析
│   │   ├── ssh/           # SSH服务破解
│   │   ├── userinfo/      # 用户信息分析
│   │   ├── webshell/      # WebShell生成
│   │   └── loadtest/      # 负载测试模块
│   └── main.go            # 主程序入口
└── README.md              # 项目文档
```

### 🔧 技术特性

#### 🚀 高性能并发
- **Go原生并发** - 基于goroutine的轻量级并发模型
- **连接池管理** - 智能连接复用，减少资源开销
- **超时控制** - 可配置的超时机制，避免无限等待

#### 🔒 安全机制
- **流量加密** - AES-256加密传输，防止数据泄露
- **代理支持** - HTTP/SOCKS5代理，增强匿名性
- **错误隔离** - 模块化错误处理，避免单点故障

#### 📊 用户体验
- **实时进度** - 详细的进度条和统计信息
- **多种输出** - 支持控制台、文件、JSON多种输出格式
- **智能提示** - 友好的错误提示和使用建议

#### 🔄 扩展性设计
- **插件架构** - 模块化设计，易于功能扩展
- **配置驱动** - 灵活的配置系统，支持多种场景
- **标准接口** - 统一的接口规范，便于二次开发

## 📊 开发状态

### 已完成功能
- [x] 项目基础结构和模块化架构
- [x] Windows C2服务器端 - 用户信息分析功能 (userinfo子命令)
- [x] Windows C2服务器端 - SSH安全配置分析功能 (ssh子命令)
- [x] Linux C2服务器端 - 用户信息分析功能 (userinfo子命令)
- [x] Linux C2服务器端 - SSH安全配置分析功能 (ssh子命令)
- [x] HTML报告生成功能 (Windows平台)
- [x] 文本报告生成功能 (Linux平台)
- [x] 子命令参数解析和路径识别
- [x] 详细的执行时间统计和扫描摘要
- [x] 客户端网络扫描和负载测试功能

## 📝 更新日志

### v2.0.1 (最新版本)
- **新增功能**: C2端的Linux系统SSH安全配置分析
- **功能优化**: 移除CVE漏洞检测功能，专注于核心安全分析
- **代码清理**: 删除Windows和Linux版本中所有CVE相关代码残留
- **版本更新**: 统一更新所有组件版本号为v2.0.1

### v2.0.0
- **架构重构**: 分离C2服务器端和客户端组件
- **平台兼容**: 增强Windows和Linux平台的兼容性
- **参数优化**: 优化子命令参数解析机制
- **报告改进**: 改进报告生成格式和内容

### v1.0.0
- **初始发布**: 集成C2服务器端和客户端组件
- **平台支持**: 支持Windows和Linux平台的系统安全分析
- **功能实现**: 实现用户信息分析功能
- **报告支持**: 支持HTML和文本报告生成
- **错误处理**: 完善的子命令参数解析和错误处理

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进项目。请确保：
1. 代码符合Go语言规范
2. 添加适当的测试用例
3. 更新相关文档
4. 遵循安全开发规范

## 📄 许可证

本工具仅用于授权的安全测试目的。使用者需承担相应的法律责任。

---

**免责声明**: 本工具仅供安全研究和授权测试使用，任何未授权的使用行为与作者无关。