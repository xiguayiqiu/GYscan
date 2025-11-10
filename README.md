# GYscan - 专业的Go语言内网横向渗透测试工具

[![Go Version](https://img.shields.io/badge/Go-1.24.5%2B-blue?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache2.0-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2FLinux-lightgrey)](https://github.com/your-repo/GYscan)

## **一款专为内网渗透测试设计的全能安全工具**

## 🚀 项目简介

GYscan是一款基于Go语言开发的现代化内网横向渗透测试工具，专为安全研究人员、渗透测试工程师和红队成员设计。项目采用模块化架构，包含C2服务器端和客户端组件，支持Windows和Linux平台，提供系统安全分析和漏洞扫描功能。

### 🌟 核心优势

| 特性 | 描述 | 价值 |
|------|------|------|
| **🔧 模块化设计** | 13个独立功能模块，按需使用 | 灵活应对不同测试场景 |
| **⚡ 高性能并发** | Go原生goroutine并发模型 | 大幅提升测试效率 |
| **🔄 跨平台兼容** | Windows/Linux全支持 | 适应各种测试环境 |
| **📚 功能全面** | 网络扫描、服务破解、信息收集一体化 | 减少工具切换成本 |
| **🔒 安全可靠** | 完善的错误处理和资源管理 | 保障测试过程稳定 |

### 🎯 适用场景

- 🛡️Windows系统的横向本项目提供了PStool工具包

- **🔍 内网安全评估** - 企业内部网络安全性测试
- **🛡️ 红队演练** - 模拟攻击者进行内网横向移动
- **📊 安全审计** - 系统和服务安全配置检查
- **🎓 安全学习** - 了解内网渗透测试技术和方法

### 📋 基本信息

| 项目信息 | 详情 |
|---------|------|
| **作者** | BiliBili-弈秋啊 |
| **版本** | v2.0.1 |
| **语言** | Go 1.24.5+ |
| **平台** | Windows/Linux |
| **许可证** | 仅限授权安全测试使用 |

## ⚠️ 重要警告

**🚨 法律声明：本工具仅用于已授权的内网安全测试，严禁未授权使用！**  

使用者必须确保：
- ✅ 获得目标系统的明确授权
- ✅ 遵守当地法律法规
- ✅ 承担使用本工具所产生的全部法律责任
- ✅ 仅用于安全研究和教育目的

## 🚀 快速上手

### 环境准备

确保您的系统满足以下要求：
- **操作系统**: Windows/Linux
- **Go版本**: 1.24.5+ (仅编译需要)
- **内存**: 至少512MB可用内存
- **网络**: 稳定的网络连接（网络扫描功能需要）

### 编译安装

#### 方法一：源码编译（推荐）
```bash
# 克隆项目
git clone https://gitee.com/bzhanyiqiua/GYscan.git
git clone https://github.com/xiguayiqiu/GYscan.git

# 编译Windows C2服务器端
cd C2\Windows
go build -o GYscan-Win-C2.exe .

# 编译Linux C2服务器端
cd C2\Linux
go build -o GYscan-linux-C2.exe .

# 编译客户端
cd Client
go build -o GYscan-Client.exe .

# 验证安装
.\GYscan-Win-C2.exe --version
```

#### 方法二：直接下载
从 [GitHub Releases页面](https://github.com/xiguayiqiu/GYscan/releases) 下载预编译的二进制文件。
从 [Gitee Releases页面](https://gitee.com/bzhanyiqiua/GYscan/releases) 下载预编译的二进制文件

### 基础使用

#### 1. C2服务器端使用
```bash
# Windows C2服务器 - 用户信息分析
.\GYscan-Win-C2.exe userinfo

# Windows C2服务器 - 容器安全扫描
.\GYscan-Win-C2.exe trivy

# Windows C2服务器 - SSH服务检测
.\GYscan-Win-C2.exe ssh

# Linux C2服务器 - 用户信息分析
.\GYscan-linux-C2.exe userinfo

# Linux C2服务器 - 容器安全扫描
.\GYscan-linux-C2.exe trivy

# Linux C2服务器 - SSH服务检测
.\GYscan-linux-C2.exe ssh
```

#### 2. 查看工具信息
```bash
.\GYscan-Win-C2.exe --version
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

#### 示例4：Linux容器安全扫描
```bash
# 扫描Linux容器安全配置
.\GYscan-linux-C2.exe trivy
```

#### 示例5：SSH服务检测
```bash
# 检测SSH服务配置和安全性
.\GYscan-Win-C2.exe ssh
```

### ⚙️ 高级配置

#### 性能调优
```bash
# 设置并发线程数
.\GYscan.exe dirscan http://target.com -t 100

# 设置超时时间
.\GYscan.exe scan 192.168.1.0/24 --timeout 10s
```

#### 输出控制
```bash
# 静默模式（仅输出结果）
.\GYscan.exe --silent scan 192.168.1.1

# 输出到文件
.\GYscan.exe scan 192.168.1.0/24 -o results.json
```

## 🛠️ 核心功能模块

GYscan采用模块化架构，包含C2服务器端和客户端组件，支持Windows和Linux平台的系统安全分析和漏洞扫描功能。

### 📊 功能模块概览

| 组件类型 | 平台 | 主要功能 | 技术特点 |
|---------|------|---------|---------|
| **C2服务器端** | Windows | 用户信息分析、系统安全检测 | 基于系统API，支持HTML报告生成 |
| **C2服务器端** | Linux | 用户信息分析、系统安全检测 | 基于系统命令，支持文本报告生成 |
| **客户端** | 跨平台 | 网络扫描、服务破解、Web安全 | 多线程并发，模块化设计 |

### 1. C2服务器端 - Windows平台
Windows C2服务器端提供系统安全分析和用户信息检测功能：

**主要功能：**
- **用户信息分析** - 分析本地用户和组信息
- **系统安全检测** - 检测Windows系统安全配置
- **HTML报告生成** - 生成美观的HTML格式安全报告
- **文本报告生成** - 生成简洁的文本格式用户信息报告

**技术特点：**
- 基于Windows系统API实现
- 支持子命令模式（userinfo/trivy/ssh）
- 自动识别输出文件路径
- 详细的扫描摘要和统计信息

### 2. C2服务器端 - Linux平台
Linux C2服务器端提供系统安全分析和用户信息检测功能：

**主要功能：**
- **用户信息分析** - 分析本地用户和组信息
- **系统安全检测** - 检测Linux系统安全配置
- **文本报告生成** - 生成文本格式的报告

**技术特点：**
- 基于Linux系统命令实现
- 支持子命令模式（userinfo/trivy/ssh）
- 跨发行版兼容性
- 详细的执行时间统计

### 3. 客户端组件
客户端组件提供网络扫描、服务破解和Web安全测试功能：

**主要功能：**
- **网络扫描** - 主机发现和端口扫描
- **服务破解** - FTP/SSH等服务密码破解
- **Web安全** - 目录扫描和WebShell生成
- **数据库安全** - 多种数据库密码破解

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
│   │   │   └── vulnscan/  # 漏洞扫描模块
│   │   ├── main.go        # 主程序入口
│   │   ├── scanner.go     # 扫描器核心
│   │   ├── report.go      # 报告生成模块
│   │   └── middleware.go  # 中间件模块
│   └── Linux/             # Linux C2服务器端
│       ├── internal/      # 内部模块
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
│   │   └── webshell/      # WebShell生成
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
- [x] Windows C2服务器端 - 漏洞扫描功能 (cve子命令)
- [x] Windows C2服务器端 - 用户信息分析功能 (userinfo子命令)
- [x] Linux C2服务器端 - 漏洞扫描功能 (cve子命令)
- [x] Linux C2服务器端 - 用户信息分析功能 (userinfo子命令)
- [x] HTML报告生成功能 (Windows平台)
- [x] 文本报告生成功能 (Linux平台)
- [x] 子命令参数解析和路径识别
- [x] 详细的执行时间统计和扫描摘要

## 📝 更新日志

### v2.0.1 (最新版本)
- **功能优化**: 移除CVE漏洞检测功能，专注于核心安全分析 [终极原因是漏洞扫描需要预置很多的POC模板「21w+的模板」就不适合嵌入程序，还有一个原因是检测不准确！]
- **代码清理**: 删除Windows和Linux版本中所有CVE相关代码残留
- **版本更新**: 统一更新所有组件版本号为v2.0.1

### v2.0.0
- 重构项目架构，分离C2服务器端和客户端组件
- 增强Windows和Linux平台的兼容性
- 优化子命令参数解析机制
- 改进报告生成格式和内容

### v1.0.0
- 初始版本发布
- 集成C2服务器端和客户端组件
- 支持Windows和Linux平台的系统安全分析
- 实现漏洞扫描和用户信息分析功能
- 支持HTML和文本报告生成
- 完善的子命令参数解析和错误处理

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