# GYscan - 内网横向边界安全测试工具

## 项目简介

GYscan是一款专注于内网横向移动和边界安全测试的专业工具。经过功能优化，当前版本专注于端口扫描、服务识别、漏洞检测和弱口令爆破等核心安全测试功能，为安全研究人员和渗透测试人员提供高效、可靠的内网安全评估解决方案。

## 核心优势

- **专注内网安全**：专门针对内网横向移动和边界安全测试场景优化
- **高度集成化**：集成了端口扫描、服务识别、漏洞检测、弱口令爆破等核心功能
- **跨平台支持**：支持Windows、Linux、macOS三大主流操作系统
- **模块化设计**：采用插件化架构，支持功能扩展和自定义模块开发
- **易用性强**：提供简洁的命令行界面和详细的帮助文档
- **性能优异**：基于Go语言开发，具备出色的并发处理能力

### 📋 基本信息

| 项目 | 信息 |
|------|------|
| **项目名称** | GYscan |
| **开发语言** | Go 1.18+ |
| **支持平台** | Windows 7+/Linux/macOS |
| **许可证** | MIT |
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
# 编译客户端
cd Client
go build -o GYscan-Windows.exe
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
GOOS=windows GOARCH=amd64 go build -o GYscan-Windows.exe

# 编译Linux版本（在Windows上）
cd Client
GOOS=linux GOARCH=amd64 go build -o GYscan-linux-amd64
```

### 基础使用
#### 主要功能
 - about       查看工具信息
 - crunch      密码字典生成工具
 - database    数据库密码破解工具
 - dirscan     网站目录扫描工具
 - ftp         FTP密码破解工具
 - help        Help about any command
 - process     进程与服务信息收集工具
 - route       路由跳数检测
 - sam         Windows SAM文件分析工具 [功能测试]
 - scan        网络扫描工具，支持主机发现、端口扫描、服务识别等功能
 - ssh         SSH密码爆破工具（Hydra风格）
 - userinfo    本地用户和组分析
 - webshell    WebShell生成工具
#### C2 功能
 - userinfo  分析本地用户和组信息
 - goss      Windows系统配置审计
 - audit     Windows安全审计
#### 端口扫描
```bash
# 扫描单个IP地址
./GYscan-linux-amd64 scan --target 192.168.1.100

# 扫描IP段
./GYscan-linux-amd64 scan --target 192.168.1.0/24

# 扫描指定端口范围
./GYscan-linux-amd64 scan --target 192.168.1.100 --ports 80,443,22,21
```

#### 服务识别
```bash
# 识别目标服务类型和版本
./GYscan-linux-amd64 service --target 192.168.1.100 --port 80

# 批量服务识别
./GYscan-linux-amd64 service --target 192.168.1.0/24 --ports 22,80,443
```

#### 弱口令爆破
```bash
# SSH弱口令检测
./GYscan-linux-amd64 brute --target 192.168.1.100 --service ssh --user admin --wordlist passwords.txt

# FTP弱口令检测
./GYscan-linux-amd64 brute --target 192.168.1.100 --service ftp --user anonymous --wordlist passwords.txt
```

#### 漏洞检测
```bash
# Web应用漏洞扫描
./GYscan-linux-amd64 vuln --target 192.168.1.100 --web

# 服务漏洞检测
./GYscan-linux-amd64 vuln --target 192.168.1.100 --service ssh
```

### 实战示例

#### 示例1：基础端口扫描
```bash
# 扫描单个IP地址
./GYscan-linux-amd64 scan --target 192.168.1.100

# 扫描IP段
./GYscan-linux-amd64 scan --target 192.168.1.0/24

# 扫描指定端口范围
./GYscan-linux-amd64 scan --target 192.168.1.100 --ports 80,443,22,21
```

#### 示例2：服务识别和指纹采集
```bash
# 识别目标服务类型和版本
./GYscan-linux-amd64 service --target 192.168.1.100 --port 80

# 批量服务识别
./GYscan-linux-amd64 service --target 192.168.1.0/24 --ports 22,80,443
```

#### 示例3：弱口令爆破
```bash
# SSH弱口令检测
./GYscan-linux-amd64 brute --target 192.168.1.100 --service ssh --user admin --wordlist passwords.txt

# FTP弱口令检测
./GYscan-linux-amd64 brute --target 192.168.1.100 --service ftp --user anonymous --wordlist passwords.txt
```

#### 示例4：漏洞检测
```bash
# Web应用漏洞扫描
./GYscan-linux-amd64 vuln --target 192.168.1.100 --web

# 服务漏洞检测
./GYscan-linux-amd64 vuln --target 192.168.1.100 --service ssh
```

### 高级配置

#### 性能调优
```bash
# 设置并发线程数
./GYscan-linux-amd64 scan --target 192.168.1.0/24 --threads 50

# 设置超时时间
./GYscan-linux-amd64 scan --target 192.168.1.100 --timeout 3
```

#### 输出控制
```bash
# 静默模式（仅输出关键结果）
./GYscan-linux-amd64 scan --target 192.168.1.100 --silent

# 输出到文件
./GYscan-linux-amd64 scan --target 192.168.1.0/24 -o scan_results.txt
```

## 核心功能模块

GYscan采用模块化架构，专注于内网安全测试的核心功能，提供专业的安全评估解决方案。

### 功能模块概览

| 功能模块 | 主要功能 | 技术特点 |
|---------|---------|---------|
| **端口扫描** | TCP/UDP端口发现、服务探测 | 多线程并发、智能端口范围 |
| **服务识别** | 协议识别、版本检测、Banner抓取 | 自动化探测、智能策略选择 |
| **漏洞检测** | Web漏洞扫描、服务漏洞检测 | 基础安全配置评估 |
| **弱口令爆破** | 多协议弱口令检测 | 智能爆破、字典管理 |

### 1. 端口扫描模块
端口扫描模块提供高效的网络端口发现功能：

**主要功能：**
- **TCP SYN扫描** - 快速端口发现，减少网络流量
- **TCP Connect扫描** - 准确的服务识别和连接验证
- **UDP扫描** - UDP服务探测和响应分析
- **智能端口范围** - 支持常用端口和自定义端口范围

**技术特点：**
- 基于Go语言原生网络库实现
- 可配置的并发线程数
- 智能超时控制和错误处理
- 详细的扫描统计信息

### 2. 服务识别模块
服务识别模块提供精准的服务类型和版本检测：

**主要功能：**
- **协议识别** - 自动识别HTTP、FTP、SSH、SMB等协议
- **版本检测** - 识别服务具体版本信息
- **Banner抓取** - 获取服务标识和配置信息
- **自动化探测** - 智能选择探测策略和参数

**技术特点：**
- 多协议指纹库支持
- 自适应探测策略
- 可配置的超时设置
- 详细的识别结果报告

### 3. 漏洞检测模块
漏洞检测模块提供基础的安全漏洞识别功能：

**主要功能：**
- **Web漏洞扫描** - SQL注入、XSS、文件包含等基础检测
- **服务漏洞检测** - 常见服务漏洞识别和风险评估
- **安全配置检查** - 基础安全配置评估和建议

**技术特点：**
- 模块化检测规则
- 可扩展的检测插件
- 详细的漏洞描述和建议
- 风险评估和优先级排序

### 4. 弱口令爆破模块
弱口令爆破模块提供多协议的密码强度检测：

**主要功能：**
- **多协议支持** - SSH、FTP、SMB、RDP等主流协议
- **字典管理** - 内置常用弱口令字典，支持自定义字典
- **智能爆破** - 基于响应特征的智能爆破策略
- **并发控制** - 可配置的并发线程数和延迟设置

**技术特点：**
- 协议特定的认证机制
- 智能错误处理和重试机制
- 详细的爆破进度和结果统计
- 安全的密码处理机制

## 全局参数

```bash
./GYscan-linux-amd64 [command] [flags]

全局参数:
  -h, --help           显示帮助信息
  -v, --version        显示版本信息
  -s, --silent         静默模式，仅输出关键结果
      --config string  配置文件路径
      --threads int    并发线程数 (默认: 10)
      --timeout int    超时时间(秒) (默认: 5)
```

## 技术架构

### 项目结构
GYscan采用简洁的客户端架构设计，专注于内网安全测试功能：

```
GYscan/
├── Client/                 # 客户端主程序
│   ├── main.go            # 程序主入口
│   ├── internal/
│   │   ├── cli/           # 命令行界面
│   │   │   ├── root.go    # 根命令定义
│   │   │   ├── scan.go    # 端口扫描命令
│   │   │   ├── service.go # 服务识别命令
│   │   │   ├── vuln.go    # 漏洞检测命令
│   │   │   └── brute.go   # 弱口令爆破命令
│   │   └── core/          # 核心功能实现
│   └── pkg/
│       └── utils/         # 工具函数
└── README.md              # 项目文档
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

## 开发状态

### 当前稳定功能
- [x] 基础端口扫描（TCP/UDP）
- [x] 服务识别和指纹采集
- [x] 弱口令爆破框架
- [x] 基础漏洞检测
- [x] 命令行界面
- [x] 配置文件管理

### 近期优化
- [x] 移除Payload生成功能，专注安全测试
- [x] 优化代码结构和性能
- [x] 完善帮助文档和示例

### 计划功能
- [ ] 高级漏洞检测插件
- [ ] 分布式扫描架构
- [ ] 自动化报告生成

## 更新日志

### 2.0.1 (最新版本)
- **功能优化**: 移除Payload生成功能，专注安全测试
- **代码优化**: 优化代码结构和性能
- **文档完善**: 更新帮助文档和示例
- **版本更新**: 统一版本号为v2.0.1

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

本工具仅用于授权的安全测试目的。使用者需承担相应的法律责任。

---

**免责声明**: 本工具仅供安全研究和授权测试使用，任何未授权的使用行为与作者无关。