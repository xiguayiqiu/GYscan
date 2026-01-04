[**English**-README](README-en.md)

# GYscan - 内网横向边界安全测试工具

## 项目简介

GYscan是一款专注于内网横向移动和边界安全测试的专业工具，基于Go语言开发。该工具集成了丰富的内网渗透测试功能，包括端口扫描、服务识别、漏洞检测、远程命令执行、弱口令爆破等核心功能，为安全研究人员和渗透测试人员提供高效、可靠的内网安全评估解决方案。

## 核心优势

- **专注内网安全**：专门针对内网横向移动和边界安全测试场景优化
- **功能丰富**：集成了端口扫描、服务识别、远程命令执行、弱口令爆破、配置审计等多种功能
- **跨平台支持**：支持Windows、Linux、macOS三大主流操作系统
- **模块化设计**：采用插件化架构，支持功能扩展和自定义模块开发
- **配置审计**：基于CIS Benchmark安全基线，支持五大类58项配置检查
- **证据追踪**：审计检查显示具体配置文件、配置项、当前值和修复建议
- **性能优异**：基于Go语言开发，具备出色的并发处理能力

### 基本信息

| 项目 | 信息 |
|------|------|
| **项目名称** | GYscan |
| **开发语言** | Go 1.24+ |
| **支持平台** | Windows 7+/Linux/macOS |
| **许可证** | Apache 2.0 |
| **最新版本** | v2.7 |

### 法律声明

**重要提示**: 本工具仅用于授权的安全测试目的。任何未授权的使用行为均属违法，使用者需承担相应的法律责任。

## 快速上手

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
   # Github
   git clone https://github.com/xiguayiqiu/GYscan.git
   # Gitee
   git clone https://gitee.com/bzhanyiqiua/GYscan.git
   cd GYscan
   ```

### 编译安装

```bash
# 编译客户端
cd Client
go build -o GYscan.exe
```

### 一键构建脚本

```bash
# Windows平台
.\build.ps1

# Linux平台
chmod +x build_linux.sh
./build_linux.sh
```

### Linux平台依赖安装

GYscan在Linux平台构建需要安装系统依赖包，不同发行版的安装命令如下：

#### Debian/Ubuntu/Kali Linux/Parrot Security
```bash
# 更新包管理器
sudo apt update

# 安装依赖包
sudo apt install -y \
    libx11-dev \
    libxcursor-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxi-dev \
    libxxf86vm-dev \
    libgl1-mesa-dev \
    libglu1-mesa-dev \
    mesa-common-dev \
    build-essential \
    pkg-config \
    dbus-x11 \
    libdbus-1-dev \
    libpcap-dev \
    man-db
```

#### RedHat/CentOS/Fedora/Rocky Linux
```bash
# 安装依赖包
sudo yum install -y \
    libX11-devel \
    libXcursor-devel \
    libXrandr-devel \
    libXinerama-devel \
    libXi-devel \
    libXxf86vm-devel \
    mesa-libGL-devel \
    mesa-libGLU-devel \
    mesa-libGLw-devel \
    gcc-c++ \
    pkgconfig \
    dbus-x11 \
    dbus-devel \
    libpcap-devel \
    man-db
```

#### Arch Linux/Manjaro
```bash
# 安装依赖包
sudo pacman -S --noconfirm \
    libx11 \
    libxcursor \
    libxrandr \
    libxinerama \
    libxi \
    libxxf86vm \
    mesa \
    glu \
    base-devel \
    pkg-config \
    dbus \
    dbus-glib \
    libpcap \
    man-db
```

#### OpenSUSE
```bash
# 安装依赖包
sudo zypper install -y \
    libX11-devel \
    libXcursor-devel \
    libXrandr-devel \
    libXinerama-devel \
    libXi-devel \
    libXxf86vm-devel \
    Mesa-libGL-devel \
    Mesa-libGLU-devel \
    Mesa-dri-devel \
    gcc-c++ \
    pkgconfig \
    dbus-1-x11 \
    dbus-1-devel \
    libpcap-devel \
    man-db
```

> **注意**: 构建脚本 `build_linux.sh` 会自动检测系统发行版并提示安装缺失的依赖包。

## 功能列表

### 正式命令

| 命令 | 功能描述 | 状态 |
|------|----------|------|
| about | 查看工具信息 | ✅ 稳定 |
| ca | 配置审计工具，基于CIS基线进行系统配置安全检查 | ✅ 稳定 |
| crunch | 密码字典生成工具 | ✅ 稳定 |
| database | 数据库密码破解工具 | ✅ 稳定 |
| dirscan | 网站目录扫描工具 | ✅ 稳定 |
| ftp | FTP密码破解 | ✅ 稳定 |
| passhash | 凭证传递攻击模块 | ✅ 稳定 |
| powershell | PowerShell远程执行工具 [WinRM服务利用] | ✅ 稳定 |
| process | 进程与服务信息收集工具 | ✅ 稳定 |
| rdp | RDP远程桌面工具 | ✅ 稳定 |
| route | 路由跳数检测 | ✅ 稳定 |
| scan | 网络扫描工具，支持主机发现、端口扫描、服务识别等功能 | ✅ 稳定 |
| scapy | 高级网络包操作工具，支持原始包构造、接口检测和功能演示 | ✅ 稳定 |
| ssh | SSH密码爆破工具（Hydra风格） | ✅ 稳定 |
| userinfo | 本地用户和组分析 | ✅ 稳定 |
| webshell | WebShell生成工具 | ✅ 稳定 |
| wmi | WMI远程管理工具 | ✅ 稳定 |
| waf | WAF检测工具，支持主流WAF识别和检测 | ✅ 稳定 |
| xss | XSS漏洞检测工具，支持反射型、存储型、DOM型XSS检测 | ✅ 稳定 |
| winlog | Windows日志查看工具，支持本地和远程日志查询 | ✅ 稳定 |
| clean | 高级黑客攻击痕迹检测与清理工具 | ✅ 稳定 |
| fu | 文件上传漏洞检查工具 | ✅ 稳定 |
| wwifi | Windows系统WiFi破解功能 | ✅ 稳定 |

### 测试阶段命令

| 命令 | 功能描述 | 状态 |
|------|----------|------|
| csrf | CSRF漏洞检测 [测试阶段] | ⚠️ 测试阶段 |
| dcom | DCOM远程执行模块 [测试阶段] | ⚠️ 测试阶段 |
| ldap | LDAP枚举模块 [测试阶段] | ⚠️ 测试阶段 |
| mg | 蜜罐识别工具 - 检测目标是否为蜜罐系统 [测试阶段] | ⚠️ 测试阶段 |

## 配置审计功能

GYscan v2.7 全新推出配置审计（Configuration Audit）模块，基于CIS Benchmark安全基线对目标系统进行配置合规性检查。

### 审计类别

GYscan配置审计支持五大类别，共58项检查：

| 类别 | 检查项数量 | 主要检查内容 |
|------|-----------|-------------|
| Windows配置审计 | 10项 | 账户策略、服务配置、注册表安全、审计策略、LSA安全、UAC配置、防火墙规则、SMB安全 |
| Linux配置审计 | 10项 | 账户管理、密码策略、服务管理、内核参数、文件权限、SSH配置、审计配置、防火墙 |
| Web配置审计 | 13项 | HTTP安全头、CORS配置、SSL/TLS配置、会话安全、XSS防护、CSRF防护、信息泄露防护 |
| SSH配置审计 | 15项 | SSH协议版本、认证方式、Root登录权限、加密算法、MAC算法、密钥交换算法、登录横幅 |
| 中间件配置审计 | 10项 | 数据库账户权限、网络访问控制、加密配置、审计日志、密码策略、应用服务器管理接口 |

### 配置证据功能

GYscan配置审计提供详细的配置证据追踪功能，当检测到配置问题时，报告会明确显示：

- **配置文件路径**：指出存在问题的具体配置文件
- **配置项名称**：标明具体的安全设置项
- **当前值**：显示当前不安全的配置值
- **期望值**：说明应该设置的合规值
- **风险说明**：解释配置问题的安全影响
- **修复建议**：提供具体的整改步骤

### 使用示例

```bash
# 执行全部类别的本地配置审计
./GYscan.exe ca run --target localhost

# 审计本地Linux系统的配置
./GYscan.exe ca run --target localhost --os-type linux

# 审计本地Windows系统的配置
./GYscan.exe ca run --target localhost --os-type windows

# 指定审计类别进行本地审计
./GYscan.exe ca run --category linux

# 审计本地Web服务配置
./GYscan.exe ca run --category web

# 审计本地SSH配置
./GYscan.exe ca run --category ssh

# 审计本地中间件配置
./GYscan.exe ca run --category middleware

# 生成JSON格式的本地审计报告
./GYscan.exe ca run --target localhost -o audit.json --format json

# 生成HTML格式的本地审计报告
./GYscan.exe ca run --target localhost -o audit.html --format html

# 列出所有可用的检查项
./GYscan.exe ca list

# 列出指定类别下的检查项
./GYscan.exe ca list --category linux

# 生成目标系统的安全基线报告
./GYscan.exe ca baseline --target localhost -o baseline.json

# 生成配置整改建议计划
./GYscan.exe ca remediate --target localhost
```

#### 本地审计说明

GYscan配置审计模块专注于本地系统配置审计，直接读取目标系统的配置文件和系统参数进行检测：

- **无需远程连接**：不依赖SSH或WMI等远程协议，直接分析本地文件系统
- **安全可靠**：避免远程连接带来的认证和权限问题
- **全面覆盖**：支持Windows、Linux、Web、SSH、中间件五大类别

### 输出格式

GYscan配置审计支持三种输出格式：

| 格式 | 说明 | 使用场景 |
|------|------|----------|
| text | 文本格式，默认输出 | 终端直接查看 |
| json | JSON格式，适合程序处理 | 自动化集成、数据分析 |
| html | HTML格式，交互式报告 | 详细审计报告、演示展示 |

## 常用功能使用示例

### 网络扫描

```bash
# 扫描单个IP地址
./GYscan.exe scan --target 192.168.1.100

# 扫描IP段
./GYscan.exe scan --target 192.168.1.0/24

# 扫描指定端口范围
./GYscan.exe scan --target 192.168.1.100 --ports 80,443,22,21
```

### PowerShell远程执行

```bash
# 执行远程PowerShell命令
./GYscan.exe powershell exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"

# 测试WinRM端口
./GYscan.exe powershell test --target 192.168.1.100 --port 5985
```

### WMI远程管理

```bash
# 获取操作系统信息
./GYscan.exe wmi osinfo --target 192.168.1.100 --user Administrator --password "Password123"

# 执行远程命令
./GYscan.exe wmi exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"
```

### DCOM远程执行

GYscan的DCOM远程执行模块通过DCOM协议在目标Windows主机上执行远程命令，支持多种执行方法。

#### 命令说明

| 子命令 | 功能描述 |
|--------|----------|
| execute | 通过DCOM执行远程命令 |
| connect | 测试DCOM连接可达性 |
| list | 枚举远程主机上的DCOM对象 |

#### 常用参数

| 参数 | 简写 | 说明 |
|------|------|------|
| --target | -t | 目标主机IP地址或主机名（必填） |
| --username | -u | 用户名（必填） |
| --password | -p | 密码（必填） |
| --domain | -d | 域名（可选） |
| --command | -c | 要执行的命令（必填） |
| --method | -m | DCOM执行方法：mmc20、shellwindows、wmiexecute（默认mmc20） |
| --timeout | -o | 连接超时时间（秒，默认30） |
| --verbose | -v | 显示详细输出 |
| --ssl | -S | 使用SSL加密连接 |

#### 使用示例

```bash
# 测试DCOM连接可达性
./GYscan.exe dcom connect --target 192.168.1.100 --username Administrator --password "Password123"

# 使用MMC20.Application方法执行远程命令（默认方法）
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "whoami"

# 使用ShellWindows方法执行远程命令
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "ipconfig" --method shellwindows

# 使用WMI Execute方法执行远程命令
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "hostname" --method wmiexecute

# 执行多条命令
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "whoami & hostname"

# 域环境下的DCOM执行
./GYscan.exe dcom execute --target 192.168.1.100 --username admin --password "Password123" --domain CORP --command "whoami"

# 带详细输出的DCOM执行
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "systeminfo" --verbose

# 枚举远程主机上的DCOM对象
./GYscan.exe dcom list --target 192.168.1.100 --username Administrator --password "Password123"
```

#### DCOM执行方法说明

| 方法 | 说明 | 适用场景 |
|------|------|----------|
| mmc20 | 使用MMC20.Application COM对象执行命令 | 通用场景，默认方法 |
| shellwindows | 使用ShellWindows COM对象执行命令 | MMC20被禁用时备选 |
| wmiexecute | 使用WMI CIM对象执行命令 | 需要WMI访问权限时 |

#### 端口要求

DCOM远程执行需要目标主机开放135端口（RPC endpoint mapper）：

```bash
# 验证目标135端口是否开放
telnet 192.168.1.100 135
```

如果135端口不可用，将返回连接错误，请检查：
- Windows防火墙是否允许135端口入站
- RPC服务（rpcss）是否正在运行
- 网络防火墙是否允许135端口通信

### RDP远程桌面

```bash
# 检查RDP服务可用性
./GYscan.exe rdp check --target 192.168.1.100

# 连接到RDP服务
./GYscan.exe rdp connect --target 192.168.1.100 --user Administrator --password "Password123"
```

### SMB协议操作

```bash
# 检测SMB版本
./GYscan.exe smb version --target 192.168.1.100

# 列出SMB共享
./GYscan.exe smb shares --target 192.168.1.100 --user Administrator --password "Password123"
```

### 漏洞检测

```bash
# XSS漏洞检测
./GYscan.exe xss --target http://example.com --payload "<script>alert('xss')</script>"

# CSRF漏洞检测
./GYscan.exe csrf --target http://example.com/vul/csrf.php -X POST -d "action=delete&id=1"
```

### 弱口令爆破

```bash
# SSH弱口令检测
./GYscan.exe ssh --target 192.168.1.100 --user admin --wordlist passwords.txt

# FTP弱口令检测
./GYscan.exe ftp --target 192.168.1.100 --user anonymous --wordlist passwords.txt

# WAF检测
./GYscan.exe waf -u "https://www.example.com/"
```

## 技术架构

### 项目结构

```
GYscan/
├── Client/                # 客户端主程序（渗透测试工具）
│   ├── internal/          # 内部功能模块
│   │   ├── cli/           # 命令行界面和命令注册
│   │   ├── config/        # 配置管理模块
│   │   ├── configaudit/   # 配置审计模块（v2.7新增）
│   │   ├── csrf/          # CSRF漏洞检测模块
│   │   ├── database/      # 数据库密码破解工具
│   │   ├── dirscan/       # 网站目录扫描模块
│   │   ├── ftp/           # FTP密码破解模块
│   │   ├── powershell/    # PowerShell远程执行模块
│   │   ├── process/       # 进程与服务信息收集
│   │   ├── rdp/           # RDP远程桌面模块
│   │   ├── smb/           # SMB协议操作模块
│   │   ├── ssh/           # SSH密码爆破模块
│   │   ├── userinfo/      # 本地用户和组分析工具
│   │   ├── waf/           # WAF检测工具
│   │   ├── weakpass/      # 弱口令检测框架
│   │   ├── webshell/      # WebShell生成工具
│   │   ├── wmi/           # WMI远程管理模块
│   │   └── xss/           # XSS漏洞检测模块
│   ├── main.go            # 程序主入口文件
│   └── go.mod             # Go模块依赖配置
├── doc/                   # 文档目录
│   └── man/               # man手册页
└── README.md              # 中文项目说明文档
```

### 技术栈

GYscan采用现代化的技术栈构建，确保高性能、可扩展性和易用性：

| 类别 | 技术/库 | 用途 |
|------|---------|------|
| **核心语言** | Go 1.24+ | 主要开发语言 |
| **命令行框架** | cobra | 命令行界面和命令注册系统 |
| **HTTP客户端** | resty/v2 | API请求和网络通信 |
| **HTML解析** | goquery | 网页内容解析和处理 |
| **彩色输出** | color | 命令行彩色输出 |
| **数据库驱动** | go-sql-driver/mysql | MySQL数据库支持 |
| **数据库驱动** | go-mssqldb | SQL Server数据库支持 |
| **数据库驱动** | lib/pq | PostgreSQL数据库支持 |
| **数据库驱动** | go-ora | Oracle数据库支持 |
| **SMB协议** | go-smb2 | SMB协议支持 |
| **YAML解析** | yaml.v3 | YAML配置文件解析 |

## 更新日志

### v2.7

**版本更新与配置审计功能发布**

#### 新增功能

- **pc命令** - 远程补丁探测工具，无需登录即可远程查询目标系统的中间层组件版本与补丁状态
  - 基于 WhatWeb 指纹识别技术，支持 1999+ 个 Web 指纹识别
  - 支持Web服务器: Nginx, Apache, Tomcat, IIS
  - 支持数据库: MySQL, SQL Server, Oracle, PostgreSQL
  - 支持缓存/消息: Redis, Memcached, RabbitMQ
  - 支持中间件: WebLogic, JBoss, GlassFish
  - 支持CMS系统: WordPress, Drupal, Joomla
  - 组件版本与官方漏洞库关联分析
  - 支持多种输出格式和过滤选项

- **配置审计（CA）模块** - 全新发布
  - 基于CIS Benchmark安全基线的配置合规性检查
  - 支持五大审计类别：Windows、Linux、Web、SSH、中间件
  - 共58项配置检查项
  - 支持JSON、HTML、Text三种输出格式

- **配置证据功能**
  - 显示具体配置文件路径
  - 显示配置项名称和当前值
  - 提供期望值和修复建议
  - 详细的风险说明和整改步骤

#### 命令调整

- 新增 `ca` 命令 - 配置审计工具
- 新增 `pc` 命令 - 远程补丁探测工具
- 将 mg（蜜罐识别工具）从正式命令移至测试阶段命令
- 移除 tui（启动 TUI 模式），不再考虑TUI的开发

#### 技术优化

- 增强 CheckResult 结构，支持配置证据字段
- 优化报告生成器，支持多种输出格式
- 完善 HTML 报告的样式和交互性

### v2.7-beta

**版本更新与命令调整**

- **版本升级**：GYscan从 v2.6.3 升级至 v2.7-beta
- **命令调整**：将 mg（蜜罐识别工具）从正式命令移至测试阶段命令
- **命令调整**：将 tui（启动 TUI 模式）从正式命令移至测试阶段命令，计划在后续版本中移除
- **蜜罐识别优化**：蜜罐识别工具新增 HFish 蜜罐支持
- **代码结构优化**：调整命令分类，使正式命令更加稳定可靠

### v2.6.3

**功能优化与增强**

- **文件上传漏洞检查机制优化**
  - 前端校验绕过检测
  - 后缀名绕过检测增强版
  - MIME类型绕过检测新增
  - 条件竞争检测新增

- **网站目录扫描功能优化**
  - 文件扩展名扫描支持
  - Ctrl+C中断处理优化
  - 跨平台清屏功能
  - 扫描结果整理显示

### v2.6.2

- **新增pc命令** - 远程补丁探测工具，无需登录即可远程查询目标系统的中间层组件版本与补丁状态
  - 基于 WhatWeb 指纹识别技术，支持 1999+ 个 Web 指纹识别
  - 支持Web服务器: Nginx, Apache, Tomcat, IIS
  - 支持数据库: MySQL, SQL Server, Oracle, PostgreSQL
  - 支持缓存/消息: Redis, Memcached, RabbitMQ
  - 支持中间件: WebLogic, JBoss, GlassFish
  - 支持CMS系统: WordPress, Drupal, Joomla
  - 组件版本与官方漏洞库关联分析
  - 支持多种输出格式和过滤选项

- **新增fu命令** - 文件上传漏洞检查功能，支持多种绕过技术
- **新增wwifi命令** - Windows系统WiFi破解功能

### v2.6.0

- **新增scapy模块** - 集成高级网络包操作工具
  - 原始网络包构造和发送功能
  - 网络接口检测和状态分析
  - 功能演示和示例代码

### v2.5.4

- **新增linenum功能** - Linux本地信息枚举和权限提升工具
- **新增linux-kernel功能** - Linux内核漏洞检测工具

### v2.5.2

- **新增winlog命令** - Windows日志查看工具
- 优化日志条目显示格式

### v2.5.1

- **新增waf命令** - WAF检测工具
- 优化WAF检测模块代码

### v2.5.0

- 统一命令注册机制
- 实现命令分组显示
- 完善PowerShell模块，添加HTTPS支持
- 增强WMI模块功能

### v2.0.0

- **新增csrf命令** - CSRF漏洞检测模块
- 完善XSS检测功能

### v1.0.0

- **初始发布**：基础端口扫描功能
- 服务识别和指纹采集
- 弱口令爆破框架
- 基础漏洞检测功能

## 贡献指南

欢迎提交Issue和Pull Request来改进项目。请确保：
1. 代码符合Go语言规范
2. 添加适当的测试用例
3. 更新相关文档
4. 遵循安全开发规范

## 许可证

本项目采用MIT许可证。详情请查看LICENSE文件。

## 免责声明

**重要提示**: 本工具仅供安全研究和授权测试使用。任何未授权的使用行为均属违法，使用者需承担相应的法律责任。作者不承担任何因使用本工具而产生的直接或间接责任。

---

**GYscan - 专注内网安全，守护网络边界** 🛡️
