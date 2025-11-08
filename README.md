# GYscan - Go语言内网横向边界安全测试工具

**作者**: BiliBili-弈秋啊  
**版本**: v1.0.0  
**寓意**: Go + 内网横向(Y) + 边界安全扫描(scan)

## ⚠️ 重要警告

**本工具仅用于已授权的内网安全测试，严禁未授权使用！**  
使用者需确保在合法合规的前提下使用本工具，并承担相应的法律责任。

## 🚀 快速开始

### 环境要求
- Go 1.24.5+ 版本
- Windows/Linux/macOS 操作系统
- 网络连接权限

### 安装与编译
```bash
# 编译项目
go build -o GYscan.exe .

# 运行工具
./GYscan.exe
```

## 📋 核心功能模块

GYscan是一个功能丰富的内网安全测试工具，集成了以下核心功能：

### 1. 网络扫描模块 (scan)
基于nmap设计理念的网络扫描工具，支持：
- **存活主机发现** - ICMP Ping + TCP探测
- **端口扫描** - TCP SYN/Connect/UDP扫描
- **服务识别** - 协议握手包匹配
- **系统识别** - OS指纹识别
- **网段扫描** - CIDR/IP范围扫描

**使用示例：**
```bash
./GYscan scan 192.168.1.1/24
./GYscan scan 192.168.1.1-192.168.1.100 -p 22,80,443
./GYscan scan example.com -p 1-1000 -n 100
./GYscan scan 10.0.0.0/8 -O -V
./GYscan scan 192.168.1.1 -O -V -p 1-1000
```

### 2. 目录扫描模块 (dirscan)
网站目录扫描工具，基于dirsearch设计：
- **多线程目录扫描** - 支持自定义并发线程
- **自定义字典文件** - 内置字典或外部字典
- **扩展名扫描** - 支持多种文件扩展名
- **状态码过滤** - 按HTTP状态码筛选结果
- **代理支持** - HTTP/SOCKS代理
- **结果导出** - 支持结果保存到文件

**使用示例：**
```bash
./GYscan dirscan -u http://example.com
./GYscan dirscan -u https://example.com -w wordlist.txt
./GYscan dirscan -u http://example.com -t 50 -e php,html
./GYscan dirscan -u http://example.com --proxy http://127.0.0.1:8080
./GYscan dirscan -u http://example.com -o results.txt
```

### 3. 数据库破解模块 (database)
支持多种主流数据库的密码破解：
- **MySQL** - 标准认证和协议级破解
- **PostgreSQL** - MD5和明文认证
- **MSSQL** - Windows和SQL Server认证
- **Oracle** - Oracle数据库认证
- **MariaDB** - 标准认证和协议级破解

**功能特性：**
- 多线程并发破解
- 用户名/密码字典攻击
- 协议级认证测试
- 实时进度显示

**使用示例：**
```bash
./GYscan database mysql://192.168.1.100:3306 -u user.txt -p pass.txt
./GYscan database postgres://192.168.1.101:5432 -u admin -p top100.txt
./GYscan database mssql://192.168.1.102:1433 -u user.txt -p pass.txt -t 10
./GYscan database oracle://192.168.1.103:1521 -u scott -p tiger -d orcl
./GYscan database mariadb://192.168.1.104:3306 -u root -p password.txt -d test
```

### 4. FTP服务破解模块 (ftp)
FTP服务密码破解工具：
- **多线程并发** - 自定义并发线程数
- **字典攻击** - 用户名和密码字典文件
- **实时进度** - 显示破解进度和统计信息
- **错误处理** - 完善的错误处理和超时控制

**使用示例：**
```bash
./GYscan ftp ftp://192.168.1.1:21 -u admin -p password
./GYscan ftp ftp://192.168.1.1:21 -u user.txt -p pass.txt
./GYscan ftp ftp://192.168.1.1:21 -u admin,root -p pass.txt
./GYscan ftp ftp://192.168.1.1:21 -u admin -p pass.txt -t 10
```

### 5. SSH服务破解模块 (ssh)
SSH服务密码爆破工具：
- **多线程并发** - 自定义并发线程数
- **字典攻击** - 用户名和密码字典文件
- **延迟控制** - 避免触发安全机制
- **详细输出** - 支持verbose和very-verbose模式

**使用示例：**
```bash
./GYscan ssh 192.168.1.1 -l root -p password
./GYscan ssh 192.168.1.1 -l user.txt -P pass.txt
./GYscan ssh 192.168.1.1 -l root -p pass.txt -t 10
./GYscan ssh 192.168.1.1 -l root -P pass.txt -D 2
```

### 6. WebShell生成模块 (webshell)
PHP大马和小马生成工具：
- **PHP小马生成** - 轻量级WebShell
- **PHP大马生成** - 功能丰富的WebShell
- **无密码模式** - 强制使用无密码版本
- **自定义配置** - 灵活的密码字段配置

**使用示例：**
```bash
./GYscan webshell -t small -o ./webshell.php
./GYscan webshell -t large -o ./large.php
```

### 7. 密码字典生成模块 (crunch)
自定义密码字典生成工具：
- **字符集自定义** - 支持任意字符组合
- **长度范围** - 指定最小和最大密码长度
- **多线程生成** - 提高字典生成效率
- **文件输出** - 生成结果保存到文件

**使用示例：**
```bash
./GYscan crunch 4 6 abcdefghijklmnopqrstuvwxyz0123456789 -o passwords.txt
./GYscan crunch 8 8 0123456789 -o numbers.txt -t 8
```

### 8. 进程服务分析模块 (process)
进程与服务信息收集工具：
- **跨平台支持** - Windows/Linux系统兼容
- **权限级别分类** - 系统权限/高权限/中权限/低权限
- **详细分析** - 进程和服务详细信息
- **多种输出格式** - 支持JSON格式输出

**权限级别说明：**
- **系统权限** - 操作系统核心组件，具有最高权限
- **高权限** - 网络服务、数据库服务等关键应用
- **中权限** - 普通系统服务和应用
- **低权限** - 普通用户应用

**使用示例：**
```bash
./GYscan process                    # 显示所有进程和服务信息
./GYscan process -H                  # 仅显示高权限进程和服务
./GYscan process -p                  # 仅显示进程信息
./GYscan process -S                  # 仅显示服务信息
./GYscan process --output json       # 以JSON格式输出
```

### 9. 用户信息分析模块 (userinfo)
本地用户和组分析工具：
- **跨平台兼容** - Windows/Linux系统支持
- **用户账户分析** - 本地用户详细信息
- **用户组分析** - 本地组信息分析
- **权限属性** - 详细的权限和属性信息

**使用示例：**
```bash
./GYscan userinfo                    # 显示本地用户和组信息
./GYscan userinfo --users-only       # 仅显示用户信息
./GYscan userinfo --groups-only      # 仅显示组信息
./GYscan userinfo --detailed         # 显示详细信息
```

### 10. SAM文件分析模块 (sam)
Windows SAM文件分析工具：
- **SAM文件解析** - 提取用户账户信息
- **密码哈希提取** - 获取密码哈希数据
- **详细用户信息** - 显示用户详细信息
- **结果导出** - 支持结果保存到文件

**SAM文件位置：**
```
C:\Windows\System32\config\SAM
```

**使用示例：**
```bash
./GYscan sam C:\Windows\System32\config\SAM
./GYscan sam C:\Windows\System32\config\SAM --details
./GYscan sam C:\Windows\System32\config\SAM --export users.txt
```

### 11. 路由检测模块 (route)
网络路由跳数检测工具：
- **ICMP路由追踪** - 使用Go原生ICMP实现
- **跳数检测** - 检测数据包路径跳数
- **延时统计** - 每个跳数的平均延时
- **丢包率计算** - 网络连接质量分析

**使用示例：**
```bash
./GYscan route 8.8.8.8                    # 检测到Google DNS的路由
./GYscan route google.com --max-hops 10   # 检测到Google的路由，最大10跳
./GYscan route 192.168.1.1 --count 5      # 每个跳数探测5次
./GYscan route example.com --timeout 5    # 设置5秒超时
```

### 12. 工具信息模块 (about)
查看工具基本信息：
- **作者信息** - 工具开发者信息
- **版本信息** - 当前工具版本
- **核心功能** - 主要功能概述
- **使用警告** - 安全使用提示

**使用示例：**
```bash
./GYscan about
```

### 13. 帮助模块 (help)
获取命令帮助信息：
- **命令帮助** - 显示具体命令的使用方法
- **参数说明** - 详细参数说明
- **使用示例** - 实际使用案例

**使用示例：**
```bash
./GYscan help                    # 显示所有命令帮助
./GYscan help scan               # 显示scan命令帮助
./GYscan help database           # 显示database命令帮助
```

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

## 🏗️ 项目结构

```
GYscan/
├── cmd/                 # 命令行入口
│   └── root.go         # 根命令定义
├── internal/           # 内部模块
│   ├── cli/           # 命令行接口
│   ├── database/      # 数据库破解模块
│   ├── dirscan/       # 目录扫描模块
│   ├── ftp/          # FTP破解模块
│   ├── network/      # 网络功能模块
│   ├── nmap/         # 网络扫描模块
│   ├── process/       # 进程服务模块
│   ├── sam/          # SAM分析模块
│   ├── samcrack/     # SAM破解模块
│   ├── security/     # 安全功能模块
│   ├── ssh/          # SSH破解模块
│   ├── userinfo/     # 用户信息模块
│   ├── utils/        # 工具函数
│   └── webshell/     # WebShell生成模块
├── main.go           # 程序入口
└── README.md         # 项目文档
```

## 🔒 安全特性

### 流量加密
- 支持AES-256流量加密
- 可自定义加密密钥
- 防止网络监听和数据泄露

### 代理支持
- 支持HTTP/SOCKS5代理
- 匿名化网络请求
- 绕过网络限制

### 错误处理
- 完善的异常处理机制
- 优雅的错误恢复
- 详细的错误日志记录

### 权限控制
- 严格的权限验证
- 安全的文件操作
- 防止权限滥用

## 📊 开发状态

### 已完成功能
- [x] 项目基础结构和CLI框架
- [x] 网络扫描模块 (scan)
- [x] 目录扫描模块 (dirscan)
- [x] 数据库破解模块 (database)
- [x] FTP服务破解模块 (ftp)
- [x] SSH服务破解模块 (ssh)
- [x] WebShell生成模块 (webshell)
- [x] 密码字典生成模块 (crunch)
- [x] 进程服务分析模块 (process)
- [x] 用户信息分析模块 (userinfo)
- [x] SAM文件分析模块 (sam)
- [x] 路由检测模块 (route)
- [x] 工具信息模块 (about)
- [x] 帮助模块 (help)

## 📝 更新日志

### v1.0.0 (当前版本)
- 初始版本发布
- 集成13个核心功能模块
- 支持Windows/Linux/macOS平台
- 完善的错误处理和进度显示

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