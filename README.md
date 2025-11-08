# GYscan - 内网横向边界安全测试工具

基于Go语言开发的专业内网横向边界安全测试工具，集成了多种安全测试功能，旨在帮助安全研究人员进行授权的内网安全评估。

**作者**: BiliBili-弈秋啊  
**寓意**: Go + 内网横向（Y） + 边界安全扫描（scan）  
**许可证**: 仅用于授权的安全测试目的，使用者需承担相应法律责任

## ⚠️ 重要警告

**本工具仅用于已授权的内网安全测试，严禁未授权使用！**  
使用者需确保在合法合规的前提下使用本工具，并承担相应的法律责任。

## 🚀 快速开始

### 环境要求
- Go 1.18+ 版本
- Windows/Linux/macOS 操作系统
- 网络连接权限

### 安装与编译
```bash
# 克隆项目
git clone <repository-url>
cd GYscan

# 编译项目
go build -o GYscan.exe

# 运行工具
./GYscan.exe
```

### 基本使用
```bash
# 查看帮助信息
./GYscan.exe help

# 查看版本信息
./GYscan.exe --version

# 静默模式运行
./GYscan.exe --silent
```

## 📋 功能模块

### 1. 资产探测模块
- **主机发现**: 网络存活主机探测
- **端口扫描**: 多线程端口扫描服务
- **服务识别**: 自动识别服务类型和版本
- **操作系统识别**: 目标系统指纹识别

### 2. 凭证处理模块
- **本地凭证抓取**: Windows/Linux系统凭证提取
- **批量验证**: 多目标凭证批量验证
- **凭证管理**: 凭证存储和安全管理

### 3. 横向执行模块
- **远程命令执行**: 支持多种协议的命令执行
- **文件传输**: 安全文件上传下载
- **漏洞利用**: 集成常见漏洞利用模块

### 4. 权限提升模块
- **提权漏洞扫描**: 系统提权漏洞检测
- **权限维持**: 后门植入和权限维持
- **安全绕过**: 安全机制绕过技术

### 5. 痕迹清理模块
- **日志清理**: 系统日志和安全日志清理
- **文件删除**: 安全删除临时文件
- **痕迹消除**: 操作痕迹全面清理

### 6. WebShell生成模块
- **PHP大马/小马生成**: 支持多种WebShell类型
- **编码混淆**: Base64、Hex等多种编码方式
- **无密码版本**: 支持无密码大马生成
- **自定义配置**: 灵活的密码和功能配置

### 7. 数据库破解模块
支持多种主流数据库的密码破解，基于THC-Hydra的设计理念实现：

#### 支持的数据库类型
- **MySQL** - 支持标准认证和协议级破解
- **PostgreSQL** - 支持MD5和明文认证
- **MSSQL** - 支持Windows和SQL Server认证
- **Oracle** - 支持Oracle数据库认证
- **MariaDB** - 支持标准认证和协议级破解

#### 功能特性
- **多线程并发**: 支持自定义并发线程数
- **字典攻击**: 支持用户名和密码字典文件
- **协议级破解**: 高级协议分析功能
- **实时进度**: 显示破解进度和统计信息
- **错误处理**: 完善的错误处理和超时控制

### 8. 其他功能模块
- **密码字典生成** (crunch): 自定义密码字典生成
- **进程服务分析** (process): 系统进程和服务分析
- **用户信息分析** (userinfo): 本地用户和组分析
- **SAM文件分析** (sam): Windows SAM文件解析
- **路由检测** (route): 网络路由跳数检测
- **FTP破解** (ftp): FTP服务密码破解
- **SSH破解** (ssh): SSH服务密码爆破
- **目录扫描** (dirscan): 网站目录结构扫描

## 🔧 详细使用指南

### 根命令参数
```bash
./GYscan.exe [command] [flags]

全局参数:
  -h, --help           显示帮助信息
  -v, --version        显示版本信息
  -s, --silent         静默模式，仅输出关键结果
      --key string     流量加密密钥 (AES-256)
      --proxy string   代理服务器 (支持 HTTP/SOCKS5)
```

### 各模块使用示例

#### WebShell生成
```bash
# 生成PHP小马
./GYscan.exe webshell -t small -o webshell.php -p password

# 生成PHP大马（无密码版本）
./GYscan.exe webshell -t large --no-password -o large.php

# 生成带编码混淆的WebShell
./GYscan.exe webshell -t small -o encoded.php -e base64 -obfuscate 2
```

#### 数据库破解
```bash
# MySQL数据库破解
./GYscan.exe database mysql://192.168.1.100:3306 -u user.txt -p pass.txt

# PostgreSQL数据库破解
./GYscan.exe database postgres://192.168.1.101:5432 -u admin -p top100.txt

# MSSQL数据库破解（多线程）
./GYscan.exe database mssql://192.168.1.102:1433 -u user.txt -p pass.txt -t 10

# Oracle数据库破解
./GYscan.exe database oracle://192.168.1.103:1521 -u scott -p tiger -d orcl

# MariaDB数据库破解
./GYscan.exe database mariadb://192.168.1.104:3306 -u root -p password.txt -d test
```

#### 密码字典生成
```bash
# 生成4-6位字母数字密码字典
./GYscan.exe crunch 4 6 abcdefghijklmnopqrstuvwxyz0123456789 -o passwords.txt

# 生成8位数字密码字典（多线程）
./GYscan.exe crunch 8 8 0123456789 -o numbers.txt -t 8
```

#### 进程服务分析
```bash
# 显示所有进程和服务信息
./GYscan.exe process

# 仅显示高权限进程和服务
./GYscan.exe process -H

# JSON格式输出
./GYscan.exe process --output json
```

#### 用户信息分析
```bash
# 分析本地用户和组信息
./GYscan.exe userinfo

# 仅显示用户信息
./GYscan.exe userinfo --users-only

# 显示详细信息
./GYscan.exe userinfo --detailed
```

#### SAM文件分析
```bash
# 分析SAM文件
./GYscan.exe sam C:\Windows\System32\config\SAM

# 显示详细用户信息
./GYscan.exe sam C:\Windows\System32\config\SAM --details

# 导出结果到文件
./GYscan.exe sam C:\Windows\System32\config\SAM --export users.txt
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
- [x] 数据库破解模块 (MySQL/PostgreSQL/MSSQL/Oracle/MariaDB)
- [x] WebShell生成模块
- [x] 密码字典生成模块
- [x] 进程服务分析模块
- [x] 用户信息分析模块
- [x] SAM文件分析模块
- [x] 路由检测模块
- [x] FTP破解模块
- [x] SSH破解模块
- [x] 目录扫描模块

### 开发中功能
- [ ] 资产探测模块
- [ ] 凭证处理模块
- [ ] 横向执行模块
- [ ] 权限提升模块
- [ ] 痕迹清理模块
- [ ] 安全加固功能

## 🤝 贡献指南

欢迎提交Issue和Pull Request来帮助改进项目：

1. Fork 项目仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 📝 更新日志

### v1.0.0 (当前版本)
- 初始版本发布
- 集成多种安全测试功能
- 支持主流数据库破解
- WebShell生成工具
- 完善的命令行界面

## 🔗 相关资源

- [Go语言官方网站](https://golang.org/)
- [Cobra CLI框架](https://github.com/spf13/cobra)
- [安全测试最佳实践](https://owasp.org/)

## 📞 技术支持

如有问题或建议，请通过以下方式联系：
- 提交GitHub Issue
- 发送邮件至作者
- 关注B站账号获取更新

---

**免责声明**: 本工具仅用于授权的安全测试和教育目的。使用者需确保遵守当地法律法规，并承担使用本工具所产生的全部责任。