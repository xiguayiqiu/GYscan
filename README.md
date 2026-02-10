[**English**](README-en.md)

# GYscan - 综合渗透测试工具

[![Version](https://img.shields.io/badge/Version-v2.8.2-blue)](https://gyscan.space)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen)](https://www.apache.org/licenses/LICENSE-2.0)

---

## ⚠️ 版权声明与防盗版警告

**【重要】本项目在分享时，不管是文章、工具介绍、视频介绍都必须保留原作者的仓库名称和署名！未经授权的转载、修改、再分发均属侵权行为！**

### 侵权行为法律后果

未经授权使用本工具进行未授权测试、修改本项目源码或重新打包发布，可能面临以下法律风险：
- **民事责任**：侵犯著作权，需承担赔偿损失、消除影响等民事责任
- **行政责任**：违反网络安全法等相关规定，可能面临行政处罚
- **刑事责任**：情节严重者可能构成非法侵入计算机信息系统罪

**我们已对所有修改版本进行技术溯源，偷梁换柱者必将被追究法律责任！**

---

## 🔒 防盗版声明

本项目仅通过以下官方渠道发布，任何其他来源均为盗版：

| 渠道 | 地址 |
|------|------|
| **GitHub主仓库** | https://github.com/gyscan/GYscan |
| **Gitee主仓库** | https://gitee.com/bzhanyiqiua/GYscan |
| **官方网站** | https://gyscan.space |

### 盗版识别方法

1. **非官方域名**：所有非 gyscan.space 域名均为盗版
2. **修改作者信息**：移除或修改原项目作者署名
3. **二次分发**：未获得授权的转载和再发布
4. **付费售卖**：本项目完全免费，任何收费行为均为诈骗

> **如发现盗版行为，请通过官网联系方式举报，我们将追究其法律责任！**

---

## 📢 官网恢复公告

GYscan官方网站（gyscan.space）已恢复正常服务。

---

## 🏢 官方网站

**请认准唯一官方网站！本软件仅此一个网站，其他均为仿冒！**

> **⚠️ 警惕仿冒网站**
> 我们不会通过任何非官方渠道要求您提供账号、密码或支付任何费用
> 如遇到仿冒网站，请立即停止访问并通过官网举报

**[GYscan官方网站](https://gyscan.space/)**

---

## 📋 目录

- [项目简介](#项目简介)
- [核心功能](#核心功能)
- [安装指南](#安装指南)
- [快速开始](#快速开始)
- [命令列表](#命令列表)
- [更新日志](#更新日志)
- [贡献指南](#贡献指南)
- [许可证](#许可证)
- [免责声明](#免责声明)

---

## 项目简介

GYscan 是一款用 Go 语言开发的专业综合渗透测试工具。基于 Go 语言的高性能特性，GYscan 具备出色的并发处理能力和跨平台兼容性，能够高效地协助安全研究人员和渗透测试人员完成安全评估工作。

该工具集成了丰富的渗透测试功能模块，涵盖端口扫描、服务识别、漏洞检测、远程命令执行、弱口令爆破、配置审计等核心能力，为用户提供了一站式的安全评估解决方案。

### 基本信息

| 属性 | 值 |
|------|-----|
| **项目名称** | GYscan |
| **开发语言** | Go 1.24+ |
| **支持平台** | Windows 7+/Linux/macOS |
| **许可证** | Apache 2.0 |
| **最新版本** | v2.8.2 |
| **作者** | BiliBili-弈秋啊 |

---

## 核心功能

### 🔍 网络探测与扫描

| 功能 | 描述 |
|------|------|
| **端口扫描** | 支持多种扫描技术，包括TCP SYN/Connect/ACK/FIN/XMAS/NULL扫描 |
| **服务识别** | 基于指纹识别的服务版本检测，支持1999+ Web指纹 |
| **主机发现** | ICMP/ARP/TCP/UDP多协议主机发现，支持IPv4/IPv6 |
| **操作系统识别** | 远程操作系统指纹识别 |

### 🔐 密码攻击与凭证获取

| 功能 | 描述 |
|------|------|
| **SSH爆破** | 支持Hydra风格的多线程SSH密码爆破 |
| **SMB攻击** | SMB连接测试、共享枚举、远程命令执行 |
| **FTP爆破** | FTP服务器密码破解 |
| **数据库爆破** | MySQL、PostgreSQL、Oracle、MSSQL数据库弱口令检测 |

### 🌐 Web应用安全

| 功能 | 描述 |
|------|------|
| **Web指纹识别** | 网站技术栈识别，支持105+技术指纹检测 |
| **XSS检测** | 反射型、存储型、DOM型XSS漏洞检测 |
| **CSRF检测** | 跨站请求伪造漏洞检测 |
| **WAF识别** | 检测目标是否部署WAF及其类型 |
| **目录扫描** | Web路径枚举，支持自定义字典和扩展名 |
| **文件上传检测** | 文件上传漏洞检测，支持多种绕过技术 |
| **WebSocket测试** | WebSocket连接测试和协议分析 |

### 🏢 域环境安全

| 功能 | 描述 |
|------|------|
| **AD CS漏洞检测** | ESC1-ESC8证书模板漏洞检测 |
| **LDAP枚举** | 域用户、组、计算机、组织单位枚举 |
| **Kerberoasting** | SPN账户发现，用于票据攻击 |
| **AS-REP Roasting** | 预认证绕过账户检测 |

### 📡 远程管理

| 功能 | 描述 |
|------|------|
| **PowerShell** | PowerShell远程命令执行 |
| **WMI** | WMI远程管理工具 |
| **RDP** | RDP远程桌面相关功能 |
| **DCOM** | DCOM远程执行 |

### 🔎 安全评估

| 功能 | 描述 |
|------|------|
| **配置审计** | 基于CIS Benchmark的58项配置检查 |
| **蜜罐检测** | 识别目标是否为蜜罐系统 |
| **补丁检测** | 远程系统补丁状态探测 |
| **Exploit-DB** | 集成46,928条漏洞利用数据 |

### 💻 系统信息收集

| 功能 | 描述 |
|------|------|
| **子域名挖掘** | 基于DNS查询的子域名枚举，支持字典爆破和通配符检测 |
| **进程信息** | 远程系统进程和服务枚举 |
| **用户枚举** | 本地用户和组信息收集 |
| **Windows日志** | Windows事件日志查看 |
| **Linux枚举** | Linux本地信息枚举和权限提升检测 |
| **WiFi密码** | Windows系统WiFi密码获取 |

---

## 安装指南

### 环境要求

- **操作系统**：Windows 10+/Linux/macOS
- **Go版本**：Go 1.24 或更高版本
- **依赖**：Nmap（部分功能需要）

### Linux 安装

```bash
# 克隆项目
git clone https://github.com/gyscan/GYscan.git
cd GYscan/Client

# 安装依赖
go mod download

# 构建项目
go build -o GYscan .

# 复制到系统路径（可选）
sudo cp GYscan /usr/local/bin/
```

### Windows 安装

```powershell
# 使用PowerShell构建
cd GYscan
.\build.ps1
```

### 依赖安装（Linux）

```bash
# Debian/Ubuntu/Kali
sudo apt install -y libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev \
    libxi-dev libxxf86vm-dev libgl1-mesa-dev libglu1-mesa-dev mesa-common-dev \
    build-essential pkg-config dbus-x11 libdbus-1-dev libpcap-dev

# RedHat/CentOS/Fedora
sudo yum install -y libX11-devel libXcursor-devel libXrandr-devel libXinerama-devel \
    libXi-devel libXxf86vm-devel mesa-libGL-devel mesa-libGLU-devel \
    gcc-c++ pkgconfig dbus-x11 dbus-devel libpcap-devel
```

---

## 快速开始

### 基本用法

```bash
# 显示帮助信息
./GYscan help

# 显示版本信息
./GYscan --version

# 禁用颜色输出
./GYscan --no-color

# 使用代理
./GYscan --proxy socks5://127.0.0.1:1080
```

### 常用命令示例

```bash
# 端口扫描
./GYscan scan -t 192.168.1.1 -p 1-1000

# SSH密码爆破
./GYscan ssh -t 192.168.1.1 -u root -P /path/to/passwords.txt

# Web目录扫描
./GYscan dirscan -u http://example.com -w dirmap/dicc.txt

# XSS漏洞检测
./GYscan xss -u "http://example.com/?id=1"

# WAF识别
./GYscan waf -u http://example.com

# 蜜罐检测
./GYscan mg -t 192.168.1.1

# AD CS漏洞检测
./GYscan adcs -t dc.example.com

# 配置审计
./GYscan ca -t 192.168.1.1
```

---

## 命令列表

### 稳定命令

| 命令 | 分组 | 描述 |
|------|------|------|
| `scan` | 网络扫描 | 综合端口扫描工具 |
| `nmap` | 网络扫描 | Nmap扫描结果解析 |
| `dirscan` | 网络扫描 | Web目录枚举 |
| `route` | 网络扫描 | 路由跳数检测 |
| `whois` | 网络扫描 | Whois域名查询 |
| `scapy` | 网络扫描 | 高级网络包操作 |
| `ssh` | 密码攻击 | SSH密码爆破 |
| `ftp` | 密码攻击 | FTP密码破解 |
| `database` | 密码攻击 | 数据库密码破解 |
| `crunch` | 密码攻击 | 密码字典生成 |
| `cupp` | 密码攻击 | 通用用户密码分析 |
| `smb` | 远程管理 | SMB协议操作 |
| `rdp` | 远程管理 | RDP远程桌面 |
| `powershell` | 远程管理 | PowerShell执行 |
| `wmi` | 远程管理 | WMI远程管理 |
| `webshell` | Web安全 | WebShell生成 |
| `waf` | Web安全 | WAF检测 |
| `xss` | Web安全 | XSS漏洞检测 |
| `fu` | Web安全 | 文件上传检测 |
| `ws` | Web安全 | WebSocket测试 |
| `exp` | Web安全 | Exploit-DB搜索 |
| `process` | 信息收集 | 进程信息枚举 |
| `userinfo` | 信息收集 | 用户信息收集 |
| `winlog` | 信息收集 | Windows日志查看 |
| `pc` | 信息收集 | 补丁探测 |
| `linenum` | 综合工具 | Linux信息枚举 |
| `linux-kernel` | 综合工具 | Linux内核漏洞 |
| `wwifi` | 综合工具 | WiFi密码获取 |
| `about` | 综合工具 | 工具信息 |

### 测试阶段命令

| 命令 | 描述 |
|------|------|
| `csrf` | CSRF漏洞检测 |
| `dcom` | DCOM远程执行 |
| `ldap` | LDAP枚举 |
| `mg` | 蜜罐识别 |
| `adcs` | AD CS漏洞检测 |

---

## 更新日志

### v2.8.2

**CUPP社会工程学密码生成工具**

#### 新增功能

- **cupp命令 - 通用用户密码分析器**
  - 基于目标用户信息生成定制化密码字典
  - 快速模式：直接基于名字生成密码变体
  - 交互式模式：通过命令行引导输入详细信息
  - 改进字典模式：对现有字典进行增强和扩展
  - Leet模式支持：字母转数字符号（e→3, a→4, o→0）
  - 特殊字符和随机数字组合
  - 支持密码词汇连接和组合

- **命令交互优化**
  - 无参数运行时自动显示帮助信息
  - 所有模块支持-h/--help参数
  - 更友好的用户交互体验

#### 命令示例

```bash
# 基于名字生成密码
./GYscan cupp john
./GYscan cupp john --leet -n -s

# 交互式输入
./GYscan cupp -i

# 改进现有字典
./GYscan cupp -w wordlist.txt --concat --leet
./GYscan cupp -w wordlist.txt -n -s
```

### v2.8.1

**子域名挖掘与Web指纹识别**

#### 新增功能

- **sub命令 - 子域名挖掘工具**
  - 基于DNS查询的子域名枚举
  - 支持自定义字典爆破（默认内置500+常见子域名字典）
  - DNS记录查询（A/CNAME/MX/TXT/NS）
  - 高并发扫描（默认50线程）
  - 自动通配符检测和过滤
  - HTTP验证确认子域名可用性
  - 实时进度显示和彩色输出
  - 支持结果保存到文件

- **webfp命令 - 网站技术指纹识别**
  - 基于HTTP响应头、HTML内容、资源文件路径的指纹识别
  - 支持105+技术指纹检测，涵盖20+类别
  - 前端框架：React、Vue.js、Angular、Svelte、Next.js、Nuxt.js等
  - 后端框架：Express、NestJS、Django、Flask、Laravel等
  - CMS系统：WordPress、Drupal、Joomla、Shopify等
  - UI框架：Bootstrap、Tailwind CSS、Ant Design等
  - JavaScript库：jQuery、Lodash、Axios等
  - CDN/托管：Cloudflare、Vercel、Netlify等
  - 分析工具：Google Analytics、Hotjar等
  - 置信度评分机制
  - JSON格式输出支持

#### 技术改进

- HTTP客户端优化，支持超时和重定向控制
- HTML解析增强，提取脚本、CSS、Meta标签
- 多维度指纹匹配算法
- 并发安全的扫描引擎
- 优雅退出支持（Ctrl+C中断处理）

#### 命令示例

```bash
# 子域名挖掘
./GYscan sub example.com
./GYscan sub example.com -w subdomains.txt
./GYscan sub example.com -t 100
./GYscan sub example.com -T CNAME
./GYscan sub example.com -f results.txt
./GYscan sub example.com --no-http

# Web指纹识别
./GYscan webfp https://example.com
./GYscan webfp https://example.com -v
./GYscan webfp https://example.com -o result.json
./GYscan webfp https://example.com -c "Frontend Frameworks"
./GYscan webfp https://example.com -t 30s
```

### v2.8.0

**Exploit-DB 集成与漏洞利用管理**

#### 新增功能

- **exp命令 - Exploit-DB漏洞利用管理模块**
  - 集成Exploit-DB数据库，包含46,928条漏洞利用和1,065条shellcode
  - 支持多种搜索方式：关键词、CVE编号、平台、漏洞类型
  - 支持精确匹配和大小写敏感搜索
  - 支持JSON和文本格式输出
  - 支持将搜索结果保存到文件

- **漏洞利用详情查看**
  - 支持通过EDB-ID查询漏洞详细信息
  - 显示漏洞描述、平台、类型、作者、发布日期、CVE等
  - 支持详细模式显示标签和别名信息

- **PoC代码管理**
  - `show`子命令：查看漏洞利用代码内容
  - `copy`子命令：复制漏洞利用代码到指定目录
  - `generate`子命令：生成带GYscan头部的PoC代码
  - 支持自定义目标参数（-t目标地址、-p端口、--ssl）

- **PoC模板生成**
  - `simple`子命令：生成简单的Python PoC模板
  - 支持快速测试和定制开发
  - 支持参数化目标地址和端口

- **Nmap NSE脚本生成**
  - `nmap`子命令：生成Nmap漏洞检测脚本
  - 可直接用于Nmap扫描
  - 支持输出到Nmap脚本目录

- **数据库管理**
  - `stats`子命令：显示数据库统计信息
  - `list`子命令：列出可用平台和漏洞类型
  - `reload`子命令：重新加载数据库
  - 支持懒加载，优化启动速度

#### 技术改进

- 数据库CSV解析优化
- 多路径查找支持（支持多种安装路径）
- 并发安全的数据库加载
- 智能文件路径匹配
- 彩色终端输出支持

#### 命令示例

```bash
# 搜索漏洞利用
./GYscan exp search "apache struts"
./GYscan exp search --cve CVE-2021-44228
./GYscan exp search --platform windows --type local

# 查看漏洞详情
./GYscan exp info 40564
./GYscan exp info 40564 -v

# 查看和复制PoC代码
./GYscan exp show 40564 > poc.py
./GYscan exp copy 40564 /tmp/exploits/

# 生成PoC
./GYscan exp generate 40564 -t 192.168.1.100 -p 8080 -o /tmp/pocs/
./GYscan exp simple 40564 -t 192.168.1.100 -o poc.py

# 生成Nmap脚本
./GYscan exp nmap 40564 -o /usr/share/nmap/scripts/

# 数据库管理
./GYscan exp stats
./GYscan exp list platforms
./GYscan exp list types
```

### v2.7.2

**IPv6支持增强**

#### 新增功能

- **IPv6扫描支持**
  - 新增 `-6, --ipv6` 标志启用IPv6扫描模式
  - 支持标准IPv6地址：`2001:db8::1`、`::1`、`fe80::1`
  - 支持IPv6地址解析和DNS查询（AAAA记录）
  - 支持IPv6主机发现（ICMPv6 Echo请求）
  - 支持IPv6端口扫描和服务识别
  - 支持IPv6链路本地地址（带zone ID）
  - 自动识别IPv4/IPv6地址并选择合适的网络连接方式

#### 技术改进

- 新增 `isIPv6()` 函数用于IPv6地址检测
- 新增 `isPrivateIPv6()` 函数支持IPv6私有地址范围
- 新增 `formatIPForConnection()` 函数处理IPv6地址格式化
- 新增 `icmpv6Ping()` 和 `systemPing6()` 函数支持ICMPv6探测
- 更新 `hostDiscovery()` 为IPv6目标跳过ARP探测

- **WebSocket测试工具（ws命令）**
  - 支持WebSocket连接测试（ws://和wss://）
  - 支持文本和二进制消息发送（支持base64/hex编码）
  - 支持自定义HTTP头和Origin请求头
  - 支持WSS TLS证书验证跳过
  - 支持WebSocket子协议
  - 支持自动重连机制（指数退避+随机抖动）
  - 支持响应断言验证
  - 支持启用心跳检测（Ping/Pong）

- **Scan模块端口扫描优化**
  - 支持完整六种端口状态检测
  - 新增隐蔽扫描类型：TCP FIN/XMAS/NULL/ACK/窗口/Maimon扫描
  - 修复UDP扫描准确性bug
  - 优化主机发现策略

### v2.7.1

**SSH模块功能增强与问题修复**

- **SSH批量目标爆破优化**
  - 支持通过 `--file` 参数从文件批量读取目标IP地址
  - 优化多目标并发爆破逻辑，支持多线程同时处理多个目标
  - 新增实时进度显示，类似Hydra风格的输出格式

- **问题修复**
  - 修复SSH目标文件解析问题
  - 修复多目标模式下结果统计不正确的问题
  - 修复批量爆破时实时进度不显示的问题
  - 优化SSH连接算法配置，提升与不同SSH服务器的兼容性

### v2.7

**版本更新与配置审计功能发布**

#### 新增功能

- **pc命令** - 远程补丁探测工具
  - 基于 WhatWeb 指纹识别技术，支持 1999+ 个 Web 指纹识别
  - 支持Web服务器、数据库、缓存消息、中间件、CMS系统识别
  - 组件版本与官方漏洞库关联分析

- **配置审计（CA）模块**
  - 基于CIS Benchmark安全基线的配置合规性检查
  - 支持五大审计类别：Windows、Linux、Web、SSH、中间件
  - 共58项配置检查项
  - 支持JSON、HTML、Text三种输出格式

- **配置证据功能**
  - 显示具体配置文件路径
  - 显示配置项名称和当前值
  - 提供期望值和修复建议

#### 命令调整

- 新增 `ca` 命令 - 配置审计工具
- 新增 `pc` 命令 - 远程补丁探测工具
- 将 `mg`（蜜罐识别工具）从正式命令移至测试阶段命令
- 移除 `tui`（启动 TUI 模式）

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

- **新增pc命令** - 远程补丁探测工具
- **新增fu命令** - 文件上传漏洞检查功能
- **新增wwifi命令** - Windows系统WiFi破解功能

### v2.6.0

- **新增scapy模块** - 集成高级网络包操作工具
  - 原始网络包构造和发送功能
  - 网络接口检测和状态分析

### v2.5.4

- **新增linenum功能** - Linux本地信息枚举和权限提升工具
- **新增linux-kernel功能** - Linux内核漏洞检测工具

### v2.5.2

- **新增winlog命令** - Windows日志查看工具

### v2.5.1

- **新增waf命令** - WAF检测工具

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

---

## 贡献指南

欢迎提交 Issue 和 Pull Request 来改进项目。请确保：

1. 代码符合 Go 语言规范
2. 添加适当的测试用例
3. 更新相关文档
4. 遵循安全开发规范

---

## 许可证

本项目采用 **Apache License 2.0** 开源协议。

**您可以**自由使用、修改、分发本项目代码，但需遵守以下条件：
- 保留原始版权声明
- 在修改后的文件中添加说明
- 衍生作品需采用相同许可证

**详情请查看**：[LICENSE](LICENSE) 文件

---

## ⚖️ 免责声明

**【使用前请仔细阅读】**

1. **用途限制**：本工具仅限用于：授权的安全测试
   - 获得明确授权的安全测试项目
   - 网络安全研究和教育目的
   - 企业内部安全评估（需获得书面授权）

2. **禁止行为**：
   - ❌ 未经授权渗透任何系统
   - ❌ 非法访问或破坏他人计算机系统
   - ❌ 用于任何违法活动
   - ❌ 在未授权目标上使用本工具

3. **责任声明**：
   - 使用者需确保已获得所有必要的授权
   - 作者和 contributors 不承担任何因滥用本工具产生的法律责任
   - 本工具不提供任何形式的担保

4. **合规要求**：使用本工具前，请确保符合以下要求：
   - 遵守当地法律法规
   - 获得目标系统所有者的书面授权
   - 仅在授权范围内使用

---

**GYscan - 专注渗透测试，守护网络安全** 🛡️
