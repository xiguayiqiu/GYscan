
# 🔍 GYscan - 全能安全审计与渗透测试工具集

![Version](https://img.shields.io/badge/version-2.9.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green.svg)
![License](https://img.shields.io/badge/license-Apache2.0-red.svg)

**一个为白帽黑客和安全爱好者打造的一站式安全测试工具箱！无需安装多个工具，GYscan帮你搞定一切。**

---

## 🎯 为什么选择GYscan？

### 🔥 六大核心优势

| 特性 | 说明 |
|------|------|
| **🔧 全能集成** | XSS/CSRF检测、密码破解、网络扫描、漏洞利用...一个工具全搞定 |
| **🐍 Go语言开发** | 跨平台、高性能、单文件部署、无需依赖地狱 |
| **👶 小白友好** | 清晰的命令行界面、详细的帮助文档、示例丰富 |
| **⚡ 高速并发** | 支持多线程、协程并发，效率翻倍 |
| **🛡️ 安全第一** | 内置防沙箱、反分析，保护你的测试环境 |
| **📊 专业报告** | HTML/JSON/文本多格式输出，方便存档和分析 |

---
## GYscan官方网站公告

**GYscan以在2.9.0版本之后会添加卡密审核机制，打击破解和非法未授权攻击！**

点击链接加入腾讯频道进行审核授权【弈秋忘忧白帽】：https://pd.qq.com/s/qi4s0obk?b=9

[GYscan官网](https://gyscan.space)




## ✨ 功能模块总览

### 🕵️ Web漏洞检测
- **XSS扫描** - 反射型、存储型、DOM型全支持，内置xss-labs级别Payload库
- **CSRF检测** - 7种攻击场景全面测试，Cookie SameSite检查
- **WAF识别** - 规则匹配+SimHash相似度分析，准确识别云WAF
- **Web指纹** - 自动识别服务器、框架、技术栈
- **目录扫描** - 并发暴力破解，按状态码分类结果

### 🔐 密码破解套件
- **数据库破解** - MySQL/PostgreSQL/Oracle/MSSQL/MariaDB全覆盖
- **FTP破解** - 完整FTP协议实现，安全机制感知
- **SSH破解** - Hydra风格输出，服务器限制智能应对
- **字典生成** - 基于个人信息的智能字典（CUPP）

### 🌐 网络工具集
- **Nmap集成** - 多种扫描类型、OS识别、服务识别
- **子域名枚举** - 字典爆破、通配符检测
- **实时主机检测** - 端口检查→HTTP探测→WAF过滤→SimHash去重
- **端口扫描** - 自定义端口范围、超时控制
- **蜜罐检测** - 协议分析+行为模式识别

### 💣 漏洞利用与PoC
- **Exploit-DB集成** - 本地数据库搜索（关键词/CVE/平台/类型）
- **PoC生成** - Python模板、Nmap NSE脚本自动生成
- **Shellcode管理** - 完整的Shellcode库

### 📡 协议栈与DoS
- **网络协议栈** - 完整的Ethernet/IP/TCP/UDP实现
- **自定义数据包** - 原始套接字编程，任意数据包构造
- **DoS测试** - TCP/UDP/ICMP/IGMP洪水攻击，Turbo模式

### 🔒 安全审计
- **Windows审计** - goss、nuclei集成
- **Linux审计** - lynis、ssh-audit、trivy集成
- **系统信息** - 完整的系统信息收集
- **进程分析** - 跨平台进程/服务分析

---

## 🚀 快速开始（3分钟上手）

### 1️⃣ 下载与安装

#### Windows用户
```powershell
# 下载GYscan
wget https://github.com/xiguayiqiu/GYscan/releases/download/v2.9.0/GYscan-Windows.zip

# 运行！
.\GYscan.exe --help
```

#### Linux用户
```bash
# 下载GYscan
wget https://github.com/xiguayiqiu/GYscan/releases/download/v2.9.0/GYscan-linux-amd64.zip

# 运行！
./GYscan-install.sh
```

> [!NOTE]
>
> GYscan有GYscan-wt程序（Windows的SYSTEM提权工具）不会被GYscan-install.sh脚本安装！因为这个程序是给您的一个合法权限提升的工具
>
> 原理和psexec类似！并不能从普通账户提升至SYSTEM权限！只能使用管理员权限提升至SYSTEM权限！这一点请注意！！！



### 2️⃣ 第一个扫描 - XSS检测

让我们扫描一个目标网站是否存在XSS漏洞：

```bash
# 扫描反射型XSS
GYscan xss --url "http://example.com/search?q=test" --type reflected

# 扫描所有类型的XSS
GYscan xss --url "http://example.com" --type all --verbose
```

### 3️⃣ 密码破解 - SSH爆破

```bash
# 使用用户名和密码列表爆破SSH
GYscan ssh --target 192.168.1.100 --port 22 \
  --username root --password-file pass.txt \
  --threads 5 --stop-on-first
```

### 4️⃣ 网络扫描

```bash
# 扫描子网存活主机
GYscan living --cidr 192.168.1.0/24

# Nmap端口扫描
GYscan nmap --target 192.168.1.100 --ports 1-1000 --scan-type syn
```

---

## 📖 详细使用指南

### 🔍 漏洞检测模块

#### XSS扫描
```bash
# 基本用法
GYscan xss --url &lt;目标URL&gt;

# 完整参数
GYscan xss --url "http://example.com/page?id=1" \
  --type all                    # 扫描类型: reflected/stored/dom/all
  --payload-level high          # Payload级别: basic/medium/high/waf
  --verbose                     # 详细输出
  --test-mode                   # 运行测试用例
```

#### CSRF检测
```bash
GYscan csrf --url "http://example.com/change-password" \
  --method POST \
  --data "newpass=123456" \
  --login-url "http://example.com/login" \
  --login-username admin \
  --login-password admin123
```

#### WAF检测
```bash
GYscan waf --url "http://example.com" --verbose
```

### 🔐 密码破解模块

#### 数据库破解
```bash
# MySQL破解
GYscan database --type mysql --host 192.168.1.100 --port 3306 \
  --username root --password-file pass.txt --threads 10

# Oracle破解
GYscan database --type oracle --host 192.168.1.100 --port 1521 \
  --username-file users.txt --password-file pass.txt
```

#### FTP破解
```bash
GYscan ftp --host 192.168.1.100 --port 21 \
  --username anonymous --password any@example.com \
  --threads 5
```

#### SSH破解
```bash
# 单个目标
GYscan ssh --target 192.168.1.100 --port 22 \
  --username-file users.txt --password-file pass.txt \
  --threads 3 --attempt-delay 1000

# 多目标（从文件）
GYscan ssh --target-file targets.txt \
  --username root --password kali --stop-on-first
```

### 🌐 网络工具模块

#### 目录扫描
```bash
GYscan dirscan --url "http://example.com" \
  --wordlist dirmap/medium.txt \
  --threads 20 --timeout 5
```

#### 子域名枚举
```bash
GYscan subdomain --domain example.com \
  --wordlist subdomains.txt --threads 10
```

#### 实时主机检测
```bash
GYscan living --cidr 192.168.1.0/24 --ports 80,443,8080
```

### 💣 Exploit-DB模块

#### 搜索漏洞
```bash
# 关键词搜索
GYscan exp search "apache struts"

# CVE搜索
GYscan exp search --cve CVE-2021-44228

# 平台搜索
GYscan exp search --platform windows --type local

# 保存结果
GYscan exp search "mysql" -o results.json --format json
```

#### 查看和生成PoC
```bash
# 查看漏洞详情
GYscan exp info 40564

# 显示PoC代码
GYscan exp show 40564

# 生成PoC（带自定义目标）
GYscan exp generate 40564 -t 192.168.1.100 -p 8080

# 生成Nmap NSE脚本
GYscan exp nmap 40564 -o vuln-40564.nse
```

---

## 🎬 实际使用示例

### 场景1：Web应用安全评估

```bash
# 1. 信息收集
GYscan webfp --url "http://target.com"
GYscan whois --domain target.com
GYscan subdomain --domain target.com

# 2. 漏洞扫描
GYscan xss --url "http://target.com/search?q=test" --type all
GYscan csrf --url "http://target.com/comment" --method POST
GYscan waf --url "http://target.com"

# 3. 目录扫描
GYscan dirscan --url "http://target.com" --wordlist dirmap/medium.txt

# 4. 生成报告
# 所有命令都支持 &gt; report.html 输出到文件
```

### 场景2：内网渗透测试

```bash
# 1. 主机发现
GYscan living --cidr 192.168.0.0/16

# 2. 端口扫描
GYscan nmap --target 192.168.1.100 --ports 1-65535

# 3. 服务爆破
GYscan ssh --target 192.168.1.100 --username-file users.txt --password-file pass.txt
GYscan ftp --host 192.168.1.101 --username anonymous --password test@test.com
GYscan database --type mysql --host 192.168.1.102 --username root --password-file pass.txt

# 4. 漏洞利用
GYscan exp search "linux kernel"
```

---

## 📋 完整命令列表

| 模块 | 命令 | 功能 |
|------|------|------|
| **Web漏洞** | `xss` | XSS漏洞检测 |
| | `csrf` | CSRF漏洞检测 |
| | `waf` | WAF识别 |
| | `webfp` | Web指纹识别 |
| | `dirscan` | 目录扫描 |
| | `webshell` | WebShell生成 |
| **密码破解** | `database` | 数据库密码破解 |
| | `ftp` | FTP密码破解 |
| | `ssh` | SSH密码破解 |
| | `cupp` | 密码字典生成 |
| **网络工具** | `nmap` | 网络扫描 |
| | `subdomain` | 子域名枚举 |
| | `living` | 实时主机检测 |
| | `whois` | Whois查询 |
| | `ws` | WebSocket测试 |
| **漏洞利用** | `exp` | Exploit-DB集成 |
| | `dos` | DoS测试 |
| **安全审计** | `lynis` | Linux安全审计 |
| | `ssh-audit` | SSH配置审计 |
| | `trivy` | 容器/镜像扫描 |
| | `goss` | Windows配置审计 |
| | `nuclei` | 模板扫描 |
| **系统工具** | `userinfo` | 用户信息收集 |
| | `process` | 进程分析 |
| | `system` | 系统信息 |
| | `wt` | Windows终端工具 |
| **其他** | `about` | 关于GYscan |
| | `help` | 帮助信息 |

---

## 🔧 配置与定制

### 自定义字典
GYscan使用标准的文本字典文件，每行一个条目：

```
# pass.txt 示例
password
123456
admin
root
qwerty
```

### Payload级别
- `basic` - 基础Payload，快速扫描
- `medium` - 中级Payload，包含编码绕过
- `high` - 高级Payload，完整的xss-labs级别
- `waf` - WAF绕过专用Payload

---

## ⚠️ 免责声明

&gt; **重要提示：**
&gt; 
&gt; 1. GYscan仅用于**授权的安全测试**和**学习研究**目的
&gt; 2. 使用本工具进行的任何操作必须符合当地法律法规
&gt; 3. 未经授权访问他人系统是违法行为
&gt; 4. 使用者需自行承担使用本工具的一切责任和后果
&gt; 5. 作者不对任何滥用或违法行为负责

---

## 🤝 贡献与反馈

欢迎提交Issue和Pull Request！

### 如何贡献
1. Fork本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

---

## 📞 联系方式

- 项目地址Gitee：[GYscan: GYscan是一个十分强大的综合渗透的工具（sam分析、ssh破解、用户本地分析、SQL数据库破解等等功能）](https://gitee.com/bzhanyiqiua/GYscan)
- 问题反馈Gitee：[Issues · BiliBili-Yiqiu/GYscan - Gitee.com](https://gitee.com/bzhanyiqiua/GYscan/issues)
- 项目地址Github：[xiguayiqiu/GYscan: GYscan是一款基于Go语言开发的现代化综合渗透测试工具，专为安全研究人员、渗透测试工程师和红队成员设计。项目采用模块化架构，包含C2服务器端和客户端组件，支持Windows和Linux平台，提供系统安全分析和漏洞扫描功能。](https://github.com/xiguayiqiu/GYscan)
- 问题反馈Github：[Issues · xiguayiqiu/GYscan](https://github.com/xiguayiqiu/GYscan/issues)

---

## 🙏 致谢

感谢以下开源项目（模仿原理没有他们的源码）：
- Exploit-DB
- Nmap
- Lynis
- Trivy
- 以及所有安全社区的贡献者！

---

## 📜 许可证

本项目采用GPL许可证 - 详见 [LICENSE](LICENSE) 文件

---

## ⭐ 如果觉得有用，请给个Star！

你的支持是我们持续改进的动力！🌟

---

**开始你的安全之旅吧！** 🚀

```bash
# 查看所有可用命令
GYscan --help

# 开始你的第一次扫描！
GYscan about
```

